"""
Code-change remediation.

    identify file -> identify function/class -> show current code ->
    generate proposed code -> generate diff -> explain why it fixes the
    vulnerability -> require human approval -> only apply after approval
    -> run tests -> (caller revalidates) -> record evidence

This is a different shape of remediation from the Docker twin
destroy/redeploy handler (services/remediation/handlers/docker_patch_handler.py):
there is no twin involved, the target is a source file, and "applying" it
means writing to disk. That makes the safety requirements stricter, not
looser:

  - Off by default. CODE_REMEDIATION_ALLOWED_ROOT must be explicitly set;
    with it unset, propose_code_change() and CodeChangeExecutor.apply()
    both refuse outright. There is no path where this silently activates.
  - Every proposal is content-hashed. apply() requires the approval it's
    given to carry the exact same hash as what was proposed -- approving
    one diff can never result in a different one being applied.
  - Never fabricates a fix. If no real LLM provider is configured,
    LLMClient falls back to a clearly-labelled placeholder string; this
    module detects that and marks the proposal as requiring manual
    authoring rather than presenting a fake diff as a real one.
  - Tests run after every apply, and a failure rolls the file back to its
    exact original content before returning -- a failed code change is
    never left in place.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import logging
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.config import settings
from core.exceptions import ASDEError
from database.models.vulnerability import Vulnerability
from services.llm.client import LLMClient

logger = logging.getLogger(__name__)

_FALLBACK_PREFIX = "code_recommendation: LLM provider is not configured."


class CodeRemediationError(ASDEError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="CODE_REMEDIATION_ERROR", status_code=422)


@dataclass(frozen=True)
class CodeChangeProposal:
    file_path: str
    function_name: str
    current_code: str
    proposed_code: str
    diff: str
    explanation: str
    requires_manual_authoring: bool
    content_hash: str
    start_line: int = 0
    end_line: int = 0
    symbol_name: str = ""


@dataclass(frozen=True)
class CodeChangeResult:
    applied: bool
    tests_passed: Optional[bool]
    test_output: str
    rolled_back: bool
    file_path: str
    content_hash: str
    applied_at: Optional[datetime] = None


def _require_allowed_root() -> Path:
    if not settings.CODE_REMEDIATION_ALLOWED_ROOT:
        raise CodeRemediationError(
            "Code-change remediation is disabled: CODE_REMEDIATION_ALLOWED_ROOT is not set."
        )
    return Path(settings.CODE_REMEDIATION_ALLOWED_ROOT).resolve()


def _resolve_safe_path(file_path: str) -> Path:
    """Resolve file_path and confirm it's actually inside the allowed
    root -- rejects path traversal (../../etc/passwd) and absolute paths
    outside the configured root.
    """

    allowed_root = _require_allowed_root()
    candidate = (allowed_root / file_path).resolve()

    try:
        candidate.relative_to(allowed_root)
    except ValueError:
        raise CodeRemediationError(
            f"{file_path!r} resolves outside CODE_REMEDIATION_ALLOWED_ROOT; refusing."
        )

    if not candidate.is_file():
        raise CodeRemediationError(f"{file_path!r} does not exist or is not a file.")

    return candidate


def _extract_function_source(source: str, function_name: str) -> tuple[str, int, int]:
    """Return (source_text, start_line, end_line) for the named function or
    class (1-indexed, inclusive) using Python's ast module. Only supports
    Python source -- a different language would need its own extractor,
    not a best-effort guess.
    """

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise CodeRemediationError(f"Could not parse source as Python: {exc}") from exc

    matches: list[ast.AST] = []

    def visit(node: ast.AST, path: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_path = (*path, child.name)
                if "." in function_name:
                    if ".".join(child_path) == function_name:
                        matches.append(child)
                elif child.name == function_name:
                    matches.append(child)
                visit(child, child_path)
            else:
                visit(child, path)

    visit(tree, ())

    if len(matches) > 1:
        raise CodeRemediationError(
            f"{function_name!r} is ambiguous; use a qualified symbol like ClassName.method."
        )

    if len(matches) == 1:
        node = matches[0]
        segment = ast.get_source_segment(source, node)
        if segment is None:
            raise CodeRemediationError(
                f"Found {function_name!r} but could not extract its source segment."
            )
        return segment, node.lineno, node.end_lineno or node.lineno

    raise CodeRemediationError(f"No function or class named {function_name!r} found.")


def propose_code_change(
    file_path: str,
    function_name: str,
    vulnerability: Vulnerability,
    llm_client: Optional[LLMClient] = None,
) -> CodeChangeProposal:
    """Build a proposed fix for one function/class in one file. Never
    writes anything -- this only reads the file and asks the LLM client
    for a suggestion.
    """

    safe_path = _resolve_safe_path(file_path)
    full_source = safe_path.read_text()

    current_code, start_line, end_line = _extract_function_source(full_source, function_name)

    client = llm_client or LLMClient()
    prompt = (
        f"The function/class below is affected by {vulnerability.cve_id} "
        f"({vulnerability.title or 'no title recorded'}).\n\n"
        f"Current code:\n{current_code}\n\n"
        "Propose a corrected version of this function/class that fixes the vulnerability. "
        "Return only the corrected code, with no explanation or markdown fencing."
    )
    llm_output = client.generate("code_recommendation", prompt)

    requires_manual_authoring = llm_output.startswith(_FALLBACK_PREFIX)
    proposed_code = current_code if requires_manual_authoring else llm_output.strip()

    diff = "".join(
        difflib.unified_diff(
            current_code.splitlines(keepends=True),
            proposed_code.splitlines(keepends=True),
            fromfile=f"a/{file_path} ({function_name})",
            tofile=f"b/{file_path} ({function_name})",
        )
    )

    explanation = (
        f"Proposed change to {function_name!r} in {file_path} addressing {vulnerability.cve_id}."
        if not requires_manual_authoring
        else (
            "No LLM provider is configured, so AutoSecTwin cannot generate a real proposed fix. "
            "This proposal shows the current code unchanged -- a human must author the actual "
            "fix before this can be approved and applied."
        )
    )

    content_hash = hashlib.sha256(proposed_code.encode("utf-8")).hexdigest()

    logger.info(
        "Code change proposed: file=%s function=%s requires_manual_authoring=%s",
        file_path,
        function_name,
        requires_manual_authoring,
    )

    return CodeChangeProposal(
        file_path=file_path,
        function_name=function_name,
        current_code=current_code,
        proposed_code=proposed_code,
        diff=diff,
        explanation=explanation,
        requires_manual_authoring=requires_manual_authoring,
        content_hash=content_hash,
        start_line=start_line,
        end_line=end_line,
        symbol_name=function_name,
    )


class CodeChangeExecutor:
    """Applies an approved CodeChangeProposal, runs tests, and rolls back
    on failure. Never applies without an approval whose stored content
    hash matches the proposal exactly.
    """

    def apply(
        self,
        proposal: CodeChangeProposal,
        approved_content_hash: str,
    ) -> CodeChangeResult:
        if proposal.requires_manual_authoring:
            raise CodeRemediationError(
                "This proposal requires manual authoring (no LLM-generated fix exists); "
                "refusing to apply unchanged code as if it were a remediation."
            )

        if approved_content_hash != proposal.content_hash:
            raise CodeRemediationError(
                "Approved content hash does not match this proposal's content hash -- "
                "refusing to apply a different change than what was approved."
            )

        safe_path = _resolve_safe_path(proposal.file_path)
        original_full_source = safe_path.read_text()

        if proposal.start_line and proposal.end_line:
            source_lines = original_full_source.splitlines(keepends=True)
            current_at_range = "".join(source_lines[proposal.start_line - 1 : proposal.end_line])
            if current_at_range.rstrip("\r\n") != proposal.current_code.rstrip("\r\n"):
                raise CodeRemediationError(
                    f"{proposal.file_path} no longer contains the exact approved symbol "
                    "at the original source range; refusing to apply a stale diff."
                )
            new_full_source = (
                "".join(source_lines[: proposal.start_line - 1])
                + proposal.proposed_code
                + ("\n" if current_at_range.endswith("\n") and not proposal.proposed_code.endswith("\n") else "")
                + "".join(source_lines[proposal.end_line :])
            )
        elif proposal.current_code not in original_full_source:
            raise CodeRemediationError(
                f"{proposal.file_path} no longer contains the exact code this proposal was "
                "generated against -- it may have changed since the proposal was made. Refusing "
                "to apply a stale diff."
            )
        else:
            new_full_source = original_full_source.replace(
                proposal.current_code, proposal.proposed_code, 1
            )

        safe_path.write_text(new_full_source)
        logger.info("Applied code change to %s (%s)", proposal.file_path, proposal.function_name)

        tests_passed, test_output = self._run_tests()

        if not tests_passed:
            safe_path.write_text(original_full_source)
            logger.warning(
                "Tests failed after applying code change to %s; rolled back.", proposal.file_path
            )
            return CodeChangeResult(
                applied=False,
                tests_passed=False,
                test_output=test_output,
                rolled_back=True,
                file_path=proposal.file_path,
                content_hash=proposal.content_hash,
            )

        return CodeChangeResult(
            applied=True,
            tests_passed=True,
            test_output=test_output,
            rolled_back=False,
            file_path=proposal.file_path,
            content_hash=proposal.content_hash,
            applied_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _run_tests() -> tuple[bool, str]:
        allowed_root = _require_allowed_root()
        command = shlex.split(settings.CODE_REMEDIATION_TEST_COMMAND)

        try:
            result = subprocess.run(
                command,
                cwd=str(allowed_root),
                capture_output=True,
                text=True,
                timeout=settings.CODE_REMEDIATION_TEST_TIMEOUT_SECONDS,
            )
            output = (result.stdout or "") + (result.stderr or "")
            return result.returncode == 0, output
        except subprocess.TimeoutExpired as exc:
            return False, f"Test command timed out after {settings.CODE_REMEDIATION_TEST_TIMEOUT_SECONDS}s: {exc}"
        except FileNotFoundError as exc:
            return False, f"Test command not found: {exc}"
