"""
Tests for services/remediation/code_remediation.py. A real temp directory
is used as CODE_REMEDIATION_ALLOWED_ROOT so path-safety and file
read/write/rollback behavior is exercised for real, not mocked.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import settings
from services.remediation.code_remediation import (
    CodeChangeExecutor,
    CodeRemediationError,
    propose_code_change,
)

SAMPLE_SOURCE = '''
def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query


def unrelated_function():
    return 42


class First:
    def duplicate(self):
        return "first"


class Second:
    def duplicate(self):
        return "second"
'''


@pytest.fixture
def code_root(tmp_path, monkeypatch):
    sample_file = tmp_path / "target_module.py"
    sample_file.write_text(SAMPLE_SOURCE)
    monkeypatch.setattr(settings, "CODE_REMEDIATION_ALLOWED_ROOT", str(tmp_path))
    return tmp_path


def _vulnerability():
    return SimpleNamespace(id=1, cve_id="CVE-2099-00001", title="SQL Injection")


# ---------------------------------------------------------
# Safety: disabled by default, path traversal
# ---------------------------------------------------------


def test_disabled_by_default_without_allowed_root(monkeypatch):
    monkeypatch.setattr(settings, "CODE_REMEDIATION_ALLOWED_ROOT", None)

    with pytest.raises(CodeRemediationError, match="disabled"):
        propose_code_change("target_module.py", "vulnerable_function", _vulnerability())


def test_rejects_path_traversal(code_root):
    with pytest.raises(CodeRemediationError, match="outside"):
        propose_code_change("../../../etc/passwd", "vulnerable_function", _vulnerability())


def test_rejects_missing_file(code_root):
    with pytest.raises(CodeRemediationError, match="does not exist"):
        propose_code_change("nonexistent.py", "vulnerable_function", _vulnerability())


def test_rejects_missing_function(code_root):
    with pytest.raises(CodeRemediationError, match="No function or class"):
        propose_code_change("target_module.py", "nope_not_here", _vulnerability())


def test_rejects_ambiguous_bare_symbol(code_root):
    with pytest.raises(CodeRemediationError, match="ambiguous"):
        propose_code_change("target_module.py", "duplicate", _vulnerability())


def test_propose_accepts_qualified_symbol(code_root):
    proposal = propose_code_change("target_module.py", "Second.duplicate", _vulnerability())

    assert 'return "second"' in proposal.current_code
    assert proposal.symbol_name == "Second.duplicate"
    assert proposal.start_line > 0
    assert proposal.end_line >= proposal.start_line


# ---------------------------------------------------------
# propose_code_change
# ---------------------------------------------------------


def test_propose_extracts_correct_function_source(code_root):
    proposal = propose_code_change("target_module.py", "vulnerable_function", _vulnerability())

    assert "def vulnerable_function(user_input):" in proposal.current_code
    assert "unrelated_function" not in proposal.current_code


def test_propose_without_llm_marks_manual_authoring_required(code_root):
    """No OPENAI_API_KEY configured in the test environment -> LLMClient
    falls back to its placeholder string -> this must be detected, never
    presented as a real fix."""

    proposal = propose_code_change("target_module.py", "vulnerable_function", _vulnerability())

    assert proposal.requires_manual_authoring is True
    assert proposal.proposed_code == proposal.current_code
    assert "cannot generate a real proposed fix" in proposal.explanation


def test_propose_with_real_llm_output_produces_real_diff(code_root):
    fixed_code = (
        "def vulnerable_function(user_input):\n"
        "    query = \"SELECT * FROM users WHERE name = %s\"\n"
        "    return query, (user_input,)\n"
    )

    with patch("services.remediation.code_remediation.LLMClient") as MockClient:
        MockClient.return_value.generate.return_value = fixed_code

        proposal = propose_code_change("target_module.py", "vulnerable_function", _vulnerability())

    assert proposal.requires_manual_authoring is False
    # propose_code_change() intentionally .strip()s LLM output (models
    # often add stray leading/trailing whitespace) -- compare stripped.
    assert proposal.proposed_code == fixed_code.strip()
    assert "+" in proposal.diff and "-" in proposal.diff


# ---------------------------------------------------------
# CodeChangeExecutor.apply
# ---------------------------------------------------------


def _real_proposal(code_root, fixed_code="def vulnerable_function(user_input):\n    return 'fixed'\n"):
    with patch("services.remediation.code_remediation.LLMClient") as MockClient:
        MockClient.return_value.generate.return_value = fixed_code
        return propose_code_change("target_module.py", "vulnerable_function", _vulnerability())


def test_apply_refuses_when_requires_manual_authoring(code_root):
    proposal = propose_code_change("target_module.py", "vulnerable_function", _vulnerability())
    assert proposal.requires_manual_authoring is True

    with pytest.raises(CodeRemediationError, match="manual authoring"):
        CodeChangeExecutor().apply(proposal, approved_content_hash=proposal.content_hash)


def test_apply_refuses_on_hash_mismatch(code_root):
    proposal = _real_proposal(code_root)

    with pytest.raises(CodeRemediationError, match="does not match"):
        CodeChangeExecutor().apply(proposal, approved_content_hash="wrong-hash")


def test_apply_refuses_on_stale_diff(code_root):
    proposal = _real_proposal(code_root)

    # File changed since the proposal was generated.
    (code_root / "target_module.py").write_text("completely different content\n")

    with pytest.raises(CodeRemediationError, match="no longer contains"):
        CodeChangeExecutor().apply(proposal, approved_content_hash=proposal.content_hash)


def test_apply_refuses_when_approved_source_range_changed(code_root):
    proposal = _real_proposal(code_root)
    text = (code_root / "target_module.py").read_text()
    (code_root / "target_module.py").write_text("# inserted line\n" + text)

    with pytest.raises(CodeRemediationError, match="original source range"):
        CodeChangeExecutor().apply(proposal, approved_content_hash=proposal.content_hash)


def test_apply_succeeds_and_keeps_change_when_tests_pass(code_root, monkeypatch):
    proposal = _real_proposal(code_root)
    monkeypatch.setattr(settings, "CODE_REMEDIATION_TEST_COMMAND", "python3 -c \"import sys; sys.exit(0)\"")

    result = CodeChangeExecutor().apply(proposal, approved_content_hash=proposal.content_hash)

    assert result.applied is True
    assert result.tests_passed is True
    assert result.rolled_back is False

    new_content = (code_root / "target_module.py").read_text()
    assert "return 'fixed'" in new_content


def test_apply_rolls_back_when_tests_fail(code_root, monkeypatch):
    proposal = _real_proposal(code_root)
    original_content = (code_root / "target_module.py").read_text()
    monkeypatch.setattr(settings, "CODE_REMEDIATION_TEST_COMMAND", "python3 -c \"import sys; sys.exit(1)\"")

    result = CodeChangeExecutor().apply(proposal, approved_content_hash=proposal.content_hash)

    assert result.applied is False
    assert result.tests_passed is False
    assert result.rolled_back is True

    restored_content = (code_root / "target_module.py").read_text()
    assert restored_content == original_content
