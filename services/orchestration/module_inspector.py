from dataclasses import dataclass
from typing import Any

from integrations.metasploit.rpc_client import MetasploitRPCClient


@dataclass(frozen=True)
class ModuleInspection:
    """Structured metadata returned by Metasploit for an exploit module."""

    available: bool
    module_type: str
    module_name: str
    fullname: str | None
    rank: str | None
    platform: Any
    architecture: Any
    privileged: bool | None
    check_supported: bool
    targets: Any
    default_target: Any
    options: dict[str, Any]
    default_options: dict[str, Any]
    references: Any
    raw_metadata: dict[str, Any]


class MetasploitModuleInspector:
    """Inspect Metasploit modules before exploit execution."""

    def __init__(
        self,
        rpc_client: MetasploitRPCClient | None = None,
    ) -> None:
        self.rpc_client = rpc_client or MetasploitRPCClient()

    async def inspect(
        self,
        module_type: str,
        module_name: str,
    ) -> ModuleInspection:

        metadata = await self.rpc_client.get_module_info(
            module_type=module_type,
            module_name=module_name,
        )

        return ModuleInspection(
            available=True,
            module_type=str(metadata.get("type", module_type)),
            module_name=module_name,
            fullname=self._optional_string(metadata.get("fullname")),
            rank=self._optional_string(metadata.get("rank")),
            platform=metadata.get("platform"),
            architecture=metadata.get("arch"),
            privileged=self._optional_bool(metadata.get("privileged")),
            check_supported=bool(metadata.get("check", False)),
            targets=metadata.get("targets", []),
            default_target=metadata.get("default_target"),
            options=metadata.get("options", {}) or {},
            default_options=metadata.get("default_options", {}) or {},
            references=metadata.get("references", []),
            raw_metadata=metadata,
        )

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if value is None:
            return None
        return bool(value)