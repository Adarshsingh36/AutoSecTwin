import logging
from typing import Any
import asyncio
import httpx
import msgpack

from core.config import settings

logger = logging.getLogger(__name__)


class MetasploitRPCClient:
    """Minimal Metasploit MessagePack RPC client for exploit orchestration."""

    def __init__(
        self,
        url: str = settings.METASPLOIT_RPC_URL,
        username: str = settings.METASPLOIT_RPC_USERNAME,
        password: str = settings.METASPLOIT_RPC_PASSWORD,
        timeout: float = 30.0,
    ) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: str | None = None

    async def login(self) -> str:
        """Authenticate with Metasploit RPC and cache the token."""

        payload = ["auth.login", self.username, self.password]

        result = await self._call_raw(payload)

        token = result.get("token")

        if not token:
            raise RuntimeError(
                f"Metasploit RPC authentication did not return a token: {result}"
            )

        self._token = token

        return token

    async def run_module(
        self,
        module_type: str,
        module_name: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a Metasploit module."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "module.execute",
                token,
                module_type,
                module_name,
                options,
            ]
        )

    async def get_module_info(
        self,
        module_type: str,
        module_name: str,
    ) -> dict[str, Any]:
        """Retrieve Metasploit module metadata without executing it."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "module.info",
                token,
                module_type,
                module_name,
            ]
        )
    async def check_module(
        self,
        module_type: str,
        module_name: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a Metasploit module check without executing the exploit."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "module.check",
                token,
                module_type,
                module_name,
                options,
            ]
        )

    async def _call_raw(
        self,
        payload: list[Any],
    ) -> dict[str, Any]:
        """Send a MessagePack RPC request to Metasploit."""

        try:
            packed_payload = msgpack.packb(
                payload,
                use_bin_type=True,
            )

            async with httpx.AsyncClient(
                timeout=self.timeout
            ) as http_client:

                response = await http_client.post(
                    self.url,
                    content=packed_payload,
                    headers={
                        "Content-Type": "binary/message-pack",
                        "Accept": "binary/message-pack",
                    },
                )

                response.raise_for_status()

                data = msgpack.unpackb(
                    response.content,
                    raw=True,
                    strict_map_key=False,
                )

                data = self._decode_bytes(data)

                if not isinstance(data, dict):
                    raise RuntimeError(
                        f"Unexpected Metasploit RPC response: {data!r}"
                    )

                if data.get("error"):
                    raise RuntimeError(
                        str(data["error"])
                    )

                return data

        except httpx.HTTPError as exc:

            logger.exception(
                "Metasploit RPC HTTP request failed"
            )

            raise RuntimeError(
                "Metasploit RPC HTTP request failed"
            ) from exc

        except (
            msgpack.exceptions.UnpackException,
            ValueError,
        ) as exc:

            logger.exception(
                "Invalid MessagePack response from Metasploit"
            )

            raise RuntimeError(
                "Invalid MessagePack response from Metasploit"
            ) from exc

    async def get_job_info(
        self,
        job_id: int,
    ) -> dict[str, Any]:
        """Retrieve information about a Metasploit background job."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "job.info",
                token,
                job_id,
            ]
        )
    async def wait_for_job(
        self,
        job_id: int,
        poll_interval: float = 1.0,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Wait until a Metasploit background job completes."""

        elapsed = 0.0

        while elapsed < timeout:
            jobs = await self.list_jobs()

            if str(job_id) not in jobs:
                return {
                    "completed": True,
                    "job_id": job_id,
                }

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        return {
            "completed": False,
            "job_id": job_id,
            "timeout": True,
        }
    async def list_jobs(self) -> dict[str, Any]:
        """Retrieve currently known Metasploit jobs."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "job.list",
                token,
            ]
        )
    
    async def create_console(self) -> dict[str, Any]:
        """Create a Metasploit console."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "console.create",
                token,
            ]
        )

    async def read_console(
        self,
        console_id: str,
    ) -> dict[str, Any]:
        """Read output from a Metasploit console."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "console.read",
                token,
                console_id,
            ]
        )

    async def write_console(
        self,
        console_id: str,
        command: str,
    ) -> dict[str, Any]:
        """Write a command to a Metasploit console."""

        token = self._token or await self.login()

        return await self._call_raw(
            [
                "console.write",
                token,
                console_id,
                command,
            ]
        )

    @staticmethod
    def _decode_bytes(value: Any) -> Any:
        """Recursively convert MessagePack byte strings to Python strings."""

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")

        if isinstance(value, dict):
            return {
                MetasploitRPCClient._decode_bytes(key):
                MetasploitRPCClient._decode_bytes(val)
                for key, val in value.items()
            }

        if isinstance(value, list):
            return [
                MetasploitRPCClient._decode_bytes(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return tuple(
                MetasploitRPCClient._decode_bytes(item)
                for item in value
            )

        return value