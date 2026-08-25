import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient
from services.orchestration.module_inspector import MetasploitModuleInspector


async def main():
    client = MetasploitRPCClient()

    await client.login()
    print("Authentication: SUCCESS")

    inspector = MetasploitModuleInspector(client)

    inspection = await inspector.inspect(
        "exploit",
        "windows/smb/ms17_010_eternalblue",
    )

    print("\n=== MODULE INSPECTION ===")

    print("Available:", inspection.available)
    print("Module:", inspection.module_name)
    print("Type:", inspection.module_type)
    print("Full name:", inspection.fullname)
    print("Rank:", inspection.rank)
    print("Platform:", inspection.platform)
    print("Architecture:", inspection.architecture)
    print("Privileged:", inspection.privileged)
    print("Check supported:", inspection.check_supported)
    print("Default target:", inspection.default_target)

    print("\nTargets:")
    print(inspection.targets)

    print("\nOptions:")
    print(inspection.options)

    print("\nDefault options:")
    print(inspection.default_options)

    print("\nReferences:")
    print(inspection.references)


if __name__ == "__main__":
    asyncio.run(main())