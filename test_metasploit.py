import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    print("\n=== LOGIN ===")
    token = await client.login()
    print(token)

    print("\n=== MODULE INFO ===")
    info = await client.get_module_info(
        "auxiliary",
        "scanner/http/http_version",
    )
    print(info)

    print("\n=== MODULE CHECK ===")
    result = await client.check_module(
        "auxiliary",
        "scanner/http/http_version",
        {},
    )
    print(result)


asyncio.run(main())