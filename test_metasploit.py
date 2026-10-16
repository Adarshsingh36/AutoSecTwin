import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    print("\n=== LOGIN ===")
    token = await client.login()
    print(token)

    print("\n=== MODULE INFO ===")
    module_type = "exploit"
    module_name = "windows/smb/ms17_010_eternalblue"
    info = await client.get_module_info(module_type, module_name)
    print(info)

    print("\n=== CHECK SUPPORT ===")
    print("Supports check:", info.get("check"))



if __name__ == "__main__":
    asyncio.run(main())
