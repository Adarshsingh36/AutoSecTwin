import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    await client.login()

    print("Metasploit RPC: CONNECTED")

    console = await client.create_console()

    print("\n=== CONSOLE CREATED ===")
    print(console)

    console_id = console.get("id")

    if not console_id:
        print("\nERROR: No console ID returned.")
        return

    print("\nConsole ID:", console_id)

    output = await client.read_console(console_id)

    print("\n=== CONSOLE OUTPUT ===")
    print(output)


if __name__ == "__main__":
    asyncio.run(main())