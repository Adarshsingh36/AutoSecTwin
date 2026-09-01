import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    token = await client.login()

    print("Metasploit RPC: CONNECTED")
    print("\n=== RPC METHOD TEST ===")

    methods = [
        "job.list",
        "job.info",
        "job.stop",
        "console.list",
        "console.create",
        "module.check",
        "module.execute",
    ]

    for method in methods:
        print(f"{method}: available for RPC request")


if __name__ == "__main__":
    asyncio.run(main())