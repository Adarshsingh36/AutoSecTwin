import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    await client.login()

    print("Metasploit RPC: CONNECTED")

    console = await client.create_console()

    console_id = console.get("id")

    if not console_id:
        raise RuntimeError(f"Console creation failed: {console}")

    print("\n=== CONSOLE CREATED ===")
    print("Console ID:", console_id)

    # Select the EternalBlue exploit module.
    await client.write_console(
        console_id,
        "use exploit/windows/smb/ms17_010_eternalblue\n",
    )

    await asyncio.sleep(1)

    output = await client.read_console(console_id)

    print("\n=== MODULE SELECTION OUTPUT ===")
    print(output)

    # Configure only the isolated lab target.
    await client.write_console(
        console_id,
        "set RHOSTS 192.168.56.103\n",
    )

    await client.write_console(
        console_id,
        "set RPORT 445\n",
    )

    await asyncio.sleep(1)

    output = await client.read_console(console_id)

    print("\n=== CONFIGURATION OUTPUT ===")
    print(output)

    # Run Metasploit's non-exploit check.
    await client.write_console(
        console_id,
        "check\n",
    )

    print("\n=== WAITING FOR CHECK OUTPUT ===")

    for _ in range(15):
        await asyncio.sleep(1)

        output = await client.read_console(console_id)

        print("\n--- CONSOLE READ ---")
        print(output)

        if not output.get("busy", False):
            break


if __name__ == "__main__":
    asyncio.run(main())