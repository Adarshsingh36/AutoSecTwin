import asyncio

from integrations.metasploit.rpc_client import MetasploitRPCClient


async def main():
    client = MetasploitRPCClient()

    await client.login()

    print("Metasploit RPC: CONNECTED")

    target = "192.168.56.103"

    module_type = "exploit"
    module_name = "windows/smb/ms17_010_eternalblue"

    options = {
        "RHOSTS": target,
        "RPORT": 445,
    }

    print("\n=== MODULE CHECK SUBMISSION ===")

    result = await client.check_module(
        module_type=module_type,
        module_name=module_name,
        options=options,
    )

    print("Target:", target)
    print("Module:", module_name)
    print("Result:", result)

    job_id = result.get("job_id")

    if job_id is None:
        print("\nNo job ID returned.")
        return

    print("\n=== JOB INFO ===")

    job_info = await client.get_job_info(job_id)

    print(job_info)

    print("\n=== JOB LIST ===")

    jobs = await client.list_jobs()

    print(jobs)

    print("\n=== WAITING FOR JOB ===")

    completion = await client.wait_for_job(
        job_id=job_id,
        poll_interval=1.0,
        timeout=30.0,
    )

    print(completion)

    print("\n=== FINAL JOB LIST ===")

    final_jobs = await client.list_jobs()

    print(final_jobs)

    if completion.get("completed"):
        print("\n=== MODULE CHECK COMPLETED ===")
        print("Check job completed successfully from the RPC perspective.")
    else:
        print("\n=== MODULE CHECK TIMEOUT ===")
        print("The Metasploit check job did not finish within the timeout.")


if __name__ == "__main__":
    asyncio.run(main())