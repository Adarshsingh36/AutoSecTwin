import docker
import time

client = docker.from_env()

def create_isolated_network(network_name: str):
    try:
        network = client.networks.get(network_name)
    except docker.errors.NotFound:
        network = client.networks.create(
            name=network_name,
            driver="bridge",
            internal=True
        )
    return network

def provision_sandbox(vuln_record):
    network_name = f"sandbox_net_{vuln_record.cve_id.replace('-', '_')}"
    create_isolated_network(network_name)
    
    image_tag = "vulnerables/web-dvwa"
    print(f"Provisioning sandbox for {vuln_record.cve_id} using {image_tag}...")
    
    container = client.containers.run(
        image_tag,
        detach=True,
        network=network_name,
        name=f"sandbox_dvwa_{int(time.time())}"
    )
    return container.id, network_name