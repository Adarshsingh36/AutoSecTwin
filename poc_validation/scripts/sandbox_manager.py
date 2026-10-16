import docker
import time

client = docker.from_env()

def create_isolated_network(network_name: str):
    """Creates an isolated Docker network with no external routing."""
    try:
        network = client.networks.get(network_name)
    except docker.errors.NotFound:
        network = client.networks.create(
            name=network_name,
            driver="bridge",
            internal=True # Forces network isolation[cite: 1]
        )
    return network

def provision_sandbox(vuln_record):
    """Provisions a Docker container matching the vulnerability profile."""
    network_name = f"sandbox_net_{vuln_record.cve_id}"
    create_isolated_network(network_name)
    
    # In a real scenario, map the vuln_record.service to a specific base image[cite: 1]
    # image_tag = "vulnerable_base_image:latest" 

    #Using a real, lightweight web server image Docker can successfully pull iy
    # Using a real, lightweight web server image so Docker can successfully pull it
    image_tag = "nginx:alpine"
    
    print(f"Provisioning sandbox for {vuln_record.cve_id} on {image_tag}...")
    
    container = client.containers.run(
        image_tag,
        detach=True,
        network=network_name,
        name=f"sandbox_{vuln_record.cve_id}_{int(time.time())}"
    )
    
    return container.id, network_name