#! venv/bin/python
import aiohttp
import argparse
import asyncio
import random
import re
import ssl
import urllib3
import warnings
from config import *
from fake_useragent import UserAgent
from functions import *
from ipaddress import IPv4Address, IPv4Network
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings(
        "ignore",
        category=Warning,
        message=".*verify_certs=False is insecure.*"
    )
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_nmap_services(file_path):
    """
    Load and parse an nmap-services file to extract TCP port usage probabilities.

    The function reads the specified nmap-services file line by line, skips comments
    and empty lines, and extracts the port number and its associated probability
    (only for TCP ports). The result is returned as a dictionary mapping port numbers
    to their usage probabilities.

    Args:
        file_path (str): Path to the nmap-services file.

    Returns:
        dict[int, float]: A dictionary where keys are TCP port numbers (as integers)
        and values are their corresponding probabilities (as floats).
    """
    ports = {}
    with open(file_path, "r") as file:
        for line in file:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            port_protocol = parts[1]
            probability = float(parts[2])
            port, protocol = port_protocol.split("/")
            if protocol == "tcp":  # We're only interested in TCP ports
                ports[int(port)] = probability
    return ports


def get_http_or_https():
    """
    Randomly select either 'http' or 'https' based on predefined probabilities.

    Uses weighted random choice to favor 'http' over 'https'. Specifically,
    the function chooses 'http' 65% of the time and 'https' 35% of the time.

    Returns:
        str: Either 'http' or 'https', chosen randomly based on weight.
    """
    return random.choices(["http", "https"], weights=[65, 35], k=1)[0]


def generate_random_port(ports, full_range=(1, 65535)):
    """
    Generate a random port with weighted probabilities.

    Ports are selected based on their observed frequency in Internet-wide scans,
    giving preference to common ports. This improves the realism of random
    selection compared to uniform randomness.

    Data sources:
    - Nmap top ports frequency study:
      https://scottbrownconsulting.com/2018/11/nmap-top-ports-frequencies-study/
    - LZR: Identifying Unexpected Internet Services:
      https://arxiv.org/pdf/2301.04841

    Args:
        ports (dict): A dictionary where keys are known TCP ports (int) and
                      values are their relative frequencies (float).
        full_range (tuple): The inclusive port range to consider (default: 1–65535).

    Returns:
        int: A randomly selected port, with selection probability weighted by
             known port frequencies or minimal fallback weights for unknown ports.
    """
    # Get all ports and their weights
    known_ports = list(ports.keys())
    known_weights = list(ports.values())

    # Assign very small weights to ports with 0.000000
    min_known_weight = min(w for w in known_weights if w > 0)
    adjusted_weights = [
        w if w > 0 else min_known_weight / 10 for w in known_weights
    ]

    # Add ports not in the known list with even smaller probabilities
    all_ports = list(range(full_range[0], full_range[1] + 1))
    unknown_ports = set(all_ports) - set(known_ports)
    min_unknown_weight = min(adjusted_weights) / 10
    unknown_weights = [min_unknown_weight] * len(unknown_ports)

    # Combine known and unknown ports
    combined_ports = known_ports + list(unknown_ports)
    combined_weights = adjusted_weights + unknown_weights

    # Normalize weights to sum up to 1
    total_weight = sum(combined_weights)
    normalized_weights = [w / total_weight for w in combined_weights]

    # Select a random port based on probabilities
    return random.choices(combined_ports, weights=normalized_weights, k=1)[0]


async def check_http(ip, port, protocol, verbose=False):
    """
    Scan an HTTP or HTTPS service on a given IP and port.

    Constructs a URL based on the provided IP, port, and protocol (either "http" or "https"),
    and sends an asynchronous GET request using a randomized User-Agent. SSL certificate
    validation is disabled to allow scanning of services with invalid or self-signed certs.

    Args:
        ip (str): The target IP address.
        port (int): The target port number.
        protocol (str): Either "http" or "https".
        verbose (bool): If True, prints detailed progress and error messages.

    Returns:
        int or None: The HTTP response status code if the request succeeds, otherwise None.
    """
    if verbose:
        print(f"Scanning IP {ip} on port {port} ({protocol})...")

    url = f"{protocol}://{ip}:{port}"
    headers = {"User-Agent": UserAgent().random}

    # Disable SSL certificate verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                url,
                timeout=5,
                ssl=ssl_context,
                allow_redirects=True
            ) as response:
                content = await response.text()  # Retrieve response body, if needed later
                http_code = response.status
                return http_code
    except Exception as e:
        if verbose:
            print(f"Error scanning {url} - {e}")

    return None


def save_to_database(ip, port, protocol, status_code, verbose=False, db=None):
    """
    Saves a discovered URL (based on IP, port, and protocol) to the database if it has a valid status code.

    Parameters:
    -----------
    ip : str
        The IP address of the host.
    port : int
        The port number the service is running on.
    protocol : str
        The protocol used (typically 'http' or 'https').
    status_code : int or None
        The HTTP status code returned from a previous request to the URL.
        If None, the URL will not be saved.
    verbose : bool, optional
        If True, additional information will be printed (currently unused in the function).
    db : object
        A database connection or handler to be passed to the `db_insert_if_new_url` function.

    Returns:
    --------
    None
    """
    if status_code is not None:
        # Build the URL string
        url = f"{protocol}://{ip}:{port}"

        # Insert into the database if it’s a new URL
        db_insert_if_new_url(
            url=url,
            visited=False,
            source='port_scanner',
            parent_host=ip,
            db=db
        )

        # Log the result
        print(f'Saved  {protocol}://{ip}:{port} status_code {status_code}')


async def scan_ips(ip_list, concurrency=4, verbose=False, db=None):
    """
    Scan a randomized list of IPs for a randomly selected protocol and port.
    """
    sem = asyncio.Semaphore(concurrency)

    async def bound_check(ip):
        # Choose a protocol at random
        protocol = get_http_or_https()
        if random.random() < RANDOM_PORT_CHANCE:
            # Choose a random non-default port
            port = generate_random_port(ports)
        else:
            # Use default ports for HTTP/HTTPS
            port = 80 if protocol == "http" else 443
        async with sem:
            http_code = await check_http(ip, port, protocol, verbose)
            if http_code:
                save_to_database(
                        ip,
                        port,
                        protocol,
                        http_code,
                        verbose=verbose,
                        db=db
                    )
    tasks = [bound_check(ip) for ip in ip_list]
    await asyncio.gather(*tasks)


def generate_random_ips(count, include_networks=None, exclude_networks=None):
    """
    Generate a random list of IPv4 addresses within specified networks,
    excluding specific ranges.

    Args:
        count: Number of IP addresses to generate
        include_networks: List of network strings (e.g. ['192.168.0.0/24',
        '10.0.0.0/8'])
                          Default: ['0.0.0.0/0'] (all IPv4 addresses)
        exclude_networks: List of network strings to exclude
                          Default: Global EXCLUDED_NETWORKS
    Returns:
        List of random IP addresses as strings
    """
    # Convert string networks to IPv4Network objects
    if include_networks is None:
        # Default to all IPv4 addresses
        include_networks_obj = [IPv4Network('0.0.0.0/0')]
    else:
        include_networks_obj = [
                IPv4Network(network) for network in include_networks
                ]
    if exclude_networks is None:
        # Assuming this is defined globally
        exclude_networks_obj = EXCLUDED_NETWORKS
    else:
        exclude_networks_obj = []
        for network in exclude_networks:
            ipv4_net = IPv4Network(network)
            exclude_networks_obj.append(ipv4_net)

    # Calculate the total number of IPs in all included networks
    network_ranges = []
    total_ips = 0

    for network in include_networks_obj:
        size = network.num_addresses
        network_ranges.append((total_ips, total_ips + size - 1, network))
        total_ips += size
    ips = []
    while len(ips) < count:
        # Pick a random number within the total range
        random_index = random.randint(0, total_ips - 1)
        # Find which network this index belongs to
        for start, end, network in network_ranges:
            if start <= random_index <= end:
                # Calculate the specific IP within this network
                ip_index = random_index - start
                ip = IPv4Address(int(network.network_address) + ip_index)
                break
        # Check if the IP is in any of the exclude networks
        if not any(ip in network for network in exclude_networks_obj):
            ips.append(str(ip))
    return ips


if __name__ == "__main__":
    db = DatabaseConnection()
    parser = argparse.ArgumentParser(
            description="Scan IP addresses for open ports and services."
        )
    parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Enable verbose output")
    args = parser.parse_args()
    # Load ports and their probabilities
    ports = load_nmap_services(SERVICES_INVENTORY)
    # Number of IPs to scan in each run
    ip_count = 4096
    concurrency = MAX_SCANNER_WORKERS
    ip_list = generate_random_ips(ip_count,
                                  include_networks=SCAN_NETWORKS,
                                  exclude_networks=NOSCAN_NETWORKS)
    asyncio.run(scan_ips(ip_list, concurrency, args.verbose, db=db))
    print("Scan completed.")
