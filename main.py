import argparse
import socket
import subprocess
import re
from scapy.all import *
from netaddr import IPNetwork, IPRange  # Ensure netaddr is installed

# Function to detect local subnet (if no target is provided)
def get_local_subnet():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)

        for line in result.stdout.split("\n"):
            if "src" in line:
                match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    local_ip = match.group(1)
                    subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
                    print(f"[*] No target specified. Scanning local subnet: {subnet}")
                    return subnet

        print("[!] Could not detect local network, using fallback method.")
        fallback_ip = socket.gethostbyname(socket.gethostname())
        subnet = fallback_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet

    except Exception as e:
        print(f"[!] Failed to detect local subnet: {e}")
        return "192.168.0.0/24"  # Default if detection fails

# Function to check if a host is online using ARP
def is_host_online(target):
    """
    Uses ARP to check if a target is online.
    Loopback addresses (127.x.x.x) are always considered reachable.
    """
    if target.startswith("127."):
        return True

    ans, _ = arping(target, timeout=1, verbose=False)
    return len(ans) > 0

# Function to perform a SYN scan on a given port
def syn_scan(target, port):
    """
    TODO:
    - Construct a SYN packet using Scapy
    - Send the SYN packet to the target
    - Analyze the response:
        - If SYN-ACK received, port is OPEN
        - If RST received, port is CLOSED
        - If no response, port is FILTERED
    - Return the appropriate status as a string: "open", "closed", or "filtered"
    """
    # Create a SYN packet to use with Scapy
    ip = IP(dst=target)
    syn = TCP(dport=port, flags="S")
    packet = ip / syn

    # Send the packet and receive the response
    response = send(packet, verbose=False)

    # Analyze the response to determine the port status
    if response is None:
        return "filtered"  # No response received
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK
            return "open"
        elif response[TCP].flags == 0x14:  # RST
            return "closed"
    else:
        print("Response not recognized")
    return "filtered"  # Placeholder (assume all ports are filtered)

# Function to scan a given target on specified ports
def scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts, portArgument):
    """
    TODO:
    - Print the scanning message with the target IP and port range.
    - Use `is_host_online(target)` to check if the host is reachable.
    - If the host is online, iterate through the ports and:
        - Call `syn_scan(target, port)` for each port.
        - Categorize the result into open, closed, or filtered lists.
    """
    print(f"[+] Scanning {target} on port(s) {portArgument}...")

    if not is_host_online(target):
        print(f"[-] {target} is unreachable. Skipping...")
        return

    for port in ports:
        print(f"[+] Scanning {target}:{port}...")
        result = syn_scan(target, port)

        if result == "open":
            open_hosts.append((target, port))
        elif result == "closed":
            closed_hosts.append((target, port))
        elif result == "filtered":
            filtered_hosts.append((target, port))

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")

    args = parser.parse_args()

    # Target parsing (supporting single IP, range, subnet)
    if not args.target:
        # args.target = get_local_subnet()
        print(f"[*] No target specified. Using local subnet: TODO")

    targets = args.target
    print(targets)
    if len(targets) == 0:
        targets = [get_local_subnet()]
    # Check for subnet notation
    elif "/" in targets:
        targets = [str(ip) for ip in IPNetwork(targets)]
    # Check for range of IPs
    elif "-" in targets:
        target_parts = targets.split("-")
        if len(target_parts) == 2:
            # Range of IPs
            start_ip = target_parts[0]
            end_ip = target_parts[1]
            targets = [str(ip) for ip in IPRange(start_ip, end_ip)]
    # Single IP
    else:
        targets = [targets]
    print(f"[*] Targets: {targets}")


    # Port parsing (supporting single ports, ranges, lists)
    print(args.ports)
    if not args.ports:
        print(f"[*] No ports specified. Scanning All 65535 Ports")
        ports = list(range(1, 65536))
        portArgument = "1-65535"
    elif args.ports:
        portArgument = args.ports
        ports = []
        for port in args.ports.split(","):
            if "-" in port:
                start, end = port.split("-")
                try:
                    ports.extend(list(range(int(start), int(end) + 1)))
                except ValueError:
                    print(f"Invalid port range: {port}")
                    exit(1)
            else:
                ports.append(int(port))
    ports = list(set(ports))



    # Show filter parsing
    valid_show = ["open", "closed", "filtered"]
    show = args.show
    if not show:
        show = valid_show
    else:
        show = show.split(",")
        for item in show:
            if item not in valid_show:
                print(f"Invalid show argument: {item}")
                print(f"Valid options: {valid_show}")
                exit(1)

    return targets, ports, show, portArgument

if __name__ == "__main__":
    """
    TODO:
    - Call `parse_arguments()` to get the list of targets and ports.
    - Create empty lists for open, closed, and filtered ports.
    - Loop through each target and call `scan_target()`.
    - Print a final summary of open, closed, and filtered ports.
    """
    targets, ports, show, portArgument = parse_arguments()

    open_hosts = []
    closed_hosts = []
    filtered_hosts = []

    print(f"Targets: {targets}")
    print(f"Ports: {ports}")
    print(f"Show: {show}")

    print("\n[+] Starting scan...")
    # 
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts, portArgument)

    print("\n[+]Final Scan Summary:")
    if ("open" in show):
        print(f"  Open Ports:")
        for host, port in open_hosts:
            print(f"    - {host}:{port}")
        print()
    if ("closed" in show):
        print(f"  Closed Ports:")
        for host, port in closed_hosts:
            print(f"    - {host}:{port}")
        print()
    if ("filtered" in show):
        print(f"  Filtered Ports:")
        for host, port in filtered_hosts:
            print(f"    - {host}:{port}")
        print()
    # print(f"  Open Ports: {open_hosts}")
    # print(f"  Closed Ports: {closed_hosts}")
    # print(f"  Filtered Ports: {filtered_hosts}")
