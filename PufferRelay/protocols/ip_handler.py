from PufferRelay.core_imports import pyshark
from ipaddress import ip_network, ip_address
from collections import defaultdict

def process_ips(pcap_file):
    """
    Extracts all unique source and destination IPs from a pcap file and groups them by subnet.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (subnet, list_of_ips)
    """
    # Open the capture file without any filter to get all packets
    capture = pyshark.FileCapture(pcap_file)
    unique_ips = set()
    
    for packet in capture:  
        try:
            # Extract source and destination IPs
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                unique_ips.add(src_ip)
                unique_ips.add(dst_ip)
        except AttributeError:
            continue
    
    capture.close()
    
    # Group IPs by subnet
    subnet_groups = defaultdict(list)
    for ip in unique_ips:
        try:
            # Convert IP to network object to get subnet
            network = ip_network(f"{ip}/24", strict=False)  # Using /24 as default subnet
            subnet = str(network)
            subnet_groups[subnet].append(ip)
        except ValueError:
            # Handle invalid IP addresses
            continue
    
    # Sort IPs within each subnet
    for subnet in subnet_groups:
        subnet_groups[subnet].sort(key=ip_address)
    
    # Convert to list of tuples and sort by subnet
    result = [(subnet, ips) for subnet, ips in subnet_groups.items()]
    result.sort(key=lambda x: ip_network(x[0]))
    
    return result 