from PufferRelay.core_imports import pyshark
from ipaddress import ip_network, ip_address

def process_ips(pcap_file):
    """
    Extracts all unique source and destination IPs from a pcap file and sorts them by subnet.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (subnet, ip) pairs
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
    
    # Create list of (subnet, ip) tuples
    ip_tuples = []
    for ip in unique_ips:
        try:
            # Convert IP to network object to get subnet
            network = ip_network(f"{ip}/24", strict=False)  # Using /24 as default subnet
            subnet = str(network)
            ip_tuples.append((subnet, ip))
        except ValueError:
            # Handle invalid IP addresses
            continue
    
    # Sort the tuples by subnet and then by IP
    ip_tuples.sort(key=lambda x: (x[0], ip_address(x[1])))
    
    return ip_tuples 