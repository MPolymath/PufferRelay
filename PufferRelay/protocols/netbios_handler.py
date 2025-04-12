from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import logging

# NetBIOS service type mapping
NETBIOS_SERVICE_TYPES = {
    '00': 'Workstation Service',
    '03': 'Messenger Service',
    '20': 'File Server Service (SMB)',
    '1B': 'Domain Master Browser',
    '1C': 'Domain Controllers (Group)',
    '1D': 'Master Browser',
    '1E': 'Browser Service Elections',
    '1F': 'NetDDE Service'
}

def get_service_type(hex_type):
    """Convert NetBIOS hex type to human-readable service type."""
    return NETBIOS_SERVICE_TYPES.get(hex_type.upper(), f'Unknown Service ({hex_type})')

def process_netbios(pcap_file):
    """
    Extracts NetBIOS information including service types from network captures.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (domain_workgroup, hostname, src_ip, src_mac, service_type)
    """
    # Filter for NetBIOS packets
    capture = pyshark.FileCapture(pcap_file, display_filter="nbns")
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source IP and MAC
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            src_mac = packet.eth.src if hasattr(packet, 'eth') else "N/A"
            
            if src_ip == "N/A" or src_mac == "N/A":
                continue
            
            # Initialize NetBIOS fields
            domain_workgroup = "N/A"
            hostname = "N/A"
            service_type = "N/A"
            
            if hasattr(packet, 'nbns'):
                # Extract domain/workgroup name
                if hasattr(packet.nbns, 'nbns_name'):
                    domain_workgroup = packet.nbns.name
                
                # Extract hostname
                if hasattr(packet.nbns, 'nbns_hostname'):
                    hostname = packet.nbns.nbns_hostname
                
                # Extract service type
                if hasattr(packet.nbns, 'type'):
                    service_type = get_service_type(packet.nbns.type)
                
                # Only add to extracted data if we have valid information
                if domain_workgroup != "N/A" and hostname != "N/A" and service_type != "N/A":
                    extracted_data.append((domain_workgroup, hostname, src_ip, src_mac, service_type))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    return extracted_data 