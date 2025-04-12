from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import logging
from collections import defaultdict

def process_netbios(pcap_file):
    """
    Extracts NetBIOS information including hostnames, IPs, MAC addresses, and domain/workgroup details.
    Ensures unique hostnames per domain and workgroup.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (domain/workgroup, hostname, ip, mac)
    """
    # Open the capture file with a filter for NetBIOS traffic
    capture = pyshark.FileCapture(pcap_file, display_filter="nbns || nbss")
    
    # Dictionary to store host information, organized by domain/workgroup
    domain_hosts = defaultdict(dict)  # For domain hosts
    workgroup_hosts = defaultdict(dict)  # For workgroup hosts
    
    for packet in capture:
        try:
            # Extract source and destination IPs and MACs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            src_mac = packet.eth.src if hasattr(packet, 'eth') else "N/A"
            dst_mac = packet.eth.dst if hasattr(packet, 'eth') else "N/A"
            
            # Initialize NetBIOS fields
            hostname = "N/A"
            domain_workgroup = "N/A"
            is_domain = False
            
            if hasattr(packet, 'nbns'):
                # Extract NetBIOS name
                if hasattr(packet.nbns, 'name'):
                    hostname = packet.nbns.name
                
                # Extract domain/workgroup information
                if hasattr(packet.nbns, 'type'):
                    if packet.nbns.type in ['0x1C', '0x1B']:  # Domain Master Browser or Domain Controller
                        domain_workgroup = packet.nbns.name.split('.')[0]  # Extract domain name
                        is_domain = True
                    elif packet.nbns.type in ['0x00', '0x1E']:  # Workstation or Browser Service Elections
                        domain_workgroup = packet.nbns.name.split('.')[0]  # Extract workgroup name
                        is_domain = False
            
            # Store information for both source and destination
            if hostname != "N/A" and domain_workgroup != "N/A":
                if src_ip != "N/A" and src_mac != "N/A":
                    if is_domain:
                        domain_hosts[domain_workgroup][hostname] = {
                            'ip': src_ip,
                            'mac': src_mac
                        }
                    else:
                        workgroup_hosts[domain_workgroup][hostname] = {
                            'ip': src_ip,
                            'mac': src_mac
                        }
                if dst_ip != "N/A" and dst_mac != "N/A":
                    if is_domain:
                        domain_hosts[domain_workgroup][hostname] = {
                            'ip': dst_ip,
                            'mac': dst_mac
                        }
                    else:
                        workgroup_hosts[domain_workgroup][hostname] = {
                            'ip': dst_ip,
                            'mac': dst_mac
                        }
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    
    # Convert the dictionaries to sorted lists of tuples
    extracted_data = []
    
    # Add domain hosts first
    for domain, hosts in sorted(domain_hosts.items()):
        for hostname, info in sorted(hosts.items()):
            extracted_data.append((
                f"DOMAIN: {domain}",
                hostname,
                info['ip'],
                info['mac']
            ))
    
    # Add workgroup hosts second
    for workgroup, hosts in sorted(workgroup_hosts.items()):
        for hostname, info in sorted(hosts.items()):
            extracted_data.append((
                f"WORKGROUP: {workgroup}",
                hostname,
                info['ip'],
                info['mac']
            ))
    
    return extracted_data 