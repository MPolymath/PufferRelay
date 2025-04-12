# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import logging

# NetBIOS service type mapping
NETBIOS_SERVICE_TYPES = {
    '0': 'Workstation Service',
    '3': 'Messenger Service',
    '32': 'File Server Service (SMB)',
    '27': 'Domain Master Browser',
    '28': 'Domain Controllers (Group)',
    '29': 'Master Browser',
    '30': 'Browser Service Elections',
    '31': 'NetDDE Service'
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
        list: List of tuples containing (domain_workgroup, hostname, other_service, src_ip, src_mac, service_type)
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
            other_service = "N/A"
            service_type = "N/A"
            
            if hasattr(packet, 'nbns'):
                # Extract service type
                if hasattr(packet.nbns, 'type'):
                    service_type = get_service_type(packet.nbns.type)
                    logging.debug(f"Found NetBIOS type: {packet.nbns.type} -> {service_type}")
                
                # Extract name based on service type
                if hasattr(packet.nbns, 'name'):
                    name = packet.nbns.name[:15].strip()  # NetBIOS names are 15 chars max
                    logging.debug(f"Found NetBIOS name: {name}")
                    
                    if service_type == 'Workstation Service':
                        hostname = name
                    elif service_type in ['Domain Master Browser', 'Domain Controllers (Group)', 
                                        'Master Browser', 'Browser Service Elections']:
                        domain_workgroup = name
                    else:
                        other_service = name

                # Only add to extracted data if we have valid information
                if service_type != "N/A" and (hostname != "N/A" or domain_workgroup != "N/A" or other_service != "N/A"):
                    entry = (domain_workgroup, hostname, other_service, src_ip, src_mac, service_type)
                    logging.debug(f"Adding NetBIOS entry: {entry}")
                    extracted_data.append(entry)
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    logging.info(f"Extracted {len(extracted_data)} NetBIOS entries")
    return extracted_data 