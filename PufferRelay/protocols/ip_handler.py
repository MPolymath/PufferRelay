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

from PufferRelay.core_imports import pyshark, logging
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
    capture = None
    try:
        # Open the capture file without any filter to get all packets
        capture = pyshark.FileCapture(
            pcap_file,
            use_json=True,  # Use JSON output for better stability
            include_raw=True,  # Include raw packet data
            debug=True  # Enable debug mode
        )
        capture.set_debug()
        
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
    except Exception as e:
        logging.error(f"Error processing IPs: {str(e)}")
        raise
    finally:
        # Properly close the capture in the finally block
        if capture is not None:
            try:
                capture.close()
            except Exception as e:
                logging.error(f"Error closing capture: {str(e)}") 