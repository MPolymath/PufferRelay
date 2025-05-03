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
from PufferRelay.database.db_queries import update_quick_win

def process_snmp(pcap_file):
    """
    Extracts SNMP community strings from network captures.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, community_string)
    """
    # Filter for SNMP packets
    capture = pyshark.FileCapture(pcap_file, display_filter="snmp")
    extracted_data = []
    snmp_count = 0
    
    try:
        for packet in capture:
            try:
                # Extract source and destination IPs
                src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                
                if src_ip == "N/A" or dst_ip == "N/A":
                    continue
                
                # Check for SNMP community string
                if hasattr(packet, 'snmp') and hasattr(packet.snmp, 'community'):
                    community_string = packet.snmp.community
                    if community_string and community_string != "N/A":
                        extracted_data.append((src_ip, dst_ip, community_string))
                        snmp_count += 1
                        logging.debug(f"Found SNMP community string: {community_string} from {src_ip} to {dst_ip}")
                
            except AttributeError as e:
                logging.error(f"Error processing SNMP packet: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"Error processing SNMP packets: {str(e)}")
        raise
    finally:
        # Properly close the capture in the finally block
        if capture is not None:
            try:
                # Get the process before closing
                process = getattr(capture, '_tshark_process', None)
                if process:
                    # Kill the process directly
                    process.kill()
                    process.wait()
                # Then close the capture
                capture.close()
            except Exception as e:
                logging.error(f"Error closing SNMP capture: {str(e)}")
    
    # Update quick win table if SNMP packets were found
    if snmp_count > 0:
        update_quick_win("SNMP", snmp_count)
    
    return extracted_data 