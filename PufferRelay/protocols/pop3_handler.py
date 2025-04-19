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

def process_pop3(pcap_file):
    """
    Extracts POP3 authentication credentials from a pcap file.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, password)
    """
    capture = None
    try:
        # Open the capture file with a filter for POP3 authentication
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter="pop && (pop.request.command==USER || pop.request.command==PASS || pop.request.command==APOP)",
            use_json=True,  # Use JSON output for better stability
            include_raw=True,  # Include raw packet data
            debug=True  # Enable debug mode
        )
        capture.set_debug()
        
        extracted_data = []
        temp_credentials = {}  # Store temporary credentials by IP pair
        
        for packet in capture:
            try:
                # Extract source and destination IPs
                src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                
                if src_ip == "N/A" or dst_ip == "N/A":
                    continue
                
                ip_pair = (src_ip, dst_ip)
                
                # Extract POP3 fields
                if hasattr(packet, 'pop'):
                    # For USER command
                    if hasattr(packet.pop, 'request_tree') and hasattr(packet.pop.request_tree, 'command') and packet.pop.request_tree.command == "USER":
                        username = packet.pop.request_tree.parameter
                        if username != 'N/A':
                            if ip_pair not in temp_credentials:
                                temp_credentials[ip_pair] = {'username': username}
                            else:
                                temp_credentials[ip_pair]['username'] = username
                    
                    # For PASS command
                    elif hasattr(packet.pop, 'request_tree') and hasattr(packet.pop.request_tree, 'command') and packet.pop.request_tree.command == "PASS":
                        password = packet.pop.request_tree.parameter
                        if password != 'N/A' and ip_pair in temp_credentials:
                            temp_credentials[ip_pair]['password'] = password
                            # Add to extracted data and clear temp storage
                            extracted_data.append((src_ip, dst_ip, 
                                                temp_credentials[ip_pair]['username'],
                                                password))
                            del temp_credentials[ip_pair]
                    
                    # For APOP command (authentication in one step)
                    elif hasattr(packet.pop, 'request_tree') and hasattr(packet.pop.request_tree, 'command') and packet.pop.request_tree.command == "APOP":
                        apop_data = packet.pop.request_tree.parameter
                        if apop_data != 'N/A':
                            try:
                                # APOP format is usually "username digest"
                                username, _ = apop_data.split(' ', 1)
                                # We can't get the actual password from APOP as it's hashed
                                extracted_data.append((src_ip, dst_ip, username, "APOP_AUTHENTICATED"))
                                logging.debug(f"Found APOP authentication for user: {username}")
                            except ValueError as e:
                                logging.error(f"Error parsing APOP data: {str(e)}")
                                continue
                
            except AttributeError as e:
                logging.error(f"Error processing POP3 packet: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"Error processing POP3 packets: {str(e)}")
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
                logging.error(f"Error closing POP3 capture: {str(e)}")
    
    return extracted_data 