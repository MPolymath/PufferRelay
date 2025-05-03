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
import base64

def process_imap(pcap_file):
    """
    Extracts IMAP authentication credentials from a pcap file.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, password)
    """
    capture = None
    try:
        # Open the capture file with a filter for IMAP authentication
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter="imap && (imap.request.command==login || imap.request.command==authenticate)",
            use_json=True,  # Use JSON output for better stability
            include_raw=True,  # Include raw packet data
            debug=True  # Enable debug mode
        )
        
        extracted_data = []
        
        for packet in capture:
            try:
                # Extract source and destination IPs
                src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                
                if src_ip == "N/A" or dst_ip == "N/A":
                    continue
                test=packet.imap
                # Extract IMAP fields
                if hasattr(packet, 'imap'):
                    if hasattr(packet.imap, 'line'):   
                        if hasattr(packet.imap.line_tree, 'command') and packet.imap.line_tree.command == "login":
                            username = packet.imap.line_tree.username
                            password = packet.imap.line_tree.password
                            extracted_data.append((src_ip, dst_ip, username, password))
                            continue
                        
                        # For AUTHENTICATE command
                        elif hasattr(packet.imap, 'request_command') and packet.imap.request_command == "authenticate":
                            # Extract base64 encoded credentials
                            auth_data = packet.imap.get('imap.request.arg', 'N/A')
                            if auth_data != 'N/A':
                                try:
                                    # Split the authentication data to get username and password
                                    # Format is usually base64(username:password)
                                    decoded = base64.b64decode(auth_data).decode('utf-8')
                                    username, password = decoded.split(':', 1)
                                    extracted_data.append((src_ip, dst_ip, username, password))
                                    logging.debug(f"Found IMAP credentials: {username}:{password}")
                                except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
                                    logging.error(f"Error decoding IMAP credentials: {str(e)}")
                                    continue
                
            except AttributeError as e:
                logging.error(f"Error processing IMAP packet: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"Error processing IMAP packets: {str(e)}")
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
                logging.error(f"Error closing IMAP capture: {str(e)}")
    
    return extracted_data 