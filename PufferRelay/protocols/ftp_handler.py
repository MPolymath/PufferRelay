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

def process_ftp(pcap_file):
    """Extracts FTP form data"""
    capture = None
    try:
        # Open the capture file with a filter for FTP Requests
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter="ftp && (ftp.request.command==USER || ftp.request.command==PASS)"
        )
        
        extracted_data = []
        for packet in capture:
            try:
                # Extract source and destination IPs
                src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                # Extract FTP fields
                ftp_request_command = packet.ftp.get('ftp.request.command', 'N/A') if hasattr(packet, 'ftp') else "N/A"  # Get command
                ftp_request_arg = packet.ftp.get('ftp.request.arg', 'N/A') if hasattr(packet, 'ftp') else "N/A"  # Get argument
                
                extracted_data.append((src_ip, dst_ip, ftp_request_command, ftp_request_arg))
            except AttributeError:
                continue  # Skip packets that don't have the expected attributes

        return extracted_data
    except Exception as e:
        logging.error(f"Error processing FTP packets: {str(e)}")
        raise
    finally:
        # Properly close the capture in the finally block
        if capture is not None:
            try:
                capture.close()
            except Exception as e:
                logging.error(f"Error closing capture: {str(e)}")