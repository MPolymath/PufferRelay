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

#SMTP extract data
def process_smtp(pcap_file):
    """Extracts SMTP form data"""
    
    # Open the capture file with a filter for SMTP Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="smtp.auth.password || smtp.auth.username")
    extracted_data = []

    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract SMTP fields
            smtp_user = packet.smtp.get('smtp.auth.username', 'N/A') if hasattr(packet, 'smtp') else "N/A"  # Get full URL
            smtp_password = packet.smtp.get('smtp.auth.password', 'N/A') if hasattr(packet, 'smtp') else "N/A"  # Get form content
            
            extracted_data.append((src_ip, dst_ip, smtp_user, smtp_password))
      
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    capture.close()

    return extracted_data