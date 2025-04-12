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
from PufferRelay.core_imports import defaultdict
from PufferRelay.core_imports import logging

#TELNET extract data
def process_telnet(pcap_file):
    """Extracts TELNET form data"""
    conversations = defaultdict(str)
    # Open the capture file with a filter for TELNET Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="telnet && (telnet.data)")
    capture.set_debug 
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract Telnet fields
            telnet_data = packet.telnet.get('telnet.data')
            key = (src_ip, dst_ip)
            conversations[key] += telnet_data
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    capture.close()
    
    # Convert the dict to a list of tuples
    return [(src, dst, data) for (src, dst), data in conversations.items()]