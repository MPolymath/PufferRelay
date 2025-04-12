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

from PufferRelay.protocols import process_ldap, process_http, process_ftp, process_telnet, process_smtp, process_ips, process_ntlm, process_netbios
from PufferRelay.core_imports import logging
from PufferRelay.utils.loading_animation import show_loading_animation
import threading
import time

def parse_pcap(pcap_file):
    """
    Parses a PCAP file and extracts data for LDAP, HTTP, FTP, TELNET, SMTP, NTLM, and IPs.

    Args:
        pcap_file (str): Path to the .pcap file.

    Returns:
        dict: Extracted data categorized by protocol.
    """
    logging.info(f"Parsing PCAP file: {pcap_file}")

    # Only show loading animation if not in debug mode
    if logging.getLogger().getEffectiveLevel() > logging.DEBUG:
        # Initialize loading animation
        update_animation, show_ready = show_loading_animation()
        animation_running = True

        def animation_loop():
            """Run the animation until stopped."""
            while animation_running:
                update_animation()
                time.sleep(0.1)

        # Start loading animation in a separate thread
        animation_thread = threading.Thread(target=animation_loop)
        animation_thread.start()
    else:
        logging.info("Starting protocol processing...")

    try:
        # Process all protocols
        ldap_data = process_ldap(pcap_file)
        http_data = process_http(pcap_file)
        ftp_data = process_ftp(pcap_file)
        telnet_data = process_telnet(pcap_file)
        smtp_data = process_smtp(pcap_file)
        ntlm_data = process_ntlm(pcap_file)
        ip_data = process_ips(pcap_file)
        netbios_data = process_netbios(pcap_file)

        # Stop animation if it was started
        if logging.getLogger().getEffectiveLevel() > logging.DEBUG:
            animation_running = False
            animation_thread.join()
            show_ready()

        return {
            "ldap": ldap_data,
            "http": http_data,
            "ftp": ftp_data,
            "telnet": telnet_data,
            "smtp": smtp_data,
            "ntlm": ntlm_data,
            "ips": ip_data,
            "netbios": netbios_data
        }
    except Exception as e:
        # Stop animation if it was started
        if logging.getLogger().getEffectiveLevel() > logging.DEBUG:
            animation_running = False
            animation_thread.join()
        logging.error(f"Error during PCAP parsing: {str(e)}")
        raise e