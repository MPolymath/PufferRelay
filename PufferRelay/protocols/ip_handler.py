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

from PufferRelay.core_imports import logging
from PufferRelay.tshark_fields import fields
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
    rows = fields(pcap_file, "ip", ["ip.src", "ip.dst"])
    unique_ips = set()
    for src_ip, dst_ip in rows:
        if src_ip:
            unique_ips.add(src_ip)
        if dst_ip:
            unique_ips.add(dst_ip)

    subnet_groups = defaultdict(list)
    for ip in unique_ips:
        try:
            network = ip_network(f"{ip}/24", strict=False)
            subnet = str(network)
            subnet_groups[subnet].append(ip)
        except ValueError:
            continue

    for subnet in subnet_groups:
        subnet_groups[subnet].sort(key=ip_address)

    result = [(subnet, ips) for subnet, ips in subnet_groups.items()]
    result.sort(key=lambda x: ip_network(x[0]))
    logging.info("Extracted %d unique IPs in %d subnets", len(unique_ips), len(result))
    return result 