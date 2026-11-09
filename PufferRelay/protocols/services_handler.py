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

"""Observed services: which TCP ports hosts were talking to.

Passive: reads SYN packets from the capture (``syn=1, ack=0``). This is the
cheapest way to build a nmap target list without scanning anything.
"""
from PufferRelay.core_imports import logging
from PufferRelay.export import service_for_port
from PufferRelay.tshark_fields import fields


def process_services(pcap_file):
    """Extract (destination_ip, port, service, transport) for observed TCP SYNs.

    Returns:
        list: list of tuples (ip, port, service, transport)
    """
    rows = fields(
        pcap_file,
        "tcp.flags.syn==1 && tcp.flags.ack==0",
        ["ip.dst", "tcp.dstport"],
    )
    out = []
    seen = set()
    for dst_ip, port_text in rows:
        try:
            dst_port = int(port_text)
        except (TypeError, ValueError):
            continue
        if not dst_ip:
            continue
        key = (dst_ip, dst_port)
        if key in seen:
            continue
        seen.add(key)
        out.append((dst_ip, dst_port, service_for_port(dst_port), "tcp"))
    logging.info("Extracted %d observed services", len(out))
    return out
