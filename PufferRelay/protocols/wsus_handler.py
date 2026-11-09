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

"""WSUS / Windows Update endpoint detection (issue #14).

Identifies HTTP requests that belong to WSUS/Windows Update by URI, host or
User-Agent. Passive only: it reports what crossed the wire.
"""

from __future__ import annotations

import logging

from PufferRelay.tshark_fields import fields

WSUS_URI_MARKERS = (
    "/wsus/",
    "/selfupdate/",
    "/clientwebservice/",
    "/simpleauthwebservice/",
    "/reportingwebservice/",
    "/dssauthwebservice/",
    "/content/",
    "/susp/",
    "wsusscn2.cab",
    "/wuident.cab",
    "/wsusscan.cab",
)

WSUS_UA_MARKERS = (
    "windows-update-agent",
    "microsoft-cryptoapi",
    "wsus",
    "windows update",
)


def is_wsus(host: str, uri: str, user_agent: str) -> str:
    """Return a short indicator ("uri:…", "ua:…", "host:…") or ""."""
    uri_l = (uri or "").lower()
    for marker in WSUS_URI_MARKERS:
        if marker in uri_l:
            return f"uri:{marker.strip('/')}"
    ua_l = (user_agent or "").lower()
    for marker in WSUS_UA_MARKERS:
        if marker in ua_l:
            return f"ua:{marker}"
    host_l = (host or "").lower()
    if "wsus" in host_l or "windowsupdate" in host_l or "update.microsoft" in host_l:
        return "host"
    return ""


def process_wsus(pcap_file):
    """Extract WSUS/Windows Update HTTP requests.

    Returns:
        list[tuple]: (src_ip, dst_ip, host, uri, user_agent, indicator)
    """
    rows = fields(
        pcap_file,
        "http.request",
        ["ip.src", "ip.dst", "http.host", "http.request.uri", "http.user_agent"],
    )
    out = []
    seen = set()
    for src, dst, host, uri, user_agent in rows:
        indicator = is_wsus(host, uri, user_agent)
        if not indicator:
            continue
        key = (dst, host or "", indicator, uri or "")
        if key in seen:
            continue
        seen.add(key)
        out.append((src, dst, host or "", uri or "", user_agent or "", indicator))

    logging.info("Extracted %d WSUS endpoint request(s)", len(out))
    return out
