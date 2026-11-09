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

"""Passive NAC / 802.1X detection (issue #30).

Reads EAPOL/EAP and RADIUS User-Name attributes from the capture: presence of
NAC, identities that authenticate, and MAC-authentication-bypass (MAB) style
usernames. No spoofing, no traffic — the active suggestions stay Tier B.
"""

from __future__ import annotations

import logging

from PufferRelay.tshark_fields import fields

EAP_METHODS = {
    "1": "identity",
    "2": "notification",
    "3": "nak",
    "4": "md5-challenge",
    "13": "tls",
    "17": "leap",
    "21": "ttls",
    "25": "peap",
    "26": "mschapv2",
    "43": "fast",
    "0": "none",
}

NAC_FILTER = "eapol || eap || radius"
NAC_FIELDS = [
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "eap.code",
    "eap.type",
    "eap.identity",
    "radius.User_Name",
]


def eap_method(type_value: str) -> str:
    value = (type_value or "").strip()
    return EAP_METHODS.get(value, f"type-{value}" if value else "unknown")


def looks_like_mac(value: str) -> bool:
    """True for MAC-shaped identities used by MAB (aa:bb:.., aabb.ccdd.eeff, ...)."""
    text = (value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    compact = text
    for separator in (":", "-", ".", " ", "_"):
        compact = compact.replace(separator, "")
    return len(compact) == 12 and all(char in "0123456789abcdef" for char in compact)


def process_nac(pcap_file):
    """Extract EAP/RADIUS identities.

    Returns:
        list[tuple]: (kind, identity, src, dst, method, mab)
    """
    rows = fields(pcap_file, NAC_FILTER, NAC_FIELDS)
    out = []
    seen = set()
    for (
        protocols,
        eth_src,
        eth_dst,
        ip_src,
        ip_dst,
        _eap_code,
        eap_type,
        eap_identity,
        radius_user,
    ) in rows:
        tokens = set((protocols or "").lower().split(":"))
        if "radius" in tokens:
            kind = "radius"
            identity = radius_user or ""
            src = ip_src or eth_src
            dst = ip_dst or eth_dst
            method = "radius"
            if not identity:
                continue
        elif "eap" in tokens or "eapol" in tokens:
            kind = "eap"
            identity = eap_identity or ""
            src = eth_src or ip_src
            dst = eth_dst or ip_dst
            method = eap_method(eap_type)
        else:
            continue

        mab = int(looks_like_mac(identity))
        key = (kind, identity, src, dst, method, mab)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)

    logging.info("Extracted %d NAC/EAP observation(s)", len(out))
    return out
