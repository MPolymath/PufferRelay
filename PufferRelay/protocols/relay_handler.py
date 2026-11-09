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

"""Confirmed NTLM relay paths observed in a capture (issue #62).

A relay needs three facts, and the pcap can show all of them:
  1. an NTLM authentication is actually happening (``ntlmssp``),
  2. the destination protocol/port (SMB, LDAP, HTTP/WebDAV),
  3. whether the destination would accept it: SMB signing flags from the SMB2
     NEGOTIATE response; LDAP/HTTP NTLM without channel binding is relayable.

The output is a list of rows suitable for a relay-target file and for leads.
"""

from __future__ import annotations

import logging
from typing import Optional

from PufferRelay.core_imports import pyshark

SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 3268}
HTTP_PORTS = {80, 8080, 5985, 8000, 8888}

SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


def classify(protocol: str, signing_required: Optional[bool]) -> bool:
    """Would this endpoint accept an relayed NTLM authentication?

    SMB: only when signing is not required (flags from NEGOTIATE).
    LDAP/HTTP NTLM: relayable unless the operator later finds channel
    binding/signing enforced server-side; the capture alone cannot prove that,
    so it is marked as a candidate.
    """
    if protocol == "smb":
        return signing_required is not True
    if protocol in {"ldap", "http"}:
        return True
    return False


def protocol_for_port(port: Optional[int], has_http: bool = False) -> str:
    if port in SMB_PORTS:
        return "smb"
    if port in LDAP_PORTS:
        return "ldap"
    if has_http or port in HTTP_PORTS:
        return "http"
    return "unknown"


def smb_signing_missing_hosts(rows) -> list:
    """Destination IPs where NTLM was seen over SMB with signing not required.

    ``rows`` uses the process_relays() tuple shape:
    (src, dst, port, protocol, username, signing_required, candidate)
    with signing_required 0/1/"" .
    """
    hosts = set()
    for row in rows:
        try:
            _src, dst, _port, protocol, _user, signing, _candidate = row
        except (TypeError, ValueError):
            continue
        if protocol == "smb" and str(signing) == "0":
            hosts.add(str(dst))
    return sorted(hosts)


def _get(packet, layer: str, field: str) -> str:
    try:
        value = getattr(packet, layer).get(field, "")
    except (AttributeError, TypeError):
        return ""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def _parse_flags(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        try:
            return int(str(value), 16)
        except ValueError:
            return None


def process_relays(pcap_file):
    """Extract relay candidates from NTLM sessions.

    Returns:
        list[tuple]: (src_ip, dst_ip, dst_port, protocol, username,
        signing_required, candidate)
    """
    capture = None
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="ntlmssp || smb2")
        signing = {}
        rows = []
        seen = set()

        for packet in capture:
            try:
                dst_ip = packet.ip.dst if hasattr(packet, "ip") else ""
                # Track SMB2 NEGOTIATE signing requirements per server.
                if hasattr(packet, "smb2") and dst_ip:
                    flags = _get(packet, "smb2", "smb2.negotiate_flags")
                    value = _parse_flags(flags)
                    if value is not None:
                        signing[dst_ip] = bool(value & SMB2_NEGOTIATE_SIGNING_REQUIRED)
                    elif _get(packet, "smb2", "smb2.signing_required"):
                        signing[dst_ip] = _get(
                            packet, "smb2", "smb2.signing_required"
                        ).lower() in {"1", "true"}

                if not hasattr(packet, "ntlmssp"):
                    continue

                src_ip = packet.ip.src if hasattr(packet, "ip") else ""
                try:
                    dst_port = int(packet.tcp.dstport)
                except (AttributeError, ValueError):
                    dst_port = None
                protocol = protocol_for_port(dst_port, hasattr(packet, "http"))
                username = _get(packet, "ntlmssp", "ntlmssp.auth.username")

                required = signing.get(dst_ip)
                candidate = classify(protocol, required)
                key = (src_ip, dst_ip, dst_port, protocol, username, candidate)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    (
                        src_ip,
                        dst_ip,
                        dst_port or 0,
                        protocol,
                        username,
                        "" if required is None else int(required),
                        int(candidate),
                    )
                )
            except Exception as packet_error:
                logging.debug("Skipping relay packet: %s", packet_error)
                continue

        logging.info("Extracted %d relay candidate row(s)", len(rows))
        return rows
    except Exception as e:
        logging.error("Error processing relay candidates: %s", str(e))
        raise
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception as e:
                logging.error("Error closing capture: %s", str(e))
