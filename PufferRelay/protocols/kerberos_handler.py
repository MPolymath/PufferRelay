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

"""AS-REP roasting detection from a passive Kerberos capture (issue #61).

If an account has "Do not require Kerberos preauthentication", the KDC answers
an AS-REQ with an AS-REP whose encrypted part can be cracked offline. The pcap
shows it: an AS-REQ without PA-ENC-TIMESTAMP (padata type 2) followed by an
AS-REP for the same principal.

Output rows are ready for hashcat mode 18200:
``$krb5asrep$<etype>$user@REALM:<checksum>$<cipher>``
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from PufferRelay.core_imports import pyshark

# Kerberos message types (RFC 4120).
AS_REQ = 10
AS_REP = 11

# PA-ENC-TIMESTAMP marks pre-authentication in an AS-REQ.
PADATA_ENC_TIMESTAMP = "2"


def normalise_hex(value) -> str:
    """tshark hex fields arrive as 'aa:bb:..' or 'aabb..'; return lowercase hex."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    for separator in (":", " ", "-"):
        text = text.replace(separator, "")
    if text.startswith("0x"):
        text = text[2:]
    try:
        int(text or "0", 16)
    except ValueError:
        return ""
    return text


def asrep_hash(
    username: str, realm: str, etype, cipher_hex: str
) -> Optional[str]:
    """Build the hashcat 18200 line, or None when the cipher is unusable.

    The AS-REP encrypted part is ``checksum (16 bytes) || cipher``. Hashcat
    wants the checksum separately and the cipher in hex.
    """
    if not username or not realm:
        return None
    cipher = normalise_hex(cipher_hex)
    if len(cipher) < 64:  # 32 bytes minimum: 16 checksum + data
        return None
    try:
        etype_text = str(int(etype))
    except (TypeError, ValueError):
        etype_text = "23"
    return f"$krb5asrep${etype_text}${username}@{realm}:{cipher[:32]}${cipher[32:]}"


def _field(packet, name: str) -> str:
    """Return the first value of a tshark field, or an empty string."""
    try:
        value = packet.kerberos.get(name, "")
    except (AttributeError, TypeError):
        return ""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def _padata_types(packet) -> List[str]:
    try:
        value = packet.kerberos.get("kerberos.padata_type", "")
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
        if isinstance(value, str) and value:
            return [part for part in value.split(",") if part]
    except (AttributeError, TypeError):
        pass
    return []


def process_kerberos(pcap_file):
    """Extract AS-REP-roastable accounts.

    Returns:
        list[tuple]: (username, realm, etype, hashcat_hash, src_ip, dst_ip)
        Only accounts whose AS-REQ carried no PA-ENC-TIMESTAMP are returned:
        those are the ones the KDC answers without pre-authentication.
    """
    capture = None
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="kerberos")
        preauth_seen: Dict[Tuple[str, str], bool] = {}
        rows: List[Tuple] = []
        seen_hashes = set()

        for packet in capture:
            try:
                msg_type = _field(packet, "kerberos.msg_type")
                if not msg_type:
                    continue
                username = _field(packet, "kerberos.CNameString") or _field(
                    packet, "kerberos.cname"
                )
                realm = _field(packet, "kerberos.realm")
                key = (username.lower(), realm.lower())

                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                except AttributeError:
                    src_ip, dst_ip = "", ""

                if str(msg_type) == str(AS_REQ):
                    preauth_seen[key] = PADATA_ENC_TIMESTAMP in _padata_types(packet)
                    continue

                if str(msg_type) != str(AS_REP) or not username or not realm:
                    continue

                # If we saw the AS-REQ and it had PA-ENC-TIMESTAMP, the KDC
                # required pre-auth: not roastable (the reply may still be
                # useful for other attacks, but not this one).
                if preauth_seen.get(key, False):
                    continue

                etype = _field(packet, "kerberos.etype")
                cipher = _field(packet, "kerberos.cipher")
                hash_line = asrep_hash(username, realm, etype, cipher)
                if hash_line and hash_line not in seen_hashes:
                    seen_hashes.add(hash_line)
                    rows.append((username, realm, etype or "23", hash_line, src_ip, dst_ip))
            except Exception as packet_error:
                logging.debug("Skipping malformed Kerberos packet: %s", packet_error)
                continue

        logging.info("Extracted %d AS-REP roasting candidate(s)", len(rows))
        return rows
    except Exception as e:
        logging.error("Error processing Kerberos packets: %s", str(e))
        raise
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception as e:
                logging.error("Error closing capture: %s", str(e))
