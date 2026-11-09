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

"""Fast NTLM extraction (issue #55).

The original handler opened pyshark on *every TCP packet* with raw data, which
dominated runtime on large captures. This version asks tshark for the few
packets that can carry NTLM (raw NTLMSSP signatures or HTTP NTLM headers) and
reuses the existing hash parser.
"""

from __future__ import annotations

import base64
import codecs
import logging
import re
import struct

from PufferRelay.tshark_fields import fields

NTLMSSP_CHALLENGE = re.compile(b"NTLMSSP\x00\x02\x00\x00\x00", re.DOTALL)
NTLMSSP_AUTH = re.compile(b"NTLMSSP\x00\x03\x00\x00\x00", re.DOTALL)


def _challenge_from_raw(raw: bytes):
    start = raw.find(b"NTLMSSP\x00\x02")
    if start == -1 or start + 32 > len(raw):
        return None
    return codecs.encode(raw[start + 24 : start + 32], "hex")


def _challenge_from_http(header: str):
    if "NTLM " not in (header or ""):
        return None
    b64_data = header.split("NTLM ", 1)[1].strip()
    try:
        decoded = base64.b64decode(b64_data)
    except Exception:
        return None
    if not NTLMSSP_CHALLENGE.search(decoded) or len(decoded) < 32:
        return None
    return codecs.encode(decoded[24:32], "hex")


def _add_hash(out, processed, src, dst, raw, challenge):
    result = parse_ntlm_hash(raw, challenge)
    if not result:
        return
    hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
    if hash_id in processed:
        return
    processed.add(hash_id)
    out.append((src, dst, result[1], result[0]))


def parse_ntlm_hash(packet_data, challenge):
    """
    Extracts NTLM hashes from packet data using Pcredz logic.
    
    Args:
        packet_data (bytes): Raw packet data containing NTLM message
        challenge (bytes): The challenge value from NTLM type 2 message
        
    Returns:
        tuple: (formatted_hash, user_domain) or None if parsing fails
    """
    try:
        # Find the start of NTLMSSP message
        ntlmssp_start = packet_data.find(b'NTLMSSP\x00\x03')
        if ntlmssp_start == -1:
            logging.error("NTLMSSP3 signature not found")
            return None
            
        # Adjust packet_data to start at NTLMSSP message
        packet_data = packet_data[ntlmssp_start:]
        
        # Extract LM hash
        lmhash_len = struct.unpack('<H', packet_data[12:14])[0]
        lmhash_offset = struct.unpack('<H', packet_data[16:18])[0]
        lmhash = codecs.encode(packet_data[lmhash_offset:lmhash_offset+lmhash_len], "hex").upper()

        # Extract NT hash
        nthash_len = struct.unpack('<H', packet_data[20:22])[0]
        nthash_offset = struct.unpack('<H', packet_data[24:26])[0]
        
        # For NTLMv2, the NT hash includes the response
        if nthash_len > 24:  # NTLMv2
            # Extract the actual NT hash (first 16 bytes) and the response
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+16], "hex").upper()
            response = codecs.encode(packet_data[nthash_offset+16:nthash_offset+nthash_len], "hex").upper()
        else:  # NTLMv1
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+nthash_len], "hex").upper()

        # Extract domain and username
        domain_len = struct.unpack('<H', packet_data[28:30])[0]
        domain_offset = struct.unpack('<H', packet_data[32:34])[0]
        domain = packet_data[domain_offset:domain_offset+domain_len].replace(b"\x00", b"")

        user_len = struct.unpack('<H', packet_data[36:38])[0]
        user_offset = struct.unpack('<H', packet_data[40:42])[0]
        user = packet_data[user_offset:user_offset+user_len].replace(b"\x00", b"")

        # Format the hash based on NTLM version
        if nthash_len == 24:  # NTLMv1
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{lmhash.decode('latin-1')}:{nthash.decode('latin-1')}:{challenge.decode('latin-1')}"
            return f"NTLMv1 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        elif nthash_len > 24:  # NTLMv2
            # For NTLMv2, we use the challenge directly from the NTLMSSP2 message
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{challenge.decode('latin-1')}:{nthash.decode('latin-1')}:{response.decode('latin-1')}"
            return f"NTLMv2 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        
        logging.warning(f"Unexpected NT hash length: {nthash_len}")
        return None
    except Exception as e:
        logging.error(f"Error parsing NTLM hash: {str(e)}")
        return None


def process_ntlm(pcap_file):
    """Extract (source_ip, destination_ip, username, ntlm_hash) tuples."""
    rows = fields(
        pcap_file,
        'tcp contains "NTLMSSP" || http.authorization || http.www_authenticate',
        [
            "ip.src",
            "ip.dst",
            "tcp.payload",
            "http.authorization",
            "http.www_authenticate",
        ],
    )
    challenges = {}
    processed = set()
    out = []

    for src_ip, dst_ip, payload, authorization, www_auth in rows:
        if not src_ip or not dst_ip:
            continue
        try:
            raw_str = (payload or "").replace(":", "")
            raw = None
            if raw_str and len(raw_str) % 2 == 0:
                try:
                    raw = bytes.fromhex(raw_str)
                except ValueError:
                    raw = None

            if raw:
                if NTLMSSP_CHALLENGE.search(raw):
                    challenge = _challenge_from_raw(raw)
                    if challenge:
                        challenges[(src_ip, dst_ip)] = challenge
                elif NTLMSSP_AUTH.search(raw):
                    challenge = challenges.get((src_ip, dst_ip)) or challenges.get(
                        (dst_ip, src_ip)
                    )
                    if challenge:
                        _add_hash(out, processed, src_ip, dst_ip, raw, challenge)

            challenge = _challenge_from_http(www_auth)
            if challenge:
                challenges[(src_ip, dst_ip)] = challenge

            if authorization and "NTLM " in authorization:
                b64_data = authorization.split("NTLM ", 1)[1].strip()
                decoded = base64.b64decode(b64_data)
                if NTLMSSP_AUTH.search(decoded):
                    challenge = challenges.get((src_ip, dst_ip)) or challenges.get(
                        (dst_ip, src_ip)
                    )
                    if challenge:
                        _add_hash(out, processed, src_ip, dst_ip, decoded, challenge)
        except Exception as packet_error:
            logging.debug("Skipping NTLM packet: %s", packet_error)
            continue

    logging.info("Extracted %d NTLM hash(es)", len(out))
    return out
