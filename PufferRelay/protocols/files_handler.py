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

"""Carve files that travelled in clear text (issue #57).

Start with HTTP response bodies and FTP-DATA objects: both are simple byte
streams that tshark already reassembles per packet. Objects are stored as BLOBs
in SQLite and written by the export step; nothing is fetched from the network.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional

from PufferRelay.tshark_fields import fields

MAX_FILE_BYTES = 1024 * 1024  # per object
MAX_TOTAL_BYTES = 16 * 1024 * 1024  # per capture

_FILENAME_RE = re.compile(r'filename\*?=(?:"([^"]+)"|([^;]+))', re.IGNORECASE)
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

HEADER_SEPARATOR = b"\r\n\r\n"
HEADER_LINE = b"\r\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(name: str, fallback: str) -> str:
    """Strip paths and unsafe characters; never allow traversal."""
    text = (name or "").strip().strip('"').strip("'")
    text = text.replace("\\", "/").split("/")[-1]
    text = _UNSAFE_RE.sub("_", text).strip("._")
    if not text:
        text = fallback
    return text[:80]


def filename_from_disposition(value: str) -> str:
    if not value:
        return ""
    match = _FILENAME_RE.search(value)
    if not match:
        return ""
    name = (match.group(1) or match.group(2) or "").strip()
    # RFC 5987: filename*=UTF-8''name
    if "''" in name:
        name = name.split("''", 1)[1]
    return name


def decode_hex_field(value: str) -> Optional[bytes]:
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace(":", "").replace(" ", "").replace("\n", "")
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2 != 0:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def headers_from_payload(payload_hex: str):
    """Parse Content-Type/Disposition from a raw HTTP header block.

    tshark does not expose http.content_disposition for HTTP/1.1, so read the
    headers from the TCP payload when needed.
    """
    raw = decode_hex_field(payload_hex)
    if not raw:
        return "", ""
    head = raw.split(HEADER_SEPARATOR, 1)[0]
    content_type = ""
    disposition = ""
    for line in head.split(HEADER_LINE)[1:]:
        try:
            text = line.decode("latin-1")
        except UnicodeDecodeError:
            continue
        if text.lower().startswith("content-type:"):
            content_type = text.split(":", 1)[1].strip()
        elif text.lower().startswith("content-disposition:"):
            disposition = text.split(":", 1)[1].strip()
    return content_type, disposition


def process_files(pcap_file):
    """Extract HTTP/FTP objects from the capture.

    Returns:
        list[tuple]: (protocol, src_ip, dst_ip, filename, content_type, size,
        sha256, data)
    """
    rows = fields(
        pcap_file,
        "(http.response && http.file_data) || ftp-data",
        [
            "ip.src",
            "ip.dst",
            "http.content_type",
            "http.file_data",
            "tcp.payload",
            "data.data",
        ],
    )
    out = []
    seen = set()
    total = 0

    for src_ip, dst_ip, content_type, http_data, tcp_payload, data_payload in rows:
        try:
            if http_data:
                protocol = "http"
                data_hex = http_data
            elif data_payload:
                protocol = "ftp-data"
                data_hex = data_payload
            else:
                continue

            raw = decode_hex_field(data_hex)
            if not raw or len(raw) > MAX_FILE_BYTES:
                continue
            if total + len(raw) > MAX_TOTAL_BYTES:
                logging.warning("File carving budget reached; stopping")
                break

            digest = sha256_bytes(raw)
            if digest in seen:
                continue
            seen.add(digest)
            total += len(raw)

            disposition = ""
            if tcp_payload:
                raw_ct, disposition = headers_from_payload(tcp_payload)
                if raw_ct and not content_type:
                    content_type = raw_ct

            name = filename_from_disposition(disposition)
            name = safe_filename(name, f"{protocol}-{digest[:12]}")
            out.append(
                (protocol, src_ip, dst_ip, name, content_type or "", len(raw), digest, raw)
            )
        except Exception as packet_error:
            logging.debug("Skipping file object: %s", packet_error)
            continue

    logging.info("Carved %d file object(s)", len(out))
    return out
