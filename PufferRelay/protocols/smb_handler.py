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

"""SMB activity extraction (issue #44).

Passively lists what the capture proves was accessed over SMB1/SMB2:
tree connects (shares), file create/read/write names, and printer shares.
No files are downloaded; only the names that already travelled on the wire.
"""

from __future__ import annotations

import logging
from typing import Optional

from PufferRelay.core_imports import pyshark

SMB2_CMD_NAMES = {
    "3": "tree_connect",
    "5": "create",
    "8": "read",
    "9": "write",
    "6": "close",
}

INTERESTING_EXTENSIONS = {
    ".config", ".xml", ".json", ".ps1", ".bat", ".cmd", ".vbs", ".ini", ".conf",
    ".key", ".pem", ".pfx", ".p12", ".kdbx", ".zip", ".7z", ".rar", ".tar",
    ".gz", ".sql", ".bak", ".old", ".txt", ".csv", ".xlsx", ".docx", ".pdf",
}


def normalise_share(value: str) -> str:
    """'\\\\host\\share' / 'host\\share' / 'share' -> 'share'."""
    if not value:
        return ""
    text = str(value).strip().strip("\x00")
    text = text.replace("/", "\\").strip("\\")
    if "\\" in text:
        text = text.split("\\")[-1]
    return text


def normalise_file(value: str) -> str:
    if not value:
        return ""
    return str(value).strip().strip("\x00")


def is_printer(share: str, file_name: str) -> bool:
    share_l = (share or "").lower()
    file_l = (file_name or "").lower()
    if share_l in {"print$", "printers"} or share_l.endswith("print$"):
        return True
    return file_l.endswith((".shd", ".spl", ".emf")) or ".spl" in file_l


def interesting_file(file_name: str) -> bool:
    name = (file_name or "").lower()
    return any(name.endswith(extension) for extension in INTERESTING_EXTENSIONS)


def _get(packet, layer: str, field: str) -> str:
    try:
        value = getattr(packet, layer).get(field, "")
    except (AttributeError, TypeError):
        return ""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def process_smb(pcap_file):
    """Extract SMB share/file activity.

    Returns:
        list[tuple]: (src_ip, dst_ip, share, file, operation, printer)
    """
    capture = None
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="smb2 || smb")
        rows = []
        seen = set()

        for packet in capture:
            try:
                src_ip = packet.ip.src if hasattr(packet, "ip") else ""
                dst_ip = packet.ip.dst if hasattr(packet, "ip") else ""
                share = ""
                file_name = ""
                operation = ""

                if hasattr(packet, "smb2"):
                    command = _get(packet, "smb2", "smb2.cmd")
                    operation = SMB2_CMD_NAMES.get(str(command), f"cmd_{command}")
                    share = _get(packet, "smb2", "smb2.tree")
                    file_name = _get(packet, "smb2", "smb2.filename")
                elif hasattr(packet, "smb"):
                    operation = "smb1"
                    share = _get(packet, "smb", "smb.path")
                    file_name = _get(packet, "smb", "smb.file")

                share = normalise_share(share)
                file_name = normalise_file(file_name)
                if not share and not file_name:
                    continue

                printer = int(is_printer(share, file_name))
                key = (src_ip, dst_ip, share, file_name, operation, printer)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(key)
            except Exception as packet_error:
                logging.debug("Skipping SMB packet: %s", packet_error)
                continue

        logging.info("Extracted %d SMB activity row(s)", len(rows))
        return rows
    except Exception as e:
        logging.error("Error processing SMB packets: %s", str(e))
        raise
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception as e:
                logging.error("Error closing capture: %s", str(e))
