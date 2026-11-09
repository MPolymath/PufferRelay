"""SMB object carving (issue #57 extension) — passive.

The SMB handler records file *names* from CREATE/READ frames. This module asks
tshark to export the reassembled SMB objects themselves (`--export-objects
smb,<dir>`), then reads them into the same `captured_files` pipeline used by
HTTP/FTP carving, with size and total caps.
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import shutil
import subprocess
import tempfile

from PufferRelay.tshark_fields import find_tshark

MAX_OBJECT_SIZE = 8 * 1024 * 1024
MAX_TOTAL_SIZE = 16 * 1024 * 1024


def collect_exported(directory, max_object=MAX_OBJECT_SIZE, max_total=MAX_TOTAL_SIZE):
    """Read exported objects into (filename, size, sha256, content_type, data)."""
    out = []
    total = 0
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size <= 0 or size > max_object:
            continue
        if total + size > max_total:
            break
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        total += len(data)
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        out.append(
            (name, len(data), hashlib.sha256(data).hexdigest(), content_type, data)
        )
    return out


def process_smb_objects(pcap_file):
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("tshark is not installed")
    directory = tempfile.mkdtemp(prefix="pufferrelay-smb-")
    try:
        command = [
            tshark,
            "-n",
            "-r",
            pcap_file,
            "--export-objects",
            f"smb,{directory}",
            "-q",
        ]
        try:
            completed = subprocess.run(command, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            logging.error("tshark SMB object export timed out on %s", pcap_file)
            return []
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", "replace").strip().splitlines()
            logging.warning(
                "tshark SMB object export failed: %s", error[-1] if error else completed.returncode
            )
        rows = []
        for name, size, digest, content_type, data in collect_exported(directory):
            rows.append(("smb", "", "", name, content_type, size, digest, data))
        return rows
    finally:
        shutil.rmtree(directory, ignore_errors=True)
