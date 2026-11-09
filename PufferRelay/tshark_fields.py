"""Tiny tshark field extraction.

pyshark decodes every matching packet into Python objects (PDML/JSON), which is
the dominant cost on large captures. `tshark -T fields` emits only the columns
we need, one line per packet, and is often 10-50x cheaper.

All handlers that can express their needs as fields should use this module.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List, Sequence, Tuple

WINDOWS_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

_FIELD_SEPARATOR = "\t"


def find_tshark() -> str:
    """Locate tshark (PATH first, then the usual Windows install dirs)."""
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in WINDOWS_TSHARK_PATHS:
        if os.path.exists(candidate):
            return candidate
    return ""


def fields(
    pcap_file: str,
    display_filter: str,
    field_names: Sequence[str],
    timeout: int = 1800,
    occurrence: str = "f",
) -> List[Tuple[str, ...]]:
    """Run one tshark pass and return the requested fields per packet.

    Occurrence is "first" and the separator is a tab, matching the previous
    pyshark `.get()` behaviour. Returns an empty list on any tshark failure
    (the caller logs and treats it as "nothing found").
    """
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("tshark is not installed")
    if not field_names:
        return []

    command = [
        tshark,
        "-n",
        "-r",
        pcap_file,
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=" + _FIELD_SEPARATOR,
        "-E",
        "occurrence=" + occurrence,
        "-E",
        "aggregator=,",
    ]
    for name in field_names:
        command.extend(["-e", name])

    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.error("tshark timed out after %ss on %s", timeout, pcap_file)
        return []
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        if not completed.stdout:
            logging.error(
                "tshark failed (%s): %s", completed.returncode, error[-1] if error else ""
            )
            return []
        # tshark exits 1 when a field is unknown but still emits the rest.
        logging.warning(
            "tshark reported an error but produced output: %s",
            error[-1] if error else "unknown",
        )

    width = len(field_names)
    rows: List[Tuple[str, ...]] = []
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        if not line:
            continue
        parts = line.split(_FIELD_SEPARATOR)
        if len(parts) < width:
            parts.extend([""] * (width - len(parts)))
        rows.append(tuple(parts[:width]))
    return rows
