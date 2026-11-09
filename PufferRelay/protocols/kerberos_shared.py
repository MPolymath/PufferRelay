"""One Kerberos+ARP extraction pass shared by three handlers.

`kerberos`, `kerberoast` and `asrepcatcher` all need Kerberos fields (and
asrepcatcher also needs ARP). Running three tshark passes over the same file
was the largest avoidable cost in a default run. This module executes one
union pass, caches it for the process, and lets each handler project the
columns it needs.
"""

from __future__ import annotations

import os
import threading

from PufferRelay.tshark_fields import fields

FIELDS = [
    "ip.src",
    "ip.dst",
    "kerberos.msg_type",
    "kerberos.CNameString",
    "kerberos.realm",
    "kerberos.etype",
    "kerberos.cipher",
    "kerberos.padata_type",
    "kerberos.SNameString",
    "tcp.reassembled.data",
    "tcp.payload",
    "udp.payload",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.proto_ipv4",
]

_CACHE = {}
_LOCK = threading.Lock()


def _key(pcap_file):
    try:
        stat = os.stat(pcap_file)
    except OSError:
        return None
    return (os.path.abspath(pcap_file), stat.st_size, stat.st_mtime_ns)


def rows(pcap_file):
    """Cached rows for the union pass (16 columns, see FIELDS)."""
    key = _key(pcap_file)
    with _LOCK:
        if key is not None and key in _CACHE:
            return _CACHE[key]
        data = fields(pcap_file, "kerberos || arp", FIELDS, occurrence="a")
        if key is not None:
            if len(_CACHE) > 8:
                _CACHE.clear()
            _CACHE[key] = data
        return data
