"""RPC coercion detection (issue #65) — passive.

Coerced authentication is the start of most NTLM relay chains. The capture
contains the DCE/RPC call over a SMB named pipe (MS-EFSRPC, MS-RPRN,
MS-DFSNM, MS-FSRVP) and often the UNC path the victim was told to contact.
"""

from __future__ import annotations

import json
import re

from PufferRelay.tshark_fields import fields

INTERFACES = {
    "c681d488-d850-11d0-8c52-00c04fd90f7e": ("MS-EFSRPC", "efsrpc"),
    "12345678-1234-abcd-ef00-0123456789ab": ("MS-RPRN", "spoolss"),
    "12345678-1234-abcd-ef00-01234567cffb": ("MS-DFSNM", "netdfs"),
    "a8e0653c-2744-4389-a61d-7373df8b2292": ("MS-FSRVP", "FssagentRpc"),
}
PIPE_KINDS = {
    "efsrpc": "MS-EFSRPC",
    "spoolss": "MS-RPRN",
    "netdfs": "MS-DFSNM",
    "lsarpc": "LSARPC",
}
UNC = re.compile(rb"\\\\[A-Za-z0-9._-]{1,64}\\[^\x00\r\n\"']{0,120}")
COERCION_FILTER = (
    'dcerpc || smb2.filename == "efsrpc" || smb2.filename == "spoolss" '
    '|| smb2.filename == "netdfs"'
)


def _decoded(hex_payload):
    text = (hex_payload or "").replace(":", "").strip()
    if not text or len(text) % 2:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def process_coercion(pcap_file):
    rows = fields(
        pcap_file,
        COERCION_FILTER,
        [
            "ip.src",
            "ip.dst",
            "smb2.filename",
            "dcerpc.cn_bind_to_uuid",
            "dcerpc.opnum",
            "tcp.reassembled.data",
            "tcp.payload",
        ],
    )
    out = []
    seen = set()
    for src, dst, pipe, interface_uuid, opnum, reassembled, payload in rows:
        pipe = (pipe or "").strip().lower()
        uuid = (interface_uuid or "").strip().lower()
        blob = _decoded(reassembled) or _decoded(payload)
        match = UNC.search(blob) if blob else None
        unc = match.group(0).decode("latin-1", "replace") if match else ""

        kind = ""
        if uuid in INTERFACES:
            kind = INTERFACES[uuid][0]
        elif pipe in PIPE_KINDS and PIPE_KINDS[pipe] != "LSARPC":
            kind = PIPE_KINDS[pipe]
        if not kind or not unc:
            # A bind or a pipe alone is normal (printing, DFS, LSA); the UNC
            # path is what makes it a coercion attempt.
            continue
        severity = "high"
        key = (kind, src, dst, unc)
        if key in seen:
            continue
        seen.add(key)
        evidence = {
            "interface": uuid,
            "pipe": pipe,
            "opnum": opnum or "",
            "unc": unc,
        }
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                pipe,
                uuid,
                opnum or "",
                unc,
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out
