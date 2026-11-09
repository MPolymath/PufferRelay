"""RDP identity and negotiation metadata (step 10) — passive.

CredSSP encrypts the credentials, but the negotiation and the client data /
routing cookie can still carry a domain\\user or user@domain, and the requested
protocols tell you how the host is configured.
"""

from __future__ import annotations

import json
import re

from PufferRelay.tshark_fields import fields

IDENTITY = re.compile(
    rb"(?i)([A-Z0-9._-]{2,64}\\[A-Z0-9._-]{1,64}|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})"
)


def _decode(hex_value):
    text = (hex_value or "").replace(":", "").strip()
    if not text or len(text) % 2:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def process_rdp(pcap_file):
    rows = fields(
        pcap_file,
        "rdp",
        [
            "ip.src",
            "ip.dst",
            "rdp.neg_type",
            "rdp.negReq.requestedProtocols",
            "rdp.rt_cookie",
            "rdp.clientData",
        ],
    )
    out = []
    seen = set()
    for src, dst, neg_type, protocols, cookie, client_data in rows:
        principal = ""
        for blob in (_decode(client_data), _decode(cookie)):
            match = IDENTITY.search(blob) if blob else None
            if match:
                principal = match.group(1).decode("latin-1")
                break
        protocol_text = (protocols or "").strip()
        kind = "rdp-identity" if principal else "rdp-negotiation"
        severity = "medium" if principal else "low"
        detail = (
            f"RDP client identity {principal}"
            if principal
            else f"RDP negotiation (type {neg_type or '?'}, protocols {protocol_text or '?'})"
        )
        evidence = {
            "neg_type": neg_type or "",
            "protocols": protocol_text,
            "principal": principal,
        }
        key = (kind, src, dst, principal, detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            (kind, severity, src or "", dst or "", principal, detail,
             json.dumps(evidence, sort_keys=True))
        )
    return out
