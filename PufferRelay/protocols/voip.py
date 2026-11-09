"""VoIP metadata (issue #17) — passive SIP and Cisco Skinny/SCCP.

Call signalling is often unencrypted on internal VLANs. This handler records
who called whom, the Call-ID and whether SIP proxy/digest authentication was
present. Media (RTP) is not decoded.
"""

from __future__ import annotations

import hashlib
import json
import re

from PufferRelay.tshark_fields import fields

DIGEST = re.compile(r'(\w+)\s*=\s*"?([^",]+)"?')


def _parse_digest(value):
    parsed = {}
    for key, item in DIGEST.findall(value or ""):
        parsed[key.lower()] = item.strip()
    response = parsed.pop("response", "")
    if response:
        parsed["response_sha256"] = hashlib.sha256(
            response.encode("utf-8", "replace")
        ).hexdigest()[:12]
    return parsed


def _sip_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "sip",
        [
            "ip.src",
            "ip.dst",
            "sip.Method",
            "sip.from.user",
            "sip.to.user",
            "sip.Call-ID",
            "sip.Authorization",
            "sip.Proxy-Authorization",
            "sip.User-Agent",
        ],
    )
    for src, dst, method, caller, callee, call_id, auth, proxy_auth, agent in rows:
        method = (method or "").strip().upper()
        if not method:
            continue
        authenticated = bool((auth or "").strip() or (proxy_auth or "").strip())
        digest = _parse_digest(auth or proxy_auth)
        if method == "REGISTER" and authenticated:
            kind, severity = "sip-register-auth", "medium"
            detail = "SIP REGISTER with digest/proxy authentication"
            if digest.get("response_sha256"):
                detail += " (digest response captured for offline cracking)"
        elif method in {"INVITE", "MESSAGE", "SUBSCRIBE"}:
            kind, severity = "sip-call", "low"
            detail = f"SIP {method} signalling"
        else:
            continue
        evidence = {
            "method": method,
            "call_id": call_id or "",
            "authenticated": authenticated,
            "user_agent": agent or "",
            "digest": digest,
        }
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                caller or "",
                callee or "",
                call_id or "",
                detail,
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def _skinny_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "skinny",
        [
            "ip.src",
            "ip.dst",
            "skinny.messageId",
            "skinny.CallingPartyNumber",
            "skinny.CallingPartyName",
        ],
    )
    for src, dst, message_id, number, name in rows:
        if not (number or name):
            continue
        evidence = {"message_id": message_id or "", "name": name or ""}
        out.append(
            (
                "skinny-call",
                "low",
                src or "",
                dst or "",
                number or "",
                "",
                "",
                "Cisco Skinny/SCCP call signalling",
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def process_voip(pcap_file):
    rows = _sip_pass(pcap_file) + _skinny_pass(pcap_file)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[2], row[3], row[4], row[6])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
