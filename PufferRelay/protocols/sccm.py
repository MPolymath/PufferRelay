"""SCCM/MECM detection (issue #68) — passive.

Management points and distribution points are recognisable by URI markers
(/SMS_MP, ccmhttp, Content_*, SMSPKG) and by the SMS_SITE / SMSPKG$ shares.
NTLM to a management point or client-push SMB is worth a lead because SCCM is
a common relay and site-takeover target.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields

HTTP_FILTER = (
    'http.request && (http.request.uri contains "/SMS_MP" '
    '|| http.request.uri contains "ccmhttp" '
    '|| http.request.uri contains "Content_" '
    '|| http.request.uri contains "SMSPKG" '
    '|| http.request.uri contains "/CCM_System" '
    '|| http.request.uri contains ".pkg")'
)
SMB_FILTER = (
    'smb2.tree contains "SMS" || smb2.tree contains "ADMIN$" '
    '|| smb2.tree contains "C$" || smb2.filename contains "SMS_"'
)


def _http_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        HTTP_FILTER,
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri",
            "http.user_agent",
            "http.authorization",
        ],
    )
    for src, dst, host, uri, user_agent, authorization in rows:
        uri_text = uri or ""
        if any(marker in uri_text for marker in ("/SMS_MP", "ccmhttp", "/CCM_System")):
            kind = "sccm-mp-http"
        elif any(marker in uri_text for marker in ("Content_", "SMSPKG", ".pkg")):
            kind = "sccm-dp-http"
        else:
            kind = "sccm-http"
        auth = (authorization or "").strip()
        ntlm = "NTLM" in auth.upper()
        severity = "high" if ntlm else "medium"
        evidence = {
            "host": host or "",
            "uri": uri_text,
            "user_agent": user_agent or "",
            "auth": "NTLM" if ntlm else (auth.split(" ", 1)[0] if auth else ""),
        }
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                host or "",
                uri_text,
                "",
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def _smb_pass(pcap_file, management_points):
    out = []
    rows = fields(
        pcap_file,
        SMB_FILTER,
        ["ip.src", "ip.dst", "smb2.tree", "smb2.filename"],
    )
    for src, dst, tree, filename in rows:
        tree_text = tree or ""
        file_text = filename or ""
        if ("ADMIN$" in tree_text or "C$" in tree_text) and src in management_points:
            kind, severity = "sccm-client-push", "high"
            detail = "site server pushed to an administrative share"
        elif "SMS_SITE" in tree_text:
            kind, severity = "sccm-site-share", "medium"
            detail = "SMS_SITE share accessed"
        elif "SMSPKG" in tree_text:
            kind, severity = "sccm-package-share", "medium"
            detail = "SMSPKG share accessed"
        elif "SMS" in tree_text or "SMS_" in file_text:
            kind, severity = "sccm-smb", "medium"
            detail = "SCCM SMB traffic observed"
        else:
            continue
        evidence = {"tree": tree_text, "filename": file_text, "detail": detail}
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                "",
                "",
                tree_text,
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def process_sccm(pcap_file):
    http_rows = _http_pass(pcap_file)
    management_points = {
        row[3] for row in http_rows if row[0] == "sccm-mp-http" and row[3]
    }
    rows = http_rows + _smb_pass(pcap_file, management_points)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[2], row[3], row[5], row[6])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
