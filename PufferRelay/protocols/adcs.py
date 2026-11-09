"""ADCS enrollment and PKINIT detection (issue #67) — passive.

ADCS abuse shows up as certificate-enrollment traffic (HTTP /certsrv or DCOM)
and as PKINIT certificate logon in Kerberos. Both are visible without touching
the network.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields

ADCS_FILTER = (
    'http.request && (http.request.uri contains "/certsrv" '
    '|| http.request.uri contains "/CertSrv" '
    '|| http.request.uri contains "certfnsh" '
    '|| http.request.uri contains "certnew")'
)


def _http_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        ADCS_FILTER,
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri",
            "http.authorization",
            "http.user_agent",
        ],
    )
    for src, dst, host, uri, authorization, user_agent in rows:
        auth = (authorization or "").strip()
        ntlm = "NTLM" in auth.upper()
        severity = "high" if ntlm else "medium"
        evidence = {
            "host": host or "",
            "uri": uri or "",
            "auth": "NTLM" if ntlm else (auth.split(" ", 1)[0] if auth else ""),
            "user_agent": user_agent or "",
        }
        out.append(
            (
                "enrollment",
                severity,
                src or "",
                dst or "",
                host or "",
                uri or "",
                "",
                "",
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def _pkinit_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "kerberos.padata_type == 16",
        [
            "ip.src",
            "ip.dst",
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.padata_type",
        ],
    )
    for src, dst, principal, realm, padata in rows:
        evidence = {"padata_type": padata or "16", "principal": principal or ""}
        out.append(
            (
                "pkinit",
                "medium",
                src or "",
                dst or "",
                "",
                "",
                principal or "",
                realm or "",
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def process_adcs(pcap_file):
    rows = _http_pass(pcap_file) + _pkinit_pass(pcap_file)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[2], row[3], row[5], row[6])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
