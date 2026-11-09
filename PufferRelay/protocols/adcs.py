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
WCCE_UUIDS = {
    "d99dfb68-8f8a-11d0-b881-00c04fc9b5a1": "ICertRequestD",
    "5422fd3a-d4b4-4cef-a72d-3f0f3d5c1c9d": "ICertRequestD2",
    "7fe0d935-dda6-443f-85d0-1cfb58fe41dd": "ICertAdminD2",
}


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


def _dcom_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "dcerpc.cn_bind_to_uuid",
        ["ip.src", "ip.dst", "dcerpc.cn_bind_to_uuid", "dcerpc.opnum"],
    )
    for src, dst, uuid, opnum in rows:
        interface = (uuid or "").strip().lower()
        if interface not in WCCE_UUIDS:
            continue
        evidence = {
            "interface": interface,
            "name": WCCE_UUIDS[interface],
            "opnum": opnum or "",
        }
        out.append(
            (
                "enrollment-dcom",
                "high",
                src or "",
                dst or "",
                "",
                "",
                "",
                "",
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out


def process_adcs(pcap_file):
    rows = _http_pass(pcap_file) + _pkinit_pass(pcap_file) + _dcom_pass(pcap_file)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[2], row[3], row[5], row[6])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
