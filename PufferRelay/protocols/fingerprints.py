"""Service fingerprints (step 9): SSH banners, TLS SNI, VNC, TFTP.

These are the last cheap protocol signals that need no new schema: they are
stored in `service_events` and exported as `fingerprints.tsv`.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields


def _ssh(pcap_file):
    out = []
    for src, dst, port, banner in fields(
        pcap_file, "ssh.protocol", ["ip.src", "ip.dst", "tcp.dstport", "ssh.protocol"]
    ):
        banner = (banner or "").strip()
        if not banner:
            continue
        out.append(
            ("ssh-banner", "low", src or "", dst or "", "",
             f"SSH banner on port {port or '22'}: {banner}",
             json.dumps({"port": port or "", "banner": banner}, sort_keys=True))
        )
    return out


def _tls(pcap_file):
    out = []
    for src, dst, port, version, sni in fields(
        pcap_file,
        "tls.handshake.extensions_server_name",
        ["ip.src", "ip.dst", "tcp.dstport", "tls.record.version",
         "tls.handshake.extensions_server_name"],
    ):
        sni = (sni or "").strip()
        if not sni:
            continue
        out.append(
            ("tls-sni", "low", src or "", dst or "", sni,
             f"TLS SNI {sni} on port {port or '443'} ({version or 'unknown version'})",
             json.dumps({"sni": sni, "version": version or "", "port": port or ""},
                        sort_keys=True))
        )
    return out


def _vnc(pcap_file):
    out = []
    for src, dst, port, version, security, name in fields(
        pcap_file,
        "vnc.server_proto_ver",
        ["ip.src", "ip.dst", "tcp.dstport", "vnc.server_proto_ver",
         "vnc.server_security_type", "vnc.server_name"],
    ):
        security = str(security or "").strip()
        if security == "1":
            kind, severity = "vnc-noauth", "high"
            detail = "VNC server advertises security type None (no authentication)"
        else:
            kind, severity = "vnc-version", "medium"
            detail = f"VNC server version {version or '?'} security type {security or '?'}"
        evidence = {
            "version": version or "",
            "security_type": security,
            "server_name": name or "",
            "port": port or "",
        }
        out.append((kind, severity, src or "", dst or "", "", detail,
                    json.dumps(evidence, sort_keys=True)))
    return out


def _tftp(pcap_file):
    out = []
    for src, dst, source_file, destination_file in fields(
        pcap_file,
        "tftp.source_file || tftp.destination_file",
        ["ip.src", "ip.dst", "tftp.source_file", "tftp.destination_file"],
    ):
        filename = (source_file or destination_file or "").strip()
        if not filename:
            continue
        out.append(
            ("tftp-file", "medium", src or "", dst or "", "",
             f"TFTP file transfer: {filename}",
             json.dumps({"filename": filename}, sort_keys=True))
        )
    return out


def process_fingerprints(pcap_file):
    rows = _ssh(pcap_file) + _tls(pcap_file) + _vnc(pcap_file) + _tftp(pcap_file)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[2], row[3], row[4], row[5])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
