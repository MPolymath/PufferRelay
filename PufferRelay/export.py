"""Exports for PufferRelay.

Everything in this module is **passive**: it reads the SQLite database that the
pcap handlers filled and writes files. No network access, no packet sending.

Two audiences:
  * humans / other tools -> line-oriented text, CSV, JSON inventories
  * AI agents            -> ``leads.json`` + ``leads.md``: every confirmed or
    potential vulnerability with its evidence and suggested next actions.
    Suggested commands are labelled ``active`` because running them sends
    traffic; the operator must confirm scope before using them.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from PufferRelay.protocols.helpers import interesting_file
from PufferRelay.protocols.asrepcatcher import REFERENCE as ASREPCATCHER_REFERENCE
from PufferRelay.graph import build_graph

ATTCK_BY_PREFIX = {
    "CRED": ["T1078", "T1552.001"],
    "HASH": ["T1110.002"],
    "ASREP": ["T1558.004"],
    "KERBEROAST": ["T1558.003"],
    "KERBEROASTCAND": ["T1558.003"],
    "TOKEN": ["T1528", "T1552.001"],
    "RELAY": ["T1557.001"],
    "COERCE": ["T1187"],
    "ADCS": ["T1649"],
    "SCCM": ["T1078"],
    "IPV6": ["T1557"],
    "DB": ["T1078", "T1552.001"],
    "LLM": ["T1528"],
    "KERB": ["T1558"],
    "SPN": ["T1558.003"],
    "LDAPSIGN": ["T1557.001"],
    "CHAIN": ["T1557"],
    "VOIP": ["T1123"],
    "RDP": ["T1021.001"],
    "CLOUD": ["T1078.004"],
    "WPAD": ["T1557"],
    "SMB": ["T1021.002"],
    "SMBFILE": ["T1039"],
    "FILE": ["T1039"],
    "NAC": ["T1557"],
    "WSUS": ["T1072"],
    "WIFI": ["T1040", "T1557", "T1110"],
    "ASREPCATCHER": ["T1557", "T1558.004"],
    "QW": ["T1040"],
    "REUSE": ["T1078"],
}


def attck_for(lead_id: str) -> List[str]:
    return ATTCK_BY_PREFIX.get((lead_id or "").split("-", 1)[0].upper(), [])

EXPORT_SCHEMA = 1

# Curated port -> service map (common pentest-relevant services). Unknown ports
# fall back to the socket service database, then to "unknown".
PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    81: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "smb",
    464: "kpasswd",
    465: "smtps",
    514: "syslog",
    515: "lpd",
    548: "afp",
    587: "smtp-submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3268: "ldap-gc",
    3269: "ldaps-gc",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

CLEARTEXT_PROTOCOLS = {"FTP", "TELNET", "SMTP", "IMAP", "POP3", "HTTP", "LDAP"}


def service_for_port(port: int) -> str:
    """Best-effort service name for a port (pure, unit-tested)."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        import socket

        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _rows(conn: sqlite3.Connection, sql: str, params: Sequence = ()) -> List[Tuple]:
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return list(cur.fetchall())
    except sqlite3.Error:
        return []


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return bool(
        _rows(conn, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    )


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #


def _normalise_username(raw: str) -> Tuple[str, str]:
    """Split DOMAIN\\user / user@domain into (user, domain). Keeps raw user."""
    if not raw:
        return "", ""
    text = str(raw).strip().strip('"')
    if "\\" in text:
        domain, user = text.split("\\", 1)
        return user, domain
    if "@" in text and not text.lower().startswith("cn="):
        user, domain = text.split("@", 1)
        return user, domain
    return text, ""


def collect_users(conn: sqlite3.Connection) -> List[Dict]:
    """Union of identities seen across protocols, with their sources."""
    seen: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    hosts: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    display_domain: Dict[Tuple[str, str], str] = {}

    def add(raw: str, source: str, host: str) -> None:
        user, domain = _normalise_username(raw)
        if not user or user.upper() in {"N/A", "ANONYMOUS", "(ANONYMOUS)"}:
            return
        key = (domain.lower(), user)
        seen[key].add(source)
        if domain and key not in display_domain:
            display_domain[key] = domain
        if host:
            hosts[key].add(host)

    for _src, dst, name, _simple in _rows(
        conn, "SELECT source_ip, destination_ip, ldap_name, ldap_simple FROM ldap_requests"
    ):
        add(name, "ldap", dst)

    for _src, dst, user, _pw in _rows(
        conn, "SELECT source_ip, destination_ip, username, password FROM imap_requests"
    ):
        add(user, "imap", dst)

    for _src, dst, user, _pw in _rows(
        conn, "SELECT source_ip, destination_ip, username, password FROM pop3_requests"
    ):
        add(user, "pop3", dst)

    for _src, dst, user, _pw in _rows(
        conn, "SELECT source_ip, destination_ip, smtp_user, smtp_password FROM smtp_requests"
    ):
        add(user, "smtp", dst)

    for _src, dst, user, _pw in _rows(
        conn, "SELECT source_ip, destination_ip, http_auth_username, http_auth_password "
        "FROM http_requests"
    ):
        add(user, "http", dst)

    # FTP: the USER command carries the identity.
    for _src, dst, _cmd, arg in _rows(
        conn,
        "SELECT source_ip, destination_ip, ftp_request_command, ftp_request_arg "
        "FROM ftp_requests WHERE UPPER(ftp_request_command)='USER'",
    ):
        add(arg, "ftp", dst)

    # NTLM: DOMAIN\\user.
    for _src, dst, user, _hash in _rows(
        conn, "SELECT source_ip, destination_ip, username, ntlm_hash FROM ntlm_requests"
    ):
        add(user, "ntlm", dst)

    # Kerberos principals seen in AS-REQ/AS-REP.
    if _has_table(conn, "kerberos_asrep"):
        for user, realm in _rows(conn, "SELECT username, realm FROM kerberos_asrep"):
            add(user, "kerberos", realm)

    # EAP/RADIUS identities (skip MAC-shaped MAB usernames).
    if _has_table(conn, "nac_events"):
        for kind, identity in _rows(conn, "SELECT kind, identity FROM nac_events"):
            if identity and not looks_like_mac(identity):
                add(identity, kind or "eap", "")

    # LDAP directory: the SPN mapping names the accounts behind service SPNs,
    # and objectSID (when captured) upgrades the BloodHound identifier.
    sid_by_user = {}
    if _has_table(conn, "ldap_spns"):
        for account, sid in _rows(
            conn, "SELECT account, sid FROM ldap_spns WHERE sid != ''"
        ):
            add(account, "ldap-spn", "")
            user, domain = _normalise_username(account)
            if user:
                sid_by_user[(domain.lower(), user)] = sid

    out = []
    for (domain_key, user), sources in seen.items():
        entry = {
            "username": user,
            "domain": display_domain.get((domain_key, user), domain_key),
            "sources": sorted(sources),
            "seen_at": sorted({h for h in hosts[(domain_key, user)] if h and h != "N/A"}),
        }
        sid = sid_by_user.get((domain_key, user))
        if sid:
            entry["sid"] = sid
        out.append(entry)
    out.sort(key=lambda u: (u["domain"], u["username"].lower()))
    return out


def _cred(protocol: str, src: str, dst: str, user: str, secret: str, context: str) -> Dict:
    return {
        "protocol": protocol,
        "source_ip": src or "",
        "destination_ip": dst or "",
        "username": user or "",
        "secret": secret or "",
        "context": context,
    }


def collect_credentials(conn: sqlite3.Connection) -> List[Dict]:
    """Explicit credentials, with protocol/source/destination."""
    creds: List[Dict] = []

    # FTP: pair USER then PASS within each conversation.
    pending: Dict[Tuple[str, str], str] = {}
    for src, dst, cmd, arg in _rows(
        conn,
        "SELECT source_ip, destination_ip, ftp_request_command, ftp_request_arg "
        "FROM ftp_requests ORDER BY id",
    ):
        command = (cmd or "").upper()
        if command == "USER":
            pending[(src, dst)] = arg
        elif command == "PASS":
            user = pending.pop((src, dst), "")
            creds.append(_cred("ftp", src, dst, user, arg, "cleartext FTP"))

    for src, dst, user, pw, url in _rows(
        conn,
        "SELECT source_ip, destination_ip, http_auth_username, http_auth_password, http_url "
        "FROM http_requests WHERE http_auth_username IS NOT NULL "
        "AND http_auth_username != 'N/A'",
    ):
        creds.append(_cred("http", src, dst, user, pw, "HTTP Basic auth"))

    for src, dst, user, pw in _rows(
        conn,
        "SELECT source_ip, destination_ip, smtp_user, smtp_password FROM smtp_requests "
        "WHERE smtp_user IS NOT NULL AND smtp_user != 'N/A'",
    ):
        creds.append(_cred("smtp", src, dst, user, pw, "SMTP auth"))

    for src, dst, user, pw in _rows(
        conn,
        "SELECT source_ip, destination_ip, username, password FROM imap_requests "
        "WHERE username IS NOT NULL AND username != 'N/A'",
    ):
        creds.append(_cred("imap", src, dst, user, pw, "IMAP LOGIN"))

    for src, dst, user, pw in _rows(
        conn,
        "SELECT source_ip, destination_ip, username, password FROM pop3_requests "
        "WHERE username IS NOT NULL AND username != 'N/A'",
    ):
        creds.append(_cred("pop3", src, dst, user, pw, "POP3 USER/PASS"))

    for src, dst, name, simple in _rows(
        conn,
        "SELECT source_ip, destination_ip, ldap_name, ldap_simple FROM ldap_requests "
        "WHERE ldap_simple IS NOT NULL AND ldap_simple != 'N/A'",
    ):
        creds.append(_cred("ldap", src, dst, name, simple, "LDAP simple bind"))

    return creds


def collect_hashes(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if _has_table(conn, "kerberos_asrep"):
        for user, realm, etype, asrep, src, dst in _rows(
            conn,
            "SELECT username, realm, etype, hash, src_ip, dst_ip FROM kerberos_asrep",
        ):
            out.append(
                {
                    "username": f"{user}@{realm}",
                    "hash": asrep or "",
                    "source_ip": src or "",
                    "destination_ip": dst or "",
                    "kind": f"AS-REP (etype {etype or '23'})",
                    "hashcat_mode": 18200,
                }
            )
    for src, dst, user, ntlm_hash in _rows(
        conn, "SELECT source_ip, destination_ip, username, ntlm_hash FROM ntlm_requests"
    ):
        out.append(
            {
                "username": user or "",
                "hash": ntlm_hash or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "kind": "NTLMv2" if "$NETNTLMv2$" in (ntlm_hash or "") else "NTLM",
                "hashcat_mode": 5600,
            }
        )
    return out


def _ip_key(ip: str):
    try:
        from ipaddress import ip_address

        return (0, int(ip_address(ip)))
    except ValueError:
        return (1, 0)


def _looks_like_ip(value: str) -> bool:
    try:
        from ipaddress import ip_address

        ip_address(value)
        return True
    except ValueError:
        return False


def _ptr_to_ip(name: str) -> str:
    """'5.0.0.10.in-addr.arpa' -> '10.0.0.5'; '' for anything else."""
    labels = (name or "").rstrip(".").split(".")
    if len(labels) < 6 or labels[-2:] != ["in-addr", "arpa"]:
        return ""
    try:
        octets = [str(int(label)) for label in labels[:4]]
    except ValueError:
        return ""
    return ".".join(reversed(octets))


def collect_hosts(conn: sqlite3.Connection) -> List[Dict]:
    """IPs from ip_requests, enriched with NetBIOS/DNS names, MACs and services."""
    names: Dict[str, Set[str]] = defaultdict(set)
    macs: Dict[str, Set[str]] = defaultdict(set)
    for row in _rows(conn, "SELECT hostname, src_ip, src_mac FROM netbios_requests"):
        hostname, ip, mac = row
        if ip and ip != "N/A":
            if hostname and hostname != "N/A":
                names[ip].add(hostname)
            if mac and mac != "N/A":
                macs[ip].add(mac)

    # DNS answers tie a name to an IP without sending a query (issues #11/#59).
    if _has_table(conn, "dns_events"):
        for qname, answer in _rows(
            conn, "SELECT query_name, answer FROM dns_events WHERE answer != ''"
        ):
            name = (qname or "").strip(".")
            value = (answer or "").strip(".")
            if not name or not value:
                continue
            if _looks_like_ip(value):
                names[value].add(name)
            elif name.endswith("in-addr.arpa"):
                ptr_ip = _ptr_to_ip(name)
                if ptr_ip:
                    names[ptr_ip].add(value)

    ports: Dict[str, Set[Tuple[int, str]]] = defaultdict(set)
    if _has_table(conn, "observed_services"):
        for ip, port, service, _transport in _rows(
            conn, "SELECT ip, port, service, transport FROM observed_services"
        ):
            try:
                ports[ip].add((int(port), service or "unknown"))
            except (TypeError, ValueError):
                continue

    hosts = []
    for _subnet, ip in _rows(conn, "SELECT subnet, ip FROM ip_requests"):
        hosts.append(
            {
                "ip": ip,
                "hostnames": sorted(names.get(ip, set())),
                "macs": sorted(macs.get(ip, set())),
                "services": [
                    {"port": port, "service": svc}
                    for port, svc in sorted(ports.get(ip, set()), key=lambda p: p[0])
                ],
            }
        )
    hosts.sort(key=lambda h: _ip_key(h["ip"]))
    return hosts


def collect_quick_wins(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    for protocol, found, details, creds_found, cred_protocols, severity, evidence in _rows(
        conn,
        "SELECT protocol, found, details, credentials_found, credential_protocols, "
        "severity, evidence FROM quick_wins",
    ):
        observed = None
        if evidence:
            try:
                observed = json.loads(evidence)
            except (TypeError, ValueError):
                observed = None
        out.append(
            {
                "protocol": protocol,
                "found": bool(found),
                "details": details or "",
                "credentials_found": bool(creds_found),
                "credential_protocols": [p for p in (cred_protocols or "").split(",") if p],
                "severity": severity or "",
                "observed": observed,
            }
        )
    return out


def collect_relays(conn: sqlite3.Connection) -> List[Dict]:
    """NTLM relay candidates observed in the capture (issue #62)."""
    out = []
    if not _has_table(conn, "relay_scenarios"):
        return out
    for src, dst, port, protocol, user, signing, candidate in _rows(
        conn,
        "SELECT src_ip, dst_ip, dst_port, protocol, username, signing_required, "
        "candidate FROM relay_scenarios",
    ):
        out.append(
            {
                "source_ip": src or "",
                "destination_ip": dst or "",
                "destination_port": port or 0,
                "protocol": protocol or "unknown",
                "username": user or "",
                "signing_required": None if signing == "" else bool(signing),
                "candidate": bool(candidate),
            }
        )
    return out


def collect_smb(conn: sqlite3.Connection) -> Dict:
    """Shares and file names observed over SMB (issue #44)."""
    if not _has_table(conn, "smb_activity"):
        return {"shares": [], "files": []}
    shares = []
    files = []
    for src, dst, share, file_name, operation, printer in _rows(
        conn,
        "SELECT src_ip, dst_ip, share, file, operation, printer FROM smb_activity",
    ):
        shares.append(
            {
                "source_ip": src or "",
                "destination_ip": dst or "",
                "share": share or "",
                "printer": bool(printer),
            }
        )
        if file_name:
            files.append(
                {
                    "source_ip": src or "",
                    "destination_ip": dst or "",
                    "share": share or "",
                    "file": file_name,
                    "operation": operation or "",
                }
            )
    return {"shares": shares, "files": files}


def collect_files(conn: sqlite3.Connection) -> List[Dict]:
    """Metadata of carved files (no payload; the BLOBs are written separately)."""
    if not _has_table(conn, "captured_files"):
        return []
    out = []
    for protocol, src, dst, filename, content_type, size, digest in _rows(
        conn,
        "SELECT protocol, src_ip, dst_ip, filename, content_type, size, sha256 "
        "FROM captured_files",
    ):
        out.append(
            {
                "protocol": protocol or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "filename": filename or "",
                "content_type": content_type or "",
                "size": size or 0,
                "sha256": digest or "",
                "stored_as": f"{(digest or '')[:12]}_{filename or 'object'}",
            }
        )
    return out


def collect_nac(conn: sqlite3.Connection) -> List[Dict]:
    """EAP/RADIUS observations (issue #30)."""
    if not _has_table(conn, "nac_events"):
        return []
    out = []
    for kind, identity, src, dst, method, mab in _rows(
        conn,
        "SELECT kind, identity, src, dst, method, mab FROM nac_events",
    ):
        out.append(
            {
                "kind": kind or "",
                "identity": identity or "",
                "src": src or "",
                "dst": dst or "",
                "method": method or "",
                "mab": bool(mab),
            }
        )
    return out


def collect_wsus(conn: sqlite3.Connection) -> List[Dict]:
    """WSUS/Windows Update endpoints (issue #14)."""
    if not _has_table(conn, "wsus_endpoints"):
        return []
    out = []
    for src, dst, host, uri, user_agent, indicator in _rows(
        conn,
        "SELECT src_ip, dst_ip, host, uri, user_agent, indicator FROM wsus_endpoints",
    ):
        out.append(
            {
                "source_ip": src or "",
                "destination_ip": dst or "",
                "host": host or "",
                "uri": uri or "",
                "user_agent": user_agent or "",
                "indicator": indicator or "",
            }
        )
    return out


def collect_dns(conn: sqlite3.Connection) -> List[Dict]:
    """DNS queries/answers observed in the capture (issues #11/#59)."""
    out = []
    if not _has_table(conn, "dns_events"):
        return out
    for src, dst, name, qtype, answer, is_response in _rows(
        conn,
        "SELECT src_ip, dst_ip, query_name, query_type, answer, is_response "
        "FROM dns_events",
    ):
        out.append(
            {
                "source_ip": src or "",
                "destination_ip": dst or "",
                "query": name or "",
                "type": qtype or "",
                "answer": answer or "",
                "is_response": bool(is_response),
            }
        )
    return out


def collect_asrepcatcher(conn: sqlite3.Connection) -> List[Dict]:
    """ASRepCatcher-compatible activity observed in the capture."""
    out = []
    if not _has_table(conn, "asrepcatcher_findings"):
        return out
    for row in _rows(
        conn,
        "SELECT kind, severity, client_ip, attacker_ip, kdc_ip, username, realm, "
        "summary, evidence FROM asrepcatcher_findings",
    ):
        kind, severity, client, attacker, kdc, user, realm, summary, evidence = row
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "high",
                "client_ip": client or "",
                "attacker_ip": attacker or "",
                "kdc_ip": kdc or "",
                "username": user or "",
                "realm": realm or "",
                "summary": summary or "",
                "evidence": parsed,
            }
        )
    return out


def collect_kerberoast(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "kerberoast"):
        return out
    for user, realm, spn, etype, digest, src, dst, confidence in _rows(
        conn,
        "SELECT username, realm, spn, etype, hash, src_ip, dst_ip, confidence "
        "FROM kerberoast",
    ):
        out.append(
            {
                "username": user or "",
                "realm": realm or "",
                "spn": spn or "",
                "etype": int(etype or 0),
                "hash": digest or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "confidence": confidence or "candidate",
            }
        )
    return out


def collect_tokens(conn: sqlite3.Connection) -> List[Dict]:
    """HTTP tokens; the full secret stays in the database only."""
    out = []
    if not _has_table(conn, "http_tokens"):
        return out
    for row in _rows(
        conn,
        "SELECT kind, severity, host, path, header, fingerprint, principal, "
        "expires, src_ip, dst_ip FROM http_tokens",
    ):
        kind, severity, host, path, header, mark, principal, expires, src, dst = row
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "high",
                "host": host or "",
                "path": path or "",
                "header": header or "",
                "fingerprint": mark or "",
                "principal": principal or "",
                "expires": expires or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
            }
        )
    return out


def collect_coercions(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "coercion_events"):
        return out
    for kind, severity, src, dst, pipe, uuid, opnum, unc, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, pipe, interface_uuid, opnum, unc, "
        "evidence FROM coercion_events",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "high",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "pipe": pipe or "",
                "interface": uuid or "",
                "opnum": opnum or "",
                "unc": unc or "",
                "evidence": parsed,
            }
        )
    return out


def collect_adcs(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "adcs_events"):
        return out
    for kind, severity, src, dst, host, uri, principal, realm, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, host, uri, principal, realm, "
        "evidence FROM adcs_events",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "host": host or "",
                "uri": uri or "",
                "principal": principal or "",
                "realm": realm or "",
                "evidence": parsed,
            }
        )
    return out


def collect_ipv6(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "ipv6_events"):
        return out
    for kind, severity, src, dst, detail, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, detail, evidence FROM ipv6_events",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "high",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "detail": detail or "",
                "evidence": parsed,
            }
        )
    return out


def collect_database_creds(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "database_creds"):
        return out
    for protocol, src, dst, user, secret, kind, mark, server, hashcat in _rows(
        conn,
        "SELECT protocol, src_ip, dst_ip, username, secret, kind, fingerprint, "
        "server, hashcat FROM database_creds",
    ):
        out.append(
            {
                "protocol": protocol or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "username": user or "",
                "secret": secret or "",
                "kind": kind or "",
                "fingerprint": mark or "",
                "server": server or "",
                "hashcat": hashcat or "",
            }
        )
    return out


def collect_service_events(conn: sqlite3.Connection, protocol: str) -> List[Dict]:
    out = []
    if not _has_table(conn, "service_events"):
        return out
    for kind, severity, src, dst, principal, detail, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, principal, detail, evidence "
        "FROM service_events WHERE protocol = ?",
        (protocol,),
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "principal": principal or "",
                "detail": detail or "",
                "evidence": parsed,
            }
        )
    return out


def collect_sccm(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "sccm_events"):
        return out
    for kind, severity, src, dst, host, uri, share, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, host, uri, share, evidence "
        "FROM sccm_events",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "host": host or "",
                "uri": uri or "",
                "share": share or "",
                "evidence": parsed,
            }
        )
    return out


def collect_llm(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "llm_events"):
        return out
    for kind, severity, src, dst, service, host, path, model, auth, detail, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, service, host, path, model, auth, "
        "detail, evidence FROM llm_events",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "service": service or "",
                "host": host or "",
                "path": path or "",
                "model": model or "",
                "auth": auth or "no",
                "detail": detail or "",
                "evidence": parsed,
            }
        )
    return out


def collect_kerberos_signals(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "kerberos_signals"):
        return out
    for kind, severity, user, realm, service, src, dst, detail, evidence in _rows(
        conn,
        "SELECT kind, severity, username, realm, service, src_ip, dst_ip, detail, "
        "evidence FROM kerberos_signals",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "username": user or "",
                "realm": realm or "",
                "service": service or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "detail": detail or "",
                "evidence": parsed,
            }
        )
    return out


def collect_ldap_spns(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "ldap_spns"):
        return out
    for account, spn, sid, src, dst in _rows(
        conn, "SELECT account, spn, sid, src_ip, dst_ip FROM ldap_spns"
    ):
        out.append(
            {
                "account": account or "",
                "spn": spn or "",
                "sid": sid or "",
                "source_ip": src or "",
                "destination_ip": dst or "",
            }
        )
    return out


def collect_ldap_signing(conn: sqlite3.Connection) -> List[Dict]:
    """Per destination: total binds vs simple (unsigned) binds.

    A destination that only ever saw simple binds is a signing candidate; a
    SASL bind is not proof that signing was enforced, so the lead stays medium.
    """
    out = []
    if not _has_table(conn, "ldap_requests"):
        return out
    for dst, binds, simple in _rows(
        conn,
        "SELECT destination_ip, COUNT(*), "
        "SUM(CASE WHEN ldap_simple IS NOT NULL AND ldap_simple != '' "
        "AND ldap_simple != 'N/A' THEN 1 ELSE 0 END) "
        "FROM ldap_requests GROUP BY destination_ip",
    ):
        binds = int(binds or 0)
        simple = int(simple or 0)
        if not binds:
            continue
        out.append(
            {
                "destination_ip": dst or "",
                "binds": binds,
                "simple_binds": simple,
                "sasl_binds": max(0, binds - simple),
            }
        )
    return out


def _unc_host(unc: str) -> str:
    match = re.match(r"^\\\\+([^\\]+)", unc or "")
    return match.group(1) if match else ""


def build_chains(inventory: Dict) -> List[Dict]:
    """Correlate coercion, credentials/hashes, LDAP signing and relay targets."""
    hosts = inventory.get("hosts", [])
    by_name = {}
    for host in hosts:
        for name in host.get("hostnames") or []:
            by_name[name.lower()] = host["ip"]
    credentials = inventory.get("credentials", [])
    hashes = inventory.get("hashes", [])
    relays = [
        relay
        for relay in inventory.get("relays", [])
        if relay.get("candidate") and relay.get("signing_required") is False
    ]
    signing = {
        row["destination_ip"]: row
        for row in inventory.get("ldap_signing", [])
        if row.get("destination_ip")
    }
    enrollments = {
        row["destination_ip"]
        for row in inventory.get("adcs", [])
        if row.get("kind") == "enrollment" and row.get("severity") == "high"
    }

    def users_at(target):
        users = {row["username"] for row in credentials if row["destination_ip"] == target}
        users |= {row["username"] for row in hashes if row["destination_ip"] == target}
        return {user for user in users if user}

    chains = []
    seen = set()

    def add(kind, severity, target, users, source, evidence, missing, confidence):
        key = (kind, target, ",".join(sorted(users)))
        if key in seen or not target:
            return
        seen.add(key)
        chains.append(
            {
                "kind": kind,
                "severity": severity,
                "confidence": confidence,
                "target": target,
                "users": sorted(users),
                "source": source,
                "evidence": evidence,
                "missing": missing,
            }
        )

    for row in inventory.get("coercions", []):
        host = _unc_host(row.get("unc", ""))
        if not host:
            continue
        target = by_name.get(host.lower(), host)
        users = users_at(target)
        relay = any(item["destination_ip"] == target for item in relays)
        ldap_sign = bool(signing.get(target, {}).get("simple_binds"))
        adcs = target in enrollments
        if not (users or relay or ldap_sign or adcs):
            continue
        missing = []
        if not users:
            missing.append("no credential or hash for the target")
        if not relay:
            missing.append("no relay candidate with signing disabled")
        if not ldap_sign and not adcs:
            missing.append("no LDAP-signing or ADCS evidence for the target")
        add(
            "coercion-relay-chain",
            "critical" if users and relay else "high",
            target,
            users,
            row.get("kind", ""),
            {
                "coercion": row.get("kind", ""),
                "unc": row.get("unc", ""),
                "relay_target": relay,
                "ldap_simple_binds": ldap_sign,
                "adcs_enrollment": adcs,
            },
            missing,
            "high" if users and relay else "medium",
        )

    for relay in relays:
        target = relay["destination_ip"]
        users = users_at(target)
        if users:
            add(
                "credential-relay-chain",
                "high",
                target,
                users,
                relay.get("protocol", ""),
                {
                    "protocol": relay.get("protocol", ""),
                    "signing_required": relay.get("signing_required"),
                },
                [],
                "high",
            )
        ldap_sign = bool(signing.get(target, {}).get("simple_binds"))
        if ldap_sign:
            add(
                "ldap-relay-chain",
                "high",
                target,
                users,
                "LDAP",
                {
                    "simple_binds": signing[target].get("simple_binds"),
                    "binds": signing[target].get("binds"),
                },
                [] if users else ["no credential or hash for the LDAP target"],
                "high" if users else "medium",
            )
        if target in enrollments:
            add(
                "adcs-relay-chain",
                "critical",
                target,
                users,
                "ADCS",
                {"enrollment": "NTLM enrollment observed", "relay_target": True},
                [] if users else ["no credential or hash for the CA"],
                "high" if users else "medium",
            )
    return chains


def collect_ldap_adcs(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "ldap_adcs"):
        return out
    for kind, severity, name, dns_name, template, detail, evidence, src, dst in _rows(
        conn,
        "SELECT kind, severity, name, dns_name, template, detail, evidence, "
        "src_ip, dst_ip FROM ldap_adcs",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "medium",
                "name": name or "",
                "dns_name": dns_name or "",
                "template": template or "",
                "detail": detail or "",
                "evidence": parsed,
                "source_ip": src or "",
                "destination_ip": dst or "",
            }
        )
    return out


def collect_voip(conn: sqlite3.Connection) -> List[Dict]:
    out = []
    if not _has_table(conn, "voip_calls"):
        return out
    for kind, severity, src, dst, caller, callee, call_id, detail, evidence in _rows(
        conn,
        "SELECT kind, severity, src_ip, dst_ip, caller, callee, call_id, detail, "
        "evidence FROM voip_calls",
    ):
        try:
            parsed = json.loads(evidence) if evidence else {}
        except (TypeError, ValueError):
            parsed = {}
        out.append(
            {
                "kind": kind or "",
                "severity": severity or "low",
                "source_ip": src or "",
                "destination_ip": dst or "",
                "caller": caller or "",
                "callee": callee or "",
                "call_id": call_id or "",
                "detail": detail or "",
                "evidence": parsed,
            }
        )
    return out


def collect_wifi(conn: sqlite3.Connection) -> Dict:
    """Passive 802.11 findings (epic #82).

    Returns the seven Wi-Fi tables keyed by short name: networks, wep,
    handshakes, wps, eap, wpa3 and events. Each row is a dict; proof levels
    are carried verbatim from the handlers.
    """
    from PufferRelay.protocols import wifi as wifi_module

    return wifi_module.collect_wifi(conn)


def collect_inventory(conn: sqlite3.Connection) -> Dict:
    inventory = {
        "hosts": collect_hosts(conn),
        "users": collect_users(conn),
        "credentials": collect_credentials(conn),
        "hashes": collect_hashes(conn),
        "quick_wins": collect_quick_wins(conn),
        "relays": collect_relays(conn),
        "smb": collect_smb(conn),
        "files": collect_files(conn),
        "nac": collect_nac(conn),
        "wsus": collect_wsus(conn),
        "dns": collect_dns(conn),
        "asrepcatcher": collect_asrepcatcher(conn),
        "kerberoast": collect_kerberoast(conn),
        "tokens": collect_tokens(conn),
        "coercions": collect_coercions(conn),
        "adcs": collect_adcs(conn),
        "ipv6": collect_ipv6(conn),
        "database_credentials": collect_database_creds(conn),
        "sccm": collect_sccm(conn),
        "llm": collect_llm(conn),
        "kerberos_signals": collect_kerberos_signals(conn),
        "ldap_spns": collect_ldap_spns(conn),
        "ldap_signing": collect_ldap_signing(conn),
        "voip": collect_voip(conn),
        "ldap_adcs": collect_ldap_adcs(conn),
        "rdp": collect_service_events(conn, "rdp"),
        "cloudapi": collect_service_events(conn, "cloudapi"),
        "fingerprints": collect_service_events(conn, "fingerprints"),
        "wifi": collect_wifi(conn),
    }
    inventory["chains"] = build_chains(inventory)
    inventory["graph"] = build_graph(inventory)
    return inventory


# --------------------------------------------------------------------------- #
# Leads for an AI agent (or a human deciding what to attack next)
# --------------------------------------------------------------------------- #

AGENT_PROMPT = """You are supporting an authorised penetration test. The operator
captured network traffic passively and PufferRelay extracted the findings in
this folder. Work only from these files; do not invent targets.

Inputs
- leads.json   machine-readable leads + full inventory (schema version 1)
- leads.md     the same leads as a briefing with evidence and commands
- hosts.tsv    ip, hostnames, MACs, port=service
- users.txt    identities (DOMAIN/user when known)
- credentials.csv, ntlm-hashes.txt, nmap-targets.txt, nmap-command.txt

Rules
1. Evidence first: every recommendation must cite the lead id and its evidence
   from leads.json. Do not suggest attacking a host that is not in the pack.
2. ACTIVE actions (leads[].suggested_actions[].active == true) send traffic or
   use captured secrets. Never run them and never present them as safe:
   - ask the operator to confirm the target is in scope,
   - warn about lockouts, IDS/IPS and service disruption,
   - prefer the least invasive check that answers the question.
3. Passive work can be done immediately: cracking NTLM offline, reading the
   inventories, ranking hosts, writing the report narrative.
4. Prioritise by impact: critical > high > medium > low, then by how directly
   the lead enables domain or host compromise (relay, reused credentials, hashes).
5. Produce a short plan: for each of the top leads, the hypothesis, the exact
   command (marked ACTIVE/passive), what result would confirm it, and the
   cleanup/rollback. Keep commands copy-paste ready for the operator.
6. Never claim a vulnerability is confirmed from traffic alone; say what the
   capture proves and what needs verification.
"""

from PufferRelay.protocols.nac_handler import looks_like_mac
from PufferRelay.severity import CLEARTEXT_PROTOCOLS, QUICK_WIN_SEVERITY

INTERESTING_SERVICES = {
    "smb",
    "ldap",
    "ldaps",
    "winrm-http",
    "winrm-https",
    "rdp",
    "mssql",
    "mysql",
    "postgresql",
    "redis",
    "docker",
    "elasticsearch",
    "memcached",
    "ftp",
    "telnet",
}


def build_leads(inventory: Dict) -> List[Dict]:
    """Turn inventory into concrete leads for an agent, ranked by exploitability.

    Every lead carries the evidence it is based on and suggested actions.
    Actions that send traffic are marked ``"active": True`` with a warning; the
    tool itself never runs them.
    """
    leads: List[Dict] = []
    hosts = inventory.get("hosts", [])
    creds = inventory.get("credentials", [])
    hashes = inventory.get("hashes", [])
    users = inventory.get("users", [])
    quick_wins = inventory.get("quick_wins", [])

    host_by_ip = {h["ip"]: h for h in hosts}

    def add(lead: Dict) -> None:
        lead.setdefault("suggested_actions", [])
        lead.setdefault("passive", True)
        lead.setdefault("confidence", "high")
        lead.setdefault("attck", attck_for(lead.get("id", "")))
        leads.append(lead)

    # 1. Quick wins that are directly exploitable.
    for qw in quick_wins:
        if not qw["found"]:
            continue
        protocol = qw["protocol"]
        stored_severity = qw.get("severity")
        severity, why = QUICK_WIN_SEVERITY.get(
            protocol, ("low", qw["details"] or "protocol observed")
        )
        if stored_severity in {"critical", "high", "medium", "low"}:
            severity = stored_severity
        evidence = {"quick_win": protocol, "details": qw["details"]}
        if qw.get("observed"):
            evidence["observed"] = qw["observed"]
        if qw["credentials_found"]:
            severity = "critical" if protocol in CLEARTEXT_PROTOCOLS else severity
            why += " (credentials seen in clear text)"
            evidence["credential_protocols"] = qw["credential_protocols"]

        actions = []
        if protocol == "SMB_SIGNING_MISSING":
            actions = [
                {
                    "intent": "Confirm SMB signing and relay feasibility from the operator host",
                    "command": "nxc smb <target> -u <user> -p <pass> --gen-relay-list "
                    "relay-targets.txt",
                    "active": True,
                    "warning": "Active: sends SMB traffic to the target. Confirm scope.",
                }
            ]
        elif protocol == "LDAP_SIGNING_MISSING":
            actions = [
                {
                    "intent": "Check LDAP signing/channel binding on the DC",
                    "command": "nxc ldap <dc> -u <user> -p <pass> -M ldap-checker",
                    "active": True,
                    "warning": "Active: authenticates to LDAP. Confirm scope.",
                }
            ]
        elif protocol in CLEARTEXT_PROTOCOLS:
            actions = [
                {
                    "intent": "Replay captured credentials against the service",
                    "command": "<reuse the credentials listed in the CRED leads>",
                    "active": True,
                    "warning": "Active: authenticates to the target. Confirm scope.",
                }
            ]

        add(
            {
                "id": f"QW-{protocol}",
                "severity": severity,
                "title": f"{protocol}: {qw['details'] or 'observed'}",
                "why": why,
                "evidence": evidence,
                "suggested_actions": actions,
            }
        )

    # 2. Captured credentials -> reuse leads.
    for i, cred in enumerate(sorted(creds, key=_cred_sort_key), start=1):
        target = host_by_ip.get(cred["destination_ip"], {})
        hostnames = ", ".join(target.get("hostnames", []) or []) or cred["destination_ip"]
        proto = cred["protocol"]
        active_hint = {
            "ftp": f"ftp {cred['destination_ip']}",
            "http": f"curl -u '{cred['username']}:{cred['secret']}' "
            f"http://{cred['destination_ip']}/",
            "smtp": f"swaks --to <mail> --server {cred['destination_ip']} "
            f"--auth-user '{cred['username']}' --auth-password '{cred['secret']}'",
            "imap": f"curl --user '{cred['username']}:{cred['secret']}' "
            f"imap://{cred['destination_ip']}/",
            "pop3": f"curl --user '{cred['username']}:{cred['secret']}' "
            f"pop3://{cred['destination_ip']}/",
            "ldap": f"ldapsearch -x -H ldap://{cred['destination_ip']} "
            f"-D '{cred['username']}' -w '{cred['secret']}' -b ''",
        }.get(proto, f"reuse {proto} credentials at {cred['destination_ip']}")
        add(
            {
                "id": f"CRED-{i:03d}",
                "severity": "high",
                "title": f"Captured {proto} credentials for {hostnames}",
                "why": "Valid credentials seen in traffic can be replayed (password reuse, "
                "same host, or lateral movement).",
                "evidence": {
                    "protocol": proto,
                    "source_ip": cred["source_ip"],
                    "destination_ip": cred["destination_ip"],
                    "username": cred["username"],
                    "secret": cred["secret"],
                    "context": cred["context"],
                },
                "suggested_actions": [
                    {
                        "intent": "Verify the credential still works (scope-gated)",
                        "command": active_hint,
                        "active": True,
                        "warning": "Active: authenticates with the captured secret. "
                        "Confirm the target is in scope.",
                    },
                    {
                        "intent": "Try the secret against other hosts in the capture",
                        "command": "reuse this user/secret across the hosts listed in "
                        "hosts.tsv",
                        "active": True,
                        "warning": "Active: can lock accounts. Respect lockout policy.",
                    },
                ],
            }
        )

    # 3a. AS-REP roastable accounts: a domain credential for offline cracking.
    asrep_hashes = [h for h in hashes if h.get("hashcat_mode") == 18200]
    for i, h in enumerate(asrep_hashes, start=1):
        add(
            {
                "id": f"ASREP-{i:03d}",
                "severity": "critical",
                "title": f"AS-REP roastable account {h['username']}",
                "why": "The KDC answered without pre-authentication, so the AS-REP "
                "encrypted part can be cracked offline to a domain password.",
                "evidence": {
                    "principal": h["username"],
                    "source_ip": h["source_ip"],
                    "destination_ip": h["destination_ip"],
                    "hash": h["hash"],
                },
                "suggested_actions": [
                    {
                        "intent": "Crack the AS-REP offline (no traffic to the target)",
                        "command": "hashcat -m 18200 asrep-hashes.txt <wordlist> "
                        "-r rules/best64.rule",
                        "active": False,
                        "warning": "Offline only; safe for the target network.",
                    },
                    {
                        "intent": "Validate the cracked password against Kerberos (scope-gated)",
                        "command": "nxc smb <dc> -u '<user>' -p '<password>'",
                        "active": True,
                        "warning": "Active: authenticates to the DC. Confirm scope and "
                        "lockout policy.",
                    },
                ],
            }
        )

    # 3b. ASRepCatcher-compatible Kerberos activity (passive detection).
    for i, finding in enumerate(inventory.get("asrepcatcher", []), start=1):
        add(
            {
                "id": f"ASREPCATCHER-{i:03d}",
                "severity": finding.get("severity") or "high",
                "confidence": "medium",
                "title": f"ASRepCatcher-compatible activity: {finding['kind']}",
                "why": finding["summary"]
                + " This matches the ASRepCatcher technique "
                f"({ASREPCATCHER_REFERENCE}): ARP/relay harvesting of AS-REP "
                "material without requiring pre-authentication to be disabled. "
                "The capture shows the traffic shape; verify before acting.",
                "evidence": {**finding, "reference": ASREPCATCHER_REFERENCE},
                "suggested_actions": [
                    {
                        "intent": "Review the Kerberos/ARP frames around this finding",
                        "command": "tshark -r <capture> -Y 'kerberos || arp'",
                        "active": False,
                        "warning": "Read-only; no traffic is sent.",
                    },
                    {
                        "intent": "Read the attack description and detection notes",
                        "command": f"open {ASREPCATCHER_REFERENCE}",
                        "active": False,
                        "warning": "Documentation only.",
                    },
                ],
            }
        )

    # 3c. Kerberoasting: offline-crackable service tickets.
    for i, row in enumerate(inventory.get("kerberoast", []), start=1):
        has_hash = bool(row.get("hash"))
        mode = {23: 13100, 17: 19600, 18: 19700}.get(row.get("etype"), 13100)
        add(
            {
                "id": f"KERBEROAST-{i:03d}" if has_hash else f"KERBEROASTCAND-{i:03d}",
                "severity": "critical" if has_hash else "high",
                "confidence": "high" if has_hash else "medium",
                "title": (
                    f"Kerberoastable service ticket for {row['spn']}"
                    if has_hash
                    else f"Kerberoasting candidate: {row['username']} -> {row['spn']}"
                ),
                "why": (
                    "A TGS-REP for a service account is encrypted with that "
                    "account's password hash; it can be cracked offline."
                    if has_hash
                    else "A service ticket was requested for an SPN without a "
                    "parsed TGS-REP; verify the exchange before acting."
                ),
                "evidence": {
                    "username": row["username"],
                    "realm": row["realm"],
                    "spn": row["spn"],
                    "etype": row["etype"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                    "hash": row["hash"],
                },
                "suggested_actions": [
                    {
                        "intent": "Crack the service ticket offline (no traffic)",
                        "command": f"hashcat -m {mode} kerberoast-hashes.txt <wordlist>",
                        "active": False,
                        "warning": "Offline only; the hash is a live secret.",
                    }
                ]
                if has_hash
                else [],
            }
        )

    # 3d. HTTP bearer/JWT/API tokens (fingerprint only in the lead feed).
    for i, row in enumerate(inventory.get("tokens", []), start=1):
        add(
            {
                "id": f"TOKEN-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['kind']} token observed for {row['host'] or 'unknown host'}",
                "why": "A reusable bearer/API secret was sent over HTTP. It may "
                "grant the same access as the user who sent it.",
                "evidence": {
                    "kind": row["kind"],
                    "host": row["host"],
                    "path": row["path"],
                    "header": row["header"],
                    "fingerprint": row["fingerprint"],
                    "principal": row["principal"],
                    "expires": row["expires"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                },
                "suggested_actions": [
                    {
                        "intent": "Replay the token against the same service (scope-gated)",
                        "command": "curl -H 'Authorization: Bearer <token>' "
                        f"https://{row['host'] or '<host>'}{row['path'] or '/'}",
                        "active": True,
                        "warning": "Active: uses a live secret. Confirm scope; "
                        "tokens may be logged or rotate on use.",
                    }
                ],
            }
        )

    # 3e. Coerced authentication over SMB/RPC.
    for i, row in enumerate(inventory.get("coercions", []), start=1):
        add(
            {
                "id": f"COERCE-{i:03d}",
                "severity": row["severity"],
                "confidence": "medium",
                "title": f"{row['kind']} coercion attempt",
                "why": "The victim was told to authenticate to "
                f"{row['unc'] or 'an attacker-controlled host'}; this is the "
                "first half of an NTLM relay chain.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Check whether a relay target accepted the authentication",
                        "command": "look for a matching NTLM exchange to the UNC "
                        "host in the capture; then review relay-targets.txt",
                        "active": False,
                        "warning": "Read-only analysis.",
                    }
                ],
            }
        )

    # 3f. ADCS enrollment / PKINIT.
    for i, row in enumerate(inventory.get("adcs", []), start=1):
        add(
            {
                "id": f"ADCS-{i:03d}",
                "severity": row["severity"],
                "confidence": "medium",
                "title": f"ADCS {row['kind']} activity"
                + (f" to {row['host']}" if row["host"] else ""),
                "why": "Certificate enrollment or PKINIT logon was observed. "
                "ADCS is a primary AD escalation path (ESC1-ESC8).",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the enrollment request and template",
                        "command": "inspect the capture around this flow; check "
                        "the CA/template references in the lead",
                        "active": False,
                    }
                ],
            }
        )

    # 3g. IPv6/DHCPv6/ADIDNS takeover.
    for i, row in enumerate(inventory.get("ipv6", []), start=1):
        add(
            {
                "id": f"IPV6-{i:03d}",
                "severity": row["severity"],
                "confidence": "medium",
                "title": f"{row['kind']} on the segment",
                "why": "A rogue DHCPv6/RA DNS source or ADIDNS dynamic update "
                "can redirect name resolution and harvest credentials.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Identify the host offering DNS and compare with "
                        "the known resolver",
                        "command": "review ipv6.tsv and the DHCPv6/RA frames in the capture",
                        "active": False,
                    }
                ],
            }
        )

    # 3h. Database credentials and crackable responses.
    for i, row in enumerate(inventory.get("database_credentials", []), start=1):
        cleartext = row["kind"] in {
            "redis-cleartext",
            "pg-cleartext",
            "mssql-sql-auth",
        }
        add(
            {
                "id": f"DB-{i:03d}",
                "severity": "critical" if cleartext else "high",
                "confidence": "high" if cleartext else "medium",
                "title": f"{row['protocol']} credential material"
                + (f" for {row['username']}" if row["username"] else ""),
                "why": (
                    "The database password was sent in clear text."
                    if cleartext
                    else "A database authentication response was captured; it "
                    "may be crackable offline."
                ),
                "evidence": {
                    "protocol": row["protocol"],
                    "username": row["username"],
                    "kind": row["kind"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                    "server": row["server"],
                    "hashcat": row.get("hashcat", ""),
                },
                "suggested_actions": [
                    {
                        "intent": "Reuse the credential against the database (scope-gated)",
                        "command": f"{row['protocol']} client to "
                        f"{row['destination_ip'] or '<host>'} with the captured secret",
                        "active": True,
                        "warning": "Active: authenticates to the database. Confirm scope.",
                    }
                ]
                if cleartext
                else [
                    {
                        "intent": "Crack the response offline",
                        "command": (
                            f"hashcat -m {row['hashcat']} db-creds.tsv <wordlist>"
                            if row.get("hashcat")
                            else "hashcat with the matching database mode"
                        ),
                        "active": False,
                    }
                ],
            }
        )

    # 3i. SCCM/MECM management traffic.
    for i, row in enumerate(inventory.get("sccm", []), start=1):
        add(
            {
                "id": f"SCCM-{i:03d}",
                "severity": row["severity"],
                "title": f"SCCM {row['kind']}"
                + (f" at {row['host']}" if row["host"] else ""),
                "why": "SCCM management/distribution traffic was observed. "
                "Management points and site shares are high-value relay and "
                "site-takeover targets.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the SCCM endpoint and authentication",
                        "command": "inspect sccm.tsv and the matching HTTP/SMB flow",
                        "active": False,
                    }
                ],
            }
        )

    # 3j. LLM / MCP / vector-DB traffic.
    for i, row in enumerate(inventory.get("llm", []), start=1):
        add(
            {
                "id": f"LLM-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['kind']}: {row['service']}"
                + (f" ({row['host']})" if row["host"] else ""),
                "why": (
                    "An inference endpoint answered without an authentication "
                    "header; anyone who can reach it can use the model."
                    if row["kind"] == "llm-unauthenticated"
                    else "LLM/MCP traffic was observed; it can expose prompts, "
                    "tool calls and API keys."
                ),
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the service and whether it should be reachable",
                        "command": "inspect llm.tsv and the matching HTTP flow",
                        "active": False,
                    }
                ],
            }
        )

    # 3k. Kerberos delegation / S4U / UnPAC signals.
    for i, row in enumerate(inventory.get("kerberos_signals", []), start=1):
        add(
            {
                "id": f"KERB-{i:03d}",
                "severity": row["severity"],
                "confidence": "medium",
                "title": f"Kerberos {row['kind']}"
                + (f" for {row['username']}" if row["username"] else ""),
                "why": row["detail"]
                + " Delegation and PKINIT/U2U signals can turn an account into "
                "a path to another service; verify the flags in the ticket.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Check delegation rights for the account",
                        "command": "review the principal in the directory and its "
                        "allowed-to-delegate settings",
                        "active": False,
                        "warning": "Read-only analysis; do not assume the path "
                        "works without confirmation.",
                    }
                ],
            }
        )

    # 3l. SPNs mapped to accounts from LDAP search results.
    for i, row in enumerate(inventory.get("ldap_spns", []), start=1):
        add(
            {
                "id": f"SPN-{i:03d}",
                "severity": "medium",
                "title": f"SPN {row['spn']} belongs to {row['account']}",
                "why": "The capture mapped a service SPN to its account. That "
                "turns a Kerberoast target into a named principal.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Request a service ticket for the named account",
                        "command": "use the Kerberoast hash/lead for this SPN; no "
                        "extra traffic is needed if the hash was captured",
                        "active": False,
                    }
                ],
            }
        )

    # 3m. LDAP signing inference per destination.
    for i, row in enumerate(inventory.get("ldap_signing", []), start=1):
        if not row["simple_binds"]:
            continue
        add(
            {
                "id": f"LDAPSIGN-{i:03d}",
                "severity": "medium",
                "confidence": "medium",
                "title": f"Simple LDAP binds to {row['destination_ip']}",
                "why": f"{row['simple_binds']} of {row['binds']} binds were "
                "simple (unsigned). That is consistent with LDAP signing not "
                "being enforced, which makes the destination a relay candidate.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Check LDAP signing/channel binding on the DC",
                        "command": "nxc ldap <dc> -u <user> -p <pass> -M "
                        "ldap-checker",
                        "active": True,
                        "warning": "Active: authenticates to LDAP. Confirm scope.",
                    }
                ],
            }
        )

    # 3n. Correlated attack chains.
    for i, chain in enumerate(inventory.get("chains", []), start=1):
        add(
            {
                "id": f"CHAIN-{i:03d}",
                "severity": chain["severity"],
                "title": f"{chain['kind']} against {chain['target']}",
                "why": "The capture contains both halves of an attack path: a "
                "coercion/credential and a host that accepts it. Treat it as a "
                "chain to verify, not a completed compromise.",
                "evidence": chain,
                "suggested_actions": [
                    {
                        "intent": "Review the correlated rows in one place",
                        "command": "compare coercions.tsv, relays.tsv and "
                        "credentials.csv for the target",
                        "active": False,
                    }
                ],
            }
        )

    # 3o. VoIP signalling.
    for i, row in enumerate(inventory.get("voip", []), start=1):
        add(
            {
                "id": f"VOIP-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['kind']}"
                + (f": {row['caller']} -> {row['callee']}" if row["callee"] else ""),
                "why": row["detail"]
                + " Call signalling can reveal extensions, registrations and "
                "authentication material; media is not decoded.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the SIP/Skinny endpoint and its exposure",
                        "command": "inspect voip.tsv and the matching signalling flow",
                        "active": False,
                    }
                ],
            }
        )

    # 3p. RDP identity and negotiation.
    for i, row in enumerate(inventory.get("rdp", []), start=1):
        add(
            {
                "id": f"RDP-{i:03d}",
                "severity": row["severity"],
                "title": f"RDP {row['kind']}"
                + (f": {row['principal']}" if row["principal"] else ""),
                "why": row["detail"]
                + " RDP exposure and identities help target interactive access; "
                "CredSSP passwords are not visible.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the RDP exposure and account",
                        "command": "inspect rdp.tsv and the host's service list",
                        "active": False,
                    }
                ],
            }
        )

    # 3q. Exposed infrastructure APIs.
    for i, row in enumerate(inventory.get("cloudapi", []), start=1):
        add(
            {
                "id": f"CLOUD-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['kind']}: {row['detail']}",
                "why": "An infrastructure API was reachable on the wire. An "
                "unauthenticated control plane is a direct compromise path.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Verify the endpoint from the operator host",
                        "command": "curl the documented base path (ACTIVE; scope)",
                        "active": True,
                        "warning": "Active: talks to the API. Confirm scope first.",
                    }
                ],
            }
        )

    # 3r. WPAD lookups (proxy auto-config abuse).
    wpad_seen = set()
    for row in inventory.get("dns", []):
        query = (row.get("query") or "").lower()
        if not query.startswith("wpad"):
            continue
        key = (row.get("source_ip"), row.get("destination_ip"), query)
        if key in wpad_seen:
            continue
        wpad_seen.add(key)
        add(
            {
                "id": f"WPAD-{len(wpad_seen):03d}",
                "severity": "medium",
                "confidence": "medium",
                "title": f"WPAD lookup from {row.get('source_ip') or 'a host'}",
                "why": "WPAD name resolution can be abused to serve a malicious "
                "proxy auto-config and harvest NTLM authentication.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Check whether the WPAD answer came from a "
                        "legitimate proxy",
                        "command": "inspect dns.txt and the proxy configuration",
                        "active": False,
                    }
                ],
            }
        )

    # 3s. Identity reuse graph.
    for i, row in enumerate(inventory.get("graph", {}).get("reuse", []), start=1):
        add(
            {
                "id": f"REUSE-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['identity']}: {row['kind']}",
                "why": row["detail"]
                + " Reuse across hosts is what turns one credential into a path.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the identity's hosts and credential sources",
                        "command": "open credential-matrix.tsv and identity-graph.json",
                        "active": False,
                    }
                ],
            }
        )

    # 3t. Service fingerprints (SSH/TLS/VNC/TFTP).
    for i, row in enumerate(inventory.get("fingerprints", []), start=1):
        add(
            {
                "id": f"FP-{i:03d}",
                "severity": row["severity"],
                "title": f"{row['kind']}: {row['destination_ip']}",
                "why": row["detail"]
                + " Service banners and encryption choices narrow the next test.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the service version/encryption",
                        "command": "inspect fingerprints.tsv and the host's services",
                        "active": False,
                    }
                ],
            }
        )

    # 3u. ADCS CA/template objects published in LDAP.
    for i, row in enumerate(inventory.get("ldap_adcs", []), start=1):
        add(
            {
                "id": f"ADCSDIR-{i:03d}",
                "severity": row["severity"],
                "title": f"ADCS {row['kind']}: {row['name']}",
                "why": row["detail"]
                + " The CA/template configuration tells you which enrollment "
                "paths exist; verify the effective rights before testing.",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the CA and template in the directory",
                        "command": "inspect ldap-adcs.tsv and the CA host",
                        "active": False,
                    }
                ],
            }
        )

    # 3. NTLM hashes -> offline cracking (safe, no network).
    for i, h in enumerate(hashes, start=1):
        if h.get("hashcat_mode") == 18200:
            continue
        add(
            {
                "id": f"HASH-{i:03d}",
                "severity": "high",
                "title": f"NTLM hash captured for {h['username'] or 'unknown user'}",
                "why": "NetNTLMv2 can be cracked offline; the plaintext then enables "
                "lateral movement.",
                "evidence": {
                    "username": h["username"],
                    "source_ip": h["source_ip"],
                    "destination_ip": h["destination_ip"],
                    "hash": h["hash"],
                },
                "suggested_actions": [
                    {
                        "intent": "Crack offline (no traffic sent to the target)",
                        "command": f"hashcat -m {h['hashcat_mode']} ntlm-hashes.txt "
                        "<wordlist> -r rules/best64.rule",
                        "active": False,
                        "warning": "Offline only; safe for the target network.",
                    }
                ],
            }
        )

    # 3a-bis. SMB shares and files observed in the capture.
    smb = inventory.get("smb", {"shares": [], "files": []})
    share_targets = {}
    for row in smb.get("shares", []):
        if row["share"]:
            share_targets.setdefault((row["destination_ip"], row["share"]), set()).add(
                row["source_ip"]
            )
    for i, ((host, share), sources) in enumerate(sorted(share_targets.items()), start=1):
        add(
            {
                "id": f"SMB-{i:03d}",
                "severity": "medium",
                "title": f"SMB share accessed: //{host}/{share}",
                "why": "The capture shows a client accessing this share. Its content and "
                "permissions were not tested; it is a candidate for data collection or "
                "write-based attacks if the current credentials still work.",
                "evidence": {"destination_ip": host, "share": share,
                             "client_ips": sorted(s for s in sources if s)},
                "suggested_actions": [
                    {
                        "intent": "List the share with in-scope credentials (scope-gated)",
                        "command": f"smbclient -L //{host}/ -N",
                        "active": True,
                        "warning": "Active: contacts the SMB service. Confirm scope.",
                    }
                ],
            }
        )

    for i, row in enumerate(
        [r for r in smb.get("files", []) if interesting_file(r["file"])], start=1
    ):
        add(
            {
                "id": f"SMBFILE-{i:03d}",
                "severity": "high",
                "title": f"Sensitive-looking file transferred over SMB: {row['file']}",
                "why": "The file name suggests configuration, credentials or archives. "
                "If the capture contains the transfer, the object can be carved offline; "
                "otherwise retrieve it with the captured credentials (scope-gated).",
                "evidence": row,
                "suggested_actions": [
                    {
                        "intent": "Review the captured transfer locally (passive)",
                        "command": "tshark -r capture.pcap -Y 'smb2.filename contains "
                        f"\"{row['file']}\"' -T fields -e data.data",
                        "active": False,
                        "warning": "Reads the capture only; no traffic.",
                    }
                ],
            }
        )

    # 3a-ter. Carved files whose names/types suggest sensitive content.
    suspicious_types = {
        "application/json",
        "application/xml",
        "text/xml",
        "application/zip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/pdf",
        "application/octet-stream",
    }
    for i, item in enumerate(
        [
            f
            for f in inventory.get("files", [])
            if interesting_file(f["filename"])
            or (f["content_type"] or "").split(";")[0].strip().lower() in suspicious_types
        ],
        start=1,
    ):
        add(
            {
                "id": f"FILE-{i:03d}",
                "severity": "high",
                "title": f"File captured from {item['protocol']}: {item['filename']}",
                "why": "A file transferred in clear text was carved from the capture. "
                "Its name or type suggests configuration, credentials or archives. "
                "Read it locally to decide the next step.",
                "evidence": {
                    "protocol": item["protocol"],
                    "source_ip": item["source_ip"],
                    "destination_ip": item["destination_ip"],
                    "filename": item["filename"],
                    "content_type": item["content_type"],
                    "size": item["size"],
                    "sha256": item["sha256"],
                    "stored_as": item["stored_as"],
                },
                "suggested_actions": [
                    {
                        "intent": "Inspect the carved object locally (passive)",
                        "command": f"file files/{item['stored_as']} && "
                        f"sha256sum files/{item['stored_as']}",
                        "active": False,
                        "warning": "Local file only; it contains client data.",
                    }
                ],
            }
        )

    # 3a-quater. NAC / 802.1X and WSUS observations.
    nac = inventory.get("nac", [])
    if nac:
        identities = sorted({row["identity"] for row in nac if row["identity"]})
        mab_identities = sorted({row["identity"] for row in nac if row["mab"]})
        add(
            {
                "id": "NAC-001",
                "severity": "medium",
                "title": "802.1X / NAC observed on the captured network",
                "why": "Port-based access control is in use. Identities and MAC "
                "authentication-bypass usernames seen in the capture can guide "
                "credential attacks or authorised port testing.",
                "evidence": {
                    "events": len(nac),
                    "kinds": sorted({row["kind"] for row in nac if row["kind"]}),
                    "identities": identities[:10],
                    "mab_count": len(mab_identities),
                    "sample_macs": mab_identities[:5],
                },
                "suggested_actions": [
                    {
                        "intent": "Review the identities for password spraying (scope-gated)",
                        "command": "nxc smb <dc> -u users.txt -p '<password>' "
                        "--continue-on-success",
                        "active": True,
                        "warning": "Active and can lock accounts. Confirm scope and "
                        "lockout policy.",
                    }
                ],
            }
        )

    wsus = inventory.get("wsus", [])
    seen_wsus = set()
    for i, row in enumerate(
        [w for w in wsus if (w["destination_ip"], w["host"]) not in seen_wsus],
        start=1,
    ):
        seen_wsus.add((row["destination_ip"], row["host"]))
        add(
            {
                "id": f"WSUS-{i:03d}",
                "severity": "medium",
                "title": f"WSUS/Windows Update endpoint: {row['host'] or row['destination_ip']}",
                "why": "Update infrastructure is visible in the capture. Compromised "
                "or spoofed WSUS can deliver malicious updates; it also reveals "
                "patch-management design for the report.",
                "evidence": {
                    "destination_ip": row["destination_ip"],
                    "host": row["host"],
                    "indicator": row["indicator"],
                    "sample_uri": row["uri"],
                },
                "suggested_actions": [
                    {
                        "intent": "Fingerprint the update service (scope-gated)",
                        "command": f"curl -sk https://{row['host'] or row['destination_ip']}/",
                        "active": True,
                        "warning": "Active: contacts the update server. Confirm scope.",
                    }
                ],
            }
        )

    # 3b. Confirmed NTLM relay paths.
    relays = inventory.get("relays", [])
    for i, relay in enumerate([r for r in relays if r.get("candidate")], start=1):
        proto = relay["protocol"]
        severity = "critical" if proto == "smb" else "high"
        signing = relay["signing_required"]
        signing_text = (
            "signing not required"
            if signing is False
            else "signing state unknown (SMB NEGOTIATE not captured)"
            if signing is None
            else "signing required"
        )
        add(
            {
                "id": f"RELAY-{i:03d}",
                "severity": severity,
                "title": f"NTLM relay candidate: {proto} to {relay['destination_ip']}"
                f":{relay['destination_port']}",
                "why": f"An NTLM authentication for "
                f"'{relay['username'] or 'unknown user'}' was captured towards this "
                f"endpoint ({signing_text}). A relay can impersonate that user if the "
                f"authentication is still valid.",
                "evidence": relay,
                "suggested_actions": [
                    {
                        "intent": "Add the endpoint to a relay target list (offline step)",
                        "command": "grep . relay-targets.txt",
                        "active": False,
                        "warning": "Reading a local file; no traffic.",
                    },
                    {
                        "intent": "Relay captured NTLM traffic to these targets (scope-gated)",
                        "command": "ntlmrelayx.py -tf relay-targets.txt -smb2support",
                        "active": True,
                        "warning": "Active: relays credentials to in-scope hosts. Confirm "
                        "authorisation; this can lock accounts or trigger alarms.",
                    },
                ],
            }
        )

    # 4. Identity list -> spraying candidates.
    if len(users) >= 3:
        domains = ", ".join(sorted({u["domain"] for u in users if u["domain"]})) or "n/a"
        add(
            {
                "id": "USERS-001",
                "severity": "medium",
                "title": f"{len(users)} usernames harvested across protocols",
                "why": "Usernames enable password spraying, AS-REP roasting and "
                f"Kerberoasting targeting. Domains seen: {domains}",
                "evidence": {
                    "count": len(users),
                    "sample": [u["username"] for u in users[:10]],
                },
                "suggested_actions": [
                    {
                        "intent": "Spray a low-lockout password once you know the policy",
                        "command": "nxc smb <dc> -u users.txt -p '<password>' "
                        "--continue-on-success",
                        "active": True,
                        "warning": "Active and can lock accounts. Check the lockout "
                        "policy and authorised scope first.",
                    }
                ],
            }
        )

    # 5. Hosts exposing many attack surfaces.
    for host in hosts:
        services = host.get("services") or []
        interesting = {s["service"] for s in services if s["service"] in INTERESTING_SERVICES}
        if len(interesting) >= 2:
            add(
                {
                    "id": f"HOST-{host['ip']}",
                    "severity": "medium",
                    "title": f"{host['ip']} exposes {', '.join(sorted(interesting))}",
                    "why": "Multiple high-value services on one host: prioritise it for "
                    "credential reuse and relay attacks.",
                    "evidence": {"host": host},
                    "suggested_actions": [
                        {
                            "intent": "Fingerprint the services in scope",
                            "command": "nmap -sV -p "
                            + ",".join(str(s["port"]) for s in services)
                            + f" {host['ip']}",
                            "active": True,
                            "warning": "Active: port scan. Confirm scope.",
                        }
                    ],
                }
            )

    # 6. Passive Wi-Fi findings (epic #82). Every lead states its proof level:
    # observed / offline-crackable / active-verification-required.
    wifi = inventory.get("wifi") or {}
    for row in wifi.get("networks") or []:
        add(
            {
                "id": f"WIFI-NET-{row['bssid']}",
                "severity": "low",
                "title": f"Wi-Fi network {row.get('ssid') or '<hidden>'} "
                f"({row.get('bssid')})",
                "why": f"Security: {row.get('security')}; PMF "
                f"{row.get('pmf')}; {row.get('clients')} client(s). "
                "Inventory only: a beacon is a capability claim.",
                "evidence": row,
                "proof_level": "observed",
            }
        )

    for row in wifi.get("wep") or []:
        bssid = row.get("bssid")
        add(
            {
                "id": f"WIFI-WEP-{bssid}",
                "severity": "critical",
                "title": f"WEP network {row.get('ssid') or bssid} ({bssid})",
                "why": "WEP is broken by design. "
                f"{row.get('unique_ivs')} unique IV(s) captured: "
                f"{row.get('readiness')}.",
                "evidence": row,
                "proof_level": row.get("proof") or "observed",
                "suggested_actions": [
                    {
                        "intent": "Crack the captured IVs offline",
                        "command": f"aircrack-ng -b {bssid} capture.pcap",
                        "active": False,
                        "warning": "Offline: operates on the local capture only.",
                    },
                    {
                        "intent": "Collect more IVs if the threshold is not met",
                        "command": f"aireplay-ng --arpreplay -b {bssid} wlan0mon",
                        "active": True,
                        "warning": "Active: injects frames and can disrupt the AP. "
                        "Confirm scope and expect client impact.",
                    },
                ],
            }
        )

    for row in wifi.get("handshakes") or []:
        bssid = row.get("bssid")
        if row.get("complete"):
            add(
                {
                    "id": f"WIFI-HANDSHAKE-{bssid}",
                    "severity": "high",
                    "title": f"WPA/WPA2 handshake captured for "
                    f"{row.get('ssid') or bssid}",
                    "why": "A complete 4-way handshake can be attacked offline "
                    "with a wordlist. It is not a password.",
                    "evidence": row,
                    "proof_level": "offline-crackable",
                    "suggested_actions": [
                        {
                            "intent": "Convert and crack the handshake offline",
                            "command": "hcxpcapngtool -o handshake.hc22000 "
                            "handshake.pcap && hashcat -m 22000 "
                            "handshake.hc22000 wordlist.txt",
                            "active": False,
                            "warning": "Offline: keep the capture and hash local.",
                        }
                    ],
                }
            )
        if len(row.get("pmkid") or "") == 32:
            add(
                {
                    "id": f"WIFI-PMKID-{bssid}",
                    "severity": "high",
                    "title": f"PMKID captured for {row.get('ssid') or bssid}",
                    "why": "A PMKID can be attacked offline with hashcat mode 22000.",
                    "evidence": row,
                    "proof_level": "offline-crackable",
                    "suggested_actions": [
                        {
                            "intent": "Crack the PMKID offline",
                            "command": "hashcat -m 22000 pmkid.hc22000 wordlist.txt",
                            "active": False,
                            "warning": "Offline: the PMKID line stays in the "
                            "engagement directory.",
                        }
                    ],
                }
            )

    for row in wifi.get("wps") or []:
        bssid = row.get("bssid")
        add(
            {
                "id": f"WIFI-WPS-{bssid}",
                "severity": row.get("risk") or "medium",
                "title": f"WPS enabled on {row.get('ssid') or bssid} ({bssid})",
                "why": f"WPS state {row.get('state') or 'unknown'}, locked "
                f"{row.get('locked')}, methods {row.get('config_methods') or '-'}. "
                "PIN/Pixie Dust require active frames.",
                "evidence": row,
                "proof_level": "observed",
                "suggested_actions": [
                    {
                        "intent": "Test WPS (PIN / Pixie Dust) from monitor mode",
                        "command": f"reaver -i wlan0mon -b {bssid} -c <CH> -vv",
                        "active": True,
                        "warning": "Active: may lock WPS or disrupt the AP. "
                        "Check lockout behaviour before starting.",
                    }
                ],
            }
        )

    for row in wifi.get("eap") or []:
        bssid = row.get("bssid")
        add(
            {
                "id": f"WIFI-EAP-{bssid}-{row.get('identity')}",
                "severity": "medium",
                "title": f"Enterprise identity {row.get('identity')} on {bssid}",
                "why": f"EAP methods: {row.get('methods') or '-'}. A rogue AP "
                "or relay needs an active step and may fail certificate validation.",
                "evidence": row,
                "proof_level": "observed",
                "suggested_actions": [
                    {
                        "intent": "Rogue authenticator / PEAP relay",
                        "command": "eaphammer -i wlan0mon --auth wpa-eap "
                        "--identity <identity> --cert-wizard",
                        "active": True,
                        "warning": "Active: clients may connect to the rogue AP. "
                        "Confirm scope and stop it immediately after the test.",
                    }
                ],
            }
        )

    for row in wifi.get("wpa3") or []:
        bssid = row.get("bssid")
        if row.get("downgrade_risk"):
            add(
                {
                    "id": f"WIFI-WPA3-DOWNGRADE-{bssid}",
                    "severity": "high",
                    "title": f"WPA3 transition mode with PMF not required on "
                    f"{row.get('ssid') or bssid}",
                    "why": "A WPA2-only rogue AP can downgrade a transition-mode "
                    "client and capture a crackable handshake.",
                    "evidence": row,
                    "proof_level": "active-verification-required",
                    "suggested_actions": [
                        {
                            "intent": "Downgrade to WPA2 and capture the handshake",
                            "command": "python3 dragonshift.py -m wlan0mon "
                            "-r <second-iface>",
                            "active": True,
                            "warning": "Active: rogue AP plus deauth. Disruptive; "
                            "scope and written authorisation required.",
                        },
                        {
                            "intent": "Read the technique",
                            "command": "https://github.com/jabbaw0nky/DragonShift",
                            "active": False,
                            "warning": "Reference only.",
                        },
                    ],
                }
            )
        else:
            add(
                {
                    "id": f"WIFI-WPA3-SAE-{bssid}",
                    "severity": "low",
                    "title": f"WPA3-SAE network {row.get('ssid') or bssid}",
                    "why": "SAE has no offline handshake or PMKID hash. "
                    "Dragonblood side channels and SSID Confusion need active "
                    "verification.",
                    "evidence": row,
                    "proof_level": "observed",
                    "suggested_actions": [
                        {
                            "intent": "Read the applicable research",
                            "command": "https://wpa3.mathyvanhoef.com/ ; "
                            "https://www.usenix.org/conference/usenixsecurity24/"
                            "presentation/vanhoef",
                            "active": False,
                            "warning": "Reference only; no local tool path from "
                            "the capture.",
                        }
                    ],
                }
            )

    for row in wifi.get("events") or []:
        bssid = row.get("bssid")
        kind = row.get("kind") or "wifi-event"
        if kind == "evil-twin-candidate":
            lead_id = f"WIFI-EVILTWIN-{bssid}"
            why = (
                "Duplicate SSID with a different BSSID/security/OUI. Passive "
                "evidence only: this is a candidate, not a proven evil twin."
            )
            proof = "active-verification-required"
        else:
            lead_id = f"WIFI-DEAUTH-{bssid}-{row.get('client') or '-'}"
            why = "Deauth/disassoc frames were observed; bursts can indicate "
            "an attack or a noisy client."
            proof = "observed"
        add(
            {
                "id": lead_id,
                "severity": row.get("severity") or "medium",
                "title": f"{kind} on {row.get('ssid') or bssid}",
                "why": why,
                "evidence": row,
                "proof_level": proof,
            }
        )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    leads.sort(key=lambda x: (severity_rank.get(x.get("severity", "low"), 9), x["id"]))
    return leads


def _cred_sort_key(cred: Dict):
    return (cred.get("protocol", ""), cred.get("username", ""))


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #


def _write_text(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for line in lines:
            handle.write(str(line).rstrip("\n") + "\n")


def _write_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


def format_nmap_targets(hosts: Sequence[Dict]) -> str:
    """One line per host: ``<ip> <comma-separated ports>`` (nmap -iL friendly)."""
    lines = []
    for host in hosts:
        ports = sorted({s["port"] for s in host.get("services", [])})
        if ports:
            lines.append(f"{host['ip']} {','.join(str(p) for p in ports)}")
        else:
            lines.append(host["ip"])
    return "\n".join(lines)


def format_nmap_command(hosts: Sequence[Dict]) -> str:
    """A single copy-paste nmap command for every host/service in the capture."""
    parts = []
    for host in hosts:
        ports = sorted({s["port"] for s in host.get("services", [])})
        if not ports:
            continue
        parts.append(f"-p {','.join(str(p) for p in ports)} {host['ip']}")
    if not parts:
        return ""
    return "nmap -sV -Pn " + " ".join(parts)


def leads_to_markdown(inventory: Dict, leads: Sequence[Dict], pcap_name: str = "") -> str:
    """Agent-facing briefing: ranked leads with evidence and next actions."""
    hosts = inventory.get("hosts", [])
    users = inventory.get("users", [])
    creds = inventory.get("credentials", [])
    hashes = inventory.get("hashes", [])

    lines: List[str] = []
    lines.append("# PufferRelay lead briefing")
    lines.append("")
    lines.append(f"- capture: `{pcap_name or '(database only)'}`")
    lines.append(f"- generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(
        f"- inventory: {len(hosts)} hosts | {len(users)} users | "
        f"{len(creds)} credentials | {len(hashes)} hashes | {len(leads)} leads"
    )
    lines.append("")
    lines.append(
        "Everything below was extracted passively from the capture. Commands marked "
        "ACTIVE send traffic: confirm authorisation and scope before running them."
    )
    if not any(qw.get("found") for qw in inventory.get("quick_wins", [])):
        lines.append("")
        lines.append(
            "> No quick-win scan is recorded in this database. Re-run with "
            "`-q <capture>` (and `--dump`) to add protocol-level leads "
            "(SMB/LDAP signing, cleartext services, LLMNR, ...)."
        )
    lines.append("")

    for lead in leads:
        lines.append(f"## [{lead['severity'].upper()}] {lead['id']} - {lead['title']}")
        lines.append("")
        lines.append(f"**Why it matters:** {lead.get('why', '')}")
        if lead.get("proof_level"):
            lines.append(f"**Proof level:** `{lead['proof_level']}`")
        evidence = lead.get("evidence") or {}
        if evidence:
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```json")
            lines.append(json.dumps(evidence, indent=2, ensure_ascii=False))
            lines.append("```")
        actions = lead.get("suggested_actions") or []
        if actions:
            lines.append("")
            lines.append("**Suggested actions:**")
            for action in actions:
                marker = "ACTIVE" if action.get("active") else "passive"
                lines.append(f"- `{marker}` {action.get('intent', '')}")
                lines.append("")
                lines.append("  ```bash")
                lines.append(f"  {action.get('command', '')}")
                lines.append("  ```")
                if action.get("warning"):
                    lines.append(f"  > {action['warning']}")
                lines.append("")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Hosts")
    for host in hosts:
        names = ", ".join(host.get("hostnames") or []) or "-"
        svc = ", ".join(f"{s['port']}/{s['service']}" for s in host.get("services", [])) or "-"
        lines.append(f"- `{host['ip']}` names={names} services={svc}")
    if not hosts:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Users")
    for user in users:
        lines.append(
            f"- `{user['username']}` domain={user['domain'] or '-'} "
            f"sources={','.join(user['sources'])}"
        )
    if not users:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Credentials")
    for cred in creds:
        lines.append(
            f"- {cred['protocol']} {cred['source_ip']} -> {cred['destination_ip']} "
            f"user=`{cred['username']}` secret=`{cred['secret']}` ({cred['context']})"
        )
    if not creds:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Hashes")
    for h in hashes:
        lines.append(f"- {h['kind']} user=`{h['username']}` `{h['hash']}`")
    if not hashes:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines)


def write_exports(
    conn: sqlite3.Connection,
    out_dir: str,
    pcap_name: str = "",
    inventory: Optional[Dict] = None,
    leads: Optional[List[Dict]] = None,
) -> List[str]:
    """Write the whole export pack. Returns the list of created files."""
    inventory = inventory or collect_inventory(conn)
    leads = leads if leads is not None else build_leads(inventory)
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []

    def path(name: str) -> str:
        full = os.path.join(out_dir, name)
        written.append(full)
        return full

    _write_text(path("ips.txt"), sorted({h["ip"] for h in inventory["hosts"]}, key=_ip_key))

    subnets: Dict[str, Set[str]] = defaultdict(set)
    for host in inventory["hosts"]:
        try:
            from ipaddress import ip_network

            subnet = str(ip_network(f"{host['ip']}/24", strict=False))
        except ValueError:
            subnet = "unknown"
        subnets[subnet].add(host["ip"])
    subnet_lines = []
    for subnet in sorted(subnets, key=lambda s: _ip_key(s.split("/")[0])):
        subnet_lines.append(subnet)
        for ip in sorted(subnets[subnet], key=_ip_key):
            subnet_lines.append(f"  {ip}")
    _write_text(path("subnets.txt"), subnet_lines)

    _write_text(
        path("users.txt"),
        [
            f"{u['domain']}\\{u['username']}" if u["domain"] else u["username"]
            for u in inventory["users"]
        ],
    )

    host_lines = []
    for host in inventory["hosts"]:
        names = ",".join(host.get("hostnames") or [])
        macs = ",".join(host.get("macs") or [])
        services = ",".join(f"{s['port']}={s['service']}" for s in host.get("services", []))
        host_lines.append(f"{host['ip']}\t{names or '-'}\t{macs or '-'}\t{services or '-'}")
    _write_text(path("hosts.tsv"), host_lines)

    targets = format_nmap_targets(inventory["hosts"])
    _write_text(path("nmap-targets.txt"), targets.splitlines() if targets else [])
    command = format_nmap_command(inventory["hosts"])
    if command:
        _write_text(path("nmap-command.txt"), [command])

    with open(path("credentials.csv"), "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["protocol", "source_ip", "destination_ip", "username", "secret", "context"]
        )
        for cred in inventory["credentials"]:
            writer.writerow(
                [
                    cred["protocol"],
                    cred["source_ip"],
                    cred["destination_ip"],
                    cred["username"],
                    cred["secret"],
                    cred["context"],
                ]
            )

    _write_text(
        path("ntlm-hashes.txt"),
        [h["hash"] for h in inventory["hashes"] if h["hash"] and h["hashcat_mode"] == 5600],
    )
    _write_text(
        path("asrep-hashes.txt"),
        [h["hash"] for h in inventory["hashes"] if h["hash"] and h["hashcat_mode"] == 18200],
    )
    relay_rows = inventory.get("relays", [])
    _write_text(
        path("relay-targets.txt"),
        sorted({r["destination_ip"] for r in relay_rows if r.get("candidate") and r["destination_ip"]}),
    )
    relay_lines = ["source_ip	destination_ip	port	protocol	username	signing	candidate"]
    for r in relay_rows:
        signing = "-" if r["signing_required"] is None else int(r["signing_required"])
        relay_lines.append(
            f"{r['source_ip']}	{r['destination_ip']}	{r['destination_port']}	"
            f"{r['protocol']}	{r['username'] or '-'}	{signing}	{int(r['candidate'])}"
        )
    _write_text(path("relays.tsv"), relay_lines)

    smb = inventory.get("smb", {"shares": [], "files": []})
    share_lines = sorted(
        {
            f"{row['destination_ip']}	{row['share'] or '-'}	"
            f"{'printer' if row['printer'] else 'share'}"
            for row in smb.get("shares", [])
        }
    )
    _write_text(path("smb-shares.txt"), share_lines)
    file_lines = sorted(
        {
            f"{row['destination_ip']}	{row['share'] or '-'}	{row['file']}	"
            f"{row['operation']}"
            for row in smb.get("files", [])
        }
    )
    _write_text(path("smb-files.txt"), file_lines)

    nac = inventory.get("nac", [])
    _write_text(
        path("nac.txt"),
        sorted(
            {
                f"{row['kind']}	{row['identity'] or '-'}	{row['src']}	{row['dst']}	"
                f"{row['method']}	{'mab' if row['mab'] else 'dot1x'}"
                for row in nac
            }
        ),
    )
    wsus = inventory.get("wsus", [])
    _write_text(
        path("wsus.txt"),
        sorted(
            {
                f"{row['destination_ip']}	{row['host'] or '-'}	{row['indicator']}	"
                f"{row['uri']}"
                for row in wsus
            }
        ),
    )
    dns = inventory.get("dns", [])
    _write_text(
        path("dns.txt"),
        sorted(
            {
                f"{row['query']}	{row['type']}	{row['answer'] or '-'}	"
                f"{row['source_ip']}	{row['destination_ip']}"
                for row in dns
            }
        ),
    )
    catcher = inventory.get("asrepcatcher", [])
    _write_text(
        path("asrepcatcher.txt"),
        sorted(
            {
                f"{row['kind']}	{row['severity']}	{row['client_ip'] or '-'}	"
                f"{row['attacker_ip'] or '-'}	{row['kdc_ip'] or '-'}	"
                f"{row['username'] or '-'}	{row['realm'] or '-'}	{row['summary']}"
                for row in catcher
            }
        ),
    )

    kerberoast = inventory.get("kerberoast", [])
    _write_text(
        path("kerberoast-hashes.txt"),
        [row["hash"] for row in kerberoast if row["hash"]],
    )
    _write_text(
        path("tokens.tsv"),
        ["kind	severity	host	path	header	fingerprint	principal	expires	src	dst"]
        + [
            f"{row['kind']}	{row['severity']}	{row['host'] or '-'}	"
            f"{row['path'] or '-'}	{row['header'] or '-'}	{row['fingerprint']}	"
            f"{row['principal'] or '-'}	{row['expires'] or '-'}	"
            f"{row['source_ip'] or '-'}	{row['destination_ip'] or '-'}"
            for row in inventory.get("tokens", [])
        ],
    )
    _write_text(
        path("coercions.tsv"),
        ["kind	severity	src	dst	pipe	opnum	unc"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['pipe'] or '-'}	"
            f"{row['opnum'] or '-'}	{row['unc'] or '-'}"
            for row in inventory.get("coercions", [])
        ],
    )
    _write_text(
        path("adcs.tsv"),
        ["kind	severity	src	dst	host	uri	principal	realm"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['host'] or '-'}	"
            f"{row['uri'] or '-'}	{row['principal'] or '-'}	{row['realm'] or '-'}"
            for row in inventory.get("adcs", [])
        ],
    )
    _write_text(
        path("ipv6.tsv"),
        ["kind	severity	src	dst	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['detail']}"
            for row in inventory.get("ipv6", [])
        ],
    )
    _write_text(
        path("db-creds.tsv"),
        ["protocol	src	dst	username	secret	kind	server	hashcat"]
        + [
            f"{row['protocol']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['username'] or '-'}	"
            f"{row['secret'] or '-'}	{row['kind']}	{row['server'] or '-'}	"
            f"{row['hashcat'] or '-'}"
            for row in inventory.get("database_credentials", [])
        ],
    )
    _write_text(
        path("sccm.tsv"),
        ["kind	severity	src	dst	host	uri	share"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['host'] or '-'}	"
            f"{row['uri'] or '-'}	{row['share'] or '-'}"
            for row in inventory.get("sccm", [])
        ],
    )
    _write_text(
        path("llm.tsv"),
        ["kind	severity	src	dst	service	host	path	model	auth	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['service'] or '-'}	"
            f"{row['host'] or '-'}	{row['path'] or '-'}	{row['model'] or '-'}	"
            f"{row['auth']}	{row['detail']}"
            for row in inventory.get("llm", [])
        ],
    )
    _write_text(
        path("kerberos-signals.tsv"),
        ["kind	severity	user	realm	service	src	dst	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['username'] or '-'}	"
            f"{row['realm'] or '-'}	{row['service'] or '-'}	"
            f"{row['source_ip'] or '-'}	{row['destination_ip'] or '-'}	{row['detail']}"
            for row in inventory.get("kerberos_signals", [])
        ],
    )
    _write_text(
        path("ldap-spns.tsv"),
        ["account	spn	sid	src	dst"]
        + [
            f"{row['account']}	{row['spn']}	{row['sid'] or '-'}	"
            f"{row['source_ip'] or '-'}	{row['destination_ip'] or '-'}"
            for row in inventory.get("ldap_spns", [])
        ],
    )
    _write_text(
        path("ldap-signing.tsv"),
        ["destination	binds	simple	sasl"]
        + [
            f"{row['destination_ip'] or '-'}	{row['binds']}	"
            f"{row['simple_binds']}	{row['sasl_binds']}"
            for row in inventory.get("ldap_signing", [])
        ],
    )
    _write_text(
        path("ldap-adcs.tsv"),
        ["kind	severity	name	dns_name	template	detail	src	dst"]
        + [
            f"{row['kind']}	{row['severity']}	{row['name'] or '-'}	"
            f"{row['dns_name'] or '-'}	{row['template'] or '-'}	{row['detail']}	"
            f"{row['source_ip'] or '-'}	{row['destination_ip'] or '-'}"
            for row in inventory.get("ldap_adcs", [])
        ],
    )
    _write_text(
        path("voip.tsv"),
        ["kind	severity	src	dst	caller	callee	call_id	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['caller'] or '-'}	"
            f"{row['callee'] or '-'}	{row['call_id'] or '-'}	{row['detail']}"
            for row in inventory.get("voip", [])
        ],
    )
    _write_text(
        path("rdp.tsv"),
        ["kind	severity	src	dst	principal	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['principal'] or '-'}	"
            f"{row['detail']}"
            for row in inventory.get("rdp", [])
        ],
    )
    _write_text(
        path("cloud-apis.tsv"),
        ["kind	severity	src	dst	principal	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['principal'] or '-'}	"
            f"{row['detail']}"
            for row in inventory.get("cloudapi", [])
        ],
    )
    _write_text(
        path("fingerprints.tsv"),
        ["kind	severity	src	dst	principal	detail"]
        + [
            f"{row['kind']}	{row['severity']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['principal'] or '-'}	"
            f"{row['detail']}"
            for row in inventory.get("fingerprints", [])
        ],
    )
    media = [
        row
        for row in inventory.get("files", [])
        if (row.get("content_type") or "").startswith(("audio/", "video/"))
    ]
    _write_text(
        path("media.tsv"),
        ["sha256	size	type	protocol	src	dst	filename"]
        + [
            f"{row['sha256']}	{row['size']}	{row['content_type']}	"
            f"{row['protocol']}	{row['source_ip'] or '-'}	"
            f"{row['destination_ip'] or '-'}	{row['filename']}"
            for row in media
        ],
    )
    graph = inventory.get("graph") or {}
    _write_text(
        path("credential-matrix.tsv"),
        ["identity	sid	sources	cleartext	hashes	destinations	credentials"]
        + [
            f"{row['identity']}	{row['sid'] or '-'}	"
            f"{','.join(row['sources']) or '-'}	"
            f"{','.join(row['cleartext_protocols']) or '-'}	"
            f"{','.join(row['hash_kinds']) or '-'}	"
            f"{','.join(row['destinations']) or '-'}	{row['credential_count']}"
            for row in graph.get("matrix", [])
        ],
    )
    _write_json(
        path("identity-graph.json"),
        {
            "nodes": graph.get("nodes", {}),
            "edges": graph.get("edges", []),
            "matrix": graph.get("matrix", []),
            "reuse": graph.get("reuse", []),
        },
    )

    # Carved file objects (issue #57). These are client data: they stay in the
    # local export directory and are never uploaded by the tool.
    files_dir = os.path.join(out_dir, "files")
    os.makedirs(files_dir, exist_ok=True)
    written.append(files_dir)
    file_entries = []
    if _has_table(conn, "captured_files"):
        for protocol, src, dst, filename, content_type, size, digest, blob in _rows(
            conn,
            "SELECT protocol, src_ip, dst_ip, filename, content_type, size, sha256, data "
            "FROM captured_files",
        ):
            stored = f"{(digest or '')[:12]}_{filename or 'object'}"
            target = os.path.join(files_dir, stored)
            if blob is not None:
                with open(target, "wb") as handle:
                    handle.write(bytes(blob))
            file_entries.append(
                f"{digest}	{size}	{content_type or '-'}	{protocol}	"
                f"{src}	{dst}	{filename}	files/{stored}"
            )
    _write_text(path("files.tsv"), file_entries)

    # BloodHound Legacy JSON (issue #15): users/computers/sessions observed.
    try:
        from PufferRelay import bloodhound

        for created in bloodhound.write(os.path.join(out_dir, "bloodhound"), inventory):
            written.append(created)
    except Exception as bloodhound_error:  # never fail the whole export for this
        print(f"bloodhound export skipped: {bloodhound_error}")

    # Passive Wi-Fi findings (epic #82). Only written for 802.11 captures.
    wifi = inventory.get("wifi") or {}
    if any(wifi.values()):
        from PufferRelay.protocols import wifi as wifi_module

        _write_text(
            path("wifi-networks.tsv"),
            ["bssid	ssid	band	channel	security	akms	ciphers	pmf	beacons	clients"]
            + [
                f"{r['bssid']}	{r['ssid'] or '-'}	{r['band'] or '-'}	"
                f"{r['channel'] or '-'}	{r['security'] or '-'}	"
                f"{r['akms'] or '-'}	{r['ciphers'] or '-'}	{r['pmf'] or '-'}	"
                f"{r['beacons']}	{r['clients']}"
                for r in wifi.get("networks") or []
            ],
        )
        _write_text(
            path("wifi-wep.tsv"),
            ["bssid	ssid	channel	ivs	unique_ivs	weak_ivs	arp	readiness	proof"]
            + [
                f"{r['bssid']}	{r['ssid'] or '-'}	{r['channel'] or '-'}	"
                f"{r['iv_count']}	{r['unique_ivs']}	{r['weak_ivs']}	"
                f"{r['arp_frames']}	{r['readiness']}	{r['proof']}"
                for r in wifi.get("wep") or []
            ],
        )
        _write_text(
            path("wifi-handshakes.tsv"),
            ["bssid	ssid	client	messages	complete	pmkid	proof"]
            + [
                f"{r['bssid']}	{r['ssid'] or '-'}	{r['client']}	"
                f"{r['messages'] or '-'}	{r['complete']}	{r['pmkid'] or '-'}	"
                f"{r['proof']}"
                for r in wifi.get("handshakes") or []
            ],
        )
        _write_text(
            path("pmkid-hashes.txt"),
            sorted(
                {
                    wifi_module.build_pmkid_line(
                        r.get("pmkid"), r.get("bssid"), r.get("client"),
                        r.get("ssid"),
                    )
                    for r in wifi.get("handshakes") or []
                }
                - {""}
            ),
        )
        _write_text(
            path("wifi-wps.tsv"),
            ["bssid	ssid	state	locked	selected_registrar	methods	vendor	model	risk"]
            + [
                f"{r['bssid']}	{r['ssid'] or '-'}	{r['state'] or '-'}	"
                f"{r['locked']}	{r['selected_registrar']}	"
                f"{r['config_methods'] or '-'}	{r['manufacturer'] or '-'}	"
                f"{r['model'] or '-'}	{r['risk']}"
                for r in wifi.get("wps") or []
            ],
        )
        _write_text(
            path("wifi-eap.tsv"),
            ["bssid	identity	methods	frames	proof"]
            + [
                f"{r['bssid']}	{r['identity'] or '-'}	{r['methods'] or '-'}	"
                f"{r['frames']}	{r['proof']}"
                for r in wifi.get("eap") or []
            ],
        )
        _write_text(
            path("wifi-wpa3.tsv"),
            ["bssid	ssid	akms	pmf	sae_frames	transition	downgrade_risk	proof"]
            + [
                f"{r['bssid']}	{r['ssid'] or '-'}	{r['akms'] or '-'}	"
                f"{r['pmf'] or '-'}	{r['sae_frames']}	{r['transition']}	"
                f"{r['downgrade_risk']}	{r['proof']}"
                for r in wifi.get("wpa3") or []
            ],
        )
        _write_text(
            path("wifi-events.tsv"),
            ["kind	severity	bssid	ssid	client	count	detail"]
            + [
                f"{r['kind']}	{r['severity']}	{r['bssid'] or '-'}	"
                f"{r['ssid'] or '-'}	{r['client'] or '-'}	{r['count']}	"
                f"{r['detail']}"
                for r in wifi.get("events") or []
            ],
        )

    _write_json(path("summary.json"), {"inventory": inventory, "leads": leads})
    _write_json(
        path("leads.json"),
        {
            "schema": EXPORT_SCHEMA,
            "tool": "PufferRelay",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "pcap": pcap_name,
            "summary": {
                "hosts": len(inventory["hosts"]),
                "users": len(inventory["users"]),
                "credentials": len(inventory["credentials"]),
                "hashes": len(inventory["hashes"]),
                "leads": len(leads),
            },
            "leads": leads,
            "inventory": inventory,
        },
    )
    _write_text(path("leads.md"), leads_to_markdown(inventory, leads, pcap_name).splitlines())
    _write_text(path("agent-prompt.md"), AGENT_PROMPT.splitlines())

    return written
