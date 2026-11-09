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
import sqlite3
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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

    out = []
    for (domain_key, user), sources in seen.items():
        out.append(
            {
                "username": user,
                "domain": display_domain.get((domain_key, user), domain_key),
                "sources": sorted(sources),
                "seen_at": sorted({h for h in hosts[(domain_key, user)] if h and h != "N/A"}),
            }
        )
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


def collect_hosts(conn: sqlite3.Connection) -> List[Dict]:
    """IPs from ip_requests, enriched with NetBIOS names, MACs and services."""
    names: Dict[str, Set[str]] = defaultdict(set)
    macs: Dict[str, Set[str]] = defaultdict(set)
    for row in _rows(conn, "SELECT hostname, src_ip, src_mac FROM netbios_requests"):
        hostname, ip, mac = row
        if ip and ip != "N/A":
            if hostname and hostname != "N/A":
                names[ip].add(hostname)
            if mac and mac != "N/A":
                macs[ip].add(mac)

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
    for protocol, found, details, creds_found, cred_protocols in _rows(
        conn,
        "SELECT protocol, found, details, credentials_found, credential_protocols "
        "FROM quick_wins",
    ):
        out.append(
            {
                "protocol": protocol,
                "found": bool(found),
                "details": details or "",
                "credentials_found": bool(creds_found),
                "credential_protocols": [p for p in (cred_protocols or "").split(",") if p],
            }
        )
    return out


def collect_inventory(conn: sqlite3.Connection) -> Dict:
    return {
        "hosts": collect_hosts(conn),
        "users": collect_users(conn),
        "credentials": collect_credentials(conn),
        "hashes": collect_hashes(conn),
        "quick_wins": collect_quick_wins(conn),
    }


# --------------------------------------------------------------------------- #
# Leads for an AI agent (or a human deciding what to attack next)
# --------------------------------------------------------------------------- #

QUICK_WIN_SEVERITY = {
    "SMB_SIGNING_MISSING": ("critical", "SMB signing disabled -> NTLM relay to SMB is possible"),
    "LDAP_SIGNING_MISSING": ("high", "LDAP signing/channel binding not enforced -> relay to LDAP"),
    "SMBv1": ("high", "SMBv1 present -> legacy exploitation surface (EternalBlue-class)"),
    "TLS1.0": ("medium", "TLS 1.0 in use"),
    "SSLv2": ("high", "SSLv2 in use"),
    "SSLv3": ("high", "SSLv3 in use (POODLE-class)"),
    "SNMPv1": ("medium", "SNMPv1 in use -> community strings readable"),
    "SNMPv2": ("medium", "SNMPv2c in use -> community strings readable"),
    "LLMNR": ("medium", "LLMNR observed -> poisoning/relay of name resolution"),
    "NETBIOS": ("medium", "NetBIOS name service observed -> poisoning surface"),
    "MDNS": ("low", "mDNS observed"),
    "SYSLOG": ("low", "Syslog in clear text"),
    "TFTP": ("medium", "TFTP in use (no authentication)"),
}

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
        leads.append(lead)

    # 1. Quick wins that are directly exploitable.
    for qw in quick_wins:
        if not qw["found"]:
            continue
        protocol = qw["protocol"]
        severity, why = QUICK_WIN_SEVERITY.get(
            protocol, ("low", qw["details"] or "protocol observed")
        )
        evidence = {"quick_win": protocol, "details": qw["details"]}
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

    # 3. NTLM hashes -> offline cracking (safe, no network).
    for i, h in enumerate(hashes, start=1):
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
    lines.append("")

    for lead in leads:
        lines.append(f"## [{lead['severity'].upper()}] {lead['id']} - {lead['title']}")
        lines.append("")
        lines.append(f"**Why it matters:** {lead.get('why', '')}")
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

    _write_text(path("ntlm-hashes.txt"), [h["hash"] for h in inventory["hashes"] if h["hash"]])

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

    return written
