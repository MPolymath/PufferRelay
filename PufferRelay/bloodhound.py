"""BloodHound (SharpHound v3 / Legacy JSON) export (issue #15).

Passive captures give identities, hosts and observed authentications — not
ACLs, group membership or SIDs. This module emits the classic SharpHound JSON
shape (users/computers with Sessions) that BloodHound Legacy and CE's "Legacy
JSON" import accept. Every object is clearly labelled in README.txt as
observed-in-traffic, not collected from the domain.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Dict, List

BLOODHOUND_NAMESPACE = "pufferrelay:bloodhound"


def _object_id(kind: str, name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{BLOODHOUND_NAMESPACE}:{kind}:{name.lower()}")).upper()


def _split_user(raw: str):
    text = (raw or "").strip().strip('"')
    if "\\" in text:
        domain, user = text.split("\\", 1)
        return user, domain
    if "@" in text and not text.lower().startswith("cn="):
        user, domain = text.split("@", 1)
        return user, domain
    return text, ""


def build(inventory: Dict) -> Dict[str, Dict]:
    users = inventory.get("users", [])
    hosts = inventory.get("hosts", [])
    credentials = inventory.get("credentials", [])
    hashes = inventory.get("hashes", [])

    domains = sorted({u.get("domain", "") for u in users if u.get("domain")})
    default_domain = domains[0] if domains else ""

    user_objects: List[Dict] = []
    user_lookup = {}
    for entry in users:
        username = entry.get("username", "")
        if not username:
            continue
        domain = entry.get("domain") or default_domain
        name = f"{username}@{domain}".upper() if domain else username.upper()
        identifier = _object_id("user", name)
        user_lookup[(username.lower(), (domain or "").lower())] = identifier
        user_lookup.setdefault((username.lower(), ""), identifier)
        user_objects.append(
            {
                "ObjectIdentifier": identifier,
                "Properties": {
                    "name": name,
                    "domain": (domain or "").upper(),
                    "samaccountname": username.lower(),
                    "enabled": True,
                    "description": "Observed by PufferRelay in captured traffic",
                },
                "Kinds": ["User"],
                "Aces": [],
                "HasSIDHistory": [],
                "AllowedToDelegate": [],
                "SPNTargets": [],
            }
        )

    computer_objects: List[Dict] = []
    computer_by_ip: Dict[str, Dict] = {}
    for host in hosts:
        ip = host.get("ip", "")
        hostname = (host.get("hostnames") or [""])[0]
        domain = default_domain
        if hostname and domain:
            name = f"{hostname}.{domain}".upper()
        else:
            name = (hostname or ip).upper()
        identifier = _object_id("computer", name)
        obj = {
            "ObjectIdentifier": identifier,
            "Properties": {
                "name": name,
                "domain": (domain or "").upper(),
                "enabled": True,
                "operatingsystem": None,
                "description": "Observed by PufferRelay in captured traffic",
            },
            "Kinds": ["Computer"],
            "Aces": [],
            "Sessions": [],
            "PrivilegedSessions": [],
            "RegistrySessions": [],
        }
        computer_objects.append(obj)
        if ip:
            computer_by_ip[ip] = obj

    def add_session(user_raw: str, dst_ip: str) -> None:
        computer = computer_by_ip.get(dst_ip)
        if computer is None:
            return
        username, domain = _split_user(user_raw)
        if not username:
            return
        domain = domain or default_domain
        user_name = f"{username}@{domain}".upper() if domain else username.upper()
        session = {"User": user_name, "Computer": computer["Properties"]["name"]}
        if session not in computer["Sessions"]:
            computer["Sessions"].append(session)

    for credential in credentials:
        add_session(credential.get("username", ""), credential.get("destination_ip", ""))
    for hash_entry in hashes:
        add_session(hash_entry.get("username", ""), hash_entry.get("destination_ip", ""))

    return {
        "users": {"users": user_objects},
        "computers": {"computers": computer_objects},
    }


README = """PufferRelay -> BloodHound (Legacy JSON) export
=================================================

These files were built PASSIVELY from a packet capture. They contain:
  * users observed in traffic (LDAP, NTLM, SMTP/IMAP/POP3, FTP, HTTP)
  * computers (IP addresses and NetBIOS names seen in the capture)
  * sessions: an authentication observed from a user towards a host

What this is NOT:
  * no SIDs, group membership, ACLs, delegation, trusts or DC information
  * identifiers are deterministic UUIDs, not real SIDs
  * a session means "credentials were seen going to that host", not "an
    interactive logon was confirmed"

Import: BloodHound Legacy -> Import -> Legacy JSON, or BloodHound CE's
"Legacy JSON" importer. Review the graph as leads, not as confirmed facts.
"""


def write(out_dir: str, inventory: Dict) -> List[str]:
    payloads = build(inventory)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, payload in payloads.items():
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        written.append(path)
    readme = os.path.join(out_dir, "README.txt")
    with open(readme, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(README)
    written.append(readme)
    return written
