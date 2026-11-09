"""Identity and credential graph (step 6) — normalize and correlate.

The inventory lists users, hosts, credentials and hashes in parallel tables.
This module joins them: one canonical identity, the hosts it authenticated to,
the credentials/hashes seen for it, and a reuse matrix that answers "who has
what, and where has it been used?".
"""

from __future__ import annotations

import hashlib
from typing import Dict, List


def _canonical(raw: str):
    text = (raw or "").strip().strip('"')
    if "\\" in text:
        domain, user = text.split("\\", 1)
        return user.lower(), domain.lower(), f"{domain}\\{user}"
    if "@" in text and not text.lower().startswith("cn="):
        user, domain = text.split("@", 1)
        return user.lower(), domain.lower(), f"{domain}\\{user}"
    return text.lower(), "", text


def _secret_fingerprint(secret: str) -> str:
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def build_graph(inventory: Dict) -> Dict:
    users = {}
    hosts = {host.get("ip", ""): host for host in inventory.get("hosts", []) if host.get("ip")}

    def user_node(raw):
        key, domain, display = _canonical(raw)
        if not key:
            return None
        node = users.setdefault(
            key,
            {
                "key": key,
                "display": display,
                "domain": domain,
                "hosts": set(),
                "sources": set(),
                "cleartext": set(),
                "hashes": set(),
                "credentials": [],
                "sid": "",
            },
        )
        return node

    for user in inventory.get("users", []):
        node = user_node(user.get("username", ""))
        if not node:
            continue
        node["domain"] = node["domain"] or (user.get("domain") or "").lower()
        node["sources"].update(user.get("sources") or [])
        if user.get("sid"):
            node["sid"] = user["sid"]
        for host in user.get("seen_at") or []:
            node["hosts"].add(host)

    for cred in inventory.get("credentials", []):
        node = user_node(cred.get("username", ""))
        if not node:
            continue
        node["cleartext"].add(cred.get("protocol", ""))
        node["hosts"].add(cred.get("destination_ip", ""))
        node["credentials"].append(
            {
                "protocol": cred.get("protocol", ""),
                "destination_ip": cred.get("destination_ip", ""),
                "secret_fingerprint": _secret_fingerprint(cred.get("secret", "")),
                "context": cred.get("context", ""),
            }
        )

    for entry in inventory.get("hashes", []):
        node = user_node(entry.get("username", ""))
        if not node:
            continue
        node["hashes"].add(entry.get("kind", "hash"))
        node["hosts"].add(entry.get("destination_ip", ""))
        node["credentials"].append(
            {
                "protocol": entry.get("kind", "hash"),
                "destination_ip": entry.get("destination_ip", ""),
                "secret_fingerprint": _secret_fingerprint(entry.get("hash", "")),
                "context": "offline crack",
            }
        )

    edges = []
    matrix = []
    reuse = []
    for key in sorted(users):
        node = users[key]
        node["hosts"].discard("")
        node["sources"] = sorted(node["sources"])
        node["hosts"] = sorted(node["hosts"])
        node["cleartext"] = sorted(node["cleartext"])
        node["hashes"] = sorted(node["hashes"])
        destinations = sorted(
            {
                cred["destination_ip"]
                for cred in node["credentials"]
                if cred["destination_ip"]
            }
        )
        for host_ip in node["hosts"]:
            host = hosts.get(host_ip, {})
            edges.append(
                {
                    "from": node["display"],
                    "to": host_ip,
                    "kind": "authenticated-host",
                    "hostnames": host.get("hostnames") or [],
                }
            )
        matrix.append(
            {
                "identity": node["display"],
                "sid": node["sid"],
                "sources": node["sources"],
                "cleartext_protocols": node["cleartext"],
                "hash_kinds": node["hashes"],
                "destinations": destinations,
                "credential_count": len(node["credentials"]),
            }
        )
        if node["cleartext"] and node["hashes"]:
            reuse.append(
                {
                    "identity": node["display"],
                    "kind": "cleartext-and-hash",
                    "severity": "medium",
                    "detail": "both a cleartext secret and crackable hash material were observed",
                    "evidence": {
                        "cleartext": node["cleartext"],
                        "hashes": node["hashes"],
                    },
                }
            )
        if len(destinations) >= 2 and node["credentials"]:
            reuse.append(
                {
                    "identity": node["display"],
                    "kind": "credential-reuse",
                    "severity": "high",
                    "detail": f"identity material was seen against {len(destinations)} destination(s)",
                    "evidence": {"destinations": destinations},
                }
            )

    return {
        "nodes": {"users": len(users), "hosts": len(hosts)},
        "users": [
            {
                key: value
                for key, value in node.items()
                if key != "credentials"
            }
            for node in users.values()
        ],
        "edges": edges,
        "matrix": matrix,
        "reuse": reuse,
    }
