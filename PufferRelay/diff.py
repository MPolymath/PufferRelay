"""Two-capture diff (step 9): what appeared or disappeared between databases.

Compares two inventories produced from two captures/databases so a retest or a
second capture can be read as delta instead of re-reading the whole report.
"""

from __future__ import annotations

from typing import Dict, List


def _host_key(host: Dict) -> str:
    return host.get("ip", "")


def _user_key(user: Dict) -> str:
    return f"{user.get('domain', '')}\\{user.get('username', '')}".lower()


def _cred_key(cred: Dict) -> str:
    return "|".join(
        str(cred.get(key, ""))
        for key in ("protocol", "source_ip", "destination_ip", "username", "secret")
    )


def _hash_key(entry: Dict) -> str:
    return entry.get("hash") or f"{entry.get('kind', '')}:{entry.get('username', '')}"


def _lead_key(lead: Dict) -> str:
    return f"{lead.get('title', '')}|{lead.get('severity', '')}"


def diff_inventories(old: Dict, new: Dict) -> Dict[str, List]:
    old_hosts = {_host_key(row) for row in old.get("hosts", [])}
    new_hosts = {_host_key(row) for row in new.get("hosts", [])}
    old_users = {_user_key(row) for row in old.get("users", [])}
    new_users = {_user_key(row) for row in new.get("users", [])}
    old_creds = {_cred_key(row) for row in old.get("credentials", [])}
    new_creds = {_cred_key(row) for row in new.get("credentials", [])}
    old_hashes = {_hash_key(row) for row in old.get("hashes", [])}
    new_hashes = {_hash_key(row) for row in new.get("hashes", [])}
    old_leads = {_lead_key(row) for row in old.get("leads", [])}
    new_leads = {_lead_key(row) for row in new.get("leads", [])}

    return {
        "new_hosts": sorted(new_hosts - old_hosts),
        "removed_hosts": sorted(old_hosts - new_hosts),
        "new_users": sorted(new_users - old_users),
        "new_credentials": sorted(new_creds - old_creds),
        "new_hashes": sorted(new_hashes - old_hashes),
        "new_leads": sorted(new_leads - old_leads),
    }


def render_diff(diff: Dict[str, List], old_label: str, new_label: str) -> str:
    lines = [
        "# Capture diff",
        "",
        f"- old: `{old_label}`",
        f"- new: `{new_label}`",
        "",
    ]
    sections = [
        ("new_hosts", "New hosts"),
        ("removed_hosts", "Hosts no longer seen"),
        ("new_users", "New users"),
        ("new_credentials", "New credentials"),
        ("new_hashes", "New hash material"),
        ("new_leads", "New leads"),
    ]
    for key, title in sections:
        values = diff.get(key, [])
        lines.append(f"## {title} ({len(values)})")
        lines.append("")
        if values:
            lines.extend(f"- {value}" for value in values)
        else:
            lines.append("- (none)")
        lines.append("")
    return "\n".join(lines)


def write_diff(path: str, diff: Dict[str, List], old_label: str, new_label: str) -> str:
    import os

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_diff(diff, old_label, new_label))
    return path
