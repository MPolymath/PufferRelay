"""Engagement report generator (step 8) — from the passive inventory.

The report is a chronological, evidence-first document: what the capture
contained, what it proves, what remains unproven, and how to reproduce the
analysis. Secrets are part of the report by design (it is a confidential
artifact), but tokens stay fingerprinted because the raw value is in the DB.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Sequence

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _counts(leads: Sequence) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for lead in leads:
        counts[lead.get("severity", "low")] = counts.get(lead.get("severity", "low"), 0) + 1
    return counts


def _table(lines: List[str], headers: List[str], rows: List[List[str]]) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    lines.append("")


def render_report(inventory: Dict, leads: List[Dict], pcap_name: str = "") -> str:
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    counts = _counts(leads)
    hosts = inventory.get("hosts", [])
    credentials = inventory.get("credentials", [])
    hashes = inventory.get("hashes", [])
    files = inventory.get("files", [])

    lines: List[str] = [
        "# Capture analysis report",
        "",
        f"- capture: `{pcap_name or '(database only)'}`",
        f"- generated: {generated}",
        "- method: passive pcap analysis (PufferRelay). No traffic was sent.",
        "",
        "> This report is client-confidential. It contains real credentials, "
        "hosts and hashes; keep it on the engagement machine.",
        "",
        "## Executive summary",
        "",
    ]
    _table(
        lines,
        ["Severity", "Leads"],
        [
            ["Critical", counts.get("critical", 0)],
            ["High", counts.get("high", 0)],
            ["Medium", counts.get("medium", 0)],
            ["Low", counts.get("low", 0)],
        ],
    )
    lines.append(
        f"Inventory: {len(hosts)} host(s), {len(inventory.get('users', []))} user(s), "
        f"{len(credentials)} credential(s), {len(hashes)} hash material item(s), "
        f"{len(files)} carved object(s)."
    )
    lines.append("")

    ranked = sorted(leads, key=lambda lead: SEVERITY_ORDER.get(lead.get("severity"), 9))
    lines.append("## Findings")
    lines.append("")
    if not ranked:
        lines.append("No leads were produced from this capture.")
        lines.append("")
    for lead in ranked:
        lines.append(
            f"### [{lead.get('severity', 'low').upper()}] {lead.get('id', '-')} — "
            f"{lead.get('title', '')}"
        )
        lines.append("")
        lines.append(f"- **Confidence:** {lead.get('confidence', 'high')}")
        lines.append(f"- **Why it matters:** {lead.get('why', '')}")
        evidence = lead.get("evidence") or {}
        if evidence:
            lines.append("")
            lines.append("**Evidence**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(evidence, indent=2, ensure_ascii=False))
            lines.append("```")
        actions = lead.get("suggested_actions") or []
        if actions:
            lines.append("")
            lines.append("**Suggested actions**")
            lines.append("")
            for action in actions:
                marker = "ACTIVE" if action.get("active") else "passive"
                lines.append(f"- `{marker}` {action.get('intent', '')}")
                if action.get("command"):
                    lines.append(f"  - `{action['command']}`")
                if action.get("warning"):
                    lines.append(f"  - {action['warning']}")
        lines.append("")

    lines.append("## Credentials")
    lines.append("")
    if credentials:
        _table(
            lines,
            ["Protocol", "User", "Secret", "Source", "Destination", "Context"],
            [
                [
                    cred.get("protocol", ""),
                    cred.get("username", ""),
                    cred.get("secret", ""),
                    cred.get("source_ip", ""),
                    cred.get("destination_ip", ""),
                    cred.get("context", ""),
                ]
                for cred in credentials
            ],
        )
    else:
        lines.extend(["None captured.", ""])

    lines.append("## Hash material")
    lines.append("")
    if hashes:
        _table(
            lines,
            ["Kind", "User", "Source", "Destination"],
            [
                [
                    row.get("kind", ""),
                    row.get("username", ""),
                    row.get("source_ip", ""),
                    row.get("destination_ip", ""),
                ]
                for row in hashes
            ],
        )
        lines.append("Hash values are in the export pack (`ntlm-hashes.txt`, "
                     "`asrep-hashes.txt`, `kerberoast-hashes.txt`).")
        lines.append("")
    else:
        lines.extend(["None captured.", ""])

    lines.append("## Artifacts")
    lines.append("")
    lines.append(
        f"- Carved objects: {len(files)} (see `files.tsv`; content stays in `files/`)."
    )
    lines.append("- Machine feed: `leads.json`; agent prompt: `agent-prompt.md`.")
    lines.append("- Detection limits: `wiki/DETECTIONS.md`.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    for item in (
        "A capture proves traffic, not intent or exploitability.",
        "Candidate findings (unparsed DER, heuristic coercion, partial flows) need verification.",
        "TLS-encrypted traffic is opaque to every passive handler.",
        "Active commands in the suggested actions were not run.",
    ):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append(f"pufferrelay -f {pcap_name or '<capture>'} --dump out")
    lines.append("pufferrelay -q <capture> --dump out   # adds protocol-level weaknesses")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def write_report(conn, out_path: str, pcap_name: str = "") -> str:
    from PufferRelay.export import build_leads, collect_inventory

    inventory = collect_inventory(conn)
    leads = build_leads(inventory)
    text = render_report(inventory, leads, pcap_name)
    directory = os.path.dirname(os.path.abspath(out_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return out_path
