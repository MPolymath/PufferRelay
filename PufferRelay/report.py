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

    lines.append("## Cleanup checklist")
    lines.append("")
    for item in (
        "Delete the capture, database, exports and this report when the rules require it.",
        "Remove any shadow credentials, added keys or certificates created during the test.",
        "Revoke tokens/API keys that were used or exposed, and rotate cracked passwords.",
        "Remove scheduled tasks, services, run keys and uploaded files created by active tests.",
        "Restore ARP tables, MAC addresses, proxy settings and DNS records.",
        "Confirm the cleanup steps in the audit trail and the final report.",
    ):
        lines.append(f"- [ ] {item}")
    lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append(f"pufferrelay -f {pcap_name or '<capture>'} --dump out")
    lines.append("pufferrelay -q <capture> --dump out   # adds protocol-level weaknesses")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def render_html(inventory: Dict, leads: List[Dict], pcap_name: str = "") -> str:
    """Same report as render_report, as a standalone HTML page."""
    import html

    counts = _counts(leads)
    ranked = sorted(leads, key=lambda lead: SEVERITY_ORDER.get(lead.get("severity"), 9))

    def esc(value):
        return html.escape(str(value))

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Capture analysis report</title><style>",
        "body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;",
        "padding:0 1rem;line-height:1.5;color:#1b1b1b}",
        "h1,h2,h3{line-height:1.2}table{border-collapse:collapse;width:100%;margin:1rem 0}",
        "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}",
        "th{background:#f3f3f3}.critical{color:#a40000}.high{color:#b45309}",
        ".medium{color:#7c6f00}.low{color:#31603d}pre{background:#f6f6f6;padding:.8rem;",
        "overflow:auto;white-space:pre-wrap}code{background:#f2f2f2;padding:0 .2rem}",
        "</style></head><body>",
        "<h1>Capture analysis report</h1>",
        f"<p><strong>Capture:</strong> <code>{esc(pcap_name or '(database only)')}</code><br>",
        f"<strong>Generated:</strong> {esc(time.strftime('%Y-%m-%d %H:%M:%S'))}<br>",
        "<strong>Method:</strong> passive pcap analysis. No traffic was sent.</p>",
        "<p><strong>Client-confidential.</strong> This report contains real "
        "credentials, hosts and hashes; keep it on the engagement machine.</p>",
        "<h2>Executive summary</h2>",
        "<table><tr><th>Severity</th><th>Leads</th></tr>",
    ]
    for severity in ("critical", "high", "medium", "low"):
        parts.append(
            f"<tr><td class='{severity}'>{severity.capitalize()}</td>"
            f"<td>{counts.get(severity, 0)}</td></tr>"
        )
    parts.append("</table>")
    parts.append(
        f"<p>{len(inventory.get('hosts', []))} hosts, "
        f"{len(inventory.get('users', []))} users, "
        f"{len(inventory.get('credentials', []))} credentials, "
        f"{len(inventory.get('hashes', []))} hash items.</p>"
    )
    parts.append("<h2>Findings</h2>")
    if not ranked:
        parts.append("<p>No leads were produced from this capture.</p>")
    for lead in ranked:
        severity = esc(lead.get("severity", "low"))
        parts.append(
            f"<h3 class='{severity}'>[{severity.upper()}] "
            f"{esc(lead.get('id', '-'))} — {esc(lead.get('title', ''))}</h3>"
        )
        parts.append(
            f"<p><strong>Confidence:</strong> {esc(lead.get('confidence', 'high'))}<br>"
            f"<strong>Why:</strong> {esc(lead.get('why', ''))}</p>"
        )
        evidence = lead.get("evidence") or {}
        if evidence:
            parts.append(
                "<pre>" + esc(json.dumps(evidence, indent=2, ensure_ascii=False)) + "</pre>"
            )
        actions = lead.get("suggested_actions") or []
        if actions:
            parts.append("<ul>")
            for action in actions:
                marker = "ACTIVE" if action.get("active") else "passive"
                parts.append(
                    f"<li><code>{marker}</code> {esc(action.get('intent', ''))}"
                    + (
                        f"<br><code>{esc(action['command'])}</code>"
                        if action.get("command")
                        else ""
                    )
                    + (
                        f"<br><em>{esc(action['warning'])}</em>"
                        if action.get("warning")
                        else ""
                    )
                    + "</li>"
                )
            parts.append("</ul>")

    parts.append("<h2>Credentials</h2>")
    if inventory.get("credentials"):
        parts.append(
            "<table><tr><th>Protocol</th><th>User</th><th>Secret</th>"
            "<th>Source</th><th>Destination</th></tr>"
        )
        for cred in inventory["credentials"]:
            parts.append(
                "<tr>"
                + "".join(
                    f"<td>{esc(cred.get(key, ''))}</td>"
                    for key in ("protocol", "username", "secret", "source_ip",
                                "destination_ip")
                )
                + "</tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>None captured.</p>")

    parts.append("<h2>Limitations</h2><ul>")
    for item in (
        "A capture proves traffic, not intent or exploitability.",
        "Candidate findings need verification; see wiki/DETECTIONS.md.",
        "TLS-encrypted traffic is opaque to every passive handler.",
        "Active commands were not run.",
    ):
        parts.append(f"<li>{esc(item)}</li>")
    parts.append("</ul>")

    parts.append("<h2>Cleanup checklist</h2><ul>")
    for item in (
        "Delete the capture, database, exports and this report when required.",
        "Remove shadow credentials, added keys and certificates.",
        "Revoke exposed tokens and rotate cracked passwords.",
        "Remove scheduled tasks, services, run keys and uploaded files.",
        "Restore ARP tables, MAC addresses, proxy settings and DNS records.",
    ):
        parts.append(f"<li><label><input type='checkbox'> {esc(item)}</label></li>")
    parts.append("</ul>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_report(conn, out_path: str, pcap_name: str = "") -> str:
    from PufferRelay.export import build_leads, collect_inventory

    inventory = collect_inventory(conn)
    leads = build_leads(inventory)
    if out_path.lower().endswith((".html", ".htm")):
        text = render_html(inventory, leads, pcap_name)
    else:
        text = render_report(inventory, leads, pcap_name)
    directory = os.path.dirname(os.path.abspath(out_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return out_path
