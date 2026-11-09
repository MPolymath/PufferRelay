# OUTPUTS — files you can move between tools

All files are plain UTF-8 (ASCII in the briefing), no ANSI, stable names.
Generate them with:

```bash
pufferrelay -f capture.pcap --dump out          # handlers only
pufferrelay -q capture.pcap --dump out          # + quick-win scan (slower)
pufferrelay -r --dump out                       # from an existing database
```

## The agent feed (issue #63)

| File | Audience | Contents |
|---|---|---|
| `leads.json` | AI agent / automation | `schema`, `tool`, `generated_at`, `pcap`, `summary`, ranked `leads[]`, full `inventory` |
| `leads.md` | AI agent / human | same leads as a briefing: severity, why, evidence, copy-paste commands, ACTIVE warnings, then compact host/user/credential/hash lists |
| `agent-prompt.md` | AI agent | ready-to-paste system/task prompt describing the inputs, the evidence rule, the ACTIVE-action confirmation rule, and the expected output (ranked plan with commands) |

`leads.json` shape:

```json
{
  "schema": 1,
  "tool": "PufferRelay",
  "generated_at": "2026-11-09T10:20:00",
  "pcap": "capture.pcap",
  "summary": {"hosts": 5, "users": 2, "credentials": 2, "hashes": 0, "leads": 2},
  "leads": [
    {
      "id": "CRED-001",
      "severity": "high",
      "title": "Captured ftp credentials for 10.0.0.10",
      "why": "Valid credentials seen in traffic can be replayed...",
      "evidence": {"protocol": "ftp", "source_ip": "10.0.0.5",
                    "destination_ip": "10.0.0.10", "username": "alice",
                    "secret": "s3cret", "context": "cleartext FTP"},
      "suggested_actions": [
        {"intent": "Verify the credential still works (scope-gated)",
         "command": "ftp 10.0.0.10", "active": true,
         "warning": "Active: authenticates with the captured secret. Confirm the target is in scope."}
      ],
      "passive": true
    }
  ],
  "inventory": {"hosts": [], "users": [], "credentials": [], "hashes": [], "dns": [], "quick_wins": []}
}
```

Rules an agent must follow when consuming it:

1. `passive: true` means the finding came from the capture, not from scanning.
2. `suggested_actions[].active: true` means the command sends traffic. Confirm
   the target is in scope before running it; never run it automatically.
3. Credentials and hashes are real secrets. Keep the pack on the engagement
   machine and clean it up with the rest of the artifacts.

## Machine files

| File | Format | Use |
|---|---|---|
| `ips.txt` | one IP per line | feed to any tool |
| `subnets.txt` | `/24` then indented IPs | scoping, `nmap` choices |
| `users.txt` | `user` or `DOMAIN\user` per line | spraying, AS-REP/kerberoast targeting |
| `hosts.tsv` | `ip<TAB>hostnames<TAB>macs<TAB>port=service,...` | spreadsheet, scripts |
| `nmap-targets.txt` | `ip port1,port2,...` | `nmap -iL`-style inventory |
| `nmap-command.txt` | one ready `nmap -sV -Pn ...` line | copy-paste (ACTIVE) |
| `credentials.csv` | `protocol,source_ip,destination_ip,username,secret,context` | reuse, reporting |
| `ntlm-hashes.txt` | NetNTLM hashes | `hashcat -m 5600` |
| `asrep-hashes.txt` | AS-REP roastable accounts | `hashcat -m 18200` |
| `relay-targets.txt` | destination IPs that accept relayed NTLM | `ntlmrelayx.py -tf` |
| `relays.tsv` | src, dst, port, protocol, username, signing, candidate | relay planning / report |
| `smb-shares.txt` | host + share + type (share/printer) | lateral movement targets |
| `smb-files.txt` | host, share, file name, operation | data accessed over SMB |
| `dns.txt` | query, type, answer, src, dst | passive name↔IP map |
| `asrepcatcher.txt` | kind, severity, client, attacker, KDC, user, realm, summary | Kerberos attack pattern; leads carry the repo link |
| `files.tsv` | sha256, size, type, protocol, src, dst, name, path | index of carved objects |
| `files/` | the carved objects themselves | **client data**, local only |
| `bloodhound/users.json`, `computers.json` | SharpHound Legacy JSON built from observed users/hosts/sessions | import as leads (no SIDs/ACLs) |
| `bloodhound/README.txt` | what the graph does and does not prove | read before importing |
| `summary.json` | inventory + leads | dashboards, diffing runs |

## CLI filters (issue #48)

```bash
pufferrelay -f capture.pcap --only ftp,http,ntlm       # run selected handlers
pufferrelay -f capture.pcap --credentials-only        # identities/credentials only
pufferrelay -r --json                                  # inventory + leads as JSON
pufferrelay -r --creds                                 # credential rows only
pufferrelay -r --inventory                             # hosts/users only
pufferrelay -r --protocol ftp,ntlm                     # raw rows for those protocols
pufferrelay -r --ip 10.0.0.5                           # every row touching that IP
pufferrelay -r --user alice --has-creds                # that identity's secrets
pufferrelay -r --table dns_events --limit 100          # raw table dump
pufferrelay -r --protocol ftp --json                  # tab-separated (machine mode)
```

## Command generators (issues #13, #60)

```bash
pufferrelay -f capture.pcap --commands --dump out   # writes out/active-commands.md
pufferrelay -f capture.pcap --serveme  --dump out   # writes out/serveme.md
pufferrelay -f capture.pcap --commands --serveme --iface ens33 --gateway 10.0.0.1
```

Both files are **text only**; PufferRelay never executes them. Every command is
labelled ACTIVE, and `active-commands.md` includes ARP/relay cleanup commands.

## Active modes (Tier B)

```bash
pufferrelay --live eth0 --bpf "port 445" --duration 120
pufferrelay --proxy --proxy-target 10.0.0.10:445 --duration 60
```

Both print a red warning and require `authorized` (interactive) or
`--confirm-authorized`. Live captures go to a temporary file and are deleted
after analysis unless `--keep-live-capture` is set.


## Notes

- Nothing in this pack is produced by touching the network.
- The nmap command is a convenience string; it is `ACTIVE` if executed.
- A capture with no quick-win scan (`-q`) still yields CRED/HASH leads; run `-q`
  to add protocol-level leads (SMB signing, cleartext services, LLMNR, ...).
- Quick-win leads carry a stored severity and an evidence block with a hit
  count and sample source/destination IPs.
