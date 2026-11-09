# Features

## Extraction (passive)

| Area | What you get |
|---|---|
| Credentials | FTP, HTTP Basic auth and POST forms, Telnet, SMTP, IMAP, POP3, LDAP simple bind |
| Hashes | NTLMv1/NTLMv2 (hashcat 5600), AS-REP roastable accounts (hashcat 18200) |
| Identities | usernames from every protocol above, NTLM/DOMAIN users, Kerberos principals, EAP/NAC identities |
| Hosts | IP inventory grouped by /24, NetBIOS/DNS names and MACs, observed TCP services |
| DNS | queries/answers (A, AAAA, PTR, ...), name↔IP map, `dns.txt` |
| AD | SMB share/file names, printer shares, relay candidates (SMB signing flags + NTLM over SMB/LDAP/HTTP) |
| Kerberos attacks | ASRepCatcher-compatible ARP/relay pattern (critical when both signals overlap), AS-REP roastable accounts |
| Clear text | HTTP/FTP file objects carved with sha256, HTTP WSUS endpoints |
| Weakness | quick wins: SMBv1, SMB signing, LDAP signing, SNMPv1/v2, SSLv2/v3, TLS1.0, LLMNR/NBT-NS/mDNS, cleartext protocols |

## Exports (files + copy/paste)

`ips.txt`, `subnets.txt`, `users.txt`, `hosts.tsv`, `nmap-targets.txt`,
`nmap-command.txt`, `credentials.csv`, `ntlm-hashes.txt`, `asrep-hashes.txt`,
`relay-targets.txt`, `relays.tsv`, `smb-shares.txt`, `smb-files.txt`,
`wsus.txt`, `nac.txt`, `dns.txt`, `asrepcatcher.txt`, `files.tsv` + `files/`,
`bloodhound/`, `summary.json`.

## Agent feed

`leads.json` (ranked, evidence, suggested actions, ACTIVE warnings),
`leads.md` (briefing) and `agent-prompt.md` (ready-to-paste instructions).
See [outputs.md](outputs.md).

## Active modes (opt-in, never default)

| Flag | What it does | Guard rails |
|---|---|---|
| `--live IFACE --bpf FILTER` | captures live traffic for `--duration` seconds, then analyses it | red warning, `authorized` confirmation (or `--confirm-authorized`), temp capture deleted unless `--keep-live-capture` |
| `--proxy --proxy-target HOST:PORT` | local TCP relay, records both directions to JSONL | red warning + confirmation; one target, bounded duration |
| `--commands` | writes `active-commands.md` (ARP spoof / relay commands) | text only; nothing executed; cleanup commands included |
| `--serveme` | writes `serveme.md` (next-step command per host/finding) | text only; ACTIVE lines flagged |

Passive analysis remains the default; these modes never run implicitly.

## Querying

`-r` with `--json`, `--creds`, `--inventory`, `--protocol ftp,ntlm`, or the
filters `--ip ADDRESS`, `--user NAME`, `--has-creds`, `--table NAME`
(`--limit N` caps rows per table).
The database is SQLite (`extracted_data.db`) if you prefer your own SQL.
