# Features

## Extraction (passive)

| Area | What you get |
|---|---|
| Credentials | FTP, HTTP Basic auth and POST forms, Telnet, SMTP, IMAP, POP3, LDAP simple bind |
| Hashes | NTLMv1/NTLMv2 (hashcat 5600), AS-REP roastable accounts (hashcat 18200) |
| Identities | usernames from every protocol above, NTLM/DOMAIN users, Kerberos principals, EAP/NAC identities |
| Hosts | IP inventory grouped by /24, NetBIOS names and MACs, observed TCP services |
| AD | SMB share/file names, printer shares, relay candidates (SMB signing flags + NTLM over SMB/LDAP/HTTP) |
| Clear text | HTTP/FTP file objects carved with sha256, HTTP WSUS endpoints |
| Weakness | quick wins: SMBv1, SMB signing, LDAP signing, SNMPv1/v2, SSLv2/v3, TLS1.0, LLMNR/NBT-NS/mDNS, cleartext protocols |

## Exports (files + copy/paste)

`ips.txt`, `subnets.txt`, `users.txt`, `hosts.tsv`, `nmap-targets.txt`,
`nmap-command.txt`, `credentials.csv`, `ntlm-hashes.txt`, `asrep-hashes.txt`,
`relay-targets.txt`, `relays.tsv`, `smb-shares.txt`, `smb-files.txt`,
`wsus.txt`, `nac.txt`, `files.tsv` + `files/`, `bloodhound/`, `summary.json`.

## Agent feed

`leads.json` (ranked, evidence, suggested actions, ACTIVE warnings),
`leads.md` (briefing) and `agent-prompt.md` (ready-to-paste instructions).
See [outputs.md](outputs.md).

## Querying

`-r` with `--json`, `--creds`, `--inventory` or `--protocol ftp,ntlm`.
The database is SQLite (`extracted_data.db`) if you prefer your own SQL.
