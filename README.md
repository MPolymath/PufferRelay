![Image Alt text](Logos/Puffer1.webp "Optional title")

# PufferRelay

**PufferRelay** is a pentesting tool designed to extract valuable information from `.pcap` (Wireshark) files.  
It focuses on parsing and analyzing network traffic to surface sensitive or actionable data that may aid in offensive security operations.

---

## 🔍 Features

- Extracts protocol-specific data
    - LDAP, HTTP, FTP, TELNET, SMTP, IMAP, POP3, NETBIOS, NTLM, SNMP
- Parses `.pcap` files and stores data in a queryable SQL format
- Designed for use in red teaming and network traffic analysis
- Modular structure for easy extension

---

## 🚀 Getting Started

### 🛠️ Install
#### ⚗️PIPX
sudo apt install tshark <br>
pipx install pufferrelay <br>
#### 👨🏿‍🔧PIP
python3 -m venv venv <br>
source venv/bin/activate.fish <br>
pip3 install -r requirements.txt <br>

### ▶️ Usage
#### ⚗️PIPX
pufferrelay {flag} {filename}
#### 👨🏿‍🔧PIP
python3 -m PufferRelay {flag} {filename}

#### Parse pcap file into sqlite3 database and display all pertinent information
pufferrelay -f {filename}

#### Read 'DB_NAME' database and extract all pertinent information
pufferrelay -r

### 🐛 DEBUG
pufferrelay -f {filename} --log-level DEBUG

### ⚡ QUICKWIN
pufferrelay -q {filename}

#### Parse only what you need (faster on big captures)
pufferrelay -f {filename} --only ftp,http,ntlm <br>
pufferrelay -f {filename} --credentials-only <br>

#### Write the export pack + the AI-agent lead briefing
pufferrelay -f {filename} --dump out <br>
pufferrelay -q {filename} --dump out <br>
pufferrelay -r --dump out <br>

The pack contains `ips.txt`, `subnets.txt`, `users.txt`, `hosts.tsv`,
`nmap-targets.txt`, `nmap-command.txt`, `credentials.csv`, `ntlm-hashes.txt`,
`kerberoast-hashes.txt`, `dns.txt`, `asrepcatcher.txt`, `tokens.tsv`,
`coercions.tsv`, `adcs.tsv`, `ipv6.tsv`, `db-creds.tsv`, `sccm.tsv`, `llm.tsv`,
`kerberos-signals.tsv`, `ldap-spns.tsv`, `ldap-signing.tsv`, `ldap-adcs.tsv`,
`voip.tsv`, `media.tsv`, `rdp.tsv`, `cloud-apis.tsv`, `fingerprints.tsv`,
`credential-matrix.tsv`, `identity-graph.json`, `summary.json`, and the agent feed: `leads.json` + `leads.md` (every lead with
its evidence, suggested next actions, and explicit warnings for anything that
sends traffic). See [docs/OUTPUTS.md](docs/OUTPUTS.md) and
[docs/PLAN.md](docs/PLAN.md).

#### Config file (optional)
pufferrelay --config config.json -f {filename} <br>
# config.json: db_path, output_dir, default_pcap, log_level
# `--dump` without a directory uses output_dir; default_pcap is used when
# -f/-q is omitted.

#### Auto profile, scale, report and diff
```bash
pufferrelay -f capture.pcapng --auto --dump out       # only relevant handlers
pufferrelay -f capture.pcapng --auto --jobs 4         # parallel passes
pufferrelay -f big.pcapng --chunk-packets 200000      # chunked, resumable
pufferrelay -f capture.pcapng --report out/report.html # Markdown or HTML
pufferrelay -r --diff old.db                          # new hosts/users/leads
pufferrelay -f capture.pcapng --report out/report.md   # confidential deliverable
pufferrelay -r --triage --triage-model llama3          # loopback Ollama only
pufferrelay --detections                               # detection catalog
```
`--triage` refuses non-loopback URLs and sends only lead metadata, never
credentials, hashes, commands or packet data.

#### Query the database
pufferrelay -r --json <br>
pufferrelay -r --creds <br>
pufferrelay -r --inventory <br>
pufferrelay -r --protocol ftp,ntlm <br>
pufferrelay -r --ip 10.0.0.5 <br>
pufferrelay -r --user alice --has-creds <br>
pufferrelay -r --table dns_events --limit 100 <br>

#### Active modes (opt-in — these send packets)
Every active mode prints a red warning and requires you to type `authorized`
(or pass `--confirm-authorized` when you already have written scope).
```bash
# Live capture, analysed like a pcap, temp file deleted afterwards
pufferrelay --live eth0 --bpf "port 445" --duration 120

# Local TCP relay to one target, both directions recorded as JSONL
pufferrelay --proxy --proxy-target 10.0.0.10:445 --duration 60

# Text-only generators (nothing is executed)
pufferrelay -f capture.pcap --commands --serveme --dump out
```
`--commands` writes `active-commands.md` (ARP spoof / relay commands with
cleanup); `--serveme` writes `serveme.md` (next-step command per host and
finding). `--keep-live-capture` keeps the temporary live capture.

### Documentation
Documentation lives in <a href="wiki/README.md">wiki/</a> (source for the GitBook: install, features, protocols, outputs, performance, privacy, FAQ).

---

## 🤝 Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Licensed under the [GPL-3.0 License](LICENSE).  
See the [NOTICE](NOTICE) file for attribution details.
