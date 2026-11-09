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
`summary.json`, and the agent feed: `leads.json` + `leads.md` (every lead with
its evidence, suggested next actions, and explicit warnings for anything that
sends traffic). See [docs/OUTPUTS.md](docs/OUTPUTS.md) and
[docs/PLAN.md](docs/PLAN.md).

#### Query the database
pufferrelay -r --json <br>
pufferrelay -r --creds <br>
pufferrelay -r --inventory <br>

### Documentation
The <a href="https://mpolymath.gitbook.io/pufferrelay">Wiki</a> is under construction but will be available soon !

---

## 🤝 Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Licensed under the [GPL-3.0 License](LICENSE).  
See the [NOTICE](NOTICE) file for attribution details.
