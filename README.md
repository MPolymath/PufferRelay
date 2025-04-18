![Image Alt text](Logos/Puffer1.webp "Optional title")

# PufferRelay

**PufferRelay** is a pentesting tool designed to extract valuable information from `.pcap` (Wireshark) files.  
It focuses on parsing and analyzing network traffic to surface sensitive or actionable data that may aid in offensive security operations.

---

## 🔍 Features

- Extracts protocol-specific data
    - LDAP, HTTP, FTP, TELNET, SMTP, NETBIOS, NTLM
- Parses `.pcap` files and stores data in a queryable SQL format
- Designed for use in red teaming and network traffic analysis
- Modular structure for easy extension

---

## 🚀 Getting Started

### 🛠️ Install
============== PIPX =============
sudo apt install tshark
pipx install pufferrelay
============== PIPX =============

============== PIP ==============
python3 -m venv venv
source venv/bin/activate.fish
pip3 install -r requirements.txt
============== PIP ==============

### ▶️ Usage

#### Parse pcap file into sqlite3 database and display all pertinent information
============== PIPX =============
pufferrelay -f {filename}
============== PIPX =============

============== PIP ==============
python3 -m PufferRelay -f {filename}
============== PIP ==============

#### Read 'DB_NAME' database and extract all pertinent information
pufferrelay -r

### 🐛 DEBUG
pufferrelay -f {filename} --log-level DEBUG

### Documentation
The <a href="https://mpolymath.gitbook.io/pufferrelay">Wiki</a> is under construction but will be available soon !

---

## 🤝 Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Licensed under the [GPL-3.0 License](LICENSE).  
See the [NOTICE](NOTICE) file for attribution details.
