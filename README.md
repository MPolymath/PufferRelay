![Image Alt text](Logos/Puffer1.webp "Optional title")

# PufferRelay

**PufferRelay** is a pentesting tool designed to extract valuable information from `.pcap` (Wireshark) files.  
It focuses on parsing and analyzing network traffic to surface sensitive or actionable data that may aid in offensive security operations.

---

## 🔍 Features

- Extracts protocol-specific data (LDAP, HTTP, FTP, etc.)
- Parses `.pcap` files and stores data in a queryable SQL format
- Designed for use in red teaming and network traffic analysis
- Modular structure for easy extension

---

## 🚀 Getting Started

### Install
python3 -m venv venv
source venv/bin/activate.fish
pip3 install -r requirements.txt

### Usage
python3 -m PufferRelay -f {filename}

---

## 🤝 Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Licensed under the [Apache License 2.0](LICENSE).  
See the [NOTICE](NOTICE) file for attribution details.
