# Getting started

PufferRelay reads a `.pcap`/`.pcapng` that you already captured and turns it
into credentials, identities, hosts, vulnerable services and an agent-ready
lead briefing. **It never sends traffic itself.**

## Install

```bash
sudo apt install tshark
pipx install pufferrelay
# or from a checkout:
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## First run

```bash
# parse + display
pufferrelay -f capture.pcapng

# parse + write the export pack and the agent feed
pufferrelay -f capture.pcapng --dump out

# quick-win scan (protocols, weak versions, cleartext credentials)
pufferrelay -q capture.pcapng --dump out

# read an existing database
pufferrelay -r
pufferrelay -r --json
```

## Flags you will actually use

| Flag | Why |
|---|---|
| `-f FILE` | parse a capture into the database |
| `-q FILE` | quick-win scan; add `-f FILE -q` to combine |
| `-r` | read the database from the current directory |
| `--dump DIR` | write every finding plus `leads.json`/`leads.md` |
| `--only ftp,http,ntlm` | run only selected handlers (faster) |
| `--credentials-only` | only handlers that can yield users/credentials |
| `--json` / `--creds` / `--inventory` | machine output for pipes |
| `--protocol ftp,ntlm` | raw rows for a protocol from the database |

## What to look at first

1. `leads.md` — ranked findings with evidence and next actions.
2. `credentials.csv` and `ntlm-hashes.txt` / `asrep-hashes.txt`.
3. `nmap-targets.txt` and `hosts.tsv`.
4. `bloodhound/` if the capture is AD-heavy.

Every suggested command that sends traffic is marked **ACTIVE**; confirm scope
before running it.
