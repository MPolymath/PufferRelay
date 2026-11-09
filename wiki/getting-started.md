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

## Config file (optional)

`pufferrelay` reads a JSON config from `--config FILE`, `PUFFERRELAY_CONFIG`,
`%APPDATA%\pufferrelay\config.json` (Windows) or
`~/.config/pufferrelay/config.json`:

```json
{
  "db_path": "/engagements/acme/extracted.db",
  "output_dir": "/engagements/acme/exports",
  "default_pcap": "/engagements/acme/capture.pcapng",
  "log_level": "INFO"
}
```

- `default_pcap` is used when you omit `-f`/`-q`; a missing file is an error.
- `--dump` without a directory writes to `output_dir`.
- `--db PATH` and `--log-level` override the file; environment variables
  (`PUFFERRELAY_DB`, `PUFFERRELAY_OUTPUT_DIR`, `PUFFERRELAY_LOG_LEVEL`,
  `PUFFERRELAY_DEFAULT_PCAP`) override the file too.
- Invalid JSON or values stop the run with a clear `config error:` message.

## Flags you will actually use

| Flag | Why |
|---|---|
| `-f FILE` | parse a capture into the database |
| `-q FILE` | quick-win scan; add `-f FILE -q` to combine |
| `-r` | read the database from the current directory |
| `--dump [DIR]` | write every finding plus `leads.json`/`leads.md` (DIR defaults to `output_dir`) |
| `--only ftp,http,ntlm` | run only selected handlers (faster) |
| `--credentials-only` | only handlers that can yield users/credentials |
| `--json` / `--creds` / `--inventory` | machine output for pipes |
| `--protocol ftp,ntlm` | raw rows for a protocol from the database |
| `--config FILE` / `--db PATH` | JSON config file and database override |

## What to look at first

1. `leads.md` — ranked findings with evidence and next actions.
2. `credentials.csv` and `ntlm-hashes.txt` / `asrep-hashes.txt`.
3. `nmap-targets.txt` and `hosts.tsv`.
4. `bloodhound/` if the capture is AD-heavy.

Every suggested command that sends traffic is marked **ACTIVE**; confirm scope
before running it.
