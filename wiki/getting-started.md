# Getting started

PufferRelay reads a `.pcap`/`.pcapng` that you already captured and turns it
into credentials, identities, hosts, vulnerable services and an agent-ready
lead briefing. **It never sends traffic itself.**

New here? Read [CHEATSHEET.md](CHEATSHEET.md) first, then
[decision-guide.md](decision-guide.md). The per-detection catalog is
[DETECTIONS.md](DETECTIONS.md).

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
| `--ip ADDRESS` / `--user NAME` | only rows touching an IP / identity |
| `--has-creds` | only rows carrying a credential or hash |
| `--table NAME` / `--limit N` | raw table dump, capped per table |
| `--live IFACE --bpf FILTER` | **ACTIVE** live capture, analysed then deleted |
| `--proxy --proxy-target HOST:PORT` | **ACTIVE** local TCP relay, JSONL recording |
| `--commands` / `--serveme` | text-only command generators (nothing executed) |
| `--auto` | profile the capture's services and run only the relevant handlers |
| `--report [FILE]` | Markdown or HTML engagement report (default `output_dir/report.md`) |
| `--diff DB` | compare with another database and write `diff.md` |
| `--triage` | rank leads with a **loopback-only** Ollama model (off by default) |
| `--config FILE` / `--db PATH` | JSON config file and database override |

Active modes print a red warning and require `authorized` (or
`--confirm-authorized` with written scope). See [features.md](features.md).

## What to look at first

1. `leads.md` — ranked findings with evidence and next actions.
2. `credentials.csv`, `tokens.tsv`, `db-creds.tsv`.
3. `ntlm-hashes.txt`, `asrep-hashes.txt`, `kerberoast-hashes.txt`.
4. `relays.tsv`, `coercions.tsv`, `adcs.tsv`, `sccm.tsv`, `ipv6.tsv`.
5. `nmap-targets.txt`, `hosts.tsv`, `dns.txt`.
6. `bloodhound/` if the capture is AD-heavy; `files/` for carved objects.

Every suggested command that sends traffic is marked **ACTIVE**; confirm scope
before running it.
