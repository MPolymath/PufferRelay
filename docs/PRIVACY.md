# PRIVACY — client captures never leave the machine

PufferRelay is often pointed at traffic captured on a client's network. Those
captures contain credentials, password hashes, internal hostnames, and personal
data. Treat every `.pcap`/`.pcapng` — and every database, export, log or report
derived from it — as **client confidential material**.

## Absolute rules

1. **Never upload or paste capture data into anything online.** That includes
   AI/LLM services (OpenAI, Anthropic, local-vs-remote chat tools), pastebins,
   issue trackers, GitHub, cloud notebooks, web converters, VirusTotal-style
   services, and email. "Just a snippet" is still client data.
2. **Never commit capture artefacts.** `.pcap`, `.pcapng`, `extracted_data.db`,
   `out/`, logs, hashes, credential files and reports containing real values
   are excluded by `.gitignore` and must never be force-added.
3. **Do not copy values into code, tests, docs, tickets or chat.** When testing
   a feature against a client capture, report only aggregates: number of rows,
   protocol coverage, timing, whether a parser matched. Never print usernames,
   passwords, hashes, hostnames, IPs, MACs or file contents.
4. **Keep test runs in temporary directories.** Use `scripts/local_smoke.py`
   (prints counts only) or a `TemporaryDirectory`; delete outputs afterwards.
5. **Sanitise before sharing.** If a bug report needs evidence, replace every
   value with a synthetic equivalent and state that it was sanitised.
6. **Client captures stay on the engagement machine.** Copy them into the
   working area only for the duration of the test and remove them afterwards if
   the engagement rules require it.

## How to test a feature against a real capture safely

```bash
# aggregate only: handler row counts, table counts, lead counts by severity
PYTHONPATH=. python scripts/local_smoke.py /path/to/client-capture.pcapng

# restrict to the protocol you are working on
PYTHONPATH=. python scripts/local_smoke.py capture.pcapng --only smb
```

`local_smoke.py` never prints field values. Do not replace it with
`pufferrelay -r` or `--dump` while a client capture is loaded unless you are
inspecting the output yourself on the client machine; `--dump` writes the raw
values by design.

## Repository hygiene

- `.gitignore` blocks `*.pcap`, `*.pcapng`, `*.cap`, `*.db`, `logs/`, `out/`.
- `extracted_data.db` and log files must stay untracked.
- CI must never download captures; tests generate synthetic traffic with scapy
  (see `PufferRelay/tests/test_e2e_pcap.py`).
