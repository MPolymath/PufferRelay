# AGENTS.md — PufferRelay working contract

Read this before touching code. It is the shared brain for every agent that
works on this repository. `docs/PLAN.md` holds the feature plan (ROI order) and
the mapping from GitHub issues to work items.

## 1. What this tool is

PufferRelay turns **Wireshark captures into exploitation leads**. It reads a
`.pcap`, extracts credentials, identities, hosts and protocol facts with
tshark/pyshark, stores them in SQLite (`extracted_data.db`), and prints Rich
tables plus **copy-paste / file-transfer friendly exports**.

Primary user: a pentester who captured traffic passively (span port, tap,
mirror) and now wants to know *what can I attack next, with what command*.

## 2. Non-negotiables

1. **Passive by default.** Everything works from a `.pcap`. No packet is ever
   sent, no interface is opened, no command is executed against a target,
   unless the operator explicitly opts in.
2. **Network actions are opt-in and warned.** Any feature that could touch a
   network (live capture, proxy, ARP spoofing, active probes, "serveme"
   command execution) must:
   - be off by default and require an explicit flag,
   - print a conspicuous warning (Rich panel, red) that states what will be
     sent, to whom, and that it is active traffic,
   - be listed in `docs/PLAN.md` under Tier B with its risk.

   Implemented Tier B surface: `live.py` (`--live IFACE --bpf FILTER`,
   `--duration`, `--confirm-authorized`, `--keep-live-capture`), `proxy.py`
   (`--proxy --proxy-target HOST:PORT`), and the text-only generators
   `commands.py` (`--commands`, `--serveme`). The first two print the red
   warning and then require `authorized` interactively (or
   `--confirm-authorized`); the generators only write files and never execute
   anything. Keep this contract when adding new active flags.
3. **Outputs must be portable.** Every finding is available as:
   - a stable, plain-text/CSV/JSON file (no ANSI, no wrapping),
   - a one-screen copy-paste block (commands or values),
   - a Rich table for humans.
   Never bury a value only in the console.
4. **Traceability.** Every row keeps `source_ip` and `destination_ip` (and
   protocol fields) so the report can say where it came from.
5. **No silent failures.** Parsing errors are logged with protocol + packet
   context; a handler that finds nothing says so explicitly.
6. **Capture confidentiality.** Client `.pcap`/`.pcapng` files and anything
   derived from them (databases, exports, hashes, credentials, reports) never
   leave the machine and are never uploaded, pasted into online services or AI
   tools, or committed. Test locally with `scripts/local_smoke.py`, which prints
   aggregate counts only. Full rules: `docs/PRIVACY.md`.
7. **Schema is versioned.** `PufferRelay/database/db_version.py` owns the
   version. Any table/column change bumps it and ships a migration path or a
   clear "delete the old DB" message.
8. **Check the attack library before feature work.** On the first tool session
   of a day, run `python scripts/library.py update` and
   `python scripts/library.py new --tag <relevant tags>` in
   `C:\Users\33695\Documents\Projects\Python\GIT\attack-library`
   (PufferRelay tags: active-directory, kerberos, ntlm, ldap, smb, dns,
   network, web, llm-ai, ci-supply-chain). Park non-ROI articles with
   `mark --tag`; only incorporate what the capture can actually prove.

## 3. Architecture map

```
PufferRelay/
  __main__.py            CLI: -f pcap, -r read, -q quick wins, --log-level
  config.py              DB_NAME, logging paths (cwd based)
  core_imports.py        single import surface (pyshark, rich, sqlite3, ...)
  pcap_processing/
    pcap_parser.py       handler registry + --only/--credentials-only filters
  tshark_fields.py       one-pass `tshark -T fields` extraction (fast path)
  live.py                #27 live capture (opt-in, warned in __main__)
  proxy.py               #16 local TCP relay + JSONL recording (opt-in)
  commands.py            #13/#60 text-only command generators
  export.py              inventories + leads.json/leads.md/agent-prompt.md
  report.py              Markdown engagement report (secrets; local only)
  triage.py              optional loopback-only Ollama lead ranking
  protocols/
    fields_handlers.py   field-based implementations of the protocol handlers
    helpers.py           shared HTTP/NetBIOS/SMB/relay/Kerberos logic
  protocols/
    __init__.py          exports every process_* handler
    nac_handler.py       EAP/RADIUS (802.1X/MAB) observations
    wsus_handler.py      WSUS/Windows Update endpoints
    dns_handler.py       DNS queries/answers (name↔IP map)
    asrepcatcher.py      ASRepCatcher-compatible ARP/Kerberos pattern
    kerberoast.py        TGS-REP DER walk + hashcat lines
    http_tokens.py       bearer/JWT/API tokens (fingerprinted)
    coercion.py          MS-EFSRPC/RPRN/DFSNM/FSRVP coercion calls
    adcs.py              ADCS enrollment + PKINIT
    ipv6_adidns.py       DHCPv6/RA DNS takeover + ADIDNS updates
    database_auth.py     Redis/MySQL/PostgreSQL auth material
    smb_objects.py       tshark SMB object export -> captured_files
    sccm.py              SCCM/MECM management and distribution traffic
    llm_traffic.py       LLM/MCP/vector-DB endpoints and tool calls
    kerberos_shared.py   one cached Kerberos/ARP pass for four handlers
    kerberos_depth.py    S4U, delegation flags, UnPAC chains
    ldapdir.py           SPN -> account and objectSID from LDAP results
    voip.py              SIP and Skinny/SCCP call metadata
    quick_wins.py        regex sweep over every packet for "quick win" flags
  database/
    db_models.py         CREATE TABLE IF NOT EXISTS + quick_wins seed
    db_queries.py        insert/store/fetch/display, quick-wins helpers
    db_version.py        schema version + check
  utils/
    display.py           Rich tables/panels
    loading_animation.py spinner + READY banner
  tests/                 pytest suite (124 tests: pure, DB, e2e pcap, CLI, relay)
```

Data flow: `parse_pcap()` -> `{protocol: [(...)...]}` ->
`process_extracted_data()` -> `insert_into_database()` -> tables ->
`fetch_all_data()` / `fetch_requests()` -> Rich tables.

## 4. Code standards

- Python 3.8+, stdlib first; `rich` for UI, `pyshark` for capture access.
- Handlers return **lists of tuples**, never print. Display lives in
  `utils/display.py` and `db_queries.py`.
- Keep pyshark field access defensive (`packet.http.get(...)`), skip packets
  missing fields, never let one packet kill a run.
- Pure helpers (formatters, parsers, exporters) go in modules importable
  without tshark so they can be unit-tested.
- Line length 100, `black` formatting, no new heavyweight dependencies without
  a note in `docs/PLAN.md`.
- Every new CLI flag is documented in README and `docs/OUTPUTS.md`.

## 5. Testing (mandatory)

- `pytest` for: pure helpers, DB round-trips (temp sqlite), export formats,
  and at least one **end-to-end pcap** test when a synthetic capture can be
  generated (scapy) or a fixture exists.
- A handler without a fixture gets a unit test on its parsing helper, not a
  "tested by hand" claim.
- CI (`.github/workflows/ci.yml`) runs `pytest`, `compileall` and
  `python scripts/build_wiki.py --check`.
- Never commit pcaps > a few hundred KB; generate them in tests.

## 6. Definition of done (per feature)

1. CLI flag / automatic detection implemented, passive.
2. Data stored (new table or column) with `INSERT OR IGNORE` semantics.
3. Export (file + copy-paste block) produced.
4. `pytest` tests pass; CI green.
5. `wiki/detections.yaml` entry added/updated, `python scripts/build_wiki.py`
   run (it regenerates `DETECTIONS.md` + `CHEATSHEET.md`), plus README,
   `docs/OUTPUTS.md` and `docs/PLAN.md` status.
6. If it touches the network: Tier B rules from §2 are followed.

## 7. Wiki knowledge (source of truth)

- `wiki/detections.yaml` is the only place detection knowledge is added. One
  entry per handler (active modes and quick wins are separate entries); the
  generator fails on missing/duplicate/unknown handlers.
- Required fields: `id, class, handler, mode, when, detects, proves, limits,
  fields, output, severity, next, status`. `proves` and `limits` are distinct
  and mandatory; a candidate-only detection uses `status: partial`.
- Run `python scripts/build_wiki.py` after editing. Never hand-edit
  `wiki/DETECTIONS.md` or `wiki/CHEATSHEET.md`; CI runs `--check` and fails on
  stale pages.
- `when` must be observable in a capture; `output` must name the real file and
  lead prefix from `export.py`; active entries must state warning/authorization.
- Add a `references` URL when the technique came from an article (the
  attack-library repo is the source list). Read `wiki/intake.md` first.
- Rule of thumb: if a detection cannot say what it proves and what it misses,
  it is not ready to be in the tool.

## 8. Known gaps

- A default full run starts 33 tshark passes for 31 handlers; the Kerberos
  family is shared, and `--only`/`--credentials-only` remain the large-capture
  lever. `scripts/benchmark.py` reports the pass count.
- ADCS DCOM-only enrollment, SCCM provider DCOM and MySQL native/SCRAM hash
  modes are not fully parsed; their catalog entries are `partial`. Encrypted
  SMB3 objects cannot be carved.
- LDAP attribute/value pairing is positional; objectSID and SPN mapping can be
  confused by commas or split searchResultEntry packets.
- `--triage` requires a local Ollama model and is loopback-only by design;
  `report.md` contains real secrets and is a confidential artifact.
- Media is carved when it travels over HTTP/FTP/SMB; RTP/SRTP media is not
  decoded. SIP/Skinny signalling is decoded, not the calls themselves.
- CI runs on Linux with the distro tshark only; Windows/macOS tshark versions
  are not in the matrix.
- GitBook is prepared (`.gitbook.yaml` + `wiki/SUMMARY.md`); publishing needs
  the GitBook space credentials/decision.
- `--read` with no `-f` still creates the DB in cwd; document/guard.

## 8. Documentation surfaces

- `wiki/` is the GitBook source (getting started, features, protocols, outputs,
  performance, privacy, FAQ). Update it with every user-visible change.
- `docs/PLAN.md` is the issue triage; `docs/OUTPUTS.md` the export contract;
  `docs/PRIVACY.md` the capture rules.

## 9. Where the ideas live

All requested features are GitHub issues on `MPolymath/PufferRelay`.
`docs/PLAN.md` maps every issue to a work item, an ROI tier, a risk class
(passive / network) and an acceptance test. When you implement one, tick it
there and in `docs/BACKLOG.md`.
