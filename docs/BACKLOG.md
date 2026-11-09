# BACKLOG — status of the plan

The authoritative, ROI-ordered plan is `docs/PLAN.md`. This file is the short
status board.

## Done on `dev-feature`

- [x] Branch created from `dev` (issue tracking unchanged).
- [x] `AGENTS.md` — working contract for agents.
- [x] `docs/PLAN.md` — every issue triaged, ROI tiers, risk classes.
- [x] `docs/OUTPUTS.md` — export pack + agent feed schema (#42, #58, #63).
- [x] `PufferRelay/export.py` — inventories, nmap targets, credentials/hashes,
      `leads.json` + `leads.md` agent briefing + `agent-prompt.md` (#42, #54,
      #58, #63).
- [x] CLI: `--dump`, `--only`, `--credentials-only`, `--json`, `--creds`,
      `--inventory` (#48, #40 partial).
- [x] Observed services handler + `observed_services` table (#54).
- [x] Schema v3 migration; fixed the NetBIOS column mismatch (data was lost).
- [x] Real test suite (14 tests) + synthetic-pcap end-to-end test (#43).
- [x] CI workflow: tshark install, compileall, pytest (#43).
- [x] Fixed `utils/display.py` syntax error, silenced pyshark debug in
      `ip_handler` (#52, #55 partial).

## Next (ROI order from PLAN.md)

- [x] #11/#59 DNS extraction (`dns_events`, `dns.txt`, A/AAAA/PTR name↔IP map,
      host inventory enrichment).
- [x] #40 query filters: `-r --ip`, `--user`, `--has-creds`, `--table`,
      `--limit` (tables that cannot satisfy a filter are skipped).
- [x] ASRepCatcher-compatible detection: ARP spoofing + relayed AS-REQ /
  diverted crackable AS-REP; critical when both overlap; leads and
  `asrepcatcher.txt` link <https://github.com/Yaxxine7/ASRepCatcher>.

### Detections from the attack library (issues #64-#71)

Issue bodies: `../attack-library/pufferrelay-issues/` (filed as #64-#71).

- [x] #64 Kerberoasting: TGS-REP DER walk + hashcat 13100/19600/19700, plus
      burst candidates (`kerberoast-hashes.txt`, `KERBEROAST-*`).
- [x] #65 RPC coercion: MS-EFSRPC / MS-RPRN / MS-DFSNM / MS-FSRVP binds and
      UNC extraction (`coercions.tsv`, `COERCE-*`).
- [x] #66 DHCPv6 / IPv6 RA takeover and ADIDNS dynamic updates
      (`ipv6.tsv`, `IPV6-*`, combined critical finding).
- [x] #67 ADCS enrollment (HTTP `/certsrv`, NTLM) and PKINIT AS-REQ
      (`adcs.tsv`, `ADCS-*`).
- [ ] #68 SCCM/MECM management-point, distribution-point and client-push traffic.
- [x] #69 Database auth material: Redis cleartext, MySQL response, PostgreSQL
      parameters/password (`db-creds.tsv`, `DB-*`).
- [x] #70 HTTP bearer/JWT/API tokens (Vault, GitLab, GitHub, AWS) with
      fingerprint-only exports (`tokens.tsv`, `TOKEN-*`).
- [ ] #71 LLM/MCP/vector-DB endpoints, API keys and tool-call metadata.
- [x] #57 extension: SMB object carving via tshark `--export-objects`, feeding
      `captured_files` with sha256 and size caps.
- [x] #61 AS-REP roasting detection (AS-REQ without PA-ENC-TIMESTAMP ->
      AS-REP -> hashcat 18200; `asrep-hashes.txt`, ASREP leads).
- [x] #62 relay scenario enumeration (SMB NEGOTIATE signing flags + NTLM
      over SMB/LDAP/HTTP; relay-targets.txt + RELAY leads).
- [x] #44 SMB extraction (shares, file names, printer shares; schema v6).
- [x] #57 file carving from HTTP responses and FTP-DATA (schema v7,
      `files/` + `files.tsv`); SMB content carving is future work.
- [x] #15 BloodHound Legacy JSON export (users/computers/sessions observed;
      deterministic UUID identifiers; no SIDs/ACLs — documented in
      `bloodhound/README.txt`).
- [x] #39 quick-win severity + evidence: stored `severity`/`evidence`
      (counts + sample source/destination IPs) in the quick_wins table and
      surfaced in the lead feed; cleartext protocols with credentials are
      stored as critical.
- [x] Tier B (network actions) with warnings: #27 live capture, #16 local
      recording relay, #13 ARP/relay command generator, #60 serve-me
      suggestions. Every entry prints a red warning and needs explicit
      authorisation; `--commands`/`--serveme` are text only.
- [x] #53 cleanup: legacy pyshark handlers and their empty test shells removed;
      shared logic lives in `protocols/helpers.py`.

## Known gaps

- `local_smoke.py` needs native paths (`C:/...`) when invoked from Git Bash,
  otherwise tshark receives `/c/...` and matches nothing.
- `-r --protocol` prints raw rows; column-level filters are not implemented yet.
- The proxy relays one target at a time and records JSONL, not pcap; replay the
  JSONL through your own tooling if you need a capture file.
- ARP command generation infers the gateway as `.1` of the dominant /24; pass
  `--gateway` when that assumption is wrong.
