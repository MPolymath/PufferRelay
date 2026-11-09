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

- [x] #61 AS-REP roasting detection (AS-REQ without PA-ENC-TIMESTAMP ->
      AS-REP -> hashcat 18200; `asrep-hashes.txt`, ASREP leads).
- [x] #62 relay scenario enumeration (SMB NEGOTIATE signing flags + NTLM
      over SMB/LDAP/HTTP; relay-targets.txt + RELAY leads).
- [ ] #44 SMB extraction (shares, files, users, signing).
- [ ] #57 file carving from HTTP/SMB/FTP streams.
- [ ] #15 BloodHound JSON export from captured identities/sessions.
- [ ] #39 quick-win severity + evidence upgrade.
- [ ] Tier B (network actions) with warnings: #27, #16, #13, #60.

## Known gaps

- Quick-win scan (`-q`) still regexes every packet; move to targeted tshark
  filters (#55).
- `-r --protocol` prints raw rows; column-level filters are not implemented yet.
- No live capture; by design until Tier B with warnings.
