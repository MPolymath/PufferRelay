# PLAN — issue triage and ROI order

Every idea the operator filed as a GitHub issue is listed here exactly once.
Order = **expected return on investment for finding a critical vulnerability
quickly from a passive capture**. "ROI" is judged on: does it produce an
actionable target/credential, does it multiply the value of data we already
have, and how cheap is it to build and trust.

Risk classes:
- **P** — passive: reads the pcap only.
- **N** — network: sends traffic or launches actions; must follow AGENTS.md §2
  (off by default, explicit flag, red warning, never auto-run).

Status legend: `[ ]` to do · `[~]` in progress · `[x]` done.

---

## Tier S — force multipliers and direct critical findings (build first)

| # | Issue | What we build | Why it pays off first | Risk | Acceptance |
|---|---|---|---|---|---|
| 63 | Agent-ready lead export (`leads.json` + `leads.md`) | A ranked, evidence-backed briefing an AI agent can consume to recommend or drive the next pentest step; commands that send traffic are marked ACTIVE with scope warnings | This is the hand-off layer: every other feature becomes an input to the agent, multiplying its value | P | pack contains ranked leads with evidence and actions; schema stable; tests on fixtures |
| 48 | Extract by protocol / credentials only | `--only proto1,proto2`, `--credentials-only`, `--hashes-only` filters that skip handlers and shrink the parse set | Biggest lever on "time to first finding": run only what matters, on huge captures | P | filtered run produces the same rows as a full run for that protocol; timing improves |
| 42 | `-d` dump of all interesting info | `--dump DIR` writing every finding to files | Turns the DB into artifacts a human can move between tools | P | `dump/` contains stable files; no ANSI; re-runnable |
| 58 | Grepable copy-paste subnets | `--export DIR` with `ips.txt`, `subnets.txt`, `nmap-targets.txt`, `users.txt` | Copy/paste is how pentesters work; zero friction to the next tool | P | files are line-oriented, deduped, stable order |
| 40 | Database query options | `--protocol`, `--ip`, `--user`, `--has-creds`, `--table` on `-r` | Ask the capture a question instead of scrolling tables | P | combinations filter correctly; `--json` variant |
| 54 | Nmap targets from dst IP/port + service | `nmap-targets.txt` + `nmap` command block (IP + ports + guessed service) | Immediately actionable recon list | P | one line per host; ports deduped; service names resolved |
| 12 | Usernames from every pcap | `users.txt` aggregating LDAP/SMTP/IMAP/POP3/FTP/HTTP/Telnet/NTLM identities, with `DOMAIN\user` when known | Usernames = spraying and AS-REP targets; highest-value passive identity signal | P | union across tables, no duplicates, source protocol kept |
| 11 / 59 | IP list for DNS resolution + subnet DNS | `hosts.txt` (IP, hostnames seen), `dns.txt` (queries/answers from pcap) and reverse-lookup command block | Network map without touching the network | P | DNS records parsed from pcap; names attached to IPs |
| 39 | Quick-win synthesis (improve) | Quick-wins table gains severity, evidence snippets, and "next command" hints | Existing feature is the fastest path to "what's weak here"; make it decisive | P | severity shown; evidence includes src/dst/pcap offset |
| 37 | Unique subnets with all IPs | `subnets.txt` with `/24` grouping + per-subnet IP lists (current code groups but display is flat) | Fast scoping of the capture | P | stable groups, sorted, counts |
| 43 | CI/CD + unit tests | `.github/workflows/ci.yml`, real pytest suite, synthetic pcap fixtures | Every later feature is only trustworthy if tests exist; also protects releases | P | CI runs pytest+black+compileall on push |

## Tier A — high-value analysis (passive, medium effort)

| # | Issue | What we build | Why | Risk | Acceptance |
|---|---|---|---|---|---|
| 61 | AS-REP roasting detection | Detect AS-REQ without pre-auth + matching AS-REP; emit hashcat `$krb5asrep$…` lines + `asrep.txt` | One hash = offline crack to a domain account; passive gold in AD captures | P | hashes formatted for hashcat; username/realm resolved; fixture test |
| 62 | Relay scenario enumeration | From SMB/LDAP/HTTP NTLM traffic: list confirmed relay paths (WebDAV→SMB, HTTP→SMB, SMB→LDAP) with signing status of the destination | Relay = immediate domain compromise when signing is off; the pcap already proves the auth flow | P | per-scenario table with src, dst, protocol, signing state |
| 44 | SMB extraction | SMB1/2/3 session users, tree connects (shares), accessed files, signing flags, SMBv1 presence | Shares + signing + users are the lateral-movement map | P | rows in DB, `smb.txt` export, signing shown in quick wins |
| 30 | NAC / EAP detection (passive half only) | Detect 802.1X/EAP and MAB in the capture, list supplicants and authenticators; **spoof suggestions are Tier B** | Tells you whether the port is defended before you touch it | P (spoof = N) | EAP identities extracted; no packets sent |
| 57 | File extraction from pcap | Carve objects from HTTP/SMB/FTP streams into `files/` with hashes (`pcapfex`-style, pure python/tshark export) | Documents, configs, keys found in transit are often the critical finding | P | files written with sha256 + source tuple; size caps |
| 15 | BloodHound support | Export users/computers/sessions observed in the pcap as BloodHound-compatible JSON (`users.json`, `computers.json`, `sessions.json`) | Feeds the standard AD attack-path tool with passive data | P | JSON loads in BloodHound CE import; documented limitations |
| 14 | HTTP WSUS detection | Flag WSUS/HTTP update traffic and the WSUS server URL | WSUS abuse (e.g., malicious update) is a known escalation path | P | detection + endpoint list |
| 55 | Parsing speed | Single-pass per protocol (or one tshark export per protocol), remove `debug=True`, avoid regex over full packet text | Big captures are the norm; slow tools don't get used | P | wall-clock improvement measured on a fixture |
| 45 | Timer/countdown | Estimate remaining time from file size/packet count during parse | Trust and UX on long runs | P | ETA shown; no false "done" |
| 52 | Remove debug output | Silence pyshark/tshark debug chatter unless `--log-level DEBUG` | Console noise hides findings | P | default run prints only results |
| 53 | Handler refactor | Shared capture helper, drop impossible filters (IMAP `authenticate`), consistent field access | Fewer bugs, less code | P | handlers share one helper; tests unchanged |
| 46 | Document what each protocol looks for | `docs/PROTOCOLS.md` + README table | Operators must know what "nothing found" means | P | one section per protocol with fields/flags |
| 19 | Config file with error handling | `~/.config/pufferrelay/config.toml` (or `.env`) for DB path/log level; clear error if missing/broken | QoL; avoids cwd DB surprises | P | config loaded or actionable error |

## Tier B — valuable but active/network or heavy (opt-in with warnings)

| # | Issue | What we build | Why later | Risk | Gate |
|---|---|---|---|---|---|
| 27 | Live capture (PCredz-style) | `--live IFACE` feeding the same pipeline | Requires a NIC and sends nothing, but touches the live network stack and captures other people's traffic | N (capture) | explicit `--live`, red warning, BPF filter required |
| 16 | Live proxy (audit-proxyshark) | Proxy mode for live capture modification | Actively intercepts/modifies traffic | N | explicit flag, warning, scope confirmation prompt |
| 13 | ARP poisoning command generator | Generate (not run) arp spoof commands for DNS/gateway/DC | Commands are passive text, but the operator will run them | N (advice) | `--generate-commands` prints red warning + target scope |
| 60 | Serveme mode | Suggest next commands (httpx, nmap, netexec, manspider) from findings | Suggestions are passive; executing them is not | P (suggest) / N (exec) | suggestions only; any `--run` needs per-command confirmation + warning |
| 30 | NAC/IP spoof proposals | Propose IP+MAC combos from broadcast traffic; exception-device list | Proposal is passive; use is active | N (use) | separate command, warning, no auto-apply |
| 17 | VoIP Skinny calls | Extract call metadata from Skinny/SCCP | Passive but niche | P | fixture test |
| 23 / 24 | Video / audio extraction | Carve media from streams | Passive but heavy; low vuln ROI | P | size caps, `files/` output |
| 51 | Ollama LLM triage | Local LLM summarises HTTP findings | Experimental; needs a model; privacy of capture data | P (local) | off by default, model URL config, no data leaves localhost |
| 21 / 22 | GitBook docs + getting started | Docs site | Important for adoption, not for findings | P | link in README |
| 10 | Long-term plan | This document + `docs/BACKLOG.md` | Meta | P | kept current |

---

## The 2-hour milestone (this session)

1. Branch `dev-feature` from `dev` and push. (done)
2. Notes for agents (`AGENTS.md`) and this plan. (done)
3. Tier S foundation:
   - `PufferRelay/export.py`: pure formatters + writers for `leads.json`,
     `leads.md` (the agent feed, issue #63), `ips.txt`,
     `subnets.txt`, `users.txt`, `hosts.txt`, `nmap-targets.txt`,
     `credentials.csv`, `ntlm-hashes.txt`, `quickwins.md`, `summary.json`.
   - CLI: `--dump DIR`, `--only`, `--credentials-only`, `--json`, query
     filters on `-r`.
   - Inventory queries in `db_queries.py` (users, hosts, ports, services).
   - Nmap target builder with a curated port→service map.
4. Fix the NetBIOS schema mismatch (data is currently lost) and add real tests
   (`pytest`, temp DB; synthetic pcap where tshark is available).
5. CI workflow (#43).
6. README + `docs/OUTPUTS.md` + progress notes.

Everything else follows the table above; do Tier S completely before Tier A.

## Progress log — 2026-11-09 (`dev-feature`)

| Commit | What landed |
|---|---|
| `ad4cf9d` | AGENTS.md, this plan, export pack + `leads.json`/`leads.md`, CLI filters, observed services, schema v3, NetBIOS repair, tests, CI |
| `e0376cf` | commit-message fix (no functional change) |
| `ec690e9` | `-r --protocol` raw views; briefing hints when no quick-win scan exists |
| `3b7101c` | `agent-prompt.md` (ready-to-paste agent instructions) |
| `13e2726` | CLI subprocess test; UTF-8 stdio so redirected output does not crash |
| `3f1a7d9` | #61 AS-REP roasting detection (hashcat 18200, `asrep-hashes.txt`, ASREP leads) |
| `03ca4c9` | #62 relay scenarios (SMB2 signing flags + NTLM over SMB/LDAP/HTTP, `relay-targets.txt`, RELAY leads) |
| `1b0d7c8` | relay signing findings feed the SMB_SIGNING_MISSING quick win |
| `3c9c7d8` | capture-confidentiality rules (`docs/PRIVACY.md`) + local-only smoke script |
| `e885117` | #44 SMB shares/files + NTLM-inside-SMB relay fallback |
| `bb5609c` | #57 file carving from HTTP/FTP |
| `d6b6442` | #55 parsing speed: tshark field extraction, 6.7x parse / 159x quick wins |
| `29baabf` | #15 BloodHound Legacy JSON export from observed identities/sessions |
| `14d9e95` | #39 quick-win severity + evidence in DB and lead feed |
| `9848b43` | wiki/ source pages; #30 NAC/802.1X and #14 WSUS detection |
| `b48a82a` | #45 ETA/countdown and #19 JSON config with CLI/env overrides |
| (this commit) | #53 cleanup: legacy pyshark handlers removed, helpers module |

Test status: 26 pytest tests passing locally and in CI (tshark installed),
including a synthetic-pcap end-to-end and a CLI subprocess test. Every feature
above is passive; the only active commands are text suggestions in leads,
flagged `active: true` with scope warnings.
