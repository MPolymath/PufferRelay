# FAQ and gotchas

**Does PufferRelay send traffic?**
Not by default. Analysis is read-only. Active modes (`--live`, `--proxy`) are
opt-in, print a red warning and require authorisation; `--commands`/`--serveme`
only write text. Leads may also *suggest* commands, marked `ACTIVE`.

**Why are there no SIDs in the BloodHound export?**
A capture does not contain directory objects. Users/computers get deterministic
UUIDs; import the files as leads, not as collected domain data.

**Why do some SMB file names not appear?**
Reads/writes reference FileIds. Names only appear when the capture includes the
tree-connect/create frames.

**Why did IMAP credentials show as `N/A` in an older version?**
tshark truncates `imap.request.password`; the handler now parses the LOGIN line
from the TCP payload.

**Why does `local_smoke.py` show zero rows for a protocol?**
Check the path style: from Git Bash pass `C:/...` (native path), otherwise
tshark receives `/c/...` and matches nothing. Also run with `--only` to confirm.

**Can I use it with live capture?**
Yes, deliberately: `--live IFACE --bpf "FILTER"` captures for `--duration`
seconds, prints a red warning, and requires you to type `authorized` (or pass
`--confirm-authorized` when you already have written scope). The capture goes
to a temporary file, is analysed like any pcap, and is deleted afterwards;
`--keep-live-capture` keeps it. There is no implicit capture: an interface and a
BPF filter are mandatory.

**What about the relay and ARP features?**
`--proxy --proxy-target HOST:PORT` runs a local TCP relay and records both
directions to JSONL, with the same warning and confirmation. `--commands` and
`--serveme` only *write text* (`active-commands.md`, `serveme.md`); nothing is
executed. Every generated line is marked ACTIVE and includes cleanup advice.

**Where do I start?**
[CHEATSHEET.md](CHEATSHEET.md) for the one-page card, then
[decision-guide.md](decision-guide.md) for the triage trees. The per-detection
detail is [DETECTIONS.md](DETECTIONS.md).

**Why is a Kerberoast row a candidate but has no hash?**
The TGS-REP was seen but the reassembled DER did not parse to the Ticket
enc-part (segmentation, encryption, or a non-DER blob). The candidate still
shows the request; treat it as a lead, not a hash.

**Why did no coercion finding appear?**
The detector requires an actual UNC path in an EFSRPC/RPRN/DFSNM/FSRVP call.
A bind or pipe alone is normal traffic (printing, DFS, LSA) and is ignored.
Encrypted RPC cannot be inspected.

**Are tokens written to disk?**
The full token is stored in the local SQLite database. `tokens.tsv`, the leads
and the agent feed only carry a fingerprint (first/last characters). Treat the
database as a secret and delete it with the other artifacts.

**How do I add or change a detection?**
Edit `wiki/detections.yaml` and read [intake.md](intake.md); then run
`python scripts/build_wiki.py`. The generator validates fields, checks that
every registered handler is covered, and regenerates `DETECTIONS.md` and
`CHEATSHEET.md`. CI runs `--check`.

**Why does a full run start so many tshark processes?**
Each handler is one field-extraction pass. With the extended detections the
registry is large; use `--only` or `--credentials-only` when you do not need
everything (see [performance.md](performance.md)).

**What are the KERB / SPN / LDAPSIGN / CHAIN / VOIP leads?**
KERB is a delegation/S4U/UnPAC signal, SPN maps a service principal to an
account (and SID when LDAP captured it), LDAPSIGN says a destination only saw
simple (unsigned) binds, CHAIN correlates coercion/credentials with a relay
target, VOIP is SIP/Skinny signalling. All are `medium` confidence heuristics
unless the evidence says otherwise.

**Does `--report` or `--triage` send my data anywhere?**
`report.md` is written locally and contains real secrets; treat it like the
export pack. `--triage` refuses any non-loopback Ollama URL and sends only lead
metadata (id, severity, confidence, title) and counts — never credentials,
hashes, commands or packet data.

**Why does a full run take so many tshark passes?**
Each handler is one pass; a few need two. The shared Kerberos pass serves
`kerberos`, `kerberoast`, `asrepcatcher` and `kerberosdepth` in one process.
Use `--only` or `--credentials-only` on large captures; `scripts/benchmark.py`
prints the pass count on synthetic data.

**Where is the database?**
By default `extracted_data.db` in the working directory. Use `--db PATH` or
`db_path` in the config file to keep it with the engagement; delete it with the
other artifacts when done.
