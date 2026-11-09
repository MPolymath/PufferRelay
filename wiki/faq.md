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

**Where is the database?**
By default `extracted_data.db` in the working directory. Use `--db PATH` or
`db_path` in the config file to keep it with the engagement; delete it with the
other artifacts when done.
