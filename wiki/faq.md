# FAQ and gotchas

**Does PufferRelay send traffic?**
No. Everything is read from the capture. Some leads *suggest* commands that send
traffic; they are marked `ACTIVE` and must be confirmed by the operator.

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
Not yet — live capture is Tier B (explicit flag + warning) and not implemented.
Use `tcpdump`/Wireshark to produce the pcap; the analysis is the same.

**Why is the database in the current directory?**
`extracted_data.db` is created in the working directory. Run from the engagement
folder and delete it with the other artifacts when done.
