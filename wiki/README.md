# PufferRelay wiki — what the capture proves, and what to do next

This wiki answers one question during an engagement: **given what I see in this
capture, what does it prove, what should I do next, and what does it miss?**

It is decision-first, not an encyclopedia:

- **[CHEATSHEET.md](CHEATSHEET.md)** — the one-page recall card. Start here.
- **[decision-guide.md](decision-guide.md)** — the triage trees for an
  AD-heavy, web-heavy, cloud/AI or mixed capture, and how to read a lead.
- **[detections.yaml](detections.yaml)** — the machine-readable catalog every
  catalog page is generated from; the single place new knowledge is added.
- **[DETECTIONS.md](DETECTIONS.md)** — the generated catalog: when a detection
  applies, what it proves, its limits, output and next step.
- **[intake.md](intake.md)** — how to turn a new article, lab result or bug
  into a catalog entry.

Reference pages: [getting-started.md](getting-started.md),
[features.md](features.md), [protocols.md](protocols.md),
[outputs.md](outputs.md), [performance.md](performance.md),
[privacy.md](privacy.md), [faq.md](faq.md).

## How to use it on an engagement

1. **Scope the capture** with `services`, `ips` and `dns`; confirm the subnets
   and hosts you are allowed to touch.
2. **Take the reusable secrets first** — `httptokens`, `ldap`, `http`, `ftp`,
   `smtp`, `imap`, `pop3`, `snmp`, `dbcreds` — before spending time on paths.
3. **Then the attack paths** — `kerberos`/`kerberoast`/`asrepcatcher`, `relays`,
   `coercion`, `adcs`, `sccm`, `ipv6`, `smb`.
4. **Read the limits before the finding.** A capture proves traffic, not
   intent or exploitability. Every catalog entry says what it cannot prove.
5. **Hand off with `--dump`** — `leads.md` for the human, `leads.json` +
   `agent-prompt.md` for an AI agent. Commands that send traffic are ACTIVE.

## How it evolves

`detections.yaml` is the source of truth. To add or change a detection:

1. Read [intake.md](intake.md).
2. Add one entry per handler with `when`, `detects`, `proves`, `limits`,
   `fields`, `output`, `severity`, `next`, `references`, `status`.
3. Run `python scripts/build_wiki.py` — it validates the entry, checks that
   every registered handler is covered, and regenerates `DETECTIONS.md` and
   `CHEATSHEET.md`.
4. Run the test suite; commit with a `docs/PLAN.md` progress line.

CI runs `python scripts/build_wiki.py --check`, so a stale catalog or an
uncovered handler cannot merge.

Rule of thumb: **if a detection cannot say what it proves and what it misses,
it is not ready to be in the tool.**
