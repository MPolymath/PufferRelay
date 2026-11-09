# Privacy

Client captures are confidential. Full rules: [`docs/PRIVACY.md`](../docs/PRIVACY.md).

- Never upload a capture, database, hash, credential or report to an online
  service or AI tool. That includes this tool's own outputs.
- Never commit captures or derived data (`.gitignore` blocks them).
- Test features locally with `scripts/local_smoke.py`, which prints aggregate
  counts only — no usernames, hashes, IPs or file contents.
- `--dump` writes real values by design: keep the output directory on the
  engagement machine and delete it when the engagement rules require it.
- Carved files (`files/`), SMB objects and BloodHound exports contain client
  data; treat the whole output directory as sensitive.
- HTTP tokens and database passwords are stored in the local SQLite database;
  `tokens.tsv`, `leads.json` and `leads.md` only carry a fingerprint. The
  database is therefore a secret: delete it with the other artifacts.
- Kerberoast/AS-REP/NTLM hashes and `db-creds.tsv` are live secrets, not
  metadata. They stay local and are never logged.
- LLM/MCP detection exports metadata only (service, endpoint, model, tool
  names); prompts and answers are not written by default.
- Live capture and the relay require `--live`/`--proxy`, a red warning and
  authorization; live captures are deleted after analysis unless
  `--keep-live-capture` is set.
