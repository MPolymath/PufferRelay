# Privacy

Client captures are confidential. Full rules: [`docs/PRIVACY.md`](../docs/PRIVACY.md).

- Never upload a capture, database, hash, credential or report to an online
  service or AI tool. That includes this tool's own outputs.
- Never commit captures or derived data (`.gitignore` blocks them).
- Test features locally with `scripts/local_smoke.py`, which prints aggregate
  counts only — no usernames, hashes, IPs or file contents.
- `--dump` writes real values by design: keep the output directory on the
  engagement machine and delete it when the engagement rules require it.
- Carved files (`files/`) and BloodHound exports contain client data; treat the
  whole output directory as sensitive.
