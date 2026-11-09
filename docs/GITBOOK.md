# Publishing the wiki to GitBook

The repository is GitBook-ready: `.gitbook.yaml` points at `wiki/`, and
`wiki/SUMMARY.md` is the table of contents. Publishing itself needs the GitBook
space (no `gitbook` CLI or `GITBOOK_TOKEN` is available in this environment).

## One-time setup

1. In GitBook, create/choose the space for PufferRelay.
2. Connect it to `MPolymath/PufferRelay` (GitHub sync), branch `dev-feature`
   first; switch to `main`/default when it is merged.
3. The sync reads `.gitbook.yaml`:
   - `root: ./wiki/`
   - `readme: README.md`
   - `summary: SUMMARY.md`
4. Set the space landing page to `wiki/README.md` and the URL to
   `mpolymath.gitbook.io/pufferrelay` (the README already links it).
5. Add the published URL to the repository README.

## What is generated vs hand-written

- Generated (never edit by hand): `wiki/DETECTIONS.md`, `wiki/CHEATSHEET.md`.
  Change `wiki/detections.yaml` and run `python scripts/build_wiki.py`.
- Hand-written: `README.md`, `decision-guide.md`, `intake.md`, `getting-started.md`,
  `features.md`, `protocols.md`, `outputs.md`, `performance.md`, `privacy.md`,
  `faq.md`, `SUMMARY.md`.

## CI guard

`python scripts/build_wiki.py --check` runs in CI and fails if the generated
pages are stale or a handler has no catalog entry. Run it locally before
pushing a wiki change.

## Privacy

The wiki contains no client data, captures, credentials or hashes — only
documentation and synthetic examples. Keep it that way when publishing.
