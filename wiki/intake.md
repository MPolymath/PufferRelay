# Intake — turning a new article or finding into the wiki

When you read a new article, finish a lab, or fix a detection bug, convert it
into entries in `detections.yaml`. Do not paste the article in; extract the
decision and the evidence.

## Template (one entry per detection handler)

```yaml
- id: det.short-name
  class: inventory|credentials|hashes|kerberos|ad|network|web|files|weakness|ai|active
  handler: the_handler_registry_key
  mode: passive|active
  when: "the observable capture condition that makes this run"
  detects: "one sentence: what it extracts"
  proves: "what the traffic actually demonstrates"
  limits: "what the capture cannot show, or where it produces a candidate only"
  fields: "tshark fields or a one-line method"
  output: "files and lead ids it produces"
  severity: critical|high|medium|low|varies
  next: "the operator's next step; mark active commands as ACTIVE"
  references: "article URL (optional)"
  status: implemented|partial|planned
```

## Rules

1. **One entry per handler.** `handler` must be a key in the handler registry
   (or one of the active-mode names). The generator fails on a missing or
   duplicate entry, so coverage cannot silently rot.
2. **`when` must be observable in a capture**: "TGS-REP present", not "the
   domain is weak".
3. **`proves` and `limits` are mandatory and distinct.** If the capture only
   yields a candidate (unparsed DER, unauthenticated heuristic, partial flow),
   say so in `limits` and use `status: partial`.
4. **`output` must match `export.py`.** Name the real file and lead prefix; a
   reader should be able to open the artifact without reading code.
5. **No claim of exploitability from traffic alone.** State what needs
   verification. Relay findings are candidates until signing and the actual
   exchange are confirmed.
6. **Active entries state their guard rails.** `--live`, `--proxy`,
   `--commands` and `--serveme` must mention the warning, authorization, and
   (for live) the temporary-capture deletion.
7. **Privacy is part of the entry.** Raw tokens and hashes stay in the local
   database; exports carry fingerprints or are explicitly marked secret. Never
   add a detection whose output must leave the engagement machine.
8. **Prefer passive.** If a question can be answered from the capture, do not
   add a network action.
9. **Mark unverified knowledge.** Use `status: planned` before implementation
   and `partial` when the capture can miss cases; flip to `implemented` only
   when the acceptance test exists.

## Workflow

```bash
# 1. edit wiki/detections.yaml
# 2. validate, check handler coverage, regenerate the catalog
python scripts/build_wiki.py
# 3. tests + CI check
python -m pytest PufferRelay/tests -q
python scripts/build_wiki.py --check
# 4. update docs/PLAN.md and commit
```

The generator refuses missing fields, unknown classes/handlers and duplicated
handlers, so a half-written entry cannot merge.
