# Writing a new detection

A detection is one handler that reads tshark fields and returns rows for one
table; `export.py` turns the rows into a file and a lead. The wiki catalog entry
(`wiki/detections.yaml`) is part of the definition of done.

## Scaffold

```bash
python scripts/new_detection.py mydetection --class network
python scripts/build_wiki.py          # after adding det.mydetection
```

The scaffold creates `PufferRelay/protocols/mydetection.py`; it does not edit
the registry or the catalog, so a half-wired handler cannot land.

## Contract

1. **Input**: `process_<name>(pcap_file)` returns a list of tuples. Use
   `PufferRelay.tshark_fields.fields()` with a display filter and only the
   columns you need. One pass per handler is the norm.
2. **Shape**: each handler's tuple shape must match its `INSERT` in
   `database/db_queries.py` and its entry in `PROTOCOL_TABLES` (used by
   `-r --protocol`).
3. **Table**: add `CREATE TABLE IF NOT EXISTS` in `database/db_models.py` and
   bump `CURRENT_SCHEMA_VERSION`; add a migration note if an existing table
   changes.
4. **Registry**: import the handler in `PufferRelay/protocols/__init__.py`, add
   it to `HANDLERS` in `pcap_processing/pcap_parser.py`, and to
   `CREDENTIAL_HANDLERS` only if it yields identities/secrets.
5. **Export**: add `collect_*` and an inventory key, a `*.tsv`/`*.txt` file in
   `write_exports`, and a lead in `build_leads` with id prefix, severity,
   confidence, evidence and suggested actions (mark ACTIVE traffic).
6. **Wiki**: add `det.<name>` to `wiki/detections.yaml` (class, handler, mode,
   when, detects, proves, limits, fields, output, severity, next, references,
   status) and run `python scripts/build_wiki.py`.
7. **Tests**: a positive case (monkeypatch `fields()` or a synthetic pcap), a
   benign case, and a malformed-input case if the parser consumes binary data.
8. **Privacy**: no capture data, credentials or hashes in the repo or in logs;
   exports are local confidential artifacts.

## Runtime plugins

There is no dynamic plugin loader: a detection is code, reviewed with the
handler registry, the schema and the catalog. The scaffold + contract is the
SDK; this keeps the table/lead/schema wiring honest. `pufferrelay --detections`
prints the catalog that is currently wired.
