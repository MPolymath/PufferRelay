#!/usr/bin/env python3
"""Scaffold a new detection handler (step 8).

Creates PufferRelay/protocols/<name>.py with the standard shape and prints the
remaining wiring steps. It never edits the registry or the catalog for you:
those changes are reviewed, not generated, so a half-wired handler cannot land.

    python scripts/new_detection.py smb3 --class files
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = '''"""Detection: {name} (TODO: one sentence).

Describe what the capture proves and what it cannot. Read docs/PLUGINS.md.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields


def process_{func}(pcap_file):
    rows = fields(
        pcap_file,
        "TODO display filter",
        ["ip.src", "ip.dst"],
    )
    out = []
    seen = set()
    for src, dst in rows:
        # TODO: project the fields this detection needs.
        detail = "TODO: what was observed"
        evidence = {{}}
        key = (src, dst, detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            ("TODO-kind", "medium", src or "", dst or "", "", detail,
             json.dumps(evidence, sort_keys=True))
        )
    return out
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="handler name (lowercase slug)")
    parser.add_argument("--class", dest="klass", default="network")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    name = args.name.strip().lower().replace("-", "_")
    if not name.isidentifier():
        print("name must be a Python identifier (letters, digits, _)", file=sys.stderr)
        return 2
    target = os.path.join(ROOT, "PufferRelay", "protocols", f"{name}.py")
    if os.path.exists(target) and not args.force:
        print(f"{target} exists (use --force to overwrite)", file=sys.stderr)
        return 1
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(TEMPLATE.format(name=name, func=name))
    print(f"created {os.path.relpath(target, ROOT)}")
    print(
        "\nNext steps (all required, see wiki/intake.md):\n"
        f"  1. register process_{name} in PufferRelay/protocols/__init__.py and\n"
        "     PufferRelay/pcap_processing/pcap_parser.py HANDLERS\n"
        "  2. add the table + INSERT mapping + PROTOCOL_TABLES entry\n"
        "  3. add an export file and lead in PufferRelay/export.py\n"
        "  4. add a test under PufferRelay/tests/ (positive + benign/malformed)\n"
        f"  5. add det.{name} (class: {args.klass}) to wiki/detections.yaml and run\n"
        "     python scripts/build_wiki.py\n"
        "  6. update docs/PLAN.md and commit"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
