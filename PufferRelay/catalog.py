"""Read the detection catalog for the CLI (step 8).

Development uses the packaged copy (regenerated from wiki/detections.yaml by
scripts/build_wiki.py), so the installed CLI works without the repository.
Set PUFFERRELAY_CATALOG to point at another YAML file.
"""

from __future__ import annotations

import os

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.environ.get(
    "PUFFERRELAY_CATALOG", os.path.join(PACKAGE_DIR, "catalog_data.yaml")
)


def parse(path=CATALOG):
    entries, current = [], None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("- "):
                if current:
                    entries.append(current)
                current = {}
                line = line[2:].strip()
            if current is None or ":" not in line:
                continue
            key, value = line.split(":", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            current[key.strip()] = value
    if current:
        entries.append(current)
    return entries


def summarize(path=CATALOG):
    return [
        {
            "handler": entry.get("handler", ""),
            "class": entry.get("class", ""),
            "mode": entry.get("mode", ""),
            "severity": entry.get("severity", ""),
            "status": entry.get("status", ""),
            "when": entry.get("when", ""),
        }
        for entry in parse(path)
    ]
