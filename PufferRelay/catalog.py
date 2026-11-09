"""Read the detection catalog (wiki/detections.yaml) for the CLI (step 8)."""

from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "wiki", "detections.yaml")


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
