#!/usr/bin/env python3
"""Validate detectors against small public captures (step 3).

Downloads a few Wireshark test captures to a temporary directory, runs the
selected handlers and prints aggregate row counts only. No capture is
committed and nothing is uploaded.

    python scripts/validate_public.py
    python scripts/validate_public.py --only dns,http,services --keep
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

DEFAULT_CAPTURES = [
    "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/dhcp.pcap",
    "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/http.pcap",
    "https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/dns_port.pcap",
]


def download(url, directory):
    name = os.path.basename(url) or "capture.pcap"
    path = os.path.join(directory, name)
    request = urllib.request.Request(
        url, headers={"User-Agent": "pufferrelay-validation/1.0"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        with open(path, "wb") as handle:
            handle.write(response.read())
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", dest="urls")
    parser.add_argument("--only", help="comma-separated handler list")
    parser.add_argument("--keep", action="store_true", help="keep the downloads")
    args = parser.parse_args(argv)

    from PufferRelay.pcap_processing.pcap_parser import parse_pcap

    only = [part.strip() for part in args.only.split(",")] if args.only else None
    urls = args.urls or DEFAULT_CAPTURES
    directory = tempfile.mkdtemp(prefix="pufferrelay-public-")
    failures = 0
    try:
        for url in urls:
            try:
                path = download(url, directory)
            except Exception as error:
                print(f"{url}: download failed ({error})", file=sys.stderr)
                failures += 1
                continue
            try:
                data = parse_pcap(path, only=only, animate=False)
            except Exception as error:
                print(f"{os.path.basename(path)}: handler failure ({error})", file=sys.stderr)
                failures += 1
                continue
            counts = {
                name: len(rows)
                for name, rows in data.items()
                if isinstance(rows, list) and rows
            }
            total = sum(counts.values())
            print(f"{os.path.basename(path)}: {total} rows {counts}")
        return 1 if failures else 0
    finally:
        if not args.keep:
            import shutil

            shutil.rmtree(directory, ignore_errors=True)
        else:
            print(f"captures kept in {directory}")


if __name__ == "__main__":
    sys.exit(main())
