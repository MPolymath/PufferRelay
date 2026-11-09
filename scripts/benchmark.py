#!/usr/bin/env python3
"""Synthetic parse benchmark — never uses a client capture.

Generates a temporary mixed DNS/HTTP pcap with scapy, runs the handler
pipeline, and prints wall time plus the number of tshark passes (each handler
is normally one pass; the shared Kerberos pass is counted once).

    python scripts/benchmark.py --packets 20000
    python scripts/benchmark.py --handlers services,ips,dns
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def build_capture(path, packets):
    from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap

    frames = []
    for index in range(packets):
        src = f"10.0.{index % 4}.{10 + index % 200}"
        if index % 3 == 0:
            frames.append(
                Ether()
                / IP(src=src, dst="10.0.0.53")
                / UDP(sport=40000 + index % 1000, dport=53)
                / DNS(id=index % 65535, qr=0, qd=DNSQR(qname=f"host{index}.corp.local"))
            )
        else:
            frames.append(
                Ether()
                / IP(src=src, dst="10.0.0.80")
                / TCP(sport=40000 + index % 1000, dport=80, flags="PA")
                / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: web.corp.local\r\n\r\n")
            )
    wrpcap(path, frames)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=20000)
    parser.add_argument(
        "--handlers",
        help="comma-separated --only list (default: every handler)",
    )
    args = parser.parse_args(argv)

    from PufferRelay import tshark_fields
    from PufferRelay.pcap_processing.pcap_parser import parse_pcap, selected_handlers

    only = [part.strip() for part in args.handlers.split(",")] if args.handlers else None
    names = selected_handlers(only)
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "benchmark.pcap")
        started = time.perf_counter()
        build_capture(pcap, args.packets)
        built = time.perf_counter() - started

        tshark_fields.reset_pass_count()
        started = time.perf_counter()
        data = parse_pcap(pcap, only=only, animate=False)
        elapsed = time.perf_counter() - started

    rows = sum(len(value) for value in data.values() if isinstance(value, list))
    print(f"packets={args.packets} build={built:.2f}s parse={elapsed:.2f}s")
    print(f"handlers={len(names)} tshark_passes={tshark_fields.PASS_COUNT} rows={rows}")
    print("handlers: " + ",".join(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
