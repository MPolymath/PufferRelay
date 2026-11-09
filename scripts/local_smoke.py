#!/usr/bin/env python3
"""Local-only smoke test for a capture. Prints AGGREGATE COUNTS ONLY.

Use this for client captures: it never prints usernames, passwords, hashes,
hostnames, IPs, MACs or file contents. See docs/PRIVACY.md.

    PYTHONPATH=. python scripts/local_smoke.py capture.pcapng
    PYTHONPATH=. python scripts/local_smoke.py capture.pcapng --only ntlm,services
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import tempfile
import time
from collections import Counter

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import process_extracted_data
from PufferRelay.export import build_leads, collect_inventory
from PufferRelay.pcap_processing.pcap_parser import parse_pcap

TABLES = [
    "ldap_requests",
    "http_requests",
    "ftp_requests",
    "telnet_requests",
    "smtp_requests",
    "ip_requests",
    "ntlm_requests",
    "netbios_requests",
    "imap_requests",
    "pop3_requests",
    "snmp_requests",
    "observed_services",
    "kerberos_asrep",
    "relay_scenarios",
    "smb_activity",
    "captured_files",
    "nac_events",
    "wsus_endpoints",
]

# Tables that hold sensitive values; report only row counts, never samples.
SENSITIVE_TABLES = {
    "ldap_requests",
    "http_requests",
    "ftp_requests",
    "telnet_requests",
    "smtp_requests",
    "ntlm_requests",
    "netbios_requests",
    "imap_requests",
    "pop3_requests",
    "snmp_requests",
    "kerberos_asrep",
    "relay_scenarios",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    parser.add_argument("--only", help="comma separated handlers")
    parser.add_argument("--credentials-only", action="store_true")
    parser.add_argument(
        "--quick-wins",
        action="store_true",
        help="run the quick-win scan (one tshark pass) and report counts only",
    )
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"not found: {args.pcap}")
        return 2

    # Keep third-party debug chatter out of the report; it can contain paths
    # and capture metadata. A filter is used because pyshark resets its logger
    # level when a FileCapture is created.
    class _NoDebug(logging.Filter):
        def filter(self, record):
            return record.levelno >= logging.WARNING

    logging.disable(logging.DEBUG)
    logging.getLogger().setLevel(logging.WARNING)
    for name in ("pyshark", "FileCapture", "asyncio"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.addFilter(_NoDebug())

    only = args.only.split(",") if args.only else None
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "smoke.db")
        conn = create_database(db_path=db_path)
        if conn is None:
            print("database creation failed")
            return 1

        started = time.time()
        data = parse_pcap(
            args.pcap,
            only=only,
            credentials_only=args.credentials_only,
            animate=False,
        )
        parse_seconds = time.time() - started
        process_extracted_data(data, db_path=db_path)

        if args.quick_wins:
            from PufferRelay.protocols.quick_wins import analyze_quick_wins

            started_qw = time.time()
            analyze_quick_wins(args.pcap, conn)
            print("quickwin_seconds=%.1f" % (time.time() - started_qw))

        handler_counts = {name: len(rows) for name, rows in data.items()}
        print(f"parse_seconds={parse_seconds:.1f}")
        print(f"handlers={len(data)} run={','.join(sorted(data))}")
        print(
            "handler_row_counts="
            + json.dumps({k: v for k, v in handler_counts.items() if v}, sort_keys=True)
        )

        counts = {}
        cursor = conn.cursor()
        for table in TABLES:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = cursor.fetchone()[0]
            except sqlite3.Error:
                continue
        print("table_counts=" + json.dumps(counts, sort_keys=True))

        # Safe field-presence aggregates (counts only, never values).
        aggregates = {}
        for table, column, flag in [
            ("http_requests", "http_auth_username", "http_rows_with_auth"),
            ("http_requests", "http_form", "http_rows_with_form"),
            ("ldap_requests", "ldap_simple", "ldap_rows_with_password"),
            ("netbios_requests", "hostname", "netbios_rows_with_hostname"),
            ("kerberos_asrep", "hash", "asrep_rows"),
            ("relay_scenarios", "candidate", "relay_candidate_rows"),
            ("smb_activity", "share", "smb_share_rows"),
            ("captured_files", "sha256", "carved_file_rows"),
        ]:
            try:
                cursor.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {column} IS NOT NULL "
                    f"AND {column} != '' AND {column} != 'N/A' AND {column} != 0"
                )
                aggregates[flag] = cursor.fetchone()[0]
            except sqlite3.Error:
                continue
        try:
            cursor.execute("SELECT COUNT(*) FROM quick_wins WHERE found = 1")
            aggregates["quick_wins_found"] = cursor.fetchone()[0]
        except sqlite3.Error:
            pass
        if args.quick_wins:
            severities = {}
            for severity, count in cursor.execute(
                "SELECT severity, COUNT(*) FROM quick_wins WHERE found=1 GROUP BY severity"
            ):
                severities[severity or "unset"] = count
            with_evidence = cursor.execute(
                "SELECT COUNT(*) FROM quick_wins WHERE found=1 AND evidence IS NOT NULL"
            ).fetchone()[0]
            aggregates["quick_win_severities"] = severities
            aggregates["quick_wins_with_evidence"] = with_evidence
        print("field_aggregates=" + json.dumps(aggregates, sort_keys=True))

        inventory = collect_inventory(conn)
        leads = build_leads(inventory)
        print(
            "inventory_counts="
            + json.dumps(
                {
                    "hosts": len(inventory["hosts"]),
                    "users": len(inventory["users"]),
                    "credentials": len(inventory["credentials"]),
                    "hashes": len(inventory["hashes"]),
                    "quick_wins": len(inventory["quick_wins"]),
                    "relays": len(inventory["relays"]),
                },
                sort_keys=True,
            )
        )
        print(
            "lead_severities="
            + json.dumps(dict(Counter(lead["severity"] for lead in leads)), sort_keys=True)
        )
        print(
            "lead_kinds="
            + json.dumps(
                dict(Counter(lead["id"].split("-")[0] for lead in leads)), sort_keys=True
            )
        )
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
