"""Database query filters (issue #40)."""

import os
import subprocess
import sys
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import (
    fetch_table,
    insert_into_database,
    query_tables,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _seeded(tmp):
    db_path = os.path.join(tmp, "data.db")
    conn = create_database(db_path=db_path)
    insert_into_database(
        "ftp",
        [
            ("10.0.0.5", "10.0.0.10", "USER", "alice"),
            ("10.0.0.5", "10.0.0.10", "PASS", "s3cret"),
        ],
        db_path=db_path,
    )
    insert_into_database(
        "http",
        [
            ("10.0.0.6", "10.0.0.20", "http://a", "", "bob", "hunter2"),
            ("10.0.0.7", "10.0.0.20", "http://b", "", "N/A", "N/A"),
        ],
        db_path=db_path,
    )
    insert_into_database(
        "ldap",
        [("10.0.0.8", "10.0.0.30", "cn=svc", "ldap-pass")],
        db_path=db_path,
    )
    return conn


def test_ip_filter_skips_tables_without_matches():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seeded(tmp)
        try:
            results = query_tables(
                conn, ip="10.0.0.6", protocols=["ftp", "http", "ldap"]
            )
            assert [name for name, _rows in results] == ["http"]
            assert results[0][1][0][1] == "10.0.0.6"
        finally:
            conn.close()


def test_user_and_has_creds_filters():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seeded(tmp)
        try:
            by_user = query_tables(
                conn, user="alice", protocols=["ftp", "http", "ldap"]
            )
            assert [name for name, _rows in by_user] == ["ftp"]

            credentialed = query_tables(
                conn, has_creds=True, protocols=["ftp", "http", "ldap"]
            )
            names = {name for name, _rows in credentialed}
            # FTP has no unambiguous secret column and is skipped by design.
            assert names == {"http", "ldap"}
            http_rows = dict(credentialed)["http"]
            assert all("N/A" not in str(row) for row in http_rows)
        finally:
            conn.close()


def test_limit_and_unknown_protocol():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seeded(tmp)
        try:
            limited = query_tables(conn, ip="10.0.0.5", protocols=["ftp"], limit=1)
            assert len(limited[0][1]) == 1
            assert query_tables(conn, ip="10.0.0.5", protocols=["nope"]) == []
        finally:
            conn.close()


def test_fetch_table_whitelist_and_raw_rows():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seeded(tmp)
        try:
            headers, rows = fetch_table(conn, "ftp_requests")
            assert "ftp_request_command" in headers
            assert len(rows) == 2
            assert fetch_table(conn, "sqlite_master") == ([], [])
        finally:
            conn.close()


pytestmark_cli = pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)


@pytestmark_cli
def test_cli_filters_and_table_dump():
    with tempfile.TemporaryDirectory() as tmp:
        from scapy.all import Ether, IP, Raw, TCP, wrpcap

        pcap = os.path.join(tmp, "cap.pcap")
        wrpcap(
            pcap,
            [
                Ether() / IP(src="10.0.0.5", dst="10.0.0.10")
                / TCP(sport=40000, dport=21, flags="PA", seq=1, ack=1)
                / Raw(load=b"USER alice" + bytes((13, 10))),
                Ether() / IP(src="10.0.0.5", dst="10.0.0.10")
                / TCP(sport=40000, dport=21, flags="PA", seq=20, ack=1)
                / Raw(load=b"PASS s3cret" + bytes((13, 10))),
            ],
        )
        env = {**os.environ, "PYTHONPATH": REPO_ROOT}
        base = [sys.executable, "-m", "PufferRelay", "-f", pcap, "--log-level", "ERROR"]
        subprocess.run(base, cwd=tmp, env=env, capture_output=True, timeout=120)

        result = subprocess.run(
            [sys.executable, "-m", "PufferRelay", "-r", "--ip", "10.0.0.5",
             "--protocol", "ftp", "--json", "--log-level", "ERROR"],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "alice" in result.stdout

        result = subprocess.run(
            [sys.executable, "-m", "PufferRelay", "-r", "--table", "ftp_requests",
             "--json", "--log-level", "ERROR"],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "ftp_request_command" in result.stdout
        assert "alice" in result.stdout
