"""Database schema and migration tests (no tshark needed)."""

import os
import sqlite3
import tempfile

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database, process_extracted_data


def test_fresh_database_has_new_schema():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        conn = create_database(db_path=db_path)
        assert conn is not None
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version")
        assert cursor.fetchone()[0] == 13

        cursor.execute("PRAGMA table_info(netbios_requests)")
        columns = {row[1] for row in cursor.fetchall()}
        assert {"domain_workgroup", "hostname", "other_service", "src_ip", "src_mac",
                "service_type"} <= columns

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='observed_services'"
        )
        assert cursor.fetchone() is not None
        conn.close()


def test_netbios_insert_no_longer_fails():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        conn = create_database(db_path=db_path)
        assert conn is not None
        entries = [("WORKGROUP", "WS01", "N/A", "10.0.0.5", "aa:bb:cc:dd:ee:ff",
                    "Workstation Service")]
        insert_into_database("netbios", entries, db_path=db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT hostname, src_ip FROM netbios_requests")
        assert cursor.fetchone() == ("WS01", "10.0.0.5")
        conn.close()


def test_legacy_netbios_table_is_rebuilt():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "legacy.db")
        # Simulate a v2 database with the broken NetBIOS schema.
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE netbios_requests (id INTEGER PRIMARY KEY, domain_workgroup TEXT,"
            " hostname TEXT, ip TEXT, mac TEXT)"
        )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()

        conn = create_database(db_path=db_path)
        assert conn is not None
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(netbios_requests)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "other_service" in columns and "src_ip" in columns
        cursor.execute("PRAGMA user_version")
        assert cursor.fetchone()[0] == 13
        conn.close()


def test_services_are_stored_once():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        conn = create_database(db_path=db_path)
        assert conn is not None
        rows = [("10.0.0.5", 445, "smb", "tcp"), ("10.0.0.5", 445, "smb", "tcp")]
        insert_into_database("services", rows, db_path=db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM observed_services")
        assert cursor.fetchone()[0] == 1
        conn.close()


def test_process_extracted_data_writes_to_given_database():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        conn = create_database(db_path=db_path)
        process_extracted_data(
            {"ftp": [("1.1.1.1", "2.2.2.2", "USER", "alice")]}, db_path=db_path
        )
        cursor = conn.cursor()
        cursor.execute("SELECT ftp_request_arg FROM ftp_requests")
        assert cursor.fetchone()[0] == "alice"
        conn.close()
