"""Raw protocol views for `-r --protocol` (issue #40)."""

import os
import tempfile

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import (
    PROTOCOL_TABLES,
    fetch_protocol,
    insert_into_database,
    protocol_headers,
)
from PufferRelay.pcap_processing.pcap_parser import HANDLERS


def test_protocol_tables_cover_every_handler():
    assert set(HANDLERS) <= set(PROTOCOL_TABLES)
    assert protocol_headers("ftp")[0] == "Protocol"


def test_fetch_protocol_returns_rows():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "ftp",
            [("10.0.0.5", "10.0.0.10", "USER", "alice")],
            db_path=db_path,
        )
        rows = fetch_protocol(conn, "ftp")
        assert rows == [("ftp", "10.0.0.5", "10.0.0.10", "USER", "alice")]
        assert fetch_protocol(conn, "nope") == []
        conn.close()
