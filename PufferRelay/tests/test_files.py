"""File carving from clear-text transfers (issue #57)."""

import hashlib
import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols.files_handler import (
    decode_hex_field,
    filename_from_disposition,
    process_files,
    safe_filename,
)

BODY = b'{"a": "b"}\n'


def test_safe_filename_and_disposition():
    assert safe_filename('../../etc/passwd', "x") == "passwd"
    assert safe_filename('..\\..\\Windows\\win.ini', "x") == "win.ini"
    assert safe_filename("weird name?.bin", "x") == "weird_name_.bin"
    assert safe_filename("", "fallback") == "fallback"
    assert filename_from_disposition('attachment; filename="notes.config"') == "notes.config"
    assert filename_from_disposition("attachment; filename*=UTF-8''a%20b.txt") == "a%20b.txt"
    assert filename_from_disposition("") == ""


def test_decode_hex_field():
    assert decode_hex_field("6162") == b"ab"
    assert decode_hex_field("61:62") == b"ab"
    assert decode_hex_field("zz") is None
    assert decode_hex_field("") is None


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_http_file_carving_end_to_end():
    pytest.importorskip("scapy")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b'Content-Disposition: attachment; filename="notes.config"\r\n'
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + BODY
    )
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "http.pcap")
        wrpcap(
            pcap,
            [
                Ether()
                / IP(src="10.0.0.10", dst="10.0.0.5")
                / TCP(sport=80, dport=40000, flags="PA", seq=1, ack=1)
                / Raw(load=response)
            ],
        )

        rows = process_files(pcap)
        assert rows, "no file objects carved"
        protocol, src, dst, name, content_type, size, digest, data = rows[0]
        assert protocol == "http"
        assert name == "notes.config"
        assert data == BODY
        assert digest == hashlib.sha256(BODY).hexdigest()
        assert content_type.startswith("application/json")

        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database("files", rows, db_path=db_path)

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name=pcap)
        stored = os.path.join(out, "files", f"{digest[:12]}_notes.config")
        assert os.path.exists(stored)
        with open(stored, "rb") as handle:
            assert handle.read() == BODY

        with open(os.path.join(out, "files.tsv"), encoding="utf-8") as handle:
            assert digest in handle.read()
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        file_leads = [lead for lead in payload["leads"] if lead["id"].startswith("FILE-")]
        assert file_leads and file_leads[0]["severity"] == "high"
        assert file_leads[0]["evidence"]["sha256"] == digest
        assert file_leads[0]["suggested_actions"][0]["active"] is False
        conn.close()
