"""SMB extraction (issue #44)."""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols.smb_handler import (
    interesting_file,
    is_printer,
    normalise_file,
    normalise_share,
    process_smb,
)

BACKSLASH = chr(92)


def test_normalisation_and_classification():
    assert normalise_share(BACKSLASH * 2 + "FS01" + BACKSLASH + "Finance") == "Finance"
    assert normalise_share("FS01/Finance") == "Finance"
    assert normalise_share("") == ""
    assert normalise_file(" report.xlsx\x00 ") == "report.xlsx"
    assert is_printer("print$", "") is True
    assert is_printer("Finance", "job.SPL") is True
    assert is_printer("Finance", "report.xlsx") is False
    assert interesting_file("web.config") is True
    assert interesting_file("notes.txt") is True
    assert interesting_file("image.png") is False


def test_smb_rows_flow_to_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        rows = [
            ("10.0.0.5", "10.0.0.40", "Finance", "", "tree_connect", 0),
            ("10.0.0.5", "10.0.0.40", "Finance", "web.config", "read", 0),
            ("10.0.0.5", "10.0.0.41", "print$", "job.SPL", "write", 1),
        ]
        insert_into_database("smb", rows, db_path=db_path)

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="smb.pcap")
        with open(os.path.join(out, "smb-shares.txt"), encoding="utf-8") as handle:
            shares = handle.read()
        assert "10.0.0.40" in shares and "Finance" in shares
        with open(os.path.join(out, "smb-files.txt"), encoding="utf-8") as handle:
            files = handle.read()
        assert "web.config" in files

        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        ids = [lead["id"] for lead in payload["leads"]]
        assert any(lead.startswith("SMB-") for lead in ids)
        file_lead = next(
            lead for lead in payload["leads"] if lead["id"].startswith("SMBFILE-")
        )
        assert file_lead["severity"] == "high"
        assert file_lead["suggested_actions"][0]["active"] is False
        conn.close()


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_process_smb_returns_empty_without_smb():
    pytest.importorskip("scapy")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "plain.pcap")
        wrpcap(
            pcap,
            [
                Ether()
                / IP(src="10.0.0.5", dst="10.0.0.10")
                / TCP(sport=40000, dport=21, flags="PA", seq=1, ack=1)
                / Raw(load=b"USER alice\r\n")
            ],
        )
        assert process_smb(pcap) == []
