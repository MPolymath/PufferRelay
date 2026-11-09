"""NTLM relay scenario enumeration (issue #62)."""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols.relay_handler import (
    classify,
    protocol_for_port,
    smb_signing_missing_hosts,
)


def test_classify_and_ports():
    assert classify("smb", False) is True
    assert classify("smb", None) is True
    assert classify("smb", True) is False
    assert classify("ldap", None) is True
    assert classify("http", None) is True
    assert classify("unknown", None) is False
    assert protocol_for_port(445) == "smb"
    assert protocol_for_port(139) == "smb"
    assert protocol_for_port(389) == "ldap"
    assert protocol_for_port(3268) == "ldap"
    assert protocol_for_port(8080) == "http"
    assert protocol_for_port(80) == "http"
    assert protocol_for_port(12345) == "unknown"


def test_smb_signing_missing_hosts():
    rows = [
        ("a", "10.0.0.40", 445, "smb", "u", 0, 1),
        ("a", "10.0.0.50", 445, "smb", "u", 1, 0),
        ("a", "10.0.0.10", 389, "ldap", "u", "", 1),
        ("a", "10.0.0.60", 445, "smb", "u", "", 1),
    ]
    assert smb_signing_missing_hosts(rows) == ["10.0.0.40"]
    assert smb_signing_missing_hosts([]) == []


def test_relay_rows_flow_to_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        rows = [
            # SMB relay candidate: signing not required (0)
            ("10.0.0.5", "10.0.0.40", 445, "smb", "CORP\\alice", 0, 1),
            # SMB with signing required: not a candidate
            ("10.0.0.5", "10.0.0.50", 445, "smb", "CORP\\bob", 1, 0),
            # LDAP NTLM bind: candidate
            ("10.0.0.5", "10.0.0.10", 389, "ldap", "CORP\\alice", "", 1),
        ]
        insert_into_database("relays", rows, db_path=db_path)

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="relay.pcap")
        with open(os.path.join(out, "relay-targets.txt"), encoding="utf-8") as handle:
            targets = [line.strip() for line in handle if line.strip()]
        assert targets == ["10.0.0.10", "10.0.0.40"]

        with open(os.path.join(out, "relays.tsv"), encoding="utf-8") as handle:
            tsv = handle.read()
        assert "10.0.0.50" in tsv and "10.0.0.40" in tsv

        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        relay_leads = [lead for lead in payload["leads"] if lead["id"].startswith("RELAY-")]
        assert len(relay_leads) == 2
        assert relay_leads[0]["severity"] == "critical"
        assert "signing not required" in relay_leads[0]["why"]
        assert relay_leads[0]["suggested_actions"][1]["active"] is True
        assert "Confirm" in relay_leads[0]["suggested_actions"][1]["warning"]
        conn.close()


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_process_relays_returns_empty_without_ntlm():
    pytest.importorskip("scapy")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    from PufferRelay.protocols.relay_handler import process_relays

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
        assert process_relays(pcap) == []
