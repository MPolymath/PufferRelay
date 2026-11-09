"""AS-REP roasting detection (issue #61)."""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import collect_hashes, write_exports
from PufferRelay.protocols.kerberos_handler import asrep_hash, normalise_hex

PAYLOAD = "0" * 64  # 32 bytes of cipher hex: 16 checksum + data


def test_normalise_hex_handles_tshark_formats():
    assert normalise_hex("aa:bb:cc") == "aabbcc"
    assert normalise_hex("0xAA BB") == "aabb"
    assert normalise_hex("not-hex") == ""
    assert normalise_hex(None) == ""


def test_asrep_hash_matches_hashcat_18200_format():
    line = asrep_hash("alice", "CORP.LOCAL", 23, PAYLOAD)
    assert line == f"$krb5asrep$23$alice@CORP.LOCAL:{'0' * 32}${'0' * 32}"
    assert asrep_hash("alice", "CORP.LOCAL", 18, PAYLOAD).startswith("$krb5asrep$18$")
    assert asrep_hash("alice", "", 23, PAYLOAD) is None
    assert asrep_hash("alice", "CORP.LOCAL", 23, "aabb") is None


def test_asrep_rows_flow_to_db_and_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        row = ("alice", "CORP.LOCAL", "23", asrep_hash("alice", "CORP.LOCAL", 23, PAYLOAD),
               "10.0.0.5", "10.0.0.10")
        insert_into_database("kerberos", [row], db_path=db_path)

        hashes = collect_hashes(conn)
        assert hashes and hashes[0]["hashcat_mode"] == 18200
        assert hashes[0]["kind"].startswith("AS-REP")

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="kerb.pcap")
        with open(os.path.join(out, "asrep-hashes.txt"), encoding="utf-8") as handle:
            assert handle.read().strip() == row[3]
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        asrep = [lead for lead in payload["leads"] if lead["id"].startswith("ASREP-")]
        assert asrep and asrep[0]["severity"] == "critical"
        assert "hashcat -m 18200" in asrep[0]["suggested_actions"][0]["command"]
        assert asrep[0]["suggested_actions"][0]["active"] is False
        conn.close()


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_process_kerberos_returns_empty_without_kerberos():
    pytest.importorskip("scapy")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    from PufferRelay.protocols.kerberos_handler import process_kerberos

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
        assert process_kerberos(pcap) == []


def test_kerberos_asrep_schema_exists():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='kerberos_asrep'"
        )
        assert cursor.fetchone() is not None
        conn.close()
