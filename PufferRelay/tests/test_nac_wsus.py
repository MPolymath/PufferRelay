"""NAC/802.1X (#30) and WSUS (#14) tests."""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import collect_nac, collect_users, write_exports
from PufferRelay.protocols.nac_handler import eap_method, looks_like_mac, process_nac
from PufferRelay.protocols.wsus_handler import is_wsus, process_wsus


def test_helpers():
    assert looks_like_mac("aa:bb:cc:dd:ee:ff")
    assert looks_like_mac("AA-BB-CC-DD-EE-FF")
    assert looks_like_mac("aabb.ccdd.eeff")
    assert not looks_like_mac("alice")
    assert not looks_like_mac("aa:bb:cc")
    assert eap_method("25") == "peap" and eap_method("99") == "type-99"
    assert is_wsus("wsus.corp", "/", "") == "host"
    assert is_wsus("", "/Wsus/ClientWebService.asmx", "") == "uri:wsus"
    assert is_wsus("", "/", "Windows-Update-Agent/10.0") == "ua:windows-update-agent"
    assert is_wsus("example.com", "/index", "curl/8") == ""


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_eap_and_wsus_end_to_end():
    pytest.importorskip("scapy")
    from scapy.all import EAP, EAPOL, Ether, IP, Raw, TCP, wrpcap

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "mixed.pcap")
        wsus_request = (
            b"GET /Wsus/ClientWebService.asmx HTTP/1.1\r\n"
            b"Host: wsus.corp.local\r\n"
            b"User-Agent: Windows-Update-Agent/10.0\r\n"
            b"Connection: close\r\n\r\n"
        )
        packets = [
            Ether(src="aa:bb:cc:dd:ee:ff", dst="01:80:c2:00:00:03")
            / EAPOL(type=0)
            / EAP(code=2, type=1, id=1, identity=b"alice"),
            Ether(src="aa:bb:cc:dd:ee:00", dst="01:80:c2:00:00:03")
            / EAPOL(type=0)
            / EAP(code=2, type=1, id=2, identity=b"aa-bb-cc-dd-ee-01"),
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.60")
            / TCP(sport=40000, dport=80, flags="PA", seq=1, ack=1)
            / Raw(load=wsus_request),
        ]
        wrpcap(pcap, packets)

        nac_rows = process_nac(pcap)
        assert any(row[1] == "alice" and row[5] == 0 for row in nac_rows), nac_rows
        assert any(row[5] == 1 for row in nac_rows), nac_rows

        wsus_rows = process_wsus(pcap)
        assert wsus_rows and wsus_rows[0][5].startswith("uri:"), wsus_rows

        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database("nac", nac_rows, db_path=db_path)
        insert_into_database("wsus", wsus_rows, db_path=db_path)

        assert any(user["username"] == "alice" for user in collect_users(conn))
        assert len(collect_nac(conn)) == len(nac_rows)

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name=pcap)
        assert os.path.exists(os.path.join(out, "nac.txt"))
        assert os.path.exists(os.path.join(out, "wsus.txt"))
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        ids = [lead["id"] for lead in payload["leads"]]
        assert "NAC-001" in ids
        assert any(lead.startswith("WSUS-") for lead in ids)
        conn.close()
