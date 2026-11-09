"""DNS visibility and host enrichment (issues #11 / #59)."""

import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import collect_dns, collect_hosts, write_exports
from PufferRelay.protocols.dns_handler import process_dns, qtype_name


def test_qtype_name_mapping():
    assert qtype_name(1) == "A"
    assert qtype_name("28") == "AAAA"
    assert qtype_name("12") == "PTR"
    assert qtype_name(9999) == "9999"
    assert qtype_name(None) == ""


def _write_dns_capture(path):
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, wrpcap

    query = (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.53")
        / UDP(sport=5555, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="fs01.corp.local", qtype="A"))
    )
    answer = (
        Ether()
        / IP(src="10.0.0.53", dst="10.0.0.5")
        / UDP(sport=53, dport=5555)
        / DNS(
            id=1,
            qr=1,
            qd=DNSQR(qname="fs01.corp.local", qtype="A"),
            an=DNSRR(rrname="fs01.corp.local", type="A", ttl=60, rdata="10.0.0.40"),
        )
    )
    wrpcap(path, [query, answer])


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_process_dns_extracts_query_and_answer():
    pytest.importorskip("scapy")
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "dns.pcap")
        _write_dns_capture(pcap)

        rows = process_dns(pcap)
        assert any(
            row[2] == "fs01.corp.local" and row[3] == "A" and row[5] == 0
            for row in rows
        ), rows
        assert any(
            row[2] == "fs01.corp.local" and row[4] == "10.0.0.40" and row[5] == 1
            for row in rows
        ), rows


def test_dns_rows_enrich_hosts_and_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database("ips", [("10.0.0.0/24", ["10.0.0.40"])], db_path=db_path)
        insert_into_database(
            "dns",
            [
                ("10.0.0.5", "10.0.0.53", "fs01.corp.local", "A", "10.0.0.40", 1),
                (
                    "10.0.0.5",
                    "10.0.0.53",
                    "40.0.0.10.in-addr.arpa",
                    "PTR",
                    "fs01.corp.local",
                    1,
                ),
            ],
            db_path=db_path,
        )

        hosts = collect_hosts(conn)
        target = next(host for host in hosts if host["ip"] == "10.0.0.40")
        assert "fs01.corp.local" in target["hostnames"]
        assert collect_dns(conn)[0]["query"] == "fs01.corp.local"

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="dns.pcap")
        with open(os.path.join(out, "dns.txt"), encoding="utf-8") as handle:
            text = handle.read()
        assert "fs01.corp.local" in text
        assert "10.0.0.40" in text
        conn.close()
