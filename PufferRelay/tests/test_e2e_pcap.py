"""End-to-end tests: synthetic pcap -> handlers -> database -> export pack.

Skipped when tshark is not installed (the CI job installs it).
"""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import process_extracted_data
from PufferRelay.pcap_processing.pcap_parser import parse_pcap
from PufferRelay.export import write_exports

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)


def _write_pcap(path):
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    packets = []

    def tcp(src, dst, sport, dport, flags, seq, ack, payload=b""):
        packet = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            packet = packet / Raw(load=payload)
        packets.append(packet)

    # FTP conversation (cleartext credentials).
    tcp("10.0.0.5", "10.0.0.10", 40000, 21, "S", 1000, 0)
    tcp("10.0.0.10", "10.0.0.5", 21, 40000, "SA", 5000, 1001)
    tcp("10.0.0.5", "10.0.0.10", 40000, 21, "PA", 1001, 5001, b"USER alice\r\n")
    tcp("10.0.0.5", "10.0.0.10", 40000, 21, "PA", 1012, 5001, b"PASS s3cret\r\n")

    # HTTP request with Basic auth.
    request = (
        b"GET /admin HTTP/1.1\r\n"
        b"Host: 10.0.0.20\r\n"
        b"Authorization: Basic YWRtaW46cGFzcw==\r\n"
        b"Connection: close\r\n\r\n"
    )
    tcp("10.0.0.5", "10.0.0.20", 40001, 80, "PA", 2001, 1, request)

    # A SYN to SMB so the services handler records 445/smb.
    tcp("10.0.0.30", "10.0.0.40", 40002, 445, "S", 3001, 0)

    wrpcap(path, packets)


def test_pcap_to_export_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        pcap_path = os.path.join(tmp, "synthetic.pcap")
        _write_pcap(pcap_path)

        parsed = parse_pcap(pcap_path, only=["ftp", "http", "services", "ips"])
        assert parsed["ftp"], "FTP credentials were not extracted"
        commands = {(cmd.upper(), arg) for _s, _d, cmd, arg in parsed["ftp"]}
        assert ("USER", "alice") in commands
        assert ("PASS", "s3cret") in commands
        assert any(row[4] in ("admin", "bob") for row in parsed["http"])
        services = {(ip, port, service) for ip, port, service, _t in parsed["services"]}
        assert ("10.0.0.40", 445, "smb") in services

        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        process_extracted_data(parsed, db_path=db_path)

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name=pcap_path)
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        ids = [lead["id"] for lead in payload["leads"]]
        assert any(lead.startswith("CRED-") for lead in ids), payload["leads"]
        assert payload["summary"]["credentials"] >= 2
        conn.close()
