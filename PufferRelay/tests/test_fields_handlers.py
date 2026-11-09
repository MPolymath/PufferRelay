"""End-to-end tests for the field-based handlers (issue #55)."""

import os
import tempfile

import pytest

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)


def _write_capture(path):
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    def handshake(src, dst, sport, dport):
        return [
            Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=1, ack=0),
            Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=100, ack=2),
            Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=2, ack=101),
        ]

    packets = []
    packets += handshake("10.0.0.5", "10.0.0.10", 40000, 143)
    packets.append(
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=40000, dport=143, flags="PA", seq=2, ack=101)
        / Raw(load=b"a1 LOGIN alice s3cret\r\n")
    )
    packets += handshake("10.0.0.5", "10.0.0.20", 40001, 110)
    packets += [
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.20")
        / TCP(sport=40001, dport=110, flags="PA", seq=2, ack=101)
        / Raw(load=b"USER bob\r\n"),
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.20")
        / TCP(sport=40001, dport=110, flags="PA", seq=20, ack=101)
        / Raw(load=b"PASS hunter2\r\n"),
    ]
    wrpcap(path, packets)


def test_imap_and_pop3_extraction():
    from PufferRelay.protocols.fields_handlers import process_imap, process_pop3

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "mail.pcap")
        _write_capture(pcap)

        imap = process_imap(pcap)
        assert any(row[2] == "alice" and row[3] == "s3cret" for row in imap), imap

        pop3 = process_pop3(pcap)
        assert any(row[2] == "bob" and row[3] == "hunter2" for row in pop3), pop3
