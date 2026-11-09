"""Benign capture corpus: the detectors must stay quiet on normal traffic."""

import os
import tempfile

import pytest

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)


def _benign_capture(path):
    from scapy.all import (
        DNS,
        DNSQR,
        ICMPv6ND_RA,
        Ether,
        IP,
        IPv6,
        Raw,
        TCP,
        UDP,
        wrpcap,
    )

    http = (
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        "Authorization: Basic dXNlcjpwYXNz\r\n"
        "Cookie: lang=en; theme=dark\r\n\r\n"
    )
    frames = [
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.80")
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(load=http.encode()),
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.53")
        / UDP(sport=40001, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com")),
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.80")
        / TCP(sport=40002, dport=445, flags="PA")
        / Raw(load=b"\x00\x01\x02\x03normal tcp bytes"),
        Ether(src="aa:aa:aa:aa:aa:aa", dst="33:33:00:00:00:01")
        / IPv6(src="fe80::2", dst="ff02::1")
        / ICMPv6ND_RA(),
    ]
    wrpcap(path, frames)


def test_benign_capture_produces_no_false_positives():
    from PufferRelay.protocols import (
        adcs,
        coercion,
        http_tokens,
        ipv6_adidns,
        kerberos_depth,
        kerberoast,
        llm_traffic,
    )

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "benign.pcap")
        _benign_capture(pcap)
        assert http_tokens.process_http_tokens(pcap) == []
        assert coercion.process_coercion(pcap) == []
        assert adcs.process_adcs(pcap) == []
        assert ipv6_adidns.process_ipv6_adidns(pcap) == []
        assert llm_traffic.process_llm_traffic(pcap) == []
        assert kerberoast.process_kerberoast(pcap) == []
        assert kerberos_depth.process_kerberos_depth(pcap) == []
