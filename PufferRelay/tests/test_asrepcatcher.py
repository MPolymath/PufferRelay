"""ASRepCatcher-compatible detection (passive)."""

import json
import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import collect_asrepcatcher, write_exports
from PufferRelay.protocols.asrepcatcher import (
    REFERENCE,
    detect,
    process_asrepcatcher,
)

# (frame, src, dst, arp_op, arp_src_ip, arp_src_mac, arp_dst_ip,
#  msg_type, user, realm, etypes, padata)


def _req(frame, src, user, padata="2"):
    return (str(frame), src, "10.0.0.10", "", "", "", "", "10", user, "CORP",
            "23,18", padata)


def _rep(frame, src, dst, user, etype="23"):
    return (str(frame), src, dst, "", "", "", "", "11", user, "CORP", etype, "")


def _arp(frame, ip, mac):
    return (str(frame), "", "", "2", ip, mac, "10.0.0.5", "", "", "", "", "")


def test_normal_kerberos_exchange_has_no_findings():
    rows = [_req(1, "10.0.0.5", "alice"), _rep(2, "10.0.0.10", "10.0.0.5", "alice")]
    assert detect(rows) == []


def test_duplicate_request_sources_is_a_relay_signal():
    rows = [
        _req(1, "10.0.0.5", "alice"),
        _req(2, "10.0.0.66", "alice"),
        _rep(3, "10.0.0.10", "10.0.0.66", "alice"),
    ]
    findings = detect(rows)
    assert [f["kind"] for f in findings] == ["relayed-asreq"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["reference"] == REFERENCE


def test_reply_diverted_to_a_host_that_never_asked():
    rows = [
        _req(1, "10.0.0.5", "alice"),
        _rep(2, "10.0.0.10", "10.0.0.66", "alice"),
    ]
    findings = detect(rows)
    assert [f["kind"] for f in findings] == ["asrep-to-third-party"]
    assert findings[0]["attacker_ip"] == "10.0.0.66"


def test_arp_spoof_plus_kerberos_is_combined_critical():
    rows = [
        _req(1, "10.0.0.5", "alice"),
        _req(2, "10.0.0.66", "alice"),
        _rep(3, "10.0.0.10", "10.0.0.66", "alice"),
        _arp(4, "10.0.0.1", "aa:aa:aa:aa:aa:aa"),
        _arp(5, "10.0.0.1", "bb:bb:bb:bb:bb:bb"),
    ]
    findings = detect(rows)
    assert [f["kind"] for f in findings] == ["asrepcatcher"]
    assert findings[0]["severity"] == "critical"
    assert "10.0.0.1" in findings[0]["evidence"]["arp"]
    assert findings[0]["evidence"]["reference"] == REFERENCE


def test_arp_alone_without_kerberos_replies_is_not_reported():
    rows = [
        _arp(1, "10.0.0.1", "aa:aa:aa:aa:aa:aa"),
        _arp(2, "10.0.0.1", "bb:bb:bb:bb:bb:bb"),
    ]
    assert detect(rows) == []


def test_preauth_less_burst_is_reported():
    rows = [_req(i, "10.0.0.66", f"user{i}", padata="") for i in range(1, 7)]
    findings = detect(rows)
    assert [f["kind"] for f in findings] == ["asrep-enumeration"]
    assert "6 pre-auth-less TGT requests" in findings[0]["summary"]
    assert findings[0]["username"] == "6 accounts"


def test_rows_flow_to_db_file_and_lead():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        finding = {
            "kind": "asrepcatcher",
            "severity": "critical",
            "client_ip": "10.0.0.5",
            "attacker_ip": "10.0.0.1",
            "kdc_ip": "10.0.0.10",
            "username": "alice",
            "realm": "CORP",
            "summary": "ARP spoofing plus Kerberos relay",
            "evidence": {"reference": REFERENCE},
        }
        insert_into_database(
            "asrepcatcher",
            [
                (
                    finding["kind"],
                    finding["severity"],
                    finding["client_ip"],
                    finding["attacker_ip"],
                    finding["kdc_ip"],
                    finding["username"],
                    finding["realm"],
                    finding["summary"],
                    json.dumps(finding["evidence"]),
                )
            ],
            db_path=db_path,
        )
        assert collect_asrepcatcher(conn)[0]["kind"] == "asrepcatcher"

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="catcher.pcap")
        with open(os.path.join(out, "asrepcatcher.txt"), encoding="utf-8") as handle:
            text = handle.read()
        assert "asrepcatcher" in text
        assert "alice" in text
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        lead = next(
            item
            for item in payload["leads"]
            if item["id"].startswith("ASREPCATCHER-")
        )
        assert lead["severity"] == "critical"
        assert REFERENCE in lead["why"]
        assert lead["evidence"]["reference"] == REFERENCE
        conn.close()


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_process_asrepcatcher_handles_a_non_kerberos_capture():
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
                / Raw(load=b"USER alice" + bytes((13, 10)))
            ],
        )
        assert process_asrepcatcher(pcap) == []
