"""Ops batch: ADCS LDAP, fingerprints, graph, ATT&CK, parallel and chunking."""

import os
import tempfile

import pytest

from PufferRelay import export, report
from PufferRelay.database.db_models import create_database
from PufferRelay.graph import build_graph
from PufferRelay.pcap_processing import chunker
from PufferRelay.protocols import fingerprints, ldapadcs


def test_catalog_covers_handlers_and_cli():
    import subprocess
    import sys

    from PufferRelay.catalog import summarize

    rows = summarize()
    handlers = {row["handler"] for row in rows}
    assert {"kerberoast", "ldapadcs", "fingerprints", "rdp", "cloudapi"} <= handlers
    assert len(rows) >= 40

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env = {**os.environ, "PYTHONPATH": root}
    listed = subprocess.run(
        [sys.executable, "-m", "PufferRelay", "--detections"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert listed.returncode == 0, listed.stderr
    assert "kerberoast" in listed.stdout

    version = subprocess.run(
        [sys.executable, "-m", "PufferRelay", "--version"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert version.returncode == 0
    assert "1.1.0" in (version.stdout + version.stderr)


def test_ldap_adcs_ca_and_template(monkeypatch):
    rows = [
        ("10.0.0.5", "10.0.0.10", "objectClass", "top,pKIEnrollmentService"),
        ("10.0.0.5", "10.0.0.10", "cn", "CORP-CA"),
        ("10.0.0.5", "10.0.0.10", "dNSHostName", "ca.corp"),
        ("10.0.0.5", "10.0.0.10", "certificateTemplates", "User,WebServer"),
        ("10.0.0.5", "10.0.0.10", "objectClass", "top,pKICertificateTemplate"),
        ("10.0.0.5", "10.0.0.10", "cn", "ESC1-Template"),
        ("10.0.0.5", "10.0.0.10", "msPKI-Certificate-Name-Flag", "1"),
        ("10.0.0.5", "10.0.0.10", "pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2"),
    ]
    monkeypatch.setattr(ldapadcs, "fields", lambda *a, **k: rows)
    result = ldapadcs.process_ldap_adcs("x.pcap")
    kinds = {row[0] for row in result}
    assert kinds == {"ca", "template"}
    template = next(row for row in result if row[0] == "template")
    assert template[1] == "high"  # ESC1 SAN indicator
    ca = next(row for row in result if row[0] == "ca")
    assert ca[3] == "ca.corp"


def test_ldap_adcs_export_and_lead():
    from PufferRelay.database.db_queries import insert_into_database
    from PufferRelay.export import write_exports

    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "ldapadcs",
            [("template", "high", "ESC1", "", "ESC1",
              "template ESC1 allows requester-supplied SAN (ESC1 indicator)",
              "{}", "10.0.0.5", "10.0.0.10")],
            db_path=db_path,
        )
        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="x.pcap")
        with open(os.path.join(out, "ldap-adcs.tsv"), encoding="utf-8") as handle:
            assert "ESC1" in handle.read()
        import json

        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        assert any(lead.startswith("ADCSDIR-") for lead in ids)
        conn.close()


def test_fingerprints(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "ssh.protocol" in display_filter:
            return [("10.0.0.5", "10.0.0.10", "22", "SSH-2.0-OpenSSH_8.9")]
        if "extensions_server_name" in display_filter:
            return [("10.0.0.5", "10.0.0.11", "443", "0x0303", "app.corp")]
        if "vnc.server_proto_ver" in display_filter:
            return [
                ("10.0.0.5", "10.0.0.12", "5900", "3.8", "1", "box"),
                ("10.0.0.5", "10.0.0.13", "5900", "3.8", "2", "box2"),
            ]
        return [("10.0.0.5", "10.0.0.14", "boot.img", "")]

    monkeypatch.setattr(fingerprints, "fields", fake_fields)
    result = fingerprints.process_fingerprints("x.pcap")
    kinds = {row[0] for row in result}
    assert {"ssh-banner", "tls-sni", "vnc-noauth", "vnc-version", "tftp-file"} <= kinds
    vnc = next(row for row in result if row[0] == "vnc-noauth")
    assert vnc[1] == "high"


def test_identity_graph_reuse():
    inventory = {
        "hosts": [{"ip": "10.0.0.10", "hostnames": ["fs01"]}],
        "users": [
            {"username": "alice", "domain": "CORP", "sources": ["ldap"],
             "seen_at": ["10.0.0.10"]}
        ],
        "credentials": [
            {"protocol": "ftp", "source_ip": "10.0.0.5",
             "destination_ip": "10.0.0.10", "username": "ALICE",
             "secret": "pw1", "context": "cleartext FTP"}
        ],
        "hashes": [
            {"username": "CORP\\alice", "destination_ip": "10.0.0.11",
             "kind": "NTLMv2", "hash": "deadbeef"}
        ],
    }
    graph = build_graph(inventory)
    assert graph["nodes"]["users"] == 1
    matrix = graph["matrix"][0]
    assert matrix["destinations"] == ["10.0.0.10", "10.0.0.11"]
    kinds = {row["kind"] for row in graph["reuse"]}
    assert kinds == {"cleartext-and-hash", "credential-reuse"}


def test_attck_mapping_and_report_meta():
    assert export.attck_for("KERBEROAST-001") == ["T1558.003"]
    assert export.attck_for("CHAIN-002") == ["T1557"]
    assert export.attck_for("NOPE-001") == []
    text = report.render_report(
        {"hosts": [], "users": [], "credentials": [], "hashes": [], "files": []},
        [],
        "x.pcap",
        meta={"title": "Acme test", "client": "Acme", "assessor": "MD"},
    )
    assert "# Acme test" in text and "client: Acme" in text
    assert "assessor: MD" in text


def test_report_attck_line():
    leads = [
        {
            "id": "TOKEN-001",
            "severity": "high",
            "confidence": "high",
            "title": "token",
            "why": "x",
            "attck": ["T1528"],
            "evidence": {},
            "suggested_actions": [],
        }
    ]
    text = report.render_report(
        {"hosts": [], "users": [], "credentials": [], "hashes": [], "files": []},
        leads,
        "x.pcap",
    )
    assert "ATT&CK:** T1528" in text


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_parallel_parse_matches_serial():
    from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap
    from PufferRelay.pcap_processing.pcap_parser import parse_pcap

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "p.pcap")
        wrpcap(
            pcap,
            [
                Ether()
                / IP(src=f"10.0.0.{i}", dst="10.0.0.53")
                / UDP(sport=40000 + i, dport=53)
                / DNS(id=i, qr=0, qd=DNSQR(qname=f"h{i}.corp"))
                for i in range(1, 10)
            ],
        )
        serial = parse_pcap(pcap, only=["dns", "services"], animate=False, jobs=1)
        parallel = parse_pcap(pcap, only=["dns", "services"], animate=False, jobs=2)
        assert list(serial) == list(parallel)
        assert serial["dns"] == parallel["dns"]


def test_chunk_checkpoint_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "x.pcap")
        with open(pcap, "wb") as handle:
            handle.write(b"0123456789")
        chunker.save_checkpoint(pcap, [1, 0, 1])
        assert chunker.load_checkpoint(pcap)["completed"] == [0, 1]
        with open(pcap, "ab") as handle:
            handle.write(b"x")
        assert chunker.load_checkpoint(pcap)["completed"] == []
        chunker.clear_checkpoint(pcap)


@pytest.mark.skipif(
    not chunker.find_editcap() or __import__("shutil").which("tshark") is None,
    reason="editcap/tshark not installed",
)
def test_chunked_run_resumes_and_stores(tmp_path, monkeypatch):
    from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap

    pcap = tmp_path / "big.pcap"
    wrpcap(
        str(pcap),
        [
            Ether()
            / IP(src=f"10.0.{i % 3}.{i}", dst="10.0.0.53")
            / UDP(sport=40000 + i, dport=53)
            / DNS(id=i, qr=0, qd=DNSQR(qname=f"h{i}.corp"))
            for i in range(1, 121)
        ],
    )
    monkeypatch.chdir(tmp_path)
    db_path = str(tmp_path / "data.db")
    conn = create_database(db_path=db_path)
    conn.close()
    import PufferRelay.database.db_queries as db_queries

    monkeypatch.setattr(db_queries, "get_db_name", lambda: db_path)
    merged = chunker.run_chunked(
        str(pcap), only=["dns", "services"], packets_per_chunk=40
    )
    assert merged.get("dns")
    import sqlite3

    check = sqlite3.connect(db_path)
    count = check.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0]
    check.close()
    assert count > 0
    assert chunker.load_checkpoint(str(pcap))["completed"] == []
