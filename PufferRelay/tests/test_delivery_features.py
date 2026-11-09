"""Report, local triage, VoIP and media delivery tests."""

import json
import os
import tempfile

import pytest

from PufferRelay import report, triage
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols import voip


def _inventory():
    return {
        "hosts": [{"ip": "10.0.0.10", "hostnames": ["dc01"], "services": []}],
        "users": [{"username": "alice", "domain": "CORP", "sources": ["ldap"]}],
        "credentials": [
            {
                "protocol": "ftp",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.10",
                "username": "alice",
                "secret": "SECRET-PASSWORD",
                "context": "cleartext FTP",
            }
        ],
        "hashes": [],
        "files": [],
    }


def _leads():
    return [
        {
            "id": "CRED-001",
            "severity": "high",
            "confidence": "high",
            "title": "Captured ftp credentials",
            "why": "replayable",
            "evidence": {"username": "alice"},
            "suggested_actions": [
                {
                    "intent": "replay",
                    "command": "ftp 10.0.0.10",
                    "active": True,
                    "warning": "Active: confirm scope.",
                }
            ],
        }
    ]


def test_report_contains_findings_secrets_and_limits():
    text = report.render_report(_inventory(), _leads(), "capture.pcap")
    assert "# Capture analysis report" in text
    assert "Executive summary" in text
    assert "CRED-001" in text
    assert "SECRET-PASSWORD" in text
    assert "ACTIVE" in text
    assert "Confidence" in text
    assert "Limitations" in text
    assert "client-confidential" in text


def test_triage_is_loopback_only_and_prompt_has_no_secrets():
    assert triage.validate_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert triage.validate_url("http://localhost:11434/") == "http://localhost:11434"
    for bad in ("http://10.0.0.5:11434", "https://api.example.com", "file:///tmp"):
        with pytest.raises(ValueError):
            triage.validate_url(bad)

    prompt = triage.build_prompt(_inventory(), _leads())
    assert "CRED-001" in prompt
    assert "SECRET-PASSWORD" not in prompt
    assert "ftp 10.0.0.10" not in prompt


def test_ask_ollama_posts_and_reads_response():
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"response": "- step one"}).encode()

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = request.data
        return Response()

    text = triage.ask_ollama("prompt", "http://127.0.0.1:11434", "llama3", opener=opener)
    assert text == "- step one"
    assert captured["url"].endswith("/api/generate")
    assert json.loads(captured["body"])["model"] == "llama3"


def test_voip_sip_and_skinny(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if display_filter == "sip":
            return [
                ("10.0.0.5", "10.0.0.6", "REGISTER", "1001", "registrar",
                 "abc@1",
                 'Digest username="1001", realm="corp", nonce="abc", '
                 'uri="sip:registrar", response="deadbeef"',
                 "", "Cisco/14"),
                ("10.0.0.5", "10.0.0.6", "INVITE", "1001", "1002",
                 "def@2", "", "", "Cisco/14"),
            ]
        return [("10.0.0.7", "10.0.0.8", "0x0001", "2001", "Bob")]

    monkeypatch.setattr(voip, "fields", fake_fields)
    result = voip.process_voip("x.pcap")
    kinds = {row[0] for row in result}
    assert kinds == {"sip-register-auth", "sip-call", "skinny-call"}
    register = next(row for row in result if row[0] == "sip-register-auth")
    evidence = json.loads(register[8])
    assert evidence["digest"]["username"] == "1001"
    assert evidence["digest"]["response_sha256"]


def test_voip_and_media_flow_to_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "voip",
            [("sip-register-auth", "medium", "10.0.0.5", "10.0.0.6", "1001",
              "registrar", "abc@1", "SIP REGISTER with digest", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "files",
            [("http", "10.0.0.5", "10.0.0.10", "clip.mp4", "video/mp4", 10,
              "a" * 64, b"video-data")],
            db_path=db_path,
        )
        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="voip.pcap")
        with open(os.path.join(out, "voip.tsv"), encoding="utf-8") as handle:
            assert "sip-register-auth" in handle.read()
        with open(os.path.join(out, "media.tsv"), encoding="utf-8") as handle:
            assert "clip.mp4" in handle.read()
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        assert any(lead.startswith("VOIP-") for lead in ids)
        conn.close()


def test_write_report_file():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        path = os.path.join(tmp, "nested", "report.md")
        written = report.write_report(conn, path, pcap_name="x.pcap")
        assert written == path and os.path.exists(path)
        with open(path, encoding="utf-8") as handle:
            assert "No leads were produced" in handle.read()
        conn.close()


def test_write_triage_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "triage.md")
        triage.write_triage(path, "- step", "llama3", "http://127.0.0.1:11434")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        assert "loopback only" in text and "- step" in text
