"""SCCM (#68) and LLM/MCP (#71) detection tests."""

import json
import os
import tempfile

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols import llm_traffic, sccm


def _hex(text):
    return text.encode("latin-1").hex()


def test_sccm_http_and_share(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "http.request" in display_filter:
            return [("10.0.0.5", "10.0.0.10", "sccm.corp",
                     "/SMS_MP/.sms_aut?mplist", "ccmhttp", "NTLM abc")]
        return [("10.0.0.5", "10.0.0.10", "\\\\sccm\\SMS_SITE", "x")]

    monkeypatch.setattr(sccm, "fields", fake_fields)
    result = sccm.process_sccm("x.pcap")
    kinds = {row[0] for row in result}
    assert kinds == {"sccm-mp-http", "sccm-site-share"}
    mp = next(row for row in result if row[0] == "sccm-mp-http")
    assert mp[1] == "high"  # NTLM to a management point


def test_llm_unauthenticated_and_mcp(monkeypatch):
    ollama = (
        "POST /api/generate HTTP/1.1\r\nHost: localhost:11434\r\n\r\n"
        '{"model":"llama3","prompt":"hello"}'
    )
    mcp = (
        "POST /mcp HTTP/1.1\r\nHost: mcp.corp\r\n"
        "Authorization: Bearer abcdef0123456789\r\n\r\n"
        '{"jsonrpc":"2.0","method":"tools/call","tools":[{"name":"exec"}]}'
    )
    rows = [
        ("10.0.0.5", "10.0.0.10", "localhost:11434", "/api/generate", "curl",
         "11434", _hex(ollama), ""),
        ("10.0.0.5", "10.0.0.11", "mcp.corp", "/mcp", "agent", "80",
         _hex(mcp), ""),
    ]
    monkeypatch.setattr(llm_traffic, "fields", lambda *a, **k: rows)
    result = llm_traffic.process_llm_traffic("x.pcap")
    by_kind = {row[0]: row for row in result}
    assert by_kind["llm-unauthenticated"][1] == "critical"
    assert by_kind["llm-unauthenticated"][4] == "ollama"
    assert by_kind["mcp-call"][1] == "high"
    assert json.loads(by_kind["mcp-call"][10])["tools"] == ["exec"]


def test_sccm_and_llm_flow_to_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "sccm",
            [("sccm-mp-http", "high", "10.0.0.5", "10.0.0.10", "sccm.corp",
              "/SMS_MP/.sms_aut", "", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "llm",
            [("llm-unauthenticated", "critical", "10.0.0.5", "10.0.0.10",
              "ollama", "localhost:11434", "/api/generate", "llama3", "no",
              "ollama inference endpoint answered without auth header", "{}")],
            db_path=db_path,
        )
        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="sccm-llm.pcap")
        with open(os.path.join(out, "sccm.tsv"), encoding="utf-8") as handle:
            assert "sccm-mp-http" in handle.read()
        with open(os.path.join(out, "llm.tsv"), encoding="utf-8") as handle:
            assert "llama3" in handle.read()
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        assert any(lead.startswith("SCCM-") for lead in ids)
        assert any(lead.startswith("LLM-") for lead in ids)
        conn.close()
