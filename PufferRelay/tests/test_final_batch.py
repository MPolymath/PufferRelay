"""Final batch: RDP, cloud APIs, DCOM ADCS, SCCM push, DB hash formats,
auto-profile, diff, HTML report, NAC proposals."""

import json
import os
import tempfile

from PufferRelay import commands, diff, profile, report
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols import adcs, cloudapi, database_auth, rdp, sccm


def _hex(text):
    return text.encode("latin-1").hex()


def test_rdp_identity_and_negotiation(monkeypatch):
    rows = [
        ("10.0.0.5", "10.0.0.10", "19", "ssl|hybrid", "",
         _hex("CORP\\alice")),
        ("10.0.0.6", "10.0.0.10", "19", "ssl", "", ""),
    ]
    monkeypatch.setattr(rdp, "fields", lambda *a, **k: rows)
    result = rdp.process_rdp("x.pcap")
    kinds = {row[0] for row in result}
    assert kinds == {"rdp-identity", "rdp-negotiation"}
    identity = next(row for row in result if row[0] == "rdp-identity")
    assert identity[4] == "CORP\\alice"


def test_cloudapi_unauth_and_exposure(monkeypatch):
    docker = (
        "GET /version HTTP/1.1\r\nHost: docker.corp\r\n\r\n"
    )
    vault = (
        "GET /v1/secret/data HTTP/1.1\r\nHost: vault.corp\r\n"
        "X-Vault-Token: s.abcdef123456\r\n\r\n"
    )
    rows = [
        ("10.0.0.5", "10.0.0.20", "2375", "/version", "docker.corp",
         _hex(docker)),
        ("10.0.0.5", "10.0.0.21", "8200", "/v1/secret/data", "vault.corp",
         _hex(vault)),
    ]
    monkeypatch.setattr(cloudapi, "fields", lambda *a, **k: rows)
    result = cloudapi.process_cloudapi("x.pcap")
    by_kind = {row[0]: row for row in result}
    assert by_kind["docker-unauthenticated"][1] == "critical"
    assert by_kind["vault-exposure"][1] == "medium"


def test_adcs_dcom_enrollment(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "certsrv" in display_filter:
            return []
        if "padata_type" in display_filter:
            return []
        return [("10.0.0.5", "10.0.0.10",
                 "d99dfb68-8f8a-11d0-b881-00c04fc9b5a1", "3")]

    monkeypatch.setattr(adcs, "fields", fake_fields)
    result = adcs.process_adcs("x.pcap")
    assert [row[0] for row in result] == ["enrollment-dcom"]
    assert result[0][1] == "high"


def test_sccm_client_push(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "http.request" in display_filter:
            return [("10.0.0.5", "10.0.0.9", "sccm.corp", "/SMS_MP/x", "ccm", "")]
        return [("10.0.0.9", "10.0.0.5", "\\\\sccm\\ADMIN$", "x")]

    monkeypatch.setattr(sccm, "fields", fake_fields)
    result = sccm.process_sccm("x.pcap")
    push = next(row for row in result if row[0] == "sccm-client-push")
    assert push[1] == "high" and push[2] == "10.0.0.9"


def test_database_hash_formats(monkeypatch):
    redis = b"*2\r\n$4\r\nAUTH\r\n$8\r\ns3cret!!\r\n".hex()
    rows = [
        ("10.0.0.20", "10.0.0.5", "3306", "", "", "", "SALT1234", "", "", "", "", "", ""),
        ("10.0.0.5", "10.0.0.20", "3306", "", "alice", "RESP", "", "", "", "", "", "", ""),
        ("10.0.0.30", "10.0.0.5", "5432", "", "", "", "", "", "", "", "5", "abcd1234", ""),
        ("10.0.0.5", "10.0.0.30", "5432", "", "", "", "", "user", "alice", "", "", "", ""),
        ("10.0.0.5", "10.0.0.30", "5432", "", "", "", "", "", "", "md5deadbeef", "5", "", ""),
        ("10.0.0.5", "10.0.0.40", "6379", redis, "", "", "", "", "", "", "", "", ""),
    ]
    monkeypatch.setattr(database_auth, "fields", lambda *a, **k: rows)
    result = database_auth.process_database_auth("x.pcap")
    mysql = next(row for row in result if row[0] == "mysql")
    assert mysql[4] == "$mysqlna$SALT1234$RESP" and mysql[8] == "11200"
    postgres = next(row for row in result if row[0] == "postgres")
    assert postgres[4] == "$postgres$*alice*abcd1234*deadbeef"
    assert postgres[8] == "12"
    redis_row = next(row for row in result if row[0] == "redis")
    assert redis_row[4] == "s3cret!!"


def test_auto_profile_selection():
    ad = [(f"10.0.0.{i}", port, "", "tcp") for i, port in enumerate((88, 389, 445))]
    selected = profile.select_profile(ad)
    assert selected is not None
    assert {"kerberos", "smb", "ldap", "ldapdir", "kerberoast"} <= set(selected)
    assert profile.select_profile([("10.0.0.5", 80, "http", "tcp")]) is None
    assert profile.select_profile([]) is None


def test_diff_inventories():
    old = {
        "hosts": [{"ip": "10.0.0.5"}],
        "users": [{"username": "alice", "domain": "CORP"}],
        "credentials": [],
        "hashes": [],
        "leads": [{"title": "old", "severity": "low"}],
    }
    new = {
        "hosts": [{"ip": "10.0.0.5"}, {"ip": "10.0.0.6"}],
        "users": [
            {"username": "alice", "domain": "CORP"},
            {"username": "bob", "domain": "CORP"},
        ],
        "credentials": [
            {"protocol": "ftp", "source_ip": "a", "destination_ip": "b",
             "username": "bob", "secret": "pw"}
        ],
        "hashes": [],
        "leads": [
            {"title": "old", "severity": "low"},
            {"title": "new", "severity": "high"},
        ],
    }
    delta = diff.diff_inventories(old, new)
    assert delta["new_hosts"] == ["10.0.0.6"]
    assert delta["new_users"] == ["corp\\bob"]
    assert len(delta["new_credentials"]) == 1
    assert delta["new_leads"] == ["new|high"]
    assert "New hosts" in diff.render_diff(delta, "a.db", "b.db")


def test_html_report_escapes_and_checklist():
    inventory = {
        "hosts": [],
        "users": [],
        "credentials": [],
        "hashes": [],
        "files": [],
    }
    leads = [
        {
            "id": "X-001",
            "severity": "high",
            "confidence": "high",
            "title": "<script>alert(1)</script>",
            "why": "x",
            "evidence": {},
            "suggested_actions": [],
        }
    ]
    html = report.render_html(inventory, leads, "x.pcap")
    assert "&lt;script&gt;" in html and "<script>alert(1)</script>" not in html
    assert "Cleanup checklist" in html
    markdown = report.render_report(inventory, leads, "x.pcap")
    assert "Cleanup checklist" in markdown


def test_nac_spoof_proposals_are_text_only():
    inventory = {
        "hosts": [{"ip": "10.0.0.5", "services": [], "hostnames": []}],
        "nac": [
            {
                "kind": "eap",
                "identity": "CORP\\alice",
                "src": "10.0.0.5",
                "dst": "10.0.0.1",
                "method": "PEAP",
                "mab": False,
            }
        ],
    }
    plan = commands.arp_spoof_plan(inventory)
    assert plan["nac"] is not None
    text = commands.render_arp_plan(plan)
    assert "NAC / 802.1X proposals" in text
    assert "eaphammer" in text
    assert "macchanger -p" in text


def test_new_service_events_flow_to_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "rdp",
            [("rdp-identity", "medium", "10.0.0.5", "10.0.0.10",
              "CORP\\alice", "RDP client identity", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "cloudapi",
            [("docker-unauthenticated", "critical", "10.0.0.5", "10.0.0.20",
              "docker.corp", "Docker API without auth", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "dbcreds",
            [("mysql", "10.0.0.5", "10.0.0.20", "alice",
              "$mysqlna$S$R", "mysql-cram", "abc", "", "11200")],
            db_path=db_path,
        )
        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="x.pcap")
        for name in ("rdp.tsv", "cloud-apis.tsv", "db-creds.tsv"):
            assert os.path.exists(os.path.join(out, name)), name
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        assert any(lead.startswith("RDP-") for lead in ids)
        assert any(lead.startswith("CLOUD-") for lead in ids)
        assert any(lead.startswith("DB-") for lead in ids)
        conn.close()
