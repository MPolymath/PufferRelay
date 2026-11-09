"""Export pack + agent lead briefing tests (no tshark needed)."""

import csv
import json
import os
import tempfile

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import (
    build_leads,
    collect_credentials,
    collect_inventory,
    collect_users,
    format_nmap_command,
    format_nmap_targets,
    service_for_port,
    write_exports,
)


def _seed(db_path):
    conn = create_database(db_path=db_path)
    assert conn is not None
    insert_into_database(
        "ftp",
        [
            ("10.0.0.5", "10.0.0.10", "USER", "alice"),
            ("10.0.0.5", "10.0.0.10", "PASS", "s3cret"),
        ],
        db_path=db_path,
    )
    insert_into_database(
        "http",
        [("10.0.0.5", "10.0.0.20", "10.0.0.20/admin", "N/A", "bob", "hunter2")],
        db_path=db_path,
    )
    insert_into_database(
        "ntlm",
        [("10.0.0.5", "10.0.0.30", "CORP\\carol",
          "$NETNTLMv2$CORP\\carol::aaaa::bbbb:0101000000000000")],
        db_path=db_path,
    )
    insert_into_database(
        "netbios",
        [("CORP", "WS01", "N/A", "10.0.0.5", "aa:bb:cc:dd:ee:ff",
          "Workstation Service")],
        db_path=db_path,
    )
    insert_into_database(
        "services",
        [("10.0.0.10", 21, "ftp", "tcp"), ("10.0.0.30", 445, "smb", "tcp")],
        db_path=db_path,
    )
    insert_into_database("ips", [("10.0.0.0/24", ["10.0.0.5", "10.0.0.10"])],
                          db_path=db_path)
    conn.execute(
        "UPDATE quick_wins SET found=1, details='SMB signing not required' "
        "WHERE protocol='SMB_SIGNING_MISSING'"
    )
    conn.execute(
        "UPDATE quick_wins SET found=1, details='credentials in FTP', "
        "credentials_found=1, credential_protocols='FTP' WHERE protocol='FTP'"
    )
    conn.commit()
    return conn


def test_service_map_and_nmap_formatting():
    assert service_for_port(445) == "smb"
    assert service_for_port(21) == "ftp"
    hosts = [
        {"ip": "10.0.0.10", "services": [{"port": 21, "service": "ftp"}]},
        {"ip": "10.0.0.30", "services": [{"port": 445, "service": "smb"},
                                          {"port": 445, "service": "smb"}]},
    ]
    assert format_nmap_targets(hosts).splitlines() == [
        "10.0.0.10 21",
        "10.0.0.30 445",
    ]
    command = format_nmap_command(hosts)
    assert command.startswith("nmap -sV -Pn")
    assert "-p 21 10.0.0.10" in command
    assert "-p 445 10.0.0.30" in command


def test_inventory_and_leads():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seed(os.path.join(tmp, "data.db"))
        users = collect_users(conn)
        names = {(u["domain"], u["username"]) for u in users}
        assert ("", "alice") in names
        assert ("", "bob") in names
        assert ("CORP", "carol") in names

        creds = collect_credentials(conn)
        ftp = [c for c in creds if c["protocol"] == "ftp"]
        assert ftp and ftp[0]["username"] == "alice" and ftp[0]["secret"] == "s3cret"

        inventory = collect_inventory(conn)
        leads = build_leads(inventory)
        ids = [lead["id"] for lead in leads]
        assert any(lead.startswith("CRED-") for lead in ids)
        assert any(lead.startswith("HASH-") for lead in ids)
        assert "QW-SMB_SIGNING_MISSING" in ids
        # SMB signing missing is the most severe lead and must rank first.
        assert leads[0]["severity"] == "critical"

        smb_lead = next(lead for lead in leads if lead["id"] == "QW-SMB_SIGNING_MISSING")
        assert smb_lead["suggested_actions"][0]["active"] is True
        assert "Confirm scope" in smb_lead["suggested_actions"][0]["warning"]

        hash_lead = next(lead for lead in leads if lead["id"].startswith("HASH-"))
        assert hash_lead["suggested_actions"][0]["active"] is False
        conn.close()


def test_write_exports_pack():
    with tempfile.TemporaryDirectory() as tmp:
        conn = _seed(os.path.join(tmp, "data.db"))
        out = os.path.join(tmp, "out")
        files = write_exports(conn, out, pcap_name="lab.pcap")
        for name in [
            "ips.txt",
            "subnets.txt",
            "users.txt",
            "hosts.tsv",
            "nmap-targets.txt",
            "nmap-command.txt",
            "credentials.csv",
            "ntlm-hashes.txt",
            "asrep-hashes.txt",
            "relay-targets.txt",
            "relays.tsv",
            "smb-shares.txt",
            "smb-files.txt",
            "files.tsv",
            "summary.json",
            "leads.json",
            "leads.md",
            "agent-prompt.md",
        ]:
            assert os.path.exists(os.path.join(out, name)), name

        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        assert payload["schema"] == 1
        assert payload["summary"]["leads"] == len(payload["leads"])
        assert any(lead["severity"] == "critical" for lead in payload["leads"])

        with open(os.path.join(out, "leads.md"), encoding="utf-8") as handle:
            briefing = handle.read()
        assert "ACTIVE" in briefing
        assert "hashcat -m 5600" in briefing
        assert "10.0.0.10" in briefing
        with open(os.path.join(out, "agent-prompt.md"), encoding="utf-8") as handle:
            prompt = handle.read()
        assert "ACTIVE" in prompt
        assert "leads.json" in prompt

        with open(os.path.join(out, "credentials.csv"), newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["protocol"] == "ftp"
        assert rows[0]["username"] == "alice"

        assert sorted(os.listdir(out)) == sorted(os.path.basename(f) for f in files)
        conn.close()
