"""BloodHound Legacy JSON export tests (issue #15)."""

import json
import os
import tempfile

from PufferRelay.bloodhound import build, write


def _inventory():
    return {
        "hosts": [
            {"ip": "10.0.0.5", "hostnames": ["WS01"], "macs": [], "services": []},
            {"ip": "10.0.0.10", "hostnames": [], "macs": [], "services": []},
        ],
        "users": [
            {"username": "alice", "domain": "CORP", "sources": ["ldap"], "seen_at": []},
            {"username": "bob", "domain": "", "sources": ["ntlm"], "seen_at": []},
        ],
        "credentials": [
            {"protocol": "ftp", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.5",
             "username": "alice", "secret": "x", "context": ""},
        ],
        "hashes": [
            {"username": "CORP\\bob", "hash": "h", "source_ip": "10.0.0.5",
             "destination_ip": "10.0.0.10", "kind": "NTLMv2", "hashcat_mode": 5600},
        ],
        "quick_wins": [],
        "relays": [],
        "files": [],
        "smb": {"shares": [], "files": []},
    }


def test_build_users_computers_sessions():
    payloads = build(_inventory())
    users = payloads["users"]["users"]
    computers = payloads["computers"]["computers"]

    names = {u["Properties"]["name"] for u in users}
    assert "ALICE@CORP" in names and "BOB@CORP" in names
    for user in users:
        assert user["Kinds"] == ["User"]
        assert user["ObjectIdentifier"]

    assert any(c["Properties"]["name"] == "WS01.CORP" for c in computers)
    assert any(c["Properties"]["name"] == "10.0.0.10" for c in computers)

    ws01 = next(c for c in computers if c["Properties"]["name"] == "WS01.CORP")
    assert {"User": "ALICE@CORP", "Computer": "WS01.CORP"} in ws01["Sessions"]
    dc_like = next(c for c in computers if c["Properties"]["name"] == "10.0.0.10")
    assert {"User": "BOB@CORP", "Computer": "10.0.0.10"} in dc_like["Sessions"]


def test_identifiers_are_deterministic():
    first = build(_inventory())["users"]["users"][0]["ObjectIdentifier"]
    second = build(_inventory())["users"]["users"][0]["ObjectIdentifier"]
    assert first == second


def test_write_outputs_valid_json_and_readme():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "bloodhound")
        written = write(out, _inventory())
        assert len(written) == 3
        for name in ("users.json", "computers.json"):
            with open(os.path.join(out, name), encoding="utf-8") as handle:
                payload = json.load(handle)
                assert isinstance(payload, dict) and payload
        with open(os.path.join(out, "README.txt"), encoding="utf-8") as handle:
            text = handle.read()
        assert "PASSIVELY" in text and "not real SIDs" in text
