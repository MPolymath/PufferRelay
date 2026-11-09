"""AD depth: Kerberos delegation/UnPAC, LDAP SPNs/signing, chains, BH SIDs."""

import json
import os
import tempfile

from PufferRelay.bloodhound import build
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import (
    build_chains,
    collect_ldap_signing,
    write_exports,
)
from PufferRelay.protocols import kerberos_depth, ldapdir


def test_kerberos_s4u_unpac_and_delegation(monkeypatch):
    rows = [
        ("10.0.0.5", "10.0.0.10", "10", "alice", "CORP", "krbtgt/CORP", "16",
         "", "", "", "", ""),
        ("10.0.0.5", "10.0.0.10", "12", "alice", "CORP", "krbtgt/CORP", "130",
         "", "", "", "", ""),
        ("10.0.0.5", "10.0.0.10", "12", "bob", "CORP", "cifs/db", "129",
         "", "", "", "", ""),
        ("10.0.0.5", "10.0.0.10", "12", "carol", "CORP", "cifs/db", "",
         "ticket-blob", "", "", "", ""),
        ("10.0.0.10", "10.0.0.5", "11", "dave", "CORP", "cifs/fs",
         "", "", "", "1", "1", "1"),
    ]
    monkeypatch.setattr(kerberos_depth, "fields", lambda *a, **k: rows)
    result = kerberos_depth.process_kerberos_depth("x.pcap")
    kinds = {row[0] for row in result}
    assert {"unpac-chain", "s4u", "s4u2proxy", "delegation-ticket"} <= kinds
    assert len({row[2] for row in result}) == 4


def test_ldap_spn_account_and_sid(monkeypatch):
    rows = [
        (
            "10.0.0.5",
            "10.0.0.10",
            "sAMAccountName,objectSID,servicePrincipalName",
            "alice,S-1-5-21-1-2-3-1104,MSSQLSvc/db.corp:1433",
        )
    ]
    monkeypatch.setattr(ldapdir, "fields", lambda *a, **k: rows)
    result = ldapdir.process_ldap_directory("x.pcap")
    assert result == [
        (
            "alice",
            "MSSQLSvc/db.corp:1433",
            "S-1-5-21-1-2-3-1104",
            "10.0.0.5",
            "10.0.0.10",
        )
    ]


def test_chain_correlation():
    inventory = {
        "hosts": [{"ip": "10.0.0.10", "hostnames": ["dc01.corp"]}],
        "coercions": [
            {"kind": "MS-EFSRPC", "unc": "\\\\dc01.corp\\share\\x"}
        ],
        "credentials": [
            {"username": "alice", "destination_ip": "10.0.0.10"}
        ],
        "hashes": [],
        "relays": [
            {
                "destination_ip": "10.0.0.10",
                "candidate": True,
                "signing_required": False,
                "protocol": "SMB",
            }
        ],
    }
    chains = build_chains(inventory)
    kinds = {chain["kind"] for chain in chains}
    assert "coercion-relay-chain" in kinds
    coercion = next(c for c in chains if c["kind"] == "coercion-relay-chain")
    assert coercion["severity"] == "critical"
    assert coercion["target"] == "10.0.0.10"
    assert coercion["users"] == ["alice"]


def test_ldap_signing_and_ad_depth_export():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        insert_into_database(
            "ldap",
            [
                ("10.0.0.5", "10.0.0.10", "cn=alice", "pw1"),
                ("10.0.0.6", "10.0.0.10", "cn=bob", "N/A"),
                ("10.0.0.7", "10.0.0.20", "cn=svc", "pw2"),
            ],
            db_path=db_path,
        )
        insert_into_database(
            "kerberosdepth",
            [("s4u", "high", "alice", "CORP", "cifs/db", "10.0.0.5",
              "10.0.0.10", "S4U request", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "ldapdir",
            [("alice", "MSSQLSvc/db:1433", "S-1-5-21-1-2-3-1104",
              "10.0.0.5", "10.0.0.10")],
            db_path=db_path,
        )
        signing = {row["destination_ip"]: row for row in collect_ldap_signing(conn)}
        assert signing["10.0.0.10"]["simple_binds"] == 1
        assert signing["10.0.0.20"]["simple_binds"] == 1

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="ad.pcap")
        for name in ("kerberos-signals.tsv", "ldap-spns.tsv", "ldap-signing.tsv"):
            assert os.path.exists(os.path.join(out, name)), name
        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        for prefix in ("KERB-", "SPN-", "LDAPSIGN-"):
            assert any(lead.startswith(prefix) for lead in ids), prefix
        conn.close()


def test_bloodhound_uses_captured_sid():
    inventory = {
        "users": [
            {
                "username": "alice",
                "domain": "CORP",
                "sources": ["ldap"],
                "seen_at": [],
                "sid": "S-1-5-21-1-2-3-1104",
            }
        ],
        "hosts": [],
        "credentials": [],
        "hashes": [],
    }
    payload = build(inventory)
    user = payload["users"]["users"][0]
    assert user["ObjectIdentifier"] == "S-1-5-21-1-2-3-1104"
    assert user["Properties"]["objectsid"] == "S-1-5-21-1-2-3-1104"
