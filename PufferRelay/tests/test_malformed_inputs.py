"""Malformed inputs must not crash detectors or invent findings."""

import os
import tempfile

from PufferRelay.protocols import (
    coercion,
    database_auth,
    http_tokens,
    kerberoast,
    ldapdir,
)


def test_kerberoast_rejects_truncated_der():
    assert kerberoast.parse_tgs_rep(b"") is None
    assert kerberoast.parse_tgs_rep(b"\x6b\x02\x00") is None
    assert kerberoast.parse_tgs_rep(b"\x6b\x82\xff\xff") is None
    assert kerberoast.format_hash("a", "B", "c", 23, b"\x00" * 10) == ""


def test_http_tokens_ignores_binary_payload(monkeypatch):
    rows = [("10.0.0.5", "10.0.0.6", "x", "/", "00ff01zz", "")]
    monkeypatch.setattr(http_tokens, "fields", lambda *a, **k: rows)
    assert http_tokens.process_http_tokens("x.pcap") == []


def test_coercion_ignores_truncated_hex(monkeypatch):
    rows = [("10.0.0.5", "10.0.0.6", "efsrpc",
             "c681d488-d850-11d0-8c52-00c04fd90f7e", "0", "", "abc")]
    monkeypatch.setattr(coercion, "fields", lambda *a, **k: rows)
    assert coercion.process_coercion("x.pcap") == []


def test_ldapdir_survives_mismatched_attribute_lists(monkeypatch):
    rows = [
        ("10.0.0.5", "10.0.0.6",
         "sAMAccountName,objectSID,servicePrincipalName",
         "alice"),
        ("10.0.0.5", "10.0.0.6", "", ""),
    ]
    monkeypatch.setattr(ldapdir, "fields", lambda *a, **k: rows)
    assert ldapdir.process_ldap_directory("x.pcap") == []


def test_database_auth_survives_binary_payload(monkeypatch):
    rows = [
        ("10.0.0.5", "10.0.0.6", "6379", "zz", "", "", "", "", "", "", "",
         "", ""),
        ("10.0.0.5", "10.0.0.7", "mysql", "3306", "", "", "", "", "", "", "",
         "", ""),
    ]
    monkeypatch.setattr(database_auth, "fields", lambda *a, **k: rows)
    assert database_auth.process_database_auth("x.pcap") == []


def test_empty_capture_is_safe():
    from PufferRelay.protocols import adcs, cloudapi, ipv6_adidns, rdp, sccm

    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "empty.pcap")
        with open(pcap, "wb") as handle:
            handle.write(b"")
        for handler in (
            adcs.process_adcs,
            cloudapi.process_cloudapi,
            ipv6_adidns.process_ipv6_adidns,
            rdp.process_rdp,
            sccm.process_sccm,
        ):
            assert handler(pcap) == []
