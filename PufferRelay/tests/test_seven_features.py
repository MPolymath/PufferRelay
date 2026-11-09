"""Tests for the seven detection features (issues #64-#70, SMB objects)."""

import json
import os
import tempfile

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import insert_into_database
from PufferRelay.export import write_exports
from PufferRelay.protocols import (
    adcs,
    coercion,
    database_auth,
    http_tokens,
    ipv6_adidns,
    kerberoast,
    smb_objects,
)


# --------------------------------------------------------------------------- #
# Kerberoasting
# --------------------------------------------------------------------------- #
def _tlv(tag, value):
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + value


def _int(value):
    return _tlv(0x02, int(value).to_bytes(1, "big"))


def _general(text):
    return _tlv(0x1B, text.encode())


def _principal(name):
    return _tlv(0x30, _tlv(0xA0, _int(1)) + _tlv(0xA1, _tlv(0x30, _general(name))))


def _kdc_rep(etype=23, cipher=b"\x11" * 32, user="alice", realm="CORP",
             spn="MSSQLSvc/db.corp:1433"):
    enc = _tlv(0x30, _int(etype) + _int(3) + _tlv(0x04, cipher))
    ticket = _tlv(
        0x61,
        _tlv(0xA0, _int(5))
        + _tlv(0xA1, _general(realm))
        + _tlv(0xA2, _principal(spn))
        + _tlv(0xA3, enc),
    )
    content = (
        _tlv(0xA0, _int(5))
        + _tlv(0xA1, _int(13))
        + _tlv(0xA3, _general(realm))
        + _tlv(0xA4, _principal(user))
        + _tlv(0xA5, ticket)
        + _tlv(0xA6, _tlv(0x30, _int(23) + _int(3) + _tlv(0x04, b"\x00" * 16)))
    )
    return _tlv(0x6B, content)


def test_kerberoast_der_and_hash_format():
    parsed = kerberoast.parse_tgs_rep(_kdc_rep())
    assert parsed is not None and parsed[0] == 23 and len(parsed[1]) == 32
    line = kerberoast.format_hash("alice", "CORP", "MSSQLSvc/db.corp:1433", 23, parsed[1])
    assert line.startswith("$krb5tgs$23$*alice$CORP$MSSQLSvc/db.corp:1433*$")
    assert "+" not in line  # hex only


def test_kerberoast_hash_and_burst(monkeypatch):
    rows = [("10.0.0.5", "10.0.0.10", "13", "alice", "CORP",
             "MSSQLSvc/db.corp:1433", "23", "", "", _kdc_rep().hex())]
    rows += [("10.0.0.6", "10.0.0.10", "12", "bob", "CORP", f"spn{i}", "23",
              "", "", "") for i in range(5)]
    monkeypatch.setattr(kerberoast, "fields", lambda *a, **k: rows)
    result = kerberoast.process_kerberoast("x.pcap")
    assert any(row[7] == "hash" and row[4] for row in result)
    assert sum(1 for row in result if row[7] == "candidate") == 5


# --------------------------------------------------------------------------- #
# HTTP tokens
# --------------------------------------------------------------------------- #
def _http_hex(text):
    return text.encode("latin-1").hex()


def test_http_tokens_headers_and_jwt(monkeypatch):
    payload = (
        "GET /api/v1/secrets HTTP/1.1\r\nHost: api.corp.local\r\n"
        "Authorization: Bearer abcdef0123456789\r\n"
        "X-Vault-Token: s.vaulttoken123456\r\n\r\n"
    )
    import base64
    import time

    claims = {"sub": "alice", "exp": int(time.time()) + 3600}
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    jwt = f"eyJhbGciOiJub25lIn0.{body}.signature12345"
    payload += jwt
    rows = [("10.0.0.5", "10.0.0.10", "api.corp.local", "/api/v1/secrets",
             _http_hex(payload), "")]
    monkeypatch.setattr(http_tokens, "fields", lambda *a, **k: rows)
    result = http_tokens.process_http_tokens("x.pcap")
    kinds = {row[0] for row in result}
    assert {"bearer", "vault", "jwt"} <= kinds, kinds
    jwt_row = next(row for row in result if row[0] == "jwt")
    assert jwt_row[7] == "alice"
    assert jwt_row[6].count("…") == 1  # fingerprint, not raw


# --------------------------------------------------------------------------- #
# Coercion
# --------------------------------------------------------------------------- #
def test_coercion_uuid_and_unc(monkeypatch):
    unc = b"\\\\attacker.corp\\share\\x\x00"
    rows = [("10.0.0.5", "10.0.0.10", "efsrpc",
             "c681d488-d850-11d0-8c52-00c04fd90f7e", "0", "", unc.hex())]
    monkeypatch.setattr(coercion, "fields", lambda *a, **k: rows)
    result = coercion.process_coercion("x.pcap")
    assert result and result[0][0] == "MS-EFSRPC"
    assert "attacker.corp" in result[0][7]
    assert result[0][1] == "high"


# --------------------------------------------------------------------------- #
# ADCS
# --------------------------------------------------------------------------- #
def test_adcs_http_and_pkinit(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "certsrv" in display_filter:
            return [("10.0.0.5", "10.0.0.10", "ca.corp",
                     "/certsrv/certfnsh.asp", "NTLM TlRMTVNTUAAB", "")]
        return [("10.0.0.5", "10.0.0.10", "alice", "CORP", "16")]

    monkeypatch.setattr(adcs, "fields", fake_fields)
    result = adcs.process_adcs("x.pcap")
    kinds = {row[0] for row in result}
    assert kinds == {"enrollment", "pkinit"}
    enrollment = next(row for row in result if row[0] == "enrollment")
    assert enrollment[1] == "high"


# --------------------------------------------------------------------------- #
# IPv6 / ADIDNS
# --------------------------------------------------------------------------- #
def test_ipv6_takeover_combination(monkeypatch):
    def fake_fields(pcap, display_filter, names, **kwargs):
        if "dhcpv6" in display_filter:
            return [("fe80::1", "ff02::1", "7", "10.0.0.53", "", "", "")]
        return [("fe80::1", "10.0.0.10", "corp.local", "1", "1")]

    monkeypatch.setattr(ipv6_adidns, "fields", fake_fields)
    result = ipv6_adidns.process_ipv6_adidns("x.pcap")
    assert result[0][0] == "ipv6-dns-takeover"
    assert result[0][1] == "critical"
    assert {"dhcpv6-dns", "adidns-update"} <= {row[0] for row in result}


# --------------------------------------------------------------------------- #
# Database auth
# --------------------------------------------------------------------------- #
def test_database_auth_redis_mysql_postgres(monkeypatch):
    redis_payload = b"*2\r\n$4\r\nAUTH\r\n$8\r\ns3cret!!\r\n".hex()

    def fake_fields(pcap, display_filter, names, **kwargs):
        if "6379" in display_filter:
            return [("10.0.0.5", "10.0.0.20", redis_payload)]
        if "mysql" in display_filter:
            return [("10.0.0.5", "10.0.0.21", "dbuser", "aabbccddeeff", "QUERY")]
        return [
            ("10.0.0.5", "10.0.0.22", "user", "alice", "", "", "", ""),
            ("10.0.0.5", "10.0.0.22", "database", "app", "", "", "", ""),
            ("10.0.0.5", "10.0.0.22", "", "", "pglit", "3", "", ""),
        ]

    monkeypatch.setattr(database_auth, "fields", fake_fields)
    result = database_auth.process_database_auth("x.pcap")
    protocols = {row[0] for row in result}
    assert protocols == {"redis", "mysql", "postgres"}
    redis = next(row for row in result if row[0] == "redis")
    assert redis[4] == "s3cret!!"
    postgres = next(row for row in result if row[0] == "postgres")
    assert postgres[3] == "alice" and postgres[4] == "pglit"


# --------------------------------------------------------------------------- #
# SMB object carving
# --------------------------------------------------------------------------- #
def test_smb_export_collection_and_caps(tmp_path):
    (tmp_path / "report.docx").write_bytes(b"PK\x03\x04" + b"x" * 100)
    (tmp_path / "notes.txt").write_bytes(b"hello")
    rows = smb_objects.collect_exported(str(tmp_path))
    names = {row[0] for row in rows}
    assert names == {"report.docx", "notes.txt"}
    assert all(len(row[2]) == 64 for row in rows)  # sha256

    capped = smb_objects.collect_exported(str(tmp_path), max_object=10)
    assert [row[0] for row in capped] == ["notes.txt"]


# --------------------------------------------------------------------------- #
# DB -> export -> leads
# --------------------------------------------------------------------------- #
def test_seven_features_flow_to_files_and_leads():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "data.db")
        conn = create_database(db_path=db_path)
        hash_line = "$krb5tgs$23$*alice$CORP$spn*$0011$2233"
        insert_into_database(
            "kerberoast",
            [("alice", "CORP", "MSSQLSvc/db:1433", 23, hash_line,
              "10.0.0.5", "10.0.0.10", "hash")],
            db_path=db_path,
        )
        insert_into_database(
            "httptokens",
            [("vault", "critical", "vault.corp", "/v1/secret", "x-vault-token",
              "s.SECRETVALUE12345", "s.SECR…2345", "", "", "10.0.0.5",
              "10.0.0.10")],
            db_path=db_path,
        )
        insert_into_database(
            "coercion",
            [("MS-EFSRPC", "high", "10.0.0.5", "10.0.0.10", "efsrpc",
              "c681d488-d850-11d0-8c52-00c04fd90f7e", "0",
              "\\\\attacker\\share", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "adcs",
            [("enrollment", "high", "10.0.0.5", "10.0.0.10", "ca.corp",
              "/certsrv/certfnsh.asp", "", "", "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "ipv6",
            [("dhcpv6-dns", "high", "fe80::1", "ff02::1", "offers DNS",
              "{}")],
            db_path=db_path,
        )
        insert_into_database(
            "dbcreds",
            [("redis", "10.0.0.5", "10.0.0.20", "", "s3cret!!",
              "redis-cleartext", "abc123", "")],
            db_path=db_path,
        )

        out = os.path.join(tmp, "out")
        write_exports(conn, out, pcap_name="seven.pcap")
        with open(os.path.join(out, "kerberoast-hashes.txt"), encoding="utf-8") as handle:
            assert hash_line in handle.read()
        with open(os.path.join(out, "tokens.tsv"), encoding="utf-8") as handle:
            tokens = handle.read()
        assert "s.SECR…2345" in tokens
        assert "s.SECRETVALUE12345" not in tokens  # redacted export
        with open(os.path.join(out, "db-creds.tsv"), encoding="utf-8") as handle:
            assert "s3cret!!" in handle.read()

        with open(os.path.join(out, "leads.json"), encoding="utf-8") as handle:
            ids = [lead["id"] for lead in json.load(handle)["leads"]]
        for prefix in ("KERBEROAST-", "TOKEN-", "COERCE-", "ADCS-", "IPV6-", "DB-"):
            assert any(lead.startswith(prefix) for lead in ids), prefix
        conn.close()
