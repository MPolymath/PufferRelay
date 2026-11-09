"""Database authentication material (issue #69) — passive.

Redis AUTH is cleartext RESP; MySQL exposes the login username and response
scramble; PostgreSQL exposes startup parameters, cleartext password auth and
MD5/SASL material. MSSQL is already covered by the NTLM handler.
"""

from __future__ import annotations

import hashlib
import re

from PufferRelay.tshark_fields import fields

REDIS_AUTH = re.compile(r"(?i)\bAUTH\r?\n?\$\d+\r?\n([^\r\n]+)")
REDIS_INLINE = re.compile(r"(?i)^\s*AUTH\s+(\S+)\s*$", re.M)


def fingerprint(secret):
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def _decode(hex_payload):
    text = (hex_payload or "").replace(":", "").strip()
    if not text or len(text) % 2:
        return ""
    try:
        return bytes.fromhex(text).decode("latin-1", "replace")
    except ValueError:
        return ""


def _redis_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "tcp.port == 6379",
        ["ip.src", "ip.dst", "tcp.payload"],
    )
    for src, dst, payload in rows:
        text = _decode(payload)
        if not text:
            continue
        match = REDIS_AUTH.search(text) or REDIS_INLINE.search(text.replace("\r", ""))
        if not match:
            continue
        password = match.group(1).strip()
        if not password:
            continue
        out.append(
            (
                "redis",
                src or "",
                dst or "",
                "",
                password,
                "redis-cleartext",
                fingerprint(password),
                "",
            )
        )
    return out


def _mysql_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "mysql",
        ["ip.src", "ip.dst", "mysql.user", "mysql.passwd", "mysql.command"],
    )
    for src, dst, user, passwd, command in rows:
        user = (user or "").strip()
        secret = (passwd or "").strip()
        if not user or not secret:
            continue
        out.append(
            (
                "mysql",
                src or "",
                dst or "",
                user,
                secret,
                "mysql-native-response",
                fingerprint(secret),
                "",
            )
        )
    return out


def _postgres_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "pgsql",
        [
            "ip.src",
            "ip.dst",
            "pgsql.parameter_name",
            "pgsql.parameter_value",
            "pgsql.password",
            "pgsql.authtype",
            "pgsql.salt",
            "pgsql.auth.sasl.mech",
        ],
    )
    pending = {}
    for src, dst, name, value, password, authtype, salt, mech in rows:
        key = (src, dst)
        params = pending.setdefault(key, {})
        if name and value:
            params[(name or "").strip().lower()] = (value or "").strip()
        user = params.get("user", "")
        database = params.get("database", "")
        secret = (password or "").strip()
        auth = str(authtype or "").strip()
        if secret:
            kind = "pg-cleartext" if auth == "3" else "pg-password"
            out.append(
                (
                    "postgres",
                    src or "",
                    dst or "",
                    user,
                    secret,
                    kind,
                    fingerprint(secret),
                    database,
                )
            )
            continue
        if auth == "5" and salt:
            # md5 response is the `pgsql.password` field in older captures;
            # keep the salt as evidence even without a response.
            pass
        if mech and mech.upper().startswith("SCRAM"):
            out.append(
                (
                    "postgres",
                    src or "",
                    dst or "",
                    user,
                    "",
                    "pg-scram-mech",
                    "",
                    database,
                )
            )
    return out


def process_database_auth(pcap_file):
    rows = _redis_pass(pcap_file) + _mysql_pass(pcap_file) + _postgres_pass(pcap_file)
    deduped = []
    seen = set()
    for row in rows:
        key = (row[0], row[1], row[2], row[3], row[6])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
