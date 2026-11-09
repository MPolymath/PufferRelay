"""Database authentication material (issue #69, step 3) — one pass, hash formats.

Redis AUTH is cleartext RESP. MySQL exposes the greeting salt and the login
response, which form a MySQL CRAM (hashcat 11200) line. PostgreSQL exposes
startup parameters plus clear-text, MD5 challenge-response (hashcat 12) or
SCRAM mechanism. One tshark pass covers all three protocols.
"""

from __future__ import annotations

import hashlib
import re

from PufferRelay.tshark_fields import fields

FILTER = "tcp.port == 6379 || mysql || pgsql"
FIELDS = [
    "ip.src",
    "ip.dst",
    "tcp.port",
    "tcp.payload",
    "mysql.user",
    "mysql.passwd",
    "mysql.salt",
    "pgsql.parameter_name",
    "pgsql.parameter_value",
    "pgsql.password",
    "pgsql.authtype",
    "pgsql.salt",
    "pgsql.auth.sasl.mech",
]
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


def _port(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def process_database_auth(pcap_file):
    rows = fields(pcap_file, FILTER, FIELDS)
    out = []
    seen = set()
    mysql_salts = {}
    pg_salts = {}
    pg_params = {}

    def add(protocol, src, dst, user, secret, kind, hashcat, server):
        mark = fingerprint(secret)
        key = (protocol, src, dst, user, mark)
        if key in seen:
            return
        seen.add(key)
        out.append(
            (protocol, src or "", dst or "", user or "", secret or "", kind,
             mark, server or "", hashcat)
        )

    for row in rows:
        padded = tuple(row) + ("",) * (13 - len(row))
        (
            src,
            dst,
            port_text,
            payload,
            mysql_user,
            mysql_pass,
            mysql_salt,
            pg_name,
            pg_value,
            pg_password,
            pg_auth,
            pg_salt,
            pg_mech,
        ) = padded[:13]
        port = _port(port_text)

        if port == 6379:
            text = _decode(payload)
            if text:
                match = REDIS_AUTH.search(text) or REDIS_INLINE.search(
                    text.replace("\r", "")
                )
                if match and match.group(1).strip():
                    add("redis", src, dst, "", match.group(1).strip(),
                        "redis-cleartext", "", "")

        if (mysql_salt or "").strip() and not (mysql_user or "").strip():
            mysql_salts[(src, dst)] = mysql_salt.strip()
        if (mysql_user or "").strip() and (mysql_pass or "").strip():
            salt = (mysql_salt or "").strip() or mysql_salts.get((dst, src), "")
            if salt:
                secret = f"$mysqlna${salt}${mysql_pass.strip()}"
                add("mysql", src, dst, mysql_user.strip(), secret,
                    "mysql-cram", "11200", "")
            else:
                add("mysql", src, dst, mysql_user.strip(), mysql_pass.strip(),
                    "mysql-response", "", "")

        if (pg_name or "").strip():
            params = pg_params.setdefault((src, dst), {})
            params[(pg_name or "").strip().lower()] = (pg_value or "").strip()
        user = pg_params.get((src, dst), {}).get("user", "")
        database = pg_params.get((src, dst), {}).get("database", "")
        auth = str(pg_auth or "").strip()
        salt = (pg_salt or "").strip()
        if salt and auth == "5":
            pg_salts[(src, dst)] = salt
        if (pg_password or "").strip():
            if auth == "5":
                salt = salt or pg_salts.get((dst, src), "")
                response = pg_password.strip()
                if response.lower().startswith("md5"):
                    response = response[3:]
                if salt:
                    secret = f"$postgres$*{user}*{salt}*{response}"
                    add("postgres", src, dst, user, secret, "pg-md5", "12",
                        database)
                else:
                    add("postgres", src, dst, user, pg_password.strip(),
                        "pg-md5-response", "12", database)
            elif auth == "3":
                add("postgres", src, dst, user, pg_password.strip(),
                    "pg-cleartext", "", database)
            else:
                add("postgres", src, dst, user, pg_password.strip(),
                    "pg-password", "", database)
        elif (pg_mech or "").upper().startswith("SCRAM"):
            add("postgres", src, dst, user, "", "pg-scram-mech", "", database)

    return out
