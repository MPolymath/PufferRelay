"""HTTP bearer/JWT/API token extraction (issue #70) — passive.

Basic auth and form credentials were already handled. This module covers the
modern secret shapes: Authorization: Bearer, JWTs, Vault/GitLab headers, cloud
and CI tokens, and session cookies. The full value is kept in the local
database; exports and leads only carry a fingerprint unless the operator asks
for more (the export pack is already confidential).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from PufferRelay.tshark_fields import fields

JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
PATTERNS = [
    ("github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
]
HEADER_KINDS = {
    "x-vault-token": "vault",
    "private-token": "gitlab",
    "x-gitlab-token": "gitlab",
    "x-api-key": "api-key",
    "x-auth-token": "api-key",
}
SEVERITY = {
    "aws": "critical",
    "github": "critical",
    "gitlab": "critical",
    "vault": "critical",
    "jwt": "high",
    "bearer": "high",
    "api-key": "high",
    "slack": "high",
    "stripe": "high",
    "cookie": "medium",
}
COOKIE_NAME = re.compile(r"^(.*(?:session|sess|auth|token|jwt).*)$", re.I)


def _b64url(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token):
    """Return (principal, expires, claims) without verifying the signature."""
    try:
        parts = token.split(".")
        claims = json.loads(_b64url(parts[1]).decode("utf-8", "replace"))
    except (ValueError, IndexError, UnicodeDecodeError):
        return "", "", {}
    if not isinstance(claims, dict):
        return "", "", {}
    principal = str(
        claims.get("upn")
        or claims.get("preferred_username")
        or claims.get("unique_name")
        or claims.get("sub")
        or ""
    )
    expires = ""
    exp = claims.get("exp")
    if isinstance(exp, int):
        from datetime import datetime, timezone

        expires = datetime.fromtimestamp(exp, timezone.utc).date().isoformat()
    return principal, expires, claims


def fingerprint(token):
    if len(token) > 16:
        return f"{token[:6]}…{token[-4:]}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _header_block(payload_text):
    """Split a raw HTTP message into lower-cased header name -> value."""
    head = payload_text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    headers = {}
    for line in head.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if not name or " " in name:
            continue
        headers[name] = value.strip()
    return headers


def _payload_text(hex_payload):
    text = (hex_payload or "").replace(":", "").strip()
    if not text or len(text) % 2:
        return ""
    try:
        return bytes.fromhex(text).decode("latin-1", "replace")
    except ValueError:
        return ""


def _candidate_secrets(headers, body):
    """Yield (kind, token, header_name) from headers and body."""
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        yield "bearer", authorization.split(None, 1)[1].strip(), "authorization"
    proxy = headers.get("proxy-authorization", "")
    if proxy.lower().startswith("bearer "):
        yield "bearer", proxy.split(None, 1)[1].strip(), "proxy-authorization"

    for name, kind in HEADER_KINDS.items():
        value = headers.get(name)
        if value:
            yield kind, value, name

    for name, value in headers.items():
        if name == "set-cookie" or name == "cookie":
            for cookie in value.split(";"):
                if "=" not in cookie:
                    continue
                cookie_name, cookie_value = cookie.split("=", 1)
                if COOKIE_NAME.match(cookie_name.strip()) and len(cookie_value.strip()) >= 8:
                    yield "cookie", cookie_value.strip(), cookie_name.strip()

    haystack = " ".join(headers.values()) + " " + body
    for token in JWT.findall(haystack):
        yield "jwt", token, "body"
    for kind, pattern in PATTERNS:
        for token in pattern.findall(haystack):
            yield kind, token, "body"

    for key in ("access_token", "refresh_token", "api_key", "apikey", "token"):
        for match in re.finditer(
            rf'"{key}"\s*:\s*"([^"\\]{{12,}})"', body, re.I
        ):
            yield "api-key", match.group(1), key


def process_http_tokens(pcap_file):
    rows = fields(
        pcap_file,
        "http.request || http.response",
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri",
            "tcp.payload",
            "http.file_data",
        ],
    )
    out = []
    seen = set()
    for src, dst, host, uri, payload, file_data in rows:
        text = _payload_text(payload)
        if not text:
            continue
        headers = _header_block(text)
        body = _payload_text(file_data)
        if not body:
            parts = text.split("\r\n\r\n", 1)
            body = parts[1] if len(parts) > 1 else ""
        host = (host or headers.get("host") or "").strip()
        path = (uri or "").strip()
        for kind, token, header in _candidate_secrets(headers, body):
            if len(token) < 8:
                continue
            principal, expires, claims = ("", "", {})
            if kind == "jwt":
                principal, expires, claims = decode_jwt(token)
                if not claims:
                    continue
            mark = fingerprint(token)
            key = (kind, mark, host)
            if key in seen:
                continue
            seen.add(key)
            severity = SEVERITY.get(kind, "high")
            out.append(
                (
                    kind,
                    severity,
                    host,
                    path,
                    header,
                    token,
                    mark,
                    principal,
                    expires,
                    src or "",
                    dst or "",
                )
            )
    return out
