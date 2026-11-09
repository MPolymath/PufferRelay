"""Shared protocol logic (no pyshark).

These helpers are used by the field-based handlers, the export layer and the
CLI. Keeping them here let the legacy pyshark handler modules be removed
(issue #53).
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Optional

# ------------------------------------------------------------------ HTTP

def clean_http_data(data: str) -> str:
    """Remove line breaks and collapse whitespace in HTTP values."""
    if data == "N/A":
        return data
    data = data.replace("\r", " ").replace("\n", " ")
    data = re.sub(r"\s+", " ", data)
    return data.strip()


def decode_basic_auth(auth_header: str):
    """Decode an HTTP Basic Authorization header to (user, password)."""
    try:
        if not auth_header or "Basic " not in auth_header:
            return None, None
        auth_string = auth_header.split("Basic ")[1]
        decoded = base64.b64decode(auth_string).decode("utf-8")
        username, password = decoded.split(":", 1)
        return clean_http_data(username), clean_http_data(password)
    except (IndexError, UnicodeDecodeError, binascii.Error):
        return None, None


# --------------------------------------------------------------- NetBIOS

NETBIOS_SERVICE_TYPES = {
    "0": "Workstation Service",
    "3": "Messenger Service",
    "32": "File Server Service (SMB)",
    "27": "Domain Master Browser",
    "28": "Domain Controllers (Group)",
    "29": "Master Browser",
    "30": "Browser Service Elections",
    "31": "NetDDE Service",
}


def get_service_type(hex_type: str) -> str:
    return NETBIOS_SERVICE_TYPES.get(
        (hex_type or "").upper(), f"Unknown Service ({hex_type})"
    )


# -------------------------------------------------------------------- SMB

INTERESTING_EXTENSIONS = {
    ".config", ".xml", ".json", ".ps1", ".bat", ".cmd", ".vbs", ".ini", ".conf",
    ".key", ".pem", ".pfx", ".p12", ".kdbx", ".zip", ".7z", ".rar", ".tar",
    ".gz", ".sql", ".bak", ".old", ".txt", ".csv", ".xlsx", ".docx", ".pdf",
}


def normalise_share(value: str) -> str:
    """'\\\\host\\share' / 'host\\share' / 'share' -> 'share'."""
    if not value:
        return ""
    text = str(value).strip().strip("\x00")
    text = text.replace("/", "\\").strip("\\")
    if "\\" in text:
        text = text.split("\\")[-1]
    return text


def normalise_file(value: str) -> str:
    if not value:
        return ""
    return str(value).strip().strip("\x00")


def is_printer(share: str, file_name: str) -> bool:
    share_l = (share or "").lower()
    file_l = (file_name or "").lower()
    if share_l in {"print$", "printers"} or share_l.endswith("print$"):
        return True
    return file_l.endswith((".shd", ".spl", ".emf")) or ".spl" in file_l


def interesting_file(file_name: str) -> bool:
    name = (file_name or "").lower()
    return any(name.endswith(extension) for extension in INTERESTING_EXTENSIONS)


# ------------------------------------------------------------------ relay

SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 3268}
HTTP_PORTS = {80, 8080, 5985, 8000, 8888}


def classify(protocol: str, signing_required: Optional[bool]) -> bool:
    """Would this endpoint accept a relayed NTLM authentication?"""
    if protocol == "smb":
        return signing_required is not True
    if protocol in {"ldap", "http"}:
        return True
    return False


def protocol_for_port(port: Optional[int], has_http: bool = False) -> str:
    if port in SMB_PORTS:
        return "smb"
    if port in LDAP_PORTS:
        return "ldap"
    if has_http or port in HTTP_PORTS:
        return "http"
    return "unknown"


def smb_signing_missing_hosts(rows) -> list:
    """Destination IPs where NTLM was seen over SMB with signing not required."""
    hosts = set()
    for row in rows:
        try:
            _src, dst, _port, protocol, _user, signing, _candidate = row
        except (TypeError, ValueError):
            continue
        if protocol == "smb" and str(signing) == "0":
            hosts.add(str(dst))
    return sorted(hosts)


# --------------------------------------------------------------- Kerberos

def normalise_hex(value) -> str:
    """tshark hex fields arrive as 'aa:bb:..' or 'aabb..'; return lowercase hex."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    for separator in (":", " ", "-"):
        text = text.replace(separator, "")
    if text.startswith("0x"):
        text = text[2:]
    try:
        int(text or "0", 16)
    except ValueError:
        return ""
    return text


def asrep_hash(username: str, realm: str, etype, cipher_hex: str):
    """Build the hashcat 18200 line, or None when the cipher is unusable."""
    if not username or not realm:
        return None
    cipher = normalise_hex(cipher_hex)
    if len(cipher) < 64:
        return None
    try:
        etype_text = str(int(etype))
    except (TypeError, ValueError):
        etype_text = "23"
    return f"$krb5asrep${etype_text}${username}@{realm}:{cipher[:32]}${cipher[32:]}"
