"""Shared severity labels for quick wins (issue #39).

Used by the quick-win scan (stored in the database) and by the lead builder, so
the ranking is identical everywhere.
"""

from typing import Tuple

QUICK_WIN_SEVERITY = {
    "SMB_SIGNING_MISSING": ("critical", "SMB signing disabled -> NTLM relay to SMB is possible"),
    "LDAP_SIGNING_MISSING": ("high", "LDAP signing/channel binding not enforced -> relay to LDAP"),
    "SMBv1": ("high", "SMBv1 present -> legacy exploitation surface (EternalBlue-class)"),
    "TLS1.0": ("medium", "TLS 1.0 in use"),
    "SSLv2": ("high", "SSLv2 in use"),
    "SSLv3": ("high", "SSLv3 in use (POODLE-class)"),
    "SNMPv1": ("medium", "SNMPv1 in use -> community strings readable"),
    "SNMPv2": ("medium", "SNMPv2c in use -> community strings readable"),
    "LLMNR": ("medium", "LLMNR observed -> poisoning/relay of name resolution"),
    "NETBIOS": ("medium", "NetBIOS name service observed -> poisoning surface"),
    "MDNS": ("low", "mDNS observed"),
    "SYSLOG": ("low", "Syslog in clear text"),
    "TFTP": ("medium", "TFTP in use (no authentication)"),
}

CLEARTEXT_PROTOCOLS = {"FTP", "TELNET", "SMTP", "IMAP", "POP3", "HTTP", "LDAP"}

DEFAULT_SEVERITY = ("low", "protocol observed")


def severity_for(protocol: str) -> Tuple[str, str]:
    return QUICK_WIN_SEVERITY.get(protocol, DEFAULT_SEVERITY)
