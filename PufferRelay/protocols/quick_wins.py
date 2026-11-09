import json
import logging

from PufferRelay.database.db_queries import update_quick_win
from PufferRelay.severity import CLEARTEXT_PROTOCOLS, severity_for
from PufferRelay.tshark_fields import fields

# One tshark pass over the protocols that quick wins care about (#55).
WINDOW_FILTER = (
    "ldap || http || ftp || telnet || smtp || imap || pop || syslog || tftp || "
    "snmp || smb || smb2 || ssl || llmnr || nbns || mdns"
)

WINDOW_FIELDS = [
    "ip.src",
    "ip.dst",
    "frame.protocols",
    "ldap.simple",
    "http.authorization",
    "http.request.method",
    "http.file_data",
    "ftp.request.command",
    "telnet.data",
    "smtp.auth.username",
    "smtp.auth.password",
    "imap.request.command",
    "pop.request.command",
    "snmp.version",
    "smb2.sec_mode.sign_required",
    "tls.record.version",
]

CREDENTIAL_PROTOCOLS = {"LDAP", "HTTP", "FTP", "TELNET", "SMTP", "IMAP", "POP3"}

SSL_VERSIONS = {
    "0x0301": "TLS1.0",
    "0x0300": "SSLv3",
    "0x0002": "SSLv2",
}

SNMP_VERSIONS = {
    "0": "SNMPv1",
    "v1": "SNMPv1",
    "version-1": "SNMPv1",
    "1": "SNMPv2",
    "v2": "SNMPv2",
    "v2c": "SNMPv2",
    "version-2": "SNMPv2",
}


def _tokens(value):
    return {token for token in (value or "").lower().split(":") if token}


def _has_credential_words(text):
    lowered = (text or "").lower()
    return any(word in lowered for word in ("user", "pass", "pwd", "login", "auth"))


def findings_from_rows(rows):
    """Classify tshark rows.

    Returns (found protocols, credential protocols, smb signing missing,
    evidence dict). Pure function so the logic is testable without tshark.
    """
    found = set()
    credentials = set()
    smb_signing_missing = False
    evidence = {}

    def note(protocol, src, dst):
        entry = evidence.setdefault(
            protocol, {"count": 0, "sources": set(), "destinations": set()}
        )
        entry["count"] += 1
        if src:
            entry["sources"].add(src)
        if dst:
            entry["destinations"].add(dst)

    for row in rows:
        values = list(row) + [""] * (len(WINDOW_FIELDS) - len(row))
        (
            src_ip,
            dst_ip,
            protocols,
            ldap_simple,
            http_authorization,
            _http_method,
            http_form,
            ftp_command,
            telnet_data,
            smtp_user,
            smtp_password,
            imap_command,
            pop_command,
            snmp_version,
            smb_signing_required,
            ssl_version,
        ) = values[: len(WINDOW_FIELDS)]
        tokens = _tokens(protocols)

        if "ldap" in tokens:
            found.add("LDAP")
            note("LDAP", src_ip, dst_ip)
            if (ldap_simple or "").strip():
                credentials.add("LDAP")

        if "http" in tokens:
            found.add("HTTP")
            note("HTTP", src_ip, dst_ip)
            if (http_authorization or "").strip() or (
                (http_form or "").strip() and _has_credential_words(http_form)
            ):
                credentials.add("HTTP")

        if "ftp" in tokens or "ftp-data" in tokens:
            found.add("FTP")
            note("FTP", src_ip, dst_ip)
            if (ftp_command or "").upper() in {"USER", "PASS"}:
                credentials.add("FTP")

        if "telnet" in tokens:
            found.add("TELNET")
            note("TELNET", src_ip, dst_ip)
            if _has_credential_words(telnet_data):
                credentials.add("TELNET")

        if "smtp" in tokens:
            found.add("SMTP")
            note("SMTP", src_ip, dst_ip)
            if (smtp_user or "").strip() or (smtp_password or "").strip():
                credentials.add("SMTP")

        if "imap" in tokens:
            found.add("IMAP")
            note("IMAP", src_ip, dst_ip)
            if (imap_command or "").lower() in {"login", "authenticate"}:
                credentials.add("IMAP")

        if "pop" in tokens:
            found.add("POP3")
            note("POP3", src_ip, dst_ip)
            if (pop_command or "").upper() in {"USER", "PASS", "APOP"}:
                credentials.add("POP3")

        if "syslog" in tokens:
            found.add("SYSLOG")
            note("SYSLOG", src_ip, dst_ip)
        if "tftp" in tokens:
            found.add("TFTP")
            note("TFTP", src_ip, dst_ip)

        if "snmp" in tokens:
            version = (snmp_version or "").strip().lower()
            if version in SNMP_VERSIONS:
                found.add(SNMP_VERSIONS[version])
                note(SNMP_VERSIONS[version], src_ip, dst_ip)

        if "smb" in tokens and "smb2" not in tokens:
            found.add("SMBv1")
            note("SMBv1", src_ip, dst_ip)

        if "llmnr" in tokens:
            found.add("LLMNR")
            note("LLMNR", src_ip, dst_ip)
        if "nbns" in tokens or "netbios" in tokens:
            found.add("NETBIOS")
            note("NETBIOS", src_ip, dst_ip)
        if "mdns" in tokens:
            found.add("MDNS")
            note("MDNS", src_ip, dst_ip)

        if "ssl" in tokens:
            version = (ssl_version or "").strip().lower()
            if version in SSL_VERSIONS:
                found.add(SSL_VERSIONS[version])
                note(SSL_VERSIONS[version], src_ip, dst_ip)

        if "smb2" in tokens:
            signing = (smb_signing_required or "").strip().lower()
            if signing in {"0", "false"}:
                smb_signing_missing = True
                note("SMB_SIGNING_MISSING", src_ip, dst_ip)

    if smb_signing_missing:
        found.add("SMB_SIGNING_MISSING")

    evidence_json = {}
    for protocol, entry in evidence.items():
        evidence_json[protocol] = {
            "count": entry["count"],
            "sources": sorted(entry["sources"])[:5],
            "destinations": sorted(entry["destinations"])[:5],
        }
    return found, credentials, smb_signing_missing, evidence_json


def analyze_quick_wins(pcap_file, conn):
    """Analyze a capture for unencrypted protocols, weak versions and creds.

    Uses a single tshark field extraction pass instead of regexing every packet
    (the previous implementation took minutes on multi-hundred-MB captures).
    Severity and evidence (counts + sample endpoints) are stored with each flag.
    """
    try:
        rows = fields(pcap_file, WINDOW_FILTER, WINDOW_FIELDS)
    except RuntimeError as e:
        logging.error("Quick-win scan skipped: %s", e)
        return

    (
        found_protocols,
        credential_protocols,
        smb_signing_missing,
        evidence,
    ) = findings_from_rows(rows)

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT protocol, found, details, credentials_found, credential_protocols "
            "FROM quick_wins"
        )
        current_state = {row[0]: row[1:] for row in cursor.fetchall()}

        for protocol in current_state:
            current_found, current_details, current_credentials_found, current_protocols = (
                current_state[protocol]
            )

            found = current_found or (protocol in found_protocols)

            credentials_found = current_credentials_found
            if protocol in CREDENTIAL_PROTOCOLS:
                credentials_found = current_credentials_found or (
                    protocol in credential_protocols
                )

            current_set = set(current_protocols.split(",")) if current_protocols else set()
            new_set = current_set.union(
                {protocol} if protocol in credential_protocols else set()
            )
            credential_protocols_str = ",".join(sorted(new_set)) if new_set else ""

            details = current_details
            if protocol in found_protocols:
                if protocol == "SMB_SIGNING_MISSING" and smb_signing_missing:
                    details = "SMB signing not required"
                elif protocol in credential_protocols:
                    details = "Credentials found in traffic"
                else:
                    details = "Protocol found in traffic"

            severity, _why = severity_for(protocol)
            if credentials_found and protocol in CLEARTEXT_PROTOCOLS:
                severity = "critical"
            update_quick_win(
                conn,
                protocol,
                found=found,
                details=details,
                credentials_found=credentials_found,
                credential_protocols=(
                    credential_protocols_str.split(",") if credential_protocols_str else None
                ),
                severity=severity,
                evidence=json.dumps(evidence[protocol]) if protocol in evidence else None,
            )

            logging.info(
                "Updated quick win for %s: found=%s, credentials=%s, severity=%s",
                protocol,
                found,
                credentials_found,
                severity,
            )
    except Exception as e:
        logging.error("Error analyzing quick wins: %s", str(e))
        raise
