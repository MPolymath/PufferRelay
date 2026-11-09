"""Quick-win classification tests (pure logic + one synthetic capture)."""

import os
import tempfile

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.protocols.quick_wins import analyze_quick_wins, findings_from_rows


def test_findings_from_rows_classifies_protocols_and_creds():
    rows = [
        # protocols, ldap_simple, http_auth, method, form, ftp_cmd, telnet, smtp_u,
        # smtp_p, imap_cmd, pop_cmd, snmp_ver, smb2_flags, ssl_ver
        ("eth:ip:tcp:ldap", "secret", "", "", "", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:http:data", "", "Basic xyz", "POST", "", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:http:data", "", "", "POST", "user=a&password=b", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:ftp", "", "", "", "", "USER", "", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:telnet", "", "", "", "", "", "login: admin password: x", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:smtp", "", "", "", "", "", "", "bob", "hunter2", "", "", "", "", ""),
        ("eth:ip:tcp:imap", "", "", "", "", "", "", "", "", "login", "", "", "", ""),
        ("eth:ip:tcp:pop", "", "", "", "", "", "", "", "", "", "PASS", "", "", ""),
        ("eth:ip:udp:snmp", "", "", "", "", "", "", "", "", "", "", "1", "", ""),
        ("eth:ip:tcp:smb", "", "", "", "", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:tcp:smb2", "", "", "", "", "", "", "", "", "", "", "", "0", ""),
        ("eth:ip:tcp:ssl", "", "", "", "", "", "", "", "", "", "", "", "", "0x0300"),
        ("eth:ip:udp:llmnr", "", "", "", "", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:udp:nbns", "", "", "", "", "", "", "", "", "", "", "", "", ""),
        ("eth:ip:udp:mdns", "", "", "", "", "", "", "", "", "", "", "", "", ""),
    ]
    found, credentials, smb_missing = findings_from_rows(rows)
    assert {"LDAP", "HTTP", "FTP", "TELNET", "SMTP", "IMAP", "POP3", "SMBv1"} <= found
    assert {"SNMPv2", "SSLv3", "LLMNR", "NETBIOS", "MDNS", "SMB_SIGNING_MISSING"} <= found
    assert "TLS1.0" not in found
    assert credentials == {"LDAP", "HTTP", "FTP", "TELNET", "SMTP", "IMAP", "POP3"}
    assert smb_missing is True


def test_findings_no_false_positives():
    found, credentials, smb_missing = findings_from_rows([])
    assert found == set() and credentials == set() and smb_missing is False

    rows = [("eth:ip:tcp:smb2", "", "", "", "", "", "", "", "", "", "", "", "1", "")]
    found, credentials, smb_missing = findings_from_rows(rows)
    assert found == set() and smb_missing is False


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)
def test_analyze_quick_wins_on_synthetic_capture():
    pytest.importorskip("scapy")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    ftp_user = b"USER alice\r\n"
    ftp_pass = b"PASS s3cret\r\n"
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "qw.pcap")
        wrpcap(
            pcap,
            [
                Ether() / IP(src="10.0.0.5", dst="10.0.0.10")
                / TCP(sport=40000, dport=21, flags="PA", seq=1, ack=1) / Raw(load=ftp_user),
                Ether() / IP(src="10.0.0.5", dst="10.0.0.10")
                / TCP(sport=40000, dport=21, flags="PA", seq=20, ack=1) / Raw(load=ftp_pass),
            ],
        )
        db_path = os.path.join(tmp, "qw.db")
        conn = create_database(db_path=db_path)
        analyze_quick_wins(pcap, conn)
        row = conn.execute(
            "SELECT found, credentials_found FROM quick_wins WHERE protocol='FTP'"
        ).fetchone()
        assert row == (1, 1)
        conn.close()
