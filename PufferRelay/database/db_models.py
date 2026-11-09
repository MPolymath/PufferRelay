# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import logging
from PufferRelay.config import get_db_name
from .db_version import migrate_database, set_db_schema_version

def create_database(db_path=None):
    """Creates (or migrates) the SQLite database with all protocol tables."""
    conn = None
    try:
        conn = sqlite3.connect(db_path or get_db_name())
        if not migrate_database(conn):
            conn.close()
            return None
        cursor = conn.cursor()

        # Create LDAP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ldap_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                ldap_name TEXT,
                ldap_simple TEXT,
                UNIQUE(source_ip, destination_ip, ldap_name, ldap_simple)
            )
        """)

        # Create HTTP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS http_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                http_url TEXT,
                http_form TEXT,
                http_auth_username TEXT,
                http_auth_password TEXT,
                UNIQUE(source_ip, destination_ip, http_url, http_form, http_auth_username, http_auth_password)
            )
        """)

        # Create FTP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ftp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                ftp_request_command TEXT,
                ftp_request_arg TEXT,
                UNIQUE(source_ip, destination_ip, ftp_request_command, ftp_request_arg)
            )
        """)

        # Create Telnet requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telnet_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                telnet_data TEXT,
                UNIQUE(source_ip, destination_ip, telnet_data)
            )
        """)

        # Create SMTP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS smtp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                smtp_user TEXT,
                smtp_password TEXT,
                UNIQUE(source_ip, destination_ip, smtp_user, smtp_password)
            )
        """)

        # Create IP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet TEXT,
                ip TEXT,
                UNIQUE(subnet, ip)
            )
        """)

        # Create NTLM requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ntlm_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                ntlm_hash TEXT,
                UNIQUE(source_ip, destination_ip, username, ntlm_hash)
            )
        """)

        # Create NetBIOS requests table (columns match insert_into_database)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS netbios_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_workgroup TEXT,
                hostname TEXT,
                other_service TEXT,
                src_ip TEXT,
                src_mac TEXT,
                service_type TEXT,
                UNIQUE(domain_workgroup, hostname, other_service, src_ip, src_mac, service_type)
            )
        """)

        # Create IMAP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS imap_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                password TEXT,
                UNIQUE(source_ip, destination_ip, username, password)
            )
        """)

        # Create POP3 requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pop3_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                password TEXT,
                UNIQUE(source_ip, destination_ip, username, password)
            )
        """)

        # Create SNMP requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snmp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                community_string TEXT,
                UNIQUE(source_ip, destination_ip, community_string)
            )
        """)

        # Create carved file objects (issue #57)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS captured_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                sha256 TEXT UNIQUE,
                data BLOB
            )
        """)

        # Create NAC / 802.1X observations (issue #30)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nac_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                identity TEXT,
                src TEXT,
                dst TEXT,
                method TEXT,
                mab INTEGER DEFAULT 0,
                UNIQUE(kind, identity, src, dst, method, mab)
            )
        """)

        # Create WSUS endpoint observations (issue #14)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wsus_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                host TEXT,
                uri TEXT,
                user_agent TEXT,
                indicator TEXT,
                UNIQUE(src_ip, dst_ip, host, uri, user_agent, indicator)
            )
        """)

        # Create SMB share/file activity (issue #44)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS smb_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                share TEXT,
                file TEXT,
                operation TEXT,
                printer INTEGER DEFAULT 0,
                UNIQUE(src_ip, dst_ip, share, file, operation, printer)
            )
        """)

        # Create NTLM relay candidates (issue #62)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS relay_scenarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                username TEXT,
                signing_required INTEGER,
                candidate INTEGER,
                UNIQUE(src_ip, dst_ip, dst_port, protocol, username, candidate)
            )
        """)

        # Create AS-REP roasting candidates (issue #61)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kerberos_asrep (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                realm TEXT,
                etype TEXT,
                hash TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                UNIQUE(username, realm, hash)
            )
        """)

        # Create observed services table (dst ip/port seen in the capture)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS observed_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                service TEXT,
                transport TEXT,
                UNIQUE(ip, port, transport)
            )
        """)

        # DNS queries/answers observed in the capture (issues #11 / #59).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                query_name TEXT,
                query_type TEXT,
                answer TEXT,
                is_response INTEGER,
                UNIQUE(src_ip, dst_ip, query_name, query_type, answer, is_response)
            )
        """)

        # Create Quick Wins table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quick_wins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT UNIQUE,
                found BOOLEAN DEFAULT FALSE,
                details TEXT,
                credentials_found BOOLEAN DEFAULT FALSE,
                credential_protocols TEXT,
                severity TEXT,
                evidence TEXT
            )
        """)

        # Initialize Quick Wins table with all protocols
        protocols = [
            # Unencrypted protocols
            ('LDAP', False, '', False, ''),
            ('HTTP', False, '', False, ''),
            ('FTP', False, '', False, ''),
            ('TELNET', False, '', False, ''),
            ('SMTP', False, '', False, ''),
            ('IMAP', False, '', False, ''),
            ('POP3', False, '', False, ''),
            ('SYSLOG', False, '', False, ''),
            ('TFTP', False, '', False, ''),
            # Deprecated protocols
            ('SNMPv1', False, '', False, ''),
            ('SNMPv2', False, '', False, ''),
            ('SMBv1', False, '', False, ''),
            ('TLS1.0', False, '', False, ''),
            ('SSLv2', False, '', False, ''),
            ('SSLv3', False, '', False, ''),
            # Multicast protocols
            ('LLMNR', False, '', False, ''),
            ('NETBIOS', False, '', False, ''),
            ('MDNS', False, '', False, ''),
            # Security issues
            ('LDAP_SIGNING_MISSING', False, '', False, ''),
            ('LDAP_SIGNING_ENFORCED', False, '', False, ''),
            ('SMB_SIGNING_MISSING', False, '', False, '')
        ]
        
        cursor.executemany("""
            INSERT OR IGNORE INTO quick_wins (protocol, found, details, credentials_found, credential_protocols)
            VALUES (?, ?, ?, ?, ?)
        """, protocols)

        # Set the schema version
        set_db_schema_version(conn)

        # Verify all tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        if not tables:
            logging.error("No tables were created in the database")
            return None
            
        return conn

    except sqlite3.Error as e:
        logging.error(f"Database error: {str(e)}")
        if conn:
            conn.close()
        return None
    except Exception as e:
        logging.error(f"Unexpected error while creating database: {str(e)}")
        if conn:
            conn.close()
        return None