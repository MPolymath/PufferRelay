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
from PufferRelay.config import DB_NAME
from .db_version import check_database_version, set_db_schema_version

def create_database():
    """Creates an SQLite database with tables for storing various protocol requests."""
    # Check database version first
    if not check_database_version():
        logging.error("Database version check failed. Exiting.")
        return None
        
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
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

        # Create NetBIOS requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS netbios_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_workgroup TEXT,
                hostname TEXT,
                ip TEXT,
                mac TEXT,
                UNIQUE(domain_workgroup, hostname, ip, mac)
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

        # Create Quick Wins table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quick_wins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT UNIQUE,
                found BOOLEAN DEFAULT FALSE,
                details TEXT,
                credentials_found BOOLEAN DEFAULT FALSE,
                credential_protocols TEXT
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