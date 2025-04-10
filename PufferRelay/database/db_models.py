from PufferRelay.core_imports import sqlite3

def create_database():
    """Creates an SQLite database with a table for storing LDAP bind requests."""
    conn = sqlite3.connect("ldap_bind_requests.db")
    cursor = conn.cursor()

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telnet_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            telnet_data TEXT,
            UNIQUE(source_ip, destination_ip, telnet_data)
        )
    """)

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet TEXT,
            ip TEXT,
            UNIQUE(subnet, ip)
        )
    """)

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

    conn.commit()
    conn.close()