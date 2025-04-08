from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import sys
from PufferRelay.core_imports import tabulate
from PufferRelay.core_imports import logging

def insert_into_database(protocol, data):
    """Inserts extracted pertinent information into the database, ensuring uniqueness."""
    
    conn = sqlite3.connect("ldap_bind_requests.db")
    cursor = conn.cursor()
    
    # Insert only if the combination does not already exist
    if protocol=="ldap":
        cursor.executemany("""
            INSERT OR IGNORE INTO ldap_requests (source_ip, destination_ip, ldap_name, ldap_simple)
            VALUES (?, ?, ?, ?)
        """, data)
    elif protocol=="http":
        cursor.executemany("""
            INSERT OR IGNORE INTO http_requests (source_ip, destination_ip, http_url, http_form, http_auth_username, http_auth_password)
            VALUES (?, ?, ?, ?, ?, ?)
        """, data)
    elif protocol=="ftp":
        cursor.executemany("""
            INSERT OR IGNORE INTO ftp_requests (source_ip, destination_ip, ftp_request_command, ftp_request_arg)
            VALUES (?, ?, ?, ?)
        """, data)
    elif protocol=="telnet":
        cursor.executemany("""
            INSERT OR IGNORE INTO telnet_requests (source_ip, destination_ip, telnet_data)
            VALUES (?, ?, ?)
        """, data)
    elif protocol=="smtp":
        cursor.executemany("""
            INSERT OR IGNORE INTO smtp_requests (source_ip, destination_ip, smtp_user, smtp_password)
            VALUES (?, ?, ?, ?)
        """, data)
    elif protocol=="ips":
        cursor.executemany("""
            INSERT OR IGNORE INTO ip_requests (subnet, ip)
            VALUES (?, ?)
        """, data)
    elif protocol=="ntlm":
        cursor.executemany("""
            INSERT OR IGNORE INTO ntlm_requests (source_ip, destination_ip, username, ntlm_hash)
            VALUES (?, ?, ?, ?)
        """, data)

    conn.commit()
    conn.close()

def store_data(protocol: str, data):
    """
    Stores extracted protocol data into the database and prints confirmation.

    Args:
        protocol (str): The name of the protocol (e.g., 'ldap', 'http', 'ftp').
        data: Extracted data related to the protocol.
    """
    if data:
        insert_into_database(protocol, data)
        print(f"{protocol.upper()} data successfully stored in the database.")

def process_extracted_data(parsed_data):
    """
    Processes extracted protocol data and stores it if available.

    Args:
        ldap_data: Extracted LDAP data.
        http_data: Extracted HTTP data.
        ftp_data: Extracted FTP data.
    """
    for protocol, data in parsed_data.items():
        if data:
            store_data(protocol, data)
            logging.info(f"{protocol.upper()} data successfully stored in the database.")

    if not any(parsed_data.values()):
        logging.info("No pertinent requests found.")
        return

def fetch_requests(conn, table_name, columns, protocol, conditions=None):
    """
    Fetch data from a specific database table and return formatted results.

    Args:
        conn (sqlite3.Connection): Active database connection.
        table_name (str): Name of the database table.
        columns (list): Columns to fetch from the table.
        protocol (str): Protocol label to include in results.
        conditions (str, optional): Additional SQL conditions.

    Returns:
        list: Formatted data rows.
    """
    if not conn:
        logging.error("Database connection is not available.")
        return []

    query = f"SELECT '{protocol}', {', '.join(columns)} FROM {table_name}"
    if conditions:
        query += f" WHERE {conditions}"

    try:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Database error while fetching {protocol} data: {e}")
        return []

def display_table(data, headers, protocol):
    """
    Display query results in a table format.

    Args:
        data (list): Data rows to display.
        headers (list): Column headers.
        protocol (str): Protocol name for logging.
    """
    if data:
        print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
    else:
        logging.warning(f"No {protocol} data found.")


def fetch_all_data(conn):
    """
    Fetch and display LDAP, HTTP, FTP, TELNET, SMTP, and IP data from the database.

    Args:
        conn (sqlite3.Connection): Active database connection.
    """
    requests = [
        ("ldap_requests", ["source_ip", "destination_ip", "ldap_name", "ldap_simple"], "LDAP"),
        ("http_requests", ["source_ip", "destination_ip", "http_url", "http_form"], "HTTP"),
        ("ftp_requests", ["source_ip", "destination_ip", "ftp_request_command", "ftp_request_arg"], "FTP", "ftp_request_command IN ('USER', 'PASS')"),
        ("telnet_requests", ["source_ip", "destination_ip", "telnet_data"], "TELNET"),
        ("smtp_requests", ["source_ip", "destination_ip", "smtp_user", "smtp_password"], "SMTP"),
        ("ip_requests", ["subnet", "ip"], "IP") 
    ]

    for request in requests:
        table_name, columns, protocol, *conditions = request
        data = fetch_requests(conn, table_name, columns, protocol, *conditions)
        headers = ["Protocol"] + [col.replace("_", " ").title() for col in columns]
        display_table(data, headers, protocol)