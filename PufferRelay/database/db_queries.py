from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import sys
from PufferRelay.core_imports import logging
from PufferRelay.core_imports import rich
from rich.table import Table
from rich.console import Console
from rich.text import Text
import re

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

def highlight_form_data(text):
    """
    Highlights sensitive keywords in red.
    
    Args:
        text (str): Text to process
        
    Returns:
        rich.text.Text: Text with highlighted sensitive keywords
    """
    if not isinstance(text, str):
        text = str(text)
        
    # List of sensitive keywords to highlight
    sensitive_keywords = [
        'password', 'pass', 'pwd', 'log', 'login', 'user', 'username',
        'pw', 'passw', 'passwd', 'pass:', 'user:', 'username:', 'password:',
        'login:', 'pass ', 'user ', 'authorization:', 'token', 'api', 'key',
        'uname', '&pass=', '&password=', '&user=', '&username=', '&login='
    ]
    
    # Create a pattern that matches any of the keywords
    pattern = '|'.join(map(re.escape, sensitive_keywords))
    
    # Split the text into parts based on the pattern
    parts = re.split(f'({pattern})', text, flags=re.IGNORECASE)
    
    # Create a Rich Text object
    rich_text = Text()
    
    # Add each part with appropriate styling
    for part in parts:
        if part.lower() in [k.lower() for k in sensitive_keywords]:
            rich_text.append(part, style="bold red")
        else:
            rich_text.append(part)
    
    return rich_text

def display_table(data, headers, protocol):
    """
    Display query results in a table format using Rich.

    Args:
        data (list): Data rows to display.
        headers (list): Column headers.
        protocol (str): Protocol name for logging.
    """
    if data:
        # Create a Rich table
        table = Table(title=f"{protocol} Data", show_header=True, header_style="bold magenta")
        
        # Add columns
        for header in headers:
            table.add_column(header, style="cyan")
        
        # Add data with highlighted sensitive information
        for row in data:
            # Convert each value to Rich Text with sensitive keyword highlighting
            rich_row = []
            for val in row:
                if isinstance(val, str):
                    rich_row.append(highlight_form_data(val))
                else:
                    rich_row.append(str(val))
            table.add_row(*rich_row)
        
        # Print the table
        console = Console()
        console.print(table)
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
        ("http_requests", ["source_ip", "destination_ip", "http_url", "http_form", "http_auth_username", "http_auth_password"], "HTTP"),
        ("ftp_requests", ["source_ip", "destination_ip", "ftp_request_command", "ftp_request_arg"], "FTP", "ftp_request_command IN ('USER', 'PASS')"),
        ("telnet_requests", ["source_ip", "destination_ip", "telnet_data"], "TELNET"),
        ("smtp_requests", ["source_ip", "destination_ip", "smtp_user", "smtp_password"], "SMTP"),
        ("ntlm_requests", ["source_ip", "destination_ip", "username", "ntlm_hash"], "NTLM"),
        ("ip_requests", ["subnet", "ip"], "IP") 
    ]

    # First, display unique IP pairs with Basic Auth credentials
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT source_ip, destination_ip, http_auth_username, http_auth_password 
            FROM http_requests 
            WHERE http_auth_username != 'N/A' AND http_auth_password != 'N/A'
            ORDER BY source_ip, destination_ip
        """)
        auth_data = cursor.fetchall()
        
        if auth_data:
            # Create a Rich table for Basic Auth credentials
            table = Table(title="HTTP Basic Authentication Credentials by IP Pair", show_header=True, header_style="bold magenta")
            table.add_column("Source IP", style="cyan")
            table.add_column("Destination IP", style="cyan")
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="cyan")
            
            # Group credentials by IP pair
            ip_pairs = {}
            for src_ip, dst_ip, username, password in auth_data:
                key = (src_ip, dst_ip)
                if key not in ip_pairs:
                    ip_pairs[key] = []
                ip_pairs[key].append((username, password))
            
            # Add data to the table
            for (src_ip, dst_ip), creds in ip_pairs.items():
                # Add IP pair row
                table.add_row(
                    src_ip,
                    dst_ip,
                    "\n".join(cred[0] for cred in creds),
                    "\n".join(cred[1] for cred in creds)
                )
            
            # Print the table
            console = Console()
            console.print("\nHTTP Basic Authentication Credentials by IP Pair:")
            console.print(table)
            print("=" * get_terminal_width())
    except sqlite3.Error as e:
        logging.error(f"Error fetching HTTP Basic Auth data: {e}")

    # Then display other protocol data
    for request in requests:
        table_name, columns, protocol, *conditions = request
        data = fetch_requests(conn, table_name, columns, protocol, *conditions)
        headers = ["Protocol"] + [col.replace("_", " ").title() for col in columns]
        display_table(data, headers, protocol)