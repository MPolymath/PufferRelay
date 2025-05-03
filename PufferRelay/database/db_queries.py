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

from PufferRelay.core_imports import (
    sqlite3,
    sys,
    logging,
    rich,
    re,
    shutil
)
from rich.table import Table
from rich.console import Console
from rich.text import Text
from PufferRelay.config import DB_NAME

def get_terminal_width():
    """Get the current terminal width, with a fallback to 80 characters."""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def insert_into_database(protocol, data):
    """Inserts extracted pertinent information into the database, ensuring uniqueness."""
    if not data:
        return
        
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Insert only if the combination does not already exist
        if protocol == "ldap":
            cursor.executemany("""
                INSERT OR IGNORE INTO ldap_requests (source_ip, destination_ip, ldap_name, ldap_simple)
                VALUES (?, ?, ?, ?)
            """, data)
        elif protocol == "http":
            cursor.executemany("""
                INSERT OR IGNORE INTO http_requests (source_ip, destination_ip, http_url, http_form, http_auth_username, http_auth_password)
                VALUES (?, ?, ?, ?, ?, ?)
            """, data)
        elif protocol == "ftp":
            cursor.executemany("""
                INSERT OR IGNORE INTO ftp_requests (source_ip, destination_ip, ftp_request_command, ftp_request_arg)
                VALUES (?, ?, ?, ?)
            """, data)
        elif protocol == "telnet":
            cursor.executemany("""
                INSERT OR IGNORE INTO telnet_requests (source_ip, destination_ip, telnet_data)
                VALUES (?, ?, ?)
            """, data)
        elif protocol == "smtp":
            cursor.executemany("""
                INSERT OR IGNORE INTO smtp_requests (source_ip, destination_ip, smtp_user, smtp_password)
                VALUES (?, ?, ?, ?)
            """, data)
        elif protocol == "ips":
            # For IP data, we need to insert each IP separately
            for subnet, ips in data:
                for ip in ips:
                    cursor.execute("""
                        INSERT OR IGNORE INTO ip_requests (subnet, ip)
                        VALUES (?, ?)
                    """, (subnet, ip))
        elif protocol == "ntlm":
            # For NTLM data, we need to check for existing usernames
            for entry in data:
                src_ip, dst_ip, username, ntlm_hash = entry
                # Check if this username already exists
                cursor.execute("""
                    SELECT COUNT(*) FROM ntlm_requests 
                    WHERE username = ?
                """, (username,))
                if cursor.fetchone()[0] == 0:
                    # If username doesn't exist, insert new record
                    cursor.execute("""
                        INSERT INTO ntlm_requests (source_ip, destination_ip, username, ntlm_hash)
                        VALUES (?, ?, ?, ?)
                    """, (src_ip, dst_ip, username, ntlm_hash))
                    logging.debug(f"Inserted new NTLM hash for username: {username}")
                else:
                    # If username exists, update the existing record
                    cursor.execute("""
                        UPDATE ntlm_requests 
                        SET source_ip = ?, destination_ip = ?, ntlm_hash = ?
                        WHERE username = ?
                    """, (src_ip, dst_ip, ntlm_hash, username))
                    logging.debug(f"Updated NTLM hash for existing username: {username}")
        elif protocol == "netbios":
            logging.debug(f"Inserting NetBIOS data: {data}")
            cursor.executemany("""
                INSERT OR IGNORE INTO netbios_requests (domain_workgroup, hostname, other_service, src_ip, src_mac, service_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, data)
            logging.debug(f"Inserted {cursor.rowcount} NetBIOS records")
        elif protocol == "imap":
            cursor.executemany("""
                INSERT OR IGNORE INTO imap_requests (source_ip, destination_ip, username, password)
                VALUES (?, ?, ?, ?)
            """, data)
            logging.debug(f"Inserted {cursor.rowcount} IMAP records")
        elif protocol == "pop3":
            cursor.executemany("""
                INSERT OR IGNORE INTO pop3_requests (source_ip, destination_ip, username, password)
                VALUES (?, ?, ?, ?)
            """, data)
            logging.debug(f"Inserted {cursor.rowcount} POP3 records")
        elif protocol == "snmp":
            cursor.executemany("""
                INSERT OR IGNORE INTO snmp_requests (source_ip, destination_ip, community_string)
                VALUES (?, ?, ?)
            """, data)
            logging.debug(f"Inserted {cursor.rowcount} SNMP records")

        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error while inserting {protocol} data: {e}")
    finally:
        if conn:
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
        logging.info(f"{protocol.upper()} data successfully stored in the database.")

def process_extracted_data(parsed_data):
    """
    Processes extracted protocol data and stores it if available.

    Args:
        parsed_data (dict): Dictionary containing protocol data to process.
    """
    for protocol, data in parsed_data.items():
        if data:
            store_data(protocol, data)

    if not any(parsed_data.values()):
        logging.info("No pertinent requests found.")

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
        'password', 'pass', 'pwd', 'log', 'login', 'user', 'username', 'session', 'motdepasse',
        'pw', 'passw', 'passwd', 'pass:', 'user:', 'username:', 'password:', 'id',
        'login:', 'pass ', 'user ', 'authorization:', 'token', 'api', 'key', 'uid',
        'uname', '&pass=', '&password=', '&user=', '&username=', '&login=', 'mdp'
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
    if not data:
        logging.warning(f"No {protocol} data found.")
        return

    # Create a Rich table with appropriate width constraints
    table = Table(
        title=f"{protocol} Data",
        show_header=True,
        header_style="bold magenta",
        expand=True,
        show_lines=True,
        box=rich.box.ROUNDED,
        padding=(0, 1)
    )
    
    # Add columns with appropriate widths based on content type
    for header in headers:
        if protocol == "IP":
            if header == "Subnet":
                table.add_column(
                    header,
                    style="cyan",
                    no_wrap=False,
                    overflow="fold",
                    width=19,
                    justify="left"
                )
            elif header == "IPs":
                table.add_column(
                    header,
                    style="cyan",
                    no_wrap=False,
                    overflow="fold",
                    justify="left",
                    min_width=30,
                    max_width=None,
                    ratio=3
                )
        elif "IP" in header and protocol != "IP":
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                width=15,
                justify="left"
            )
        elif header == "Protocol":
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                width=8,
                justify="left"
            )
        elif header in ["HTTP Form", "Telnet Data"]:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                min_width=60,
                max_width=None,
                ratio=3
            )
        elif header in ["LDAP Name", "LDAP Simple"]:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                width=30
            )
        elif header in ["SMTP User", "SMTP Password"]:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                width=20
            )
        elif header in ["HTTP URL", "FTP Request Arg", "NTLM Hash"]:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                min_width=30,
                max_width=None,
                ratio=2
            )
        elif header in ["Username", "Password", "HTTP Auth Username", "HTTP Auth Password"]:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                min_width=15,
                max_width=None,
                ratio=1
            )
        else:
            table.add_column(
                header,
                style="cyan",
                no_wrap=False,
                overflow="fold",
                justify="left",
                width=20
            )
    
    # Add data with highlighted sensitive information
    for row in data:
        rich_row = []
        for val in row:
            if protocol == "IP" and isinstance(val, list):
                # For IP protocol, join the list of IPs with newlines
                rich_row.append("\n".join(val))
            elif isinstance(val, str):
                rich_row.append(highlight_form_data(val))
            else:
                rich_row.append(str(val))
        table.add_row(*rich_row)
    
    # Print the table with appropriate width constraints
    console = Console(
        width=None,
        force_terminal=True,
        color_system="auto",
        soft_wrap=True
    )
    console.print(table)
    console.print()

def fetch_all_data(conn):
    """Fetch and display all data from the database"""
    try:
        if not conn:
            logging.error("No database connection available")
            return

        console = Console()
        terminal_width = get_terminal_width()

        # First check if we have any FTP data
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ftp_requests")
        ftp_count = cursor.fetchone()[0]
        logging.debug(f"Total FTP records in database: {ftp_count}")

        if ftp_count > 0:
            # Get FTP credentials grouped by source and destination IP pairs
            cursor.execute("""
                WITH user_pass_pairs AS (
                    SELECT 
                        source_ip as src_ip,
                        destination_ip as dst_ip,
                        GROUP_CONCAT(CASE WHEN ftp_request_command = 'USER' THEN ftp_request_arg END) as usernames,
                        GROUP_CONCAT(CASE WHEN ftp_request_command = 'PASS' THEN ftp_request_arg END) as passwords
                    FROM ftp_requests
                    GROUP BY source_ip, destination_ip
                    HAVING usernames IS NOT NULL OR passwords IS NOT NULL
                )
                SELECT 
                    src_ip,
                    dst_ip,
                    usernames,
                    passwords
                FROM user_pass_pairs
                ORDER BY src_ip, dst_ip
            """)
            
            ftp_results = cursor.fetchall()
            logging.debug(f"Found {len(ftp_results)} FTP credential pairs")
            
            if ftp_results:
                table = Table(title="FTP Credentials", width=terminal_width)
                table.add_column("Source IP", style="magenta")
                table.add_column("Destination IP", style="magenta")
                table.add_column("Username", style="yellow")
                table.add_column("Password", style="red")
                
                for src_ip, dst_ip, usernames, passwords in ftp_results:
                    # Split the usernames and passwords into lists
                    username_list = usernames.split(',') if usernames else []
                    password_list = passwords.split(',') if passwords else []
                    
                    # Display each pair on its own line
                    for i in range(max(len(username_list), len(password_list))):
                        username = username_list[i] if i < len(username_list) else "N/A"
                        password = password_list[i] if i < len(password_list) else "N/A"
                        table.add_row(src_ip, dst_ip, username, password)
                
                console.print(table)
            else:
                logging.warning("No FTP credentials found in database")
                # Show raw data for debugging
                cursor.execute("SELECT * FROM ftp_requests ORDER BY source_ip, destination_ip")
                raw_data = cursor.fetchall()
                logging.debug("Raw FTP data:")
                for row in raw_data:
                    logging.debug(row)
        else:
            logging.warning("No FTP records found in database")

        # Display IP data
        cursor.execute("SELECT DISTINCT subnet, GROUP_CONCAT(ip, '\n') FROM ip_requests GROUP BY subnet ORDER BY subnet")
        ip_data = cursor.fetchall()
        if ip_data:
            table = Table(title="IP Data", width=terminal_width)
            table.add_column("Subnet", style="cyan")
            table.add_column("IPs", style="cyan")
            
            for subnet, ips in ip_data:
                table.add_row(subnet, ips)
            
            console.print(table)

        # Display other protocol data
        requests = [
            ("ldap_requests", ["source_ip", "destination_ip", "ldap_name", "ldap_simple"], "LDAP"),
            ("http_requests", ["source_ip", "destination_ip", "http_url", "http_form", "http_auth_username", "http_auth_password"], "HTTP"),
            ("telnet_requests", ["source_ip", "destination_ip", "telnet_data"], "TELNET"),
            ("smtp_requests", ["source_ip", "destination_ip", "smtp_user", "smtp_password"], "SMTP"),
            ("ntlm_requests", ["source_ip", "destination_ip", "username", "ntlm_hash"], "NTLM"),
            ("netbios_requests", ["domain_workgroup", "hostname", "ip", "mac"], "NetBIOS"),
            ("imap_requests", ["source_ip", "destination_ip", "username", "password"], "IMAP"),
            ("pop3_requests", ["source_ip", "destination_ip", "username", "password"], "POP3"),
            ("snmp_requests", ["source_ip", "destination_ip", "community_string"], "SNMP")
        ]

        for request in requests:
            table_name, columns, protocol, *conditions = request
            if protocol == "NetBIOS":
                # Special handling for NetBIOS data
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN domain_workgroup != 'N/A' THEN domain_workgroup
                            WHEN hostname != 'N/A' THEN hostname
                            ELSE ip
                        END as identifier,
                        ip,
                        mac,
                        domain_workgroup
                    FROM netbios_requests 
                    ORDER BY identifier, domain_workgroup
                """)
                data = cursor.fetchall()
                headers = ["Identifier", "IP", "MAC", "Domain/Workgroup"]
            else:
                data = fetch_requests(conn, table_name, columns, protocol, *conditions)
                headers = ["Protocol"] + [col.replace("_", " ").title() for col in columns]
            display_table(data, headers, protocol)

    except sqlite3.Error as e:
        logging.error(f"SQLite error: {str(e)}")
        raise

def check_unencrypted_protocols(conn):
    """
    Check for unencrypted protocols in the database and return a summary.
    
    Args:
        conn (sqlite3.Connection): Active database connection.
        
    Returns:
        list: List of unencrypted protocols found with their counts
    """
    if not conn:
        logging.error("Database connection is not available.")
        return []

    # Define unencrypted protocols and their tables
    unencrypted_protocols = {
        "FTP": "ftp_requests",
        "Telnet": "telnet_requests",
        "SNMP": "snmp_requests",
        "IMAP": "imap_requests",
        "POP3": "pop3_requests",
        "SMTP": "smtp_requests",
        "LDAP": "ldap_requests",
        "HTTP": "http_requests",
        "NTLM": "ntlm_requests"
    }

    found_protocols = []
    cursor = conn.cursor()

    for protocol, table in unencrypted_protocols.items():
        try:
            # Check if table exists
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                continue

            # Count entries in the table
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            
            if count > 0:
                found_protocols.append((protocol, count))
        except sqlite3.Error as e:
            logging.error(f"Error checking {protocol} table: {e}")
            continue

    return found_protocols

def update_quick_win(conn, protocol, found=True, details='', credentials_found=False, credential_protocols=None):
    """
    Update a quick win entry in the database.
    
    Args:
        conn: Database connection
        protocol (str): Protocol name
        found (bool): Whether the protocol was found
        details (str): Additional details about the finding
        credentials_found (bool): Whether credentials were found
        credential_protocols (list): List of protocols where credentials were found
    """
    try:
        cursor = conn.cursor()
        
        # If updating credentials, we need to merge with existing credential protocols
        if credentials_found and credential_protocols:
            # Get existing credential protocols
            cursor.execute("""
                SELECT credential_protocols 
                FROM quick_wins 
                WHERE protocol = ?
            """, (protocol,))
            result = cursor.fetchone()
            existing_protocols = set()
            if result and result[0]:
                existing_protocols = set(result[0].split(','))
            
            # Merge with new protocols
            new_protocols = existing_protocols.union(set(credential_protocols))
            credential_protocols_str = ','.join(sorted(new_protocols))
            
            cursor.execute("""
                UPDATE quick_wins 
                SET found = ?, details = ?, credentials_found = ?, credential_protocols = ?
                WHERE protocol = ?
            """, (found, details, credentials_found, credential_protocols_str, protocol))
        else:
            cursor.execute("""
                UPDATE quick_wins 
                SET found = ?, details = ?
                WHERE protocol = ?
            """, (found, details, protocol))
        
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error updating quick win for {protocol}: {str(e)}")
        raise

def display_quick_wins(results):
    """
    Display quick wins in a nice Rich table format.
    
    Args:
        results: Either a database connection or a list of quick wins tuples
    """
    try:
        # If results is a connection, fetch the data
        if hasattr(results, 'cursor'):
            cursor = results.cursor()
            cursor.execute("""
                SELECT protocol, found, details, credentials_found, credential_protocols 
                FROM quick_wins 
                ORDER BY 
                    CASE 
                        WHEN protocol IN ('LDAP', 'HTTP', 'FTP', 'TELNET', 'SMTP', 'IMAP', 'POP3', 'SYSLOG', 'TFTP') THEN 1
                        WHEN protocol IN ('SNMPv1', 'SNMPv2', 'SMBv1', 'TLS1.0', 'SSLv2', 'SSLv3') THEN 2
                        WHEN protocol IN ('LLMNR', 'NETBIOS', 'MDNS') THEN 3
                        ELSE 4
                    END,
                    protocol
            """)
            results = cursor.fetchall()
        
        if not results:
            logging.warning("No quick wins found to display")
            return
        
        console = Console()
        table = Table(title="Quick Wins Summary", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Protocol", style="cyan")
        table.add_column("Found", style="green")
        table.add_column("Details", style="yellow")
        table.add_column("Credentials Found", style="red")
        
        current_category = ""
        for protocol, found, details, credentials_found, credential_protocols in results:
            # Determine category
            if protocol in ['LDAP', 'HTTP', 'FTP', 'TELNET', 'SMTP', 'IMAP', 'POP3', 'SYSLOG', 'TFTP']:
                category = "Unencrypted Protocols"
            elif protocol in ['SNMPv1', 'SNMPv2', 'SMBv1', 'TLS1.0', 'SSLv2', 'SSLv3']:
                category = "Deprecated Protocols"
            elif protocol in ['LLMNR', 'NETBIOS', 'MDNS']:
                category = "Multicast Protocols"
            else:
                category = "Security Findings"
            
            # Format credentials information
            credentials_info = ""
            if credentials_found and credential_protocols:
                credentials_info = f"Found in: {credential_protocols}"
            
            # Only show category once
            if category != current_category:
                table.add_row(category, protocol, "✓" if found else "✗", details, credentials_info)
                current_category = category
            else:
                table.add_row("", protocol, "✓" if found else "✗", details, credentials_info)
        
        console.print(table)
    except Exception as e:
        logging.error(f"Error displaying quick wins: {str(e)}")
        raise

def get_quick_wins(conn):
    """
    Get all quick wins from the database.
    
    Args:
        conn: Database connection
        
    Returns:
        list: List of quick wins tuples (protocol, found, details, credentials_found, credential_protocols)
    """
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT protocol, found, details, credentials_found, credential_protocols 
            FROM quick_wins 
            ORDER BY 
                CASE 
                    WHEN protocol IN ('LDAP', 'HTTP', 'FTP', 'TELNET', 'SMTP', 'IMAP', 'POP3', 'SYSLOG', 'TFTP') THEN 1
                    WHEN protocol IN ('SNMPv1', 'SNMPv2', 'SMBv1', 'TLS1.0', 'SSLv2', 'SSLv3') THEN 2
                    WHEN protocol IN ('LLMNR', 'NETBIOS', 'MDNS') THEN 3
                    ELSE 4
                END,
                protocol
        """)
        return cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Error getting quick wins: {str(e)}")
        raise