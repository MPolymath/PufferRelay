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
            cursor.executemany("""
                INSERT OR IGNORE INTO ntlm_requests (source_ip, destination_ip, username, ntlm_hash)
                VALUES (?, ?, ?, ?)
            """, data)
        elif protocol == "netbios":
            cursor.executemany("""
                INSERT OR IGNORE INTO netbios_requests (domain_workgroup, hostname, ip, mac)
                VALUES (?, ?, ?, ?)
            """, data)

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
    """
    Fetch and display LDAP, HTTP, FTP, TELNET, SMTP, IP, NTLM, and NetBIOS data from the database.

    Args:
        conn (sqlite3.Connection): Active database connection.
    """
    if not conn:
        logging.error("Database connection is not available.")
        return

    requests = [
        ("ldap_requests", ["source_ip", "destination_ip", "ldap_name", "ldap_simple"], "LDAP"),
        ("http_requests", ["source_ip", "destination_ip", "http_url", "http_form", "http_auth_username", "http_auth_password"], "HTTP"),
        ("ftp_requests", ["source_ip", "destination_ip", "ftp_request_command", "ftp_request_arg"], "FTP", "ftp_request_command IN ('USER', 'PASS')"),
        ("telnet_requests", ["source_ip", "destination_ip", "telnet_data"], "TELNET"),
        ("smtp_requests", ["source_ip", "destination_ip", "smtp_user", "smtp_password"], "SMTP"),
        ("ntlm_requests", ["source_ip", "destination_ip", "username", "ntlm_hash"], "NTLM"),
        ("ip_requests", ["subnet", "ip"], "IP"),
        ("netbios_requests", ["domain_workgroup", "hostname", "ip", "mac"], "NetBIOS")
    ]

    # First, display unique IP pairs with Basic Auth credentials
    try:
        cursor = conn.cursor()
        
        # Check if the http_requests table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='http_requests'")
        if not cursor.fetchone():
            logging.warning("http_requests table does not exist in the database.")
        else:
            # Check if the table has the required columns
            cursor.execute("PRAGMA table_info(http_requests)")
            columns = [col[1] for col in cursor.fetchall()]
            required_columns = {'http_auth_username', 'http_auth_password'}
            if not all(col in columns for col in required_columns):
                logging.warning("http_requests table is missing required columns for Basic Auth.")
            else:
                # Query for Basic Auth credentials
                cursor.execute("""
                    SELECT DISTINCT source_ip, destination_ip, http_auth_username, http_auth_password 
                    FROM http_requests 
                    WHERE http_auth_username != 'N/A' AND http_auth_password != 'N/A'
                    ORDER BY source_ip, destination_ip
                """)
                auth_data = cursor.fetchall()
                
                if auth_data:
                    # Create a Rich table for Basic Auth credentials
                    table = Table(
                        title="HTTP Basic Authentication Credentials by IP Pair",
                        show_header=True,
                        header_style="bold magenta",
                        expand=False,
                        show_lines=True,
                        box=rich.box.ROUNDED,
                        padding=(0, 1)
                    )
                    
                    # Add columns with fixed widths
                    table.add_column("Source IP", style="cyan", no_wrap=True, overflow="fold", width=15, justify="left")
                    table.add_column("Destination IP", style="cyan", no_wrap=True, overflow="fold", width=15, justify="left")
                    table.add_column("Username", style="cyan", no_wrap=False, overflow="fold", min_width=15, max_width=40, justify="left")
                    table.add_column("Password", style="cyan", no_wrap=False, overflow="fold", min_width=15, max_width=40, justify="left")
                    
                    # Group credentials by IP pair
                    ip_pairs = {}
                    for src_ip, dst_ip, username, password in auth_data:
                        key = (src_ip, dst_ip)
                        if key not in ip_pairs:
                            ip_pairs[key] = []
                        ip_pairs[key].append((username, password))
                    
                    # Add data to the table
                    for (src_ip, dst_ip), creds in ip_pairs.items():
                        table.add_row(
                            src_ip,
                            dst_ip,
                            "\n".join(cred[0] for cred in creds),
                            "\n".join(cred[1] for cred in creds)
                        )
                    
                    # Print the table
                    console = Console(
                        width=None,
                        force_terminal=True,
                        color_system="auto",
                        soft_wrap=True
                    )
                    console.print("\nHTTP Basic Authentication Credentials by IP Pair:")
                    console.print(table)
                    console.print("=" * get_terminal_width())
    except sqlite3.Error as e:
        logging.error(f"Error fetching HTTP Basic Auth data: {e}")

    # Then display other protocol data
    for request in requests:
        table_name, columns, protocol, *conditions = request
        if protocol == "IP":
            # Special handling for IP data
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT subnet, GROUP_CONCAT(ip, '\n') FROM ip_requests GROUP BY subnet ORDER BY subnet")
            data = cursor.fetchall()
            headers = ["Subnet", "IPs"]
        elif protocol == "NetBIOS":
            # Special handling for NetBIOS data
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain_workgroup, hostname, src_ip, src_mac, service_type 
                FROM netbios_requests 
                ORDER BY domain_workgroup, hostname
            """)
            data = cursor.fetchall()
            headers = ["Domain/Workgroup", "Hostname", "Source IP", "Source MAC", "Service Type"]
        else:
            data = fetch_requests(conn, table_name, columns, protocol, *conditions)
            headers = ["Protocol"] + [col.replace("_", " ").title() for col in columns]
        display_table(data, headers, protocol)