from PufferRelay.core_imports import logging
from PufferRelay.core_imports import os
from PufferRelay.core_imports import textwrap
from PufferRelay.core_imports import shutil
from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import rich
from PufferRelay.core_imports import rich.table
from PufferRelay.core_imports import rich.console
from PufferRelay.core_imports import re

def highlight_sensitive_data(text):
    """
    Highlights sensitive keywords in green.
    
    Args:
        text (str): Text to process
        
    Returns:
        rich.text.Text: Text with highlighted keywords
    """
    if not isinstance(text, str):
        text = str(text)
        
    # List of sensitive keywords to highlight
    sensitive_keywords = [
        'password', 'pass', 'pwd', 'log', 'login', 'user', 'username', 'mdp'
        'pw', 'passw', 'passwd', 'pass:', 'user:', 'username:', 'password:', 'motdepasse'
        'login:', 'pass ', 'user ', 'authorization:', 'token', 'api', 'key', 'id',
        'uname', '&pass=', '&password=', '&user=', '&username=', '&login=', 'session'
    ]
    
    # Create a pattern that matches any of the keywords
    pattern = '|'.join(map(re.escape, sensitive_keywords))
    
    # Split the text into parts based on the pattern
    parts = re.split(f'({pattern})', text, flags=re.IGNORECASE)
    
    # Create a Rich Text object
    rich_text = rich.text.Text()
    
    # Add each part with appropriate styling
    for part in parts:
        if part.lower() in [k.lower() for k in sensitive_keywords]:
            rich_text.append(part, style="bold green")
        else:
            rich_text.append(part)
    
    return rich_text

def get_terminal_width():
    """Get the current terminal width, with a fallback to 80 characters."""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def format_table(data, headers, max_width=None):
    """
    Format data into a readable table that fits the terminal width.
    
    Args:
        data: List of tuples containing the data
        headers: List of column headers
        max_width: Optional maximum width (defaults to terminal width)
    """
    if not data:
        return "No data to display"
    
    if max_width is None:
        max_width = get_terminal_width()
    
    # Calculate column widths
    col_widths = [len(str(h)) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Adjust column widths to fit terminal
    total_width = sum(col_widths) + (len(headers) * 3) - 1  # Account for separators
    if total_width > max_width:
        # Reduce the widest column(s) to fit
        while total_width > max_width:
            max_col = max(col_widths)
            if max_col <= 10:  # Don't make columns too narrow
                break
            col_widths[col_widths.index(max_col)] -= 1
            total_width = sum(col_widths) + (len(headers) * 3) - 1
    
    # Create format string
    format_str = " | ".join([f"{{:<{w}}}" for w in col_widths])
    
    # Create separator line
    separator = "-+-".join(["-" * w for w in col_widths])
    
    # Build the table
    table = []
    table.append(format_str.format(*headers))
    table.append(separator)
    
    for row in data:
        # Handle multi-line cells
        wrapped_rows = []
        for i, cell in enumerate(row):
            wrapped = textwrap.wrap(str(cell), width=col_widths[i])
            wrapped_rows.append(wrapped)
        
        # Get the maximum number of lines needed
        max_lines = max(len(w) for w in wrapped_rows)
        
        # Pad shorter lists with empty strings
        for i in range(len(wrapped_rows)):
            wrapped_rows[i].extend([''] * (max_lines - len(wrapped_rows[i])))
        
        # Add each line of wrapped content
        for line in zip(*wrapped_rows):
            table.append(format_str.format(*line))
    
    return "\n".join(table)

def display_protocol_data(conn, protocol):
    """
    Display protocol data in a formatted table.
    
    Args:
        conn: Database connection
        protocol: Protocol name (e.g., 'http', 'ldap', etc.)
    """
    cursor = conn.cursor()
    
    try:
        # Special handling for IP data
        if protocol == "ips":
            cursor.execute("SELECT subnet, ip FROM ip_requests ORDER BY subnet, ip")
            data = cursor.fetchall()
            if not data:
                print("\nNo IP data found.")
                return
            
            print("\nIP Data:")
            print("=" * get_terminal_width())
            
            # Create a Rich table for IP data
            table = rich.table.Table(title="IP Data", show_header=True, header_style="bold magenta")
            table.add_column("Subnet", style="cyan")
            table.add_column("IP Address", style="cyan")
            
            # Group IPs by subnet for better readability
            current_subnet = None
            for subnet, ip in data:
                if subnet != current_subnet:
                    current_subnet = subnet
                table.add_row(subnet, ip)
            
            # Print the table
            console = rich.console.Console()
            console.print(table)
            print("=" * get_terminal_width())
            return
        
        # Special handling for NTLM data
        if protocol == "ntlm":
            # First check if the table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ntlm_requests'")
            if not cursor.fetchone():
                print("\nNTLM table does not exist in the database.")
                return
            
            # Get the count of records
            cursor.execute("SELECT COUNT(*) FROM ntlm_requests")
            count = cursor.fetchone()[0]
            print(f"\nFound {count} NTLM records in the database.")
            
            # Get all NTLM data
            cursor.execute("SELECT source_ip, destination_ip, username, ntlm_hash FROM ntlm_requests")
            data = cursor.fetchall()
            
            if not data:
                print("\nNo NTLM data found in the table.")
                return
            
            print("\nNTLM Data:")
            print("=" * get_terminal_width())
            
            # Create a Rich table for NTLM data
            table = rich.table.Table(title="NTLM Data", show_header=True, header_style="bold magenta")
            table.add_column("Source IP", style="cyan")
            table.add_column("Destination IP", style="cyan")
            table.add_column("Username", style="cyan")
            table.add_column("NTLM Hash", style="cyan")
            
            # Add data to the table
            for src_ip, dst_ip, username, ntlm_hash in data:
                table.add_row(
                    highlight_sensitive_data(src_ip),
                    highlight_sensitive_data(dst_ip),
                    highlight_sensitive_data(username),
                    highlight_sensitive_data(ntlm_hash)
                )
            
            # Print the table
            console = rich.console.Console()
            console.print(table)
            print("=" * get_terminal_width())
            return
        
        # Get table schema for other protocols
        cursor.execute(f"PRAGMA table_info({protocol}_requests)")
        columns = [col[1] for col in cursor.fetchall() if col[1] != 'id']
        
        if not columns:
            print(f"\nNo {protocol.upper()} data found.")
            return
        
        # Properly escape column names and construct the query
        column_list = ", ".join([f'"{col}"' for col in columns])
        query = f'SELECT {column_list} FROM "{protocol}_requests"'
        
        # Get data
        cursor.execute(query)
        data = cursor.fetchall()
        
        if not data:
            print(f"\nNo {protocol.upper()} data found.")
            return
        
        print(f"\n{protocol.upper()} Data:")
        print("=" * get_terminal_width())
        
        # Create a Rich table
        table = rich.table.Table(title=f"{protocol.upper()} Data", show_header=True, header_style="bold magenta")
        
        # Add columns
        for col in columns:
            table.add_column(col, style="cyan")
        
        # Add data with highlighted sensitive information
        for row in data:
            table.add_row(*[highlight_sensitive_data(val) for val in row])
        
        # Print the table
        console = rich.console.Console()
        console.print(table)
        print("=" * get_terminal_width())
        
    except sqlite3.OperationalError as e:
        print(f"\nError accessing {protocol.upper()} data: {str(e)}")
    except Exception as e:
        print(f"\nUnexpected error displaying {protocol.upper()} data: {str(e)}") 