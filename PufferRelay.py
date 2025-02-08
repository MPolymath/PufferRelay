import pyshark
from tabulate import tabulate
import sqlite3
import binascii
import urllib.parse

#LDAP extract data
def extract_ldap_bind_requests(pcap_file):
    """Extracts LDAP bind request name and simple fields from a pcap file."""
    
    # Open the capture file with a filter for LDAP Bind Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="ldap && ldap.protocolOp==bindRequest")
    capture.set_debug 
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract LDAP fields
            ldap_name = packet.ldap.get('ldap.name', 'N/A') if hasattr(packet, 'ldap') else "N/A"  # Get name
            ldap_simple = packet.ldap.get('ldap.simple', 'N/A') if hasattr(packet, 'ldap') else "N/A"  # Get simple
            extracted_data.append((src_ip, dst_ip, ldap_name, ldap_simple))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    return extracted_data

#HTTP extract data
def extract_http_bind_requests(pcap_file):
    """Extracts HTTP form data"""
    
    # Open the capture file with a filter for LDAP Bind Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="http && http.request.method==POST")
    capture.set_debug 
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract HTTP fields
            http_full_url_path = packet.http.get('http.host', 'N/A') + packet.http.get('http.request.uri', 'N/A') if hasattr(packet, 'http') else "N/A"  # Get full URL
            http_form_content = urllib.parse.unquote(binascii.unhexlify(packet.http.get('http.file_data', 'N/A').replace(":", "")).decode('utf-8')) if hasattr(packet, 'http') else "N/A"  # Get form content
            
            extracted_data.append((src_ip, dst_ip, http_full_url_path, http_form_content))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    return extracted_data

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
            UNIQUE(source_ip, destination_ip, http_url, http_form)
        )
    """)

    conn.commit()
    conn.close()

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
            INSERT OR IGNORE INTO http_requests (source_ip, destination_ip, http_url, http_form)
            VALUES (?, ?, ?, ?)
        """, data)

    conn.commit()
    conn.close()

def main(pcap_file):
    create_database()   # Ensure the database exists
    ldap_data = extract_ldap_bind_requests(pcap_file)  # Extract ldap data from .pcap
    http_data = extract_http_bind_requests(pcap_file)  # Extract http data from .pcap

    if ldap_data:
        insert_into_database("ldap", ldap_data)  # Store in database
        print("LDAP bind request data successfully stored in the database.")
    elif http_data:
        insert_into_database("http", http_data)  # Store in database
        print("HTTP data successfully stored in the database.")
    else:
        print("No pertinent requests found.")
        return

    # Connect to SQLite database
    db_file = "ldap_bind_requests.db"  # Update with your actual DB file
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Fetch LDAP requests from the database
    cursor.execute("SELECT 'LDAP', source_ip, destination_ip, ldap_name, ldap_simple FROM ldap_requests")
    rows = cursor.fetchall()

    # Define column headers
    headers = ["Protocol", "Source IP", "Destination IP", "Name", "Password"]

    # Print the table in a readable format
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))  # Options: "fancy_grid", "grid", "psql"

    # Fetch HTTP requests from the database
    cursor.execute("SELECT 'HTTP', source_ip, destination_ip, http_url, http_form FROM http_requests")
    rows = cursor.fetchall()

    # Define column headers
    headers = ["Protocol", "Source IP", "Destination IP", "URL", "FORM"]

    # Print the table in a readable format
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))  # Options: "fancy_grid", "grid", "psql"

    # Close the connection
    conn.close()    

# Run the script with a sample pcap file
# pcap_file = "network_capture_http.pcapng"
pcap_file = "network_capture_ldap.pcapng"
main(pcap_file)
