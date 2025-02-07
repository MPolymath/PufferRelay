import pyshark
import sqlite3

def extract_ldap_bind_requests(pcap_file):
    """Extracts LDAP bind request name and simple fields from a pcap file."""
    
    # Open the capture file with a filter for LDAP Bind Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="ldap.bindRequest")

    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Extract LDAP fields
            ldap_layer = packet['LDAP']
            ldap_name = ldap_layer.get('bindRequest.name', 'N/A')  # Get name
            ldap_simple = ldap_layer.get('bindRequest.simple', 'N/A')  # Get simple

            extracted_data.append((src_ip, dst_ip, ldap_name, ldap_simple))
        
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
            ldap_simple TEXT
        )
    """)
    
    conn.commit()
    conn.close()

def insert_into_database(data):
    """Inserts extracted LDAP bind request data into the database."""
    conn = sqlite3.connect("ldap_bind_requests.db")
    cursor = conn.cursor()
    
    cursor.executemany("""
        INSERT INTO ldap_requests (source_ip, destination_ip, ldap_name, ldap_simple)
        VALUES (?, ?, ?, ?)
    """, data)
    
    conn.commit()
    conn.close()

def main(pcap_file):
    create_database()  # Ensure the database exists
    ldap_data = extract_ldap_bind_requests(pcap_file)  # Extract data from .pcap
    
    if ldap_data:
        insert_into_database(ldap_data)  # Store in database
        print("LDAP bind request data successfully stored in the database.")
    else:
        print("No LDAP bind requests found.")

# Run the script with a sample pcap file
pcap_file = "network_capture.pcap"
main(pcap_file)
