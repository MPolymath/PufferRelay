from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import tabulate
from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import binascii
from PufferRelay.core_imports import urllib
from PufferRelay.core_imports import argparse
from PufferRelay.pcap_processing.pcap_parser import *
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import *
from PufferRelay.database.db_connector import get_db_connection, close_connection
from PufferRelay.config import PCAP_STORAGE_FILE

def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file and extract network traffic data.")
    parser.add_argument("-f", "--file", required=True, help="Path to the PCAP file")

    args = parser.parse_args()

    # If no file is provided, print usage guide and exit
    if not args.file:
        print("\n❌ Error: No PCAP file provided.\n")
        print("Usage:")
        print("  python -m PufferRelay -f path/to/your.pcap")
        print("  python -m PufferRelay --file path/to/your.pcap")
        print("\nExample:")
        print("  python -m PufferRelay -f network_capture.pcap\n")
        sys.exit(1)  # Exit with an error code

    create_database()   # Ensure the database exists
    parsed_data = parse_pcap(args.file)

    process_extracted_data(parsed_data)

    # Connect to SQLite database
    conn = get_db_connection()

    # Fetch ldap, http and ftp data from database
    fetch_all_data(conn)

main()
