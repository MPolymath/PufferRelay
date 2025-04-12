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

from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import binascii
from PufferRelay.core_imports import urllib
from PufferRelay.core_imports import argparse
from PufferRelay.core_imports import logging
from PufferRelay.pcap_processing.pcap_parser import *
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import *
from PufferRelay.database.db_connector import get_db_connection, close_connection
from PufferRelay.config import PCAP_STORAGE_FILE, LOG_LEVEL, DB_NAME

def main():
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info("Starting PufferRelay...")

    parser = argparse.ArgumentParser(description="Analyze a PCAP file and extract network traffic data.")
    parser.add_argument("-f", "--file", help="Path to the PCAP file")
    parser.add_argument("-r", "--read-db", action="store_true", help="Read and display data from the database")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                       default=LOG_LEVEL, help="Set the logging level")

    args = parser.parse_args()

    # Update logging level if specified
    if args.log_level != LOG_LEVEL:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
        logging.info(f"Logging level set to {args.log_level}")

    # If reading from database
    if args.read_db:
        logging.info(f"Reading data from database: {DB_NAME}")
        conn = get_db_connection()
        if not conn:
            logging.error("Failed to connect to database")
            return
        fetch_all_data(conn)
        close_connection(conn)
        return

    # If no file is provided, print usage guide and exit
    if not args.file:
        print("\n❌ Error: No PCAP file provided.\n")
        print("Usage:")
        print("  python -m PufferRelay -f path/to/your.pcap")
        print("  python -m PufferRelay --file path/to/your.pcap")
        print("  python -m PufferRelay -r  # Read from database")
        print("\nExample:")
        print("  python -m PufferRelay -f network_capture.pcap")
        print("  python -m PufferRelay -r\n")
        sys.exit(1)  # Exit with an error code

    logging.info(f"Processing PCAP file: {args.file}")
    create_database()   # Ensure the database exists
    parsed_data = parse_pcap(args.file)
    logging.debug(f"Parsed data: {parsed_data}")

    process_extracted_data(parsed_data)

    # Connect to SQLite database
    conn = get_db_connection()
    if not conn:
        logging.error("Failed to connect to database")
        return

    # Fetch ldap, http and ftp data from database
    fetch_all_data(conn)
    close_connection(conn)

if __name__ == "__main__":
    main()
