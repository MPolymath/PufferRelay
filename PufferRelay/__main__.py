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

import argparse
import logging
import os
import sys
import time
import threading
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from rich.logging import RichHandler
from PufferRelay.core_imports import pyshark
from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import (
    get_quick_wins,
    display_quick_wins,
    update_quick_win,
    fetch_all_data,
    insert_into_database
)
from PufferRelay.protocols.quick_wins import analyze_quick_wins
from PufferRelay.protocols.pop3_handler import process_pop3
from PufferRelay.logger import setup_logger
from PufferRelay.utils.loading_animation import show_loading_animation

# Suppress asyncio proactor message
logging.getLogger('asyncio').setLevel(logging.WARNING)

def read_quick_wins_from_db(conn, show_ready_func=None):
    """
    Read and display quick wins from the database.
    
    Args:
        conn: Database connection
        show_ready_func: Function to show the ready banner
    """
    try:
        # Clear screen first if we're going to show the banner
        if show_ready_func:
            os.system('cls' if os.name == 'nt' else 'clear')
            show_ready_func(quick_wins=True)
            logging.info("\033[33mQuick Wins Analysis Starting...\033[0m")
        
        # Get all quick wins from the database
        quick_wins = get_quick_wins(conn)
        
        if not quick_wins:
            rprint(Panel("[yellow]No quick wins found in the database.[/yellow]"))
            return
        
        # Display the quick wins in a table
        display_quick_wins(quick_wins)
        
    except Exception as e:
        logging.error(f"Error reading quick wins from database: {str(e)}")
        raise

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='PufferRelay - Network Protocol Analyzer')
    parser.add_argument('-f', '--file', help='PCAP file to analyze')
    parser.add_argument('-r', '--read', action='store_true', help='Read from database')
    parser.add_argument('-q', '--quick-wins', nargs='?', const=True, help='PCAP file to analyze for quick wins (optional with -r)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      default='INFO', help='Set the logging level')
    args = parser.parse_args()

    # Setup logging
    setup_logger(args.log_level)

    # Initialize loading animation
    update_animation, show_ready = show_loading_animation()

    try:
        # Create database tables first
        conn = create_database()
        if not conn:
            logging.error("Failed to create database connection. Exiting.")
            sys.exit(1)
        
        # Show loading animation
        animation_running = True
        
        def run_animation():
            while animation_running:
                update_animation(quick_wins=bool(args.quick_wins))
                time.sleep(0.2)
        
        # Start animation in a separate thread
        animation_thread = threading.Thread(target=run_animation)
        animation_thread.start()

        try:
            if args.quick_wins:
                if args.read:
                    # Read quick wins from database
                    read_quick_wins_from_db(conn, show_ready)
                else:
                    # Analyze PCAP file for quick wins
                    analyze_quick_wins(args.quick_wins, conn)
                    # Clear screen and show the final banner only for quick wins mode
                    os.system('cls' if os.name == 'nt' else 'clear')
                    show_ready(quick_wins=True)
                    logging.info("\033[33mQuick Wins Analysis Starting...\033[0m")
                    # Display quick wins after analysis
                    read_quick_wins_from_db(conn, show_ready)
            elif args.file:
                # Parse PCAP file and process all protocols
                from PufferRelay.pcap_processing.pcap_parser import parse_pcap
                parsed_data = parse_pcap(args.file)
                
                # Store the parsed data in the database
                from PufferRelay.database.db_queries import process_extracted_data
                process_extracted_data(parsed_data)
                
                # Clear screen and show the final banner
                os.system('cls' if os.name == 'nt' else 'clear')
                show_ready(quick_wins=False)
                logging.info("\033[35mPufferRelay Ready...\033[0m")
                
                # Display results after showing the banner
                fetch_all_data(conn)
            elif args.read:
                # Read from database and display all tables
                os.system('cls' if os.name == 'nt' else 'clear')
                show_ready(quick_wins=False)
                logging.info("\033[35mPufferRelay Ready...\033[0m")
                fetch_all_data(conn)
        except Exception as e:
            logging.error(f"Error during processing: {str(e)}")
            raise
        finally:
            # Stop the animation
            animation_running = False
            animation_thread.join()
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                logging.error(f"Error closing database connection: {str(e)}")

if __name__ == "__main__":
    main()
