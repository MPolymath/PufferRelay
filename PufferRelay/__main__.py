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
import json
import logging
import os
import sys
import time
import threading

from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import (
    get_quick_wins,
    display_quick_wins,
    fetch_all_data,
    process_extracted_data,
)
from PufferRelay.protocols.quick_wins import analyze_quick_wins
from PufferRelay.logger import setup_logger
from PufferRelay.utils.loading_animation import show_loading_animation
from PufferRelay import export


def read_quick_wins_from_db(conn, show_ready_func=None):
    """Read and display quick wins from the database."""
    try:
        if show_ready_func:
            os.system("cls" if os.name == "nt" else "clear")
            show_ready_func(quick_wins=True)
            logging.info("\033[33mQuick Wins Analysis Starting...\033[0m")

        quick_wins = get_quick_wins(conn)
        if not quick_wins:
            rprint(Panel("[yellow]No quick wins found in the database.[/yellow]"))
            return
        display_quick_wins(quick_wins)
    except Exception as e:
        logging.error(f"Error reading quick wins from database: {str(e)}")
        raise


def run_exports(conn, out_dir, pcap_name=""):
    """Write the export pack (files + agent lead briefing)."""
    try:
        files = export.write_exports(conn, out_dir, pcap_name=pcap_name)
    except Exception as e:
        logging.error(f"Export failed: {str(e)}")
        raise
    leads_md = os.path.join(out_dir, "leads.md")
    rprint(
        Panel(
            "\n".join(
                ["[green]Export pack written:[/green]"]
                + [f"  {path}" for path in files]
                + ["", f"[bold]Agent feed:[/bold] {leads_md}"]
            ),
            title="Exports",
            border_style="green",
        )
    )
    return files


def _print_machine_output(args, inventory, leads):
    """stdout only, for pipes and other tools."""
    if args.json:
        print(
            json.dumps(
                {"inventory": inventory, "leads": leads},
                indent=2,
                ensure_ascii=False,
            )
        )
    elif args.creds:
        for cred in inventory["credentials"]:
            print(
                f"{cred['protocol']},{cred['source_ip']},"
                f"{cred['destination_ip']},{cred['username']},"
                f"{cred['secret']},{cred['context']}"
            )
    elif args.inventory:
        for host in inventory["hosts"]:
            names = ",".join(host["hostnames"]) or "-"
            print(f"{host['ip']}\t{names}")
        for user in inventory["users"]:
            domain = user["domain"] or "-"
            print(f"USER\t{user['username']}\t{domain}")


def main():
    parser = argparse.ArgumentParser(
        description="PufferRelay - passive network capture analyzer"
    )
    parser.add_argument("-f", "--file", help="PCAP file to analyze")
    parser.add_argument("-r", "--read", action="store_true", help="Read from database")
    parser.add_argument(
        "-q",
        "--quick-wins",
        nargs="?",
        const=True,
        help="PCAP file to analyze for quick wins (optional with -r or -f)",
    )
    parser.add_argument(
        "--only",
        help="Run only these handlers, comma separated "
        "(ldap,http,ftp,telnet,smtp,imap,pop3,ntlm,netbios,snmp,services,ips)",
    )
    parser.add_argument(
        "--credentials-only",
        action="store_true",
        help="Run only handlers that can yield identities or credentials",
    )
    parser.add_argument(
        "--dump",
        metavar="DIR",
        help="Write the export pack (inventories, credentials, hashes, nmap "
        "targets, leads.json, leads.md for AI agents) to DIR",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON (inventory + leads) instead of tables",
    )
    parser.add_argument(
        "--creds", action="store_true", help="Print credentials only (CSV lines)"
    )
    parser.add_argument(
        "--inventory", action="store_true", help="Print hosts/users only"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level",
    )
    args = parser.parse_args()

    setup_logger(getattr(logging, args.log_level))

    if not any([args.file, args.read, args.quick_wins]):
        parser.print_help()
        return

    # Machine modes keep stdout clean: no banner, no spinner, no tables.
    machine = bool(args.json or args.creds or args.inventory)
    # The loading animation writes cursor/clear escape codes to stdout; do not
    # even initialise it for machine-readable modes.
    if machine:
        update_animation, show_ready = None, None
    else:
        update_animation, show_ready = show_loading_animation()
    only = args.only.split(",") if args.only else None

    conn = None
    try:
        conn = create_database()
        if not conn:
            logging.error("Failed to create database connection. Exiting.")
            sys.exit(1)

        animation_running = not machine
        animation_thread = None
        if animation_running:

            def run_animation():
                while animation_running:
                    update_animation(quick_wins=bool(args.quick_wins))
                    time.sleep(0.2)

            animation_thread = threading.Thread(target=run_animation)
            animation_thread.start()

        try:
            if args.quick_wins and args.quick_wins is not True:
                # Quick-win scan of a capture.
                analyze_quick_wins(args.quick_wins, conn)
                if not machine:
                    os.system("cls" if os.name == "nt" else "clear")
                    show_ready(quick_wins=True)
                    logging.info("\033[33mQuick Wins Analysis Starting...\033[0m")
                    read_quick_wins_from_db(conn, show_ready)
            elif args.file:
                from PufferRelay.pcap_processing.pcap_parser import parse_pcap

                parsed_data = parse_pcap(
                    args.file,
                    only=only,
                    credentials_only=args.credentials_only,
                )
                process_extracted_data(parsed_data)

                # `-f capture -q` adds the quick-win scan to a handler run.
                if args.quick_wins is True:
                    analyze_quick_wins(args.file, conn)

                if not machine:
                    os.system("cls" if os.name == "nt" else "clear")
                    show_ready(quick_wins=False)
                    logging.info("\033[35mPufferRelay Ready...\033[0m")
                    fetch_all_data(conn)
            elif args.read:
                if args.quick_wins:
                    if not machine:
                        read_quick_wins_from_db(conn, show_ready)
                elif not machine:
                    os.system("cls" if os.name == "nt" else "clear")
                    show_ready(quick_wins=False)
                    logging.info("\033[35mPufferRelay Ready...\033[0m")
                    fetch_all_data(conn)

            if machine:
                inventory = export.collect_inventory(conn)
                leads = export.build_leads(inventory)
                _print_machine_output(args, inventory, leads)

            if args.dump:
                run_exports(conn, args.dump, pcap_name=args.file or args.quick_wins or "")
        except Exception as e:
            logging.error(f"Error during processing: {str(e)}")
            raise
        finally:
            animation_running = False
            if animation_thread is not None:
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
