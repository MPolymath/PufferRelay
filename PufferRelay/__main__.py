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
    display_table,
    fetch_all_data,
    fetch_protocol,
    fetch_table,
    protocol_headers,
    process_extracted_data,
    query_tables,
    update_quick_win,
)
from PufferRelay.protocols.quick_wins import analyze_quick_wins
from PufferRelay.config import ConfigError, configure, get_output_dir, set_db_path
from PufferRelay.logger import setup_logger
from PufferRelay.utils.loading_animation import show_loading_animation
from PufferRelay import commands as command_pack
from PufferRelay import export, live
from PufferRelay.proxy import ProxyError, run_proxy


def _warn_active(machine, title, details):
    """Conspicuous red warning before anything that sends packets."""
    lines = list(details) + [
        "",
        "[bold]This action sends packets on the network.[/bold]",
        "Only continue inside an authorised engagement with an agreed scope.",
        "PufferRelay is passive by default; this mode is opt-in.",
    ]
    text = "\n".join(lines)
    if machine:
        print(f"WARNING — {title}\n{text}", file=sys.stderr)
    else:
        rprint(
            Panel(
                text,
                title=f"[bold red]WARNING — {title}[/bold red]",
                border_style="red",
            )
        )


def _refuse_active(machine, what):
    message = (
        f"refusing {what}: authorisation not confirmed "
        "(use --confirm-authorized when you have written scope, "
        "or run interactively and type 'authorized')"
    )
    print(message, file=sys.stderr)
    sys.exit(2)


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
    # Windows consoles/pipes default to a legacy code page; Rich output and
    # UTF-8 findings must not crash when stdout is redirected.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

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
        "--auto",
        action="store_true",
        help="Profile the capture's services and run only the relevant handlers",
    )
    parser.add_argument(
        "--only",
        help="Run only these handlers, comma separated "
        "(ldap,http,ftp,telnet,smtp,imap,pop3,ntlm,netbios,snmp,kerberos,"
        "kerberosdepth,kerberoast,ldapdir,httptokens,coercion,adcs,ipv6,dbcreds,"
        "smbobjects,sccm,llm,voip,rdp,cloudapi,services,dns,asrepcatcher,ips)",
    )
    parser.add_argument(
        "--credentials-only",
        action="store_true",
        help="Run only handlers that can yield identities or credentials",
    )
    parser.add_argument(
        "--dump",
        nargs="?",
        const="",
        metavar="DIR",
        help="Write the export pack (inventories, credentials, hashes, nmap "
        "targets, leads.json, leads.md for AI agents). DIR defaults to the "
        "configured output_dir (./out).",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="JSON config file (db_path, log_level, output_dir, default_pcap)",
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        help="Database path (overrides the config file)",
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
        "--protocol",
        help="With -r: show the raw rows of these protocols "
        "(ldap,http,ftp,telnet,smtp,netbios,imap,pop3,snmp,kerberos,"
        "kerberosdepth,kerberoast,ldapdir,httptokens,coercion,adcs,ipv6,dbcreds,"
        "sccm,llm,voip,rdp,cloudapi,services,dns,asrepcatcher,ips)",
    )
    parser.add_argument(
        "--ip",
        metavar="ADDRESS",
        help="With -r: only rows where this IP appears (source or destination)",
    )
    parser.add_argument(
        "--user",
        metavar="NAME",
        help="With -r: only rows for this identity (username/name)",
    )
    parser.add_argument(
        "--has-creds",
        action="store_true",
        help="With -r: only rows carrying a credential or a hash",
    )
    parser.add_argument(
        "--table",
        metavar="NAME",
        help="With -r: raw dump of one table (e.g. dns_events, quick_wins)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Max rows per table for -r filters (default 500)",
    )
    parser.add_argument(
        "--report",
        nargs="?",
        const="",
        metavar="FILE",
        help="Write a Markdown engagement report (default: output_dir/report.md)",
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="Ask a LOCAL Ollama model to rank the leads (loopback only; off by "
        "default; no secrets are sent)",
    )
    parser.add_argument(
        "--triage-model",
        default="llama3",
        help="Ollama model for --triage (default: llama3)",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://127.0.0.1:11434",
        help="Ollama base URL; must be loopback (default: 127.0.0.1:11434)",
    )
    parser.add_argument(
        "--triage-out",
        metavar="FILE",
        help="Triage output path (default: output_dir/triage.md)",
    )
    parser.add_argument(
        "--diff",
        metavar="DB",
        help="Compare the current database with another database and write diff.md",
    )
    parser.add_argument(
        "--diff-out",
        metavar="FILE",
        help="Diff output path (default: output_dir/diff.md)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Set the logging level (default: config file or INFO)",
    )
    active = parser.add_argument_group(
        "active modes (opt-in, send packets, require authorisation)"
    )
    active.add_argument(
        "--live",
        metavar="IFACE",
        help="Capture from a network interface, then analyse it like a pcap "
        "(requires --bpf; the temporary capture is deleted afterwards)",
    )
    active.add_argument(
        "--bpf",
        metavar="FILTER",
        help="BPF capture filter (mandatory with --live, e.g. 'port 445')",
    )
    active.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Live capture / relay duration in seconds (default 60)",
    )
    active.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Skip the interactive prompt; use only with written scope",
    )
    active.add_argument(
        "--keep-live-capture",
        action="store_true",
        help="Keep the temporary live capture after analysis",
    )
    active.add_argument(
        "--proxy",
        nargs="?",
        const="127.0.0.1",
        metavar="LISTEN_HOST",
        help="Run a local TCP relay to --proxy-target and record both "
        "directions to JSONL (default listen host 127.0.0.1)",
    )
    active.add_argument(
        "--proxy-port",
        type=int,
        default=0,
        help="Listen port for --proxy (default: pick a free port)",
    )
    active.add_argument(
        "--proxy-target",
        metavar="HOST:PORT",
        help="Target of the --proxy relay (mandatory with --proxy)",
    )
    active.add_argument(
        "--proxy-out",
        metavar="FILE",
        help="JSONL recording path for --proxy (default: output_dir/proxy-recording.jsonl)",
    )
    parser.add_argument(
        "--commands",
        action="store_true",
        help="Write active-commands.md: ARP spoof / relay commands derived from "
        "the inventory (text only; nothing is executed)",
    )
    parser.add_argument(
        "--serveme",
        action="store_true",
        help="Write serveme.md: next-step commands per host and finding "
        "(text only; nothing is executed)",
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Interface written into generated commands (text only, default eth0)",
    )
    parser.add_argument(
        "--gateway",
        help="Gateway written into generated ARP commands (default: inferred)",
    )
    args = parser.parse_args()

    try:
        settings = configure(args.config)
        if args.db:
            set_db_path(args.db)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        sys.exit(2)

    setup_logger(getattr(logging, args.log_level or settings["log_level"]))

    machine = bool(args.json or args.creds or args.inventory)

    # Query filters and report generation imply reading an existing database.
    if args.ip or args.user or args.has_creds or args.table:
        args.read = True
    if args.report is not None and not (args.file or args.quick_wins or args.read):
        args.read = True
    if args.triage and not (args.file or args.quick_wins or args.read):
        args.read = True
    if args.diff and not (args.file or args.quick_wins or args.read):
        args.read = True

    # ---- active modes: explicit, warned, confirmed, never default -----
    if args.proxy is not None:
        if not args.proxy_target:
            print("error: --proxy requires --proxy-target HOST:PORT", file=sys.stderr)
            sys.exit(2)
        _warn_active(
            machine,
            "LOCAL TCP RELAY",
            [
                f"Listen: {args.proxy}:{args.proxy_port or '<free port>'}",
                f"Forward to: {args.proxy_target}",
                f"Duration: {args.duration}s",
                "Both directions will be recorded to JSONL.",
            ],
        )
        if not live.confirm_authorization(args.confirm_authorized, sys.stdin.isatty()):
            _refuse_active(machine, "proxy")
        out_path = args.proxy_out or os.path.join(
            get_output_dir() or "out", "proxy-recording.jsonl"
        )
        out_dir = os.path.dirname(os.path.abspath(out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        try:
            host, port = run_proxy(
                args.proxy_target,
                out_path,
                listen_port=args.proxy_port,
                seconds=args.duration,
                host=args.proxy,
            )
        except ProxyError as e:
            print(f"proxy error: {e}", file=sys.stderr)
            sys.exit(2)
        print(f"relay finished: {host}:{port} -> {args.proxy_target}")
        print(f"recording: {out_path}")
        return

    live_temp = None
    if args.live:
        _warn_active(
            machine,
            "LIVE CAPTURE",
            [
                f"Interface: {args.live}",
                f"BPF filter: {args.bpf or '(missing)'}",
                f"Duration: {args.duration}s",
            ],
        )
        if not args.bpf:
            print("error: --live requires --bpf (a capture filter)", file=sys.stderr)
            sys.exit(2)
        if not live.confirm_authorization(args.confirm_authorized, sys.stdin.isatty()):
            _refuse_active(machine, "live capture")
        try:
            live_temp = live.capture(args.live, args.bpf, args.duration)
        except live.LiveCaptureError as e:
            print(f"live capture error: {e}", file=sys.stderr)
            sys.exit(2)
        args.file = live_temp

    # No capture on the command line: fall back to the configured default.
    if not args.file and not args.quick_wins and not args.read:
        default_pcap = settings.get("default_pcap") or ""
        if default_pcap:
            if not os.path.exists(default_pcap):
                print(
                    f"config error: default_pcap not found: {default_pcap}",
                    file=sys.stderr,
                )
                sys.exit(2)
            args.file = default_pcap

    if not any([args.file, args.read, args.quick_wins]):
        parser.print_help()
        return

    # Machine modes keep stdout clean: no banner, no spinner, no tables.
    # The loading animation writes cursor/clear escape codes to stdout; do not
    # even initialise it for machine-readable modes.
    if machine:
        update_animation, show_ready = None, None
    else:
        update_animation, show_ready = show_loading_animation()
    only = args.only.split(",") if args.only else None
    if args.auto:
        if args.only:
            print("error: use --auto or --only, not both", file=sys.stderr)
            sys.exit(2)
        if not args.file:
            print("error: --auto requires a capture (-f/--live)", file=sys.stderr)
            sys.exit(2)
        from PufferRelay.profile import select_profile
        from PufferRelay.protocols.services_handler import process_services

        observed = process_services(args.file)
        only = select_profile(observed)
        if only:
            logging.info("auto profile: %s", ",".join(only))
        else:
            logging.info("auto profile: capture too generic, running all handlers")

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

                # ASRepCatcher-compatible traffic is worth interrupting the
                # operator for: it means Kerberos hashes may already be leaving
                # the segment. Passive finding; we only print the reference.
                catcher = parsed_data.get("asrepcatcher") or []
                if catcher:
                    from PufferRelay.protocols.asrepcatcher import REFERENCE

                    summary = (
                        f"[bold]{len(catcher)} ASRepCatcher-compatible "
                        "finding(s) in this capture[/bold]\n"
                        "Review the evidence in the lead feed before acting.\n"
                        f"Technique: {REFERENCE}"
                    )
                    if machine:
                        print(
                            f"ASREPCATCHER: {len(catcher)} finding(s); "
                            f"see leads.json; {REFERENCE}",
                            file=sys.stderr,
                        )
                    else:
                        rprint(
                            Panel(
                                summary,
                                title="[bold red]Kerberos attack pattern detected[/bold red]",
                                border_style="red",
                            )
                        )

                # Relay findings feed the SMB-signing quick win so it shows up
                # in every view (table, report, agent feed).
                from PufferRelay.protocols.helpers import smb_signing_missing_hosts

                signing_missing = smb_signing_missing_hosts(parsed_data.get("relays", []))
                if signing_missing:
                    update_quick_win(
                        conn,
                        "SMB_SIGNING_MISSING",
                        found=True,
                        details="SMB signing not required: " + ", ".join(signing_missing),
                    )

                # `-f capture -q` adds the quick-win scan to a handler run.
                if args.quick_wins is True:
                    analyze_quick_wins(args.file, conn)

                if not machine:
                    os.system("cls" if os.name == "nt" else "clear")
                    show_ready(quick_wins=False)
                    logging.info("\033[35mPufferRelay Ready...\033[0m")
                    fetch_all_data(conn)
            elif args.read and (
                args.protocol or args.ip or args.user or args.has_creds or args.table
            ):
                if args.table:
                    headers, rows = fetch_table(conn, args.table, limit=args.limit)
                    if not rows:
                        print(f"(no rows for {args.table})")
                    elif machine:
                        print("\t".join(headers))
                        for row in rows:
                            print("\t".join(str(value) for value in row))
                    else:
                        display_table(rows, headers, args.table.upper())
                elif args.protocol and not (args.ip or args.user or args.has_creds):
                    for name in [p.strip().lower() for p in args.protocol.split(",") if p.strip()]:
                        rows = fetch_protocol(conn, name)
                        if not rows:
                            print(f"(no rows for {name})")
                            continue
                        headers = protocol_headers(name)
                        if machine:
                            print("\t".join(headers))
                            for row in rows:
                                print("\t".join(str(value) for value in row))
                        else:
                            display_table(rows, headers, name.upper())
                else:
                    protocols = (
                        [p.strip().lower() for p in args.protocol.split(",") if p.strip()]
                        if args.protocol
                        else None
                    )
                    results = query_tables(
                        conn,
                        ip=args.ip,
                        user=args.user,
                        has_creds=args.has_creds,
                        protocols=protocols,
                        limit=args.limit,
                    )
                    if not results:
                        print("(no matching rows)")
                    for name, rows in results:
                        headers = protocol_headers(name)
                        if machine:
                            print("\t".join(headers))
                            for row in rows:
                                print("\t".join(str(value) for value in row))
                        else:
                            display_table(rows, headers, name.upper())
            elif args.read:
                if args.quick_wins:
                    if not machine:
                        read_quick_wins_from_db(conn, show_ready)
                elif not machine:
                    os.system("cls" if os.name == "nt" else "clear")
                    show_ready(quick_wins=False)
                    logging.info("\033[35mPufferRelay Ready...\033[0m")
                    fetch_all_data(conn)

            if machine and not (
                args.protocol or args.ip or args.user or args.has_creds or args.table
            ):
                inventory = export.collect_inventory(conn)
                leads = export.build_leads(inventory)
                _print_machine_output(args, inventory, leads)

            if args.dump is not None:
                dump_dir = args.dump or get_output_dir() or "out"
                run_exports(conn, dump_dir, pcap_name=args.file or args.quick_wins or "")

            if args.report is not None:
                from PufferRelay import report as report_module

                report_path = args.report or os.path.join(
                    get_output_dir() or "out", "report.md"
                )
                try:
                    written = report_module.write_report(
                        conn, report_path, pcap_name=args.file or args.quick_wins or ""
                    )
                except Exception as report_error:
                    logging.error("Report generation failed: %s", report_error)
                    raise
                if machine:
                    print(written, file=sys.stderr)
                else:
                    rprint(
                        Panel(
                            "[green]Engagement report written:[/green]\n"
                            f"  {written}\n\n"
                            "[bold red]Confidential:[/bold red] it contains real "
                            "credentials and hashes.",
                            title="Report",
                            border_style="red",
                        )
                    )

            if args.triage:
                from PufferRelay import triage as triage_module

                inventory = export.collect_inventory(conn)
                leads = export.build_leads(inventory)
                try:
                    text = triage_module.run_triage(
                        inventory,
                        leads,
                        url=args.ollama_url,
                        model=args.triage_model,
                    )
                except ValueError as triage_error:
                    print(f"triage error: {triage_error}", file=sys.stderr)
                    sys.exit(2)
                except Exception as triage_error:
                    logging.error("Local triage failed: %s", triage_error)
                    sys.exit(1)
                triage_path = args.triage_out or os.path.join(
                    get_output_dir() or "out", "triage.md"
                )
                triage_module.write_triage(
                    triage_path, text, args.triage_model, args.ollama_url
                )
                if machine:
                    print(triage_path, file=sys.stderr)
                else:
                    rprint(
                        Panel(
                            "[green]Local triage written:[/green]\n"
                            f"  {triage_path}\n\n"
                            "Loopback model only; lead metadata was sent, never "
                            "credentials or packet data.",
                            title="Local LLM triage",
                            border_style="green",
                        )
                    )

            if args.diff:
                import sqlite3 as sqlite_module

                from PufferRelay import diff as diff_module

                if not os.path.exists(args.diff):
                    print(f"diff error: database not found: {args.diff}", file=sys.stderr)
                    sys.exit(2)
                old = sqlite_module.connect(f"file:{args.diff}?mode=ro", uri=True)
                try:
                    old_inventory = export.collect_inventory(old)
                finally:
                    old.close()
                new_inventory = export.collect_inventory(conn)
                old_inventory["leads"] = export.build_leads(old_inventory)
                new_inventory["leads"] = export.build_leads(new_inventory)
                delta = diff_module.diff_inventories(old_inventory, new_inventory)
                diff_path = args.diff_out or os.path.join(
                    get_output_dir() or "out", "diff.md"
                )
                diff_module.write_diff(diff_path, delta, args.diff, "current database")
                if machine:
                    print(diff_path, file=sys.stderr)
                else:
                    rprint(
                        Panel(
                            "[green]Capture diff written:[/green]\n"
                            f"  {diff_path}\n\n"
                            f"New hosts: {len(delta['new_hosts'])} · "
                            f"users: {len(delta['new_users'])} · "
                            f"credentials: {len(delta['new_credentials'])} · "
                            f"leads: {len(delta['new_leads'])}",
                            title="Diff",
                            border_style="green",
                        )
                    )

            if args.commands or args.serveme:
                include = []
                if args.commands:
                    include.append("arp")
                if args.serveme:
                    include.append("serve")
                out_dir = (args.dump if args.dump else "") or get_output_dir() or "out"
                inventory = export.collect_inventory(conn)
                written = command_pack.write_command_pack(
                    inventory,
                    out_dir,
                    interface=args.iface,
                    gateway=args.gateway,
                    include=tuple(include),
                )
                if machine:
                    for path in written.values():
                        print(path, file=sys.stderr)
                else:
                    rprint(
                        Panel(
                            "\n".join(
                                ["[green]Command pack written (text only):[/green]"]
                                + [f"  {path}" for path in written.values()]
                                + [
                                    "",
                                    "[bold red]Every line in these files sends "
                                    "packets when run.[/bold red]",
                                ]
                            ),
                            title="Active commands",
                            border_style="red",
                        )
                    )
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
        if live_temp and not args.keep_live_capture:
            try:
                os.remove(live_temp)
                logging.info("Removed temporary live capture")
            except OSError:
                pass
        if conn:
            try:
                conn.close()
            except Exception as e:
                logging.error(f"Error closing database connection: {str(e)}")


if __name__ == "__main__":
    main()
