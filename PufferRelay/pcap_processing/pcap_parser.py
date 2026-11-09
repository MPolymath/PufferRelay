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

from PufferRelay.protocols import (
    process_ldap,
    process_http,
    process_ftp,
    process_telnet,
    process_smtp,
    process_ips,
    process_ntlm,
    process_netbios,
    process_imap,
    process_pop3,
    process_snmp,
    process_services,
    process_kerberos,
    process_relays,
    process_smb,
    process_files,
    process_nac,
    process_wsus,
    process_dns,
    process_asrepcatcher,
    process_kerberoast,
    process_http_tokens,
    process_coercion,
    process_adcs,
    process_ipv6_adidns,
    process_database_auth,
    process_smb_objects,
    process_sccm,
    process_llm_traffic,
    process_kerberos_depth,
    process_ldap_directory,
    process_voip,
)
from PufferRelay.core_imports import logging
from PufferRelay.utils.loading_animation import show_loading_animation
from PufferRelay.utils.progress import ProgressTracker
import os
import threading
import time

# Handler registry (credentials first, inventory last).
HANDLERS = {
    "ldap": process_ldap,
    "http": process_http,
    "ftp": process_ftp,
    "telnet": process_telnet,
    "smtp": process_smtp,
    "imap": process_imap,
    "pop3": process_pop3,
    "ntlm": process_ntlm,
    "netbios": process_netbios,
    "snmp": process_snmp,
    "kerberos": process_kerberos,
    "relays": process_relays,
    "smb": process_smb,
    "files": process_files,
    "nac": process_nac,
    "wsus": process_wsus,
    "dns": process_dns,
    "asrepcatcher": process_asrepcatcher,
    "kerberoast": process_kerberoast,
    "httptokens": process_http_tokens,
    "coercion": process_coercion,
    "adcs": process_adcs,
    "ipv6": process_ipv6_adidns,
    "dbcreds": process_database_auth,
    "smbobjects": process_smb_objects,
    "sccm": process_sccm,
    "llm": process_llm_traffic,
    "kerberosdepth": process_kerberos_depth,
    "ldapdir": process_ldap_directory,
    "voip": process_voip,
    "services": process_services,
    "ips": process_ips,
}

# Handlers that can yield usernames or credentials (#48).
CREDENTIAL_HANDLERS = {"ldap", "http", "ftp", "telnet", "smtp", "imap", "pop3", "ntlm",
                       "kerberos", "relays", "smb", "files", "nac", "httptokens",
                       "dbcreds", "kerberoast", "asrepcatcher", "smbobjects",
                       "kerberosdepth", "ldapdir"}


def selected_handlers(only=None, credentials_only=False):
    """Return the handler names to run for the given filters (pure, testable)."""
    selected = None
    if only:
        selected = {name.strip().lower() for name in only if name and name.strip()}
        unknown = selected - set(HANDLERS)
        for name in sorted(unknown):
            logging.warning(
                "Unknown protocol %r ignored (known: %s)", name, ", ".join(HANDLERS)
            )
        selected = selected & set(HANDLERS)
    names = []
    for name in HANDLERS:
        if selected is not None and name not in selected:
            continue
        if credentials_only and name not in CREDENTIAL_HANDLERS:
            continue
        names.append(name)
    return names


def parse_pcap(pcap_file, only=None, credentials_only=False, animate=None):
    """Parses a PCAP file and extracts data for the selected protocol handlers.

    Args:
        pcap_file (str): Path to the .pcap file.
        only (iterable[str] | None): run only these handlers (issue #48).
        credentials_only (bool): run only handlers that can yield identities
            or credentials (issue #48).

    Returns:
        dict: Extracted data categorized by protocol.
    """
    logging.info("Parsing PCAP file: %s", pcap_file)
    names = selected_handlers(only=only, credentials_only=credentials_only)
    logging.info("Handlers: %s", ", ".join(names))
    try:
        size_mb = os.path.getsize(pcap_file) / (1024 * 1024)
        logging.info("Capture size: %.1f MiB, %d handler pass(es)", size_mb, len(names))
    except OSError:
        pass
    tracker = ProgressTracker(len(names))
    tracker.start()

    animation_running = False
    animation_thread = None
    if animate is None:
        animate = logging.getLogger().getEffectiveLevel() > logging.DEBUG
    if animate:
        update_animation, _ = show_loading_animation()
        animation_running = True

        def animation_loop():
            """Run the animation until stopped."""
            while animation_running:
                update_animation(quick_wins=False, status=tracker.status_line())
                time.sleep(0.1)

        animation_thread = threading.Thread(target=animation_loop)
        animation_thread.start()
    else:
        logging.info("Starting protocol processing...")

    try:
        data = {}
        for name in names:
            data[name] = HANDLERS[name](pcap_file)
            tracker.step(name)
            logging.info("%s", tracker.status_line())
        return data
    except Exception as e:
        logging.error("Error during PCAP parsing: %s", str(e))
        raise
    finally:
        if animation_running and animation_thread is not None:
            animation_running = False
            animation_thread.join()
