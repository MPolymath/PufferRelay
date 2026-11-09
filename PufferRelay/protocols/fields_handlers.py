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

"""Fast protocol handlers backed by tshark fields (issue #55).

Each function replaces a pyshark handler that decoded every matching packet to
Python objects. `tshark -T fields` returns only the needed columns, which is
much cheaper on large captures. Output tuples are identical to the legacy
handlers.
"""

from __future__ import annotations

import base64
import binascii
import logging
import urllib.parse

from PufferRelay.protocols.helpers import (
    asrep_hash,
    classify,
    clean_http_data,
    decode_basic_auth,
    get_service_type,
    is_printer,
    normalise_file,
    normalise_share,
    protocol_for_port,
)
from PufferRelay.tshark_fields import fields
from PufferRelay.protocols.kerberos_shared import rows as kerberos_rows


def process_ftp(pcap_file):
    rows = fields(
        pcap_file,
        "ftp && (ftp.request.command==USER || ftp.request.command==PASS)",
        ["ip.src", "ip.dst", "ftp.request.command", "ftp.request.arg"],
    )
    return [
        (src or "N/A", dst or "N/A", command or "N/A", argument or "N/A")
        for src, dst, command, argument in rows
    ]


def process_http(pcap_file):
    rows = fields(
        pcap_file,
        "http && (http.request.method==POST || http.authorization)",
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri",
            "http.authorization",
            "http.file_data",
        ],
    )
    out = []
    for src, dst, host, uri, authorization, file_data in rows:
        if not src or not dst:
            continue
        url = clean_http_data((host or "") + (uri or ""))
        username = "N/A"
        password = "N/A"
        form = "N/A"

        if authorization:
            user, secret = decode_basic_auth(authorization)
            if user and secret:
                username, password = user, secret

        if file_data:
            hex_data = file_data.replace(":", "")
            try:
                if hex_data and len(hex_data) % 2 == 0:
                    decoded = binascii.unhexlify(hex_data).decode("utf-8")
                    form = clean_http_data(urllib.parse.unquote(decoded))
            except (binascii.Error, UnicodeDecodeError, AttributeError):
                form = "N/A"

        if username != "N/A" and password != "N/A":
            out.append((src, dst, url, form, username, password))
        elif form != "N/A":
            out.append((src, dst, url, form, username, password))
    return out


def process_ldap(pcap_file):
    rows = fields(
        pcap_file,
        "ldap && ldap.protocolOp==bindRequest",
        ["ip.src", "ip.dst", "ldap.name", "ldap.simple"],
    )
    return [
        (src or "N/A", dst or "N/A", name or "N/A", simple or "N/A")
        for src, dst, name, simple in rows
    ]


def process_telnet(pcap_file):
    rows = fields(pcap_file, "telnet && (telnet.data)", ["ip.src", "ip.dst", "telnet.data"])
    return [(src, dst, data) for src, dst, data in rows if data]


def process_smtp(pcap_file):
    rows = fields(
        pcap_file,
        "smtp.auth.password || smtp.auth.username",
        ["ip.src", "ip.dst", "smtp.auth.username", "smtp.auth.password"],
    )
    return [
        (src or "N/A", dst or "N/A", user or "N/A", password or "N/A")
        for src, dst, user, password in rows
    ]


def _imap_login_from_payload(payload_hex):
    text = (payload_hex or "").replace(":", "")
    if not text:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    for raw_line in raw.splitlines():
        tokens = raw_line.decode("latin-1", "replace").split()
        for index, token in enumerate(tokens):
            if token.upper() == "LOGIN" and index + 2 < len(tokens):
                return tokens[index + 1].strip('"'), tokens[index + 2].strip('"')
    return None


def process_imap(pcap_file):
    rows = fields(
        pcap_file,
        "imap.request.command",
        [
            "ip.src",
            "ip.dst",
            "imap.request.command",
            "imap.request.username",
            "imap.request.password",
            "tcp.payload",
        ],
    )
    out = []
    for src, dst, command, username, password, payload in rows:
        if not src or not dst:
            continue
        command = (command or "").lower()
        if command == "login":
            credentials = _imap_login_from_payload(payload)
            if credentials is None and username:
                credentials = (username, password or "")
            if credentials:
                out.append((src, dst, credentials[0], credentials[1]))
        elif command == "authenticate" and username:
            out.append((src, dst, username, password or ""))
    return out


def process_pop3(pcap_file):
    rows = fields(
        pcap_file,
        "pop && (pop.request.command==USER || pop.request.command==PASS || "
        "pop.request.command==APOP)",
        ["ip.src", "ip.dst", "pop.request.command", "pop.request.parameter"],
    )
    temp = {}
    out = []
    for src, dst, command, parameter in rows:
        if not src or not dst:
            continue
        pair = (src, dst)
        command = (command or "").upper()
        if command == "USER" and parameter:
            temp.setdefault(pair, {})["username"] = parameter
        elif command == "PASS" and parameter and pair in temp:
            out.append((src, dst, temp[pair].get("username", ""), parameter))
            del temp[pair]
        elif command == "APOP" and parameter:
            username = parameter.split(" ", 1)[0]
            out.append((src, dst, username, "APOP_AUTHENTICATED"))
    return out


def process_snmp(pcap_file):
    rows = fields(pcap_file, "snmp", ["ip.src", "ip.dst", "snmp.community"])
    return [(src or "N/A", dst or "N/A", community) for src, dst, community in rows if community]


def process_netbios(pcap_file):
    rows = fields(pcap_file, "nbns", ["ip.src", "eth.src", "nbns.name", "nbns.type"])
    out = []
    for src_ip, src_mac, name, nbns_type in rows:
        if not src_ip or not src_mac:
            continue
        service_type = get_service_type(nbns_type or "")
        hostname = domain_workgroup = other_service = "N/A"
        if name:
            short = name[:15].strip()
            if service_type == "Workstation Service":
                hostname = short
            elif service_type in [
                "Domain Master Browser",
                "Domain Controllers (Group)",
                "Master Browser",
                "Browser Service Elections",
            ]:
                domain_workgroup = short
            else:
                other_service = short
        if service_type != "N/A" and (
            hostname != "N/A" or domain_workgroup != "N/A" or other_service != "N/A"
        ):
            out.append(
                (domain_workgroup, hostname, other_service, src_ip, src_mac, service_type)
            )
    return out


SMB2_CMD_NAMES = {
    "3": "tree_connect",
    "5": "create",
    "6": "close",
    "8": "read",
    "9": "write",
}


def process_smb(pcap_file):
    rows = fields(
        pcap_file,
        "smb2 || smb",
        [
            "ip.src",
            "ip.dst",
            "frame.protocols",
            "smb2.cmd",
            "smb2.tree",
            "smb2.filename",
            "smb.path",
            "smb.file",
        ],
    )
    out = []
    seen = set()
    for src, dst, protocols, command, tree, filename, smb_path, smb_file in rows:
        tokens = set((protocols or "").lower().split(":"))
        if "smb2" in tokens:
            operation = SMB2_CMD_NAMES.get((command or "").strip(), f"cmd_{command}")
            share = normalise_share(tree)
            file_name = normalise_file(filename)
        else:
            operation = "smb1"
            share = normalise_share(smb_path)
            file_name = normalise_file(smb_file)
        if not share and not file_name:
            continue
        printer = int(is_printer(share, file_name))
        key = (src, dst, share, file_name, operation, printer)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def process_kerberos(pcap_file):
    rows = kerberos_rows(pcap_file)
    preauth_seen = {}
    out = []
    seen_hashes = set()
    for row in rows:
        src, dst, msg_type, username, realm, etype, cipher, padata = row[:8]
        kind = (msg_type or "").split(",", 1)[0].strip()
        user = (username or "").split(",", 1)[0].strip()
        realm_value = (realm or "").split(",", 1)[0].strip()
        key = (user.lower(), realm_value.lower())
        if kind == "10":
            padata_types = {part.strip() for part in (padata or "").split(",") if part.strip()}
            preauth_seen[key] = "2" in padata_types
            continue
        if kind != "11" or not user or not realm_value:
            continue
        if preauth_seen.get(key, False):
            continue
        etype_value = (etype or "").split(",", 1)[0].strip() or "23"
        cipher_value = (cipher or "").split(",", 1)[0]
        hash_line = asrep_hash(user, realm_value, etype_value, cipher_value)
        if hash_line and hash_line not in seen_hashes:
            seen_hashes.add(hash_line)
            out.append((user, realm_value, etype_value, hash_line, src, dst))
    return out


def process_relays(pcap_file):
    rows = fields(
        pcap_file,
        'ntlmssp || smb2 || tcp contains "NTLMSSP"',
        [
            "ip.src",
            "ip.dst",
            "frame.protocols",
            "tcp.dstport",
            "tcp.payload",
            "ntlmssp.auth.username",
            "smb2.sec_mode.sign_required",
        ],
    )
    signing = {}
    out = []
    seen = set()
    for src, dst, protocols, port_text, payload, username, sign_required in rows:
        tokens = set((protocols or "").lower().split(":"))
        sign_value = (sign_required or "").strip().lower()
        if "smb2" in tokens and sign_value in {"0", "false", "1", "true"}:
            signing[dst] = sign_value in {"1", "true"}

        has_ntlm = "ntlmssp" in tokens
        if not has_ntlm and payload:
            try:
                has_ntlm = b"NTLMSSP" in bytes.fromhex(payload.replace(":", ""))
            except ValueError:
                has_ntlm = False
        if not has_ntlm:
            continue

        try:
            port = int(port_text) if port_text else None
        except ValueError:
            port = None
        protocol = protocol_for_port(port, "http" in tokens)
        required = signing.get(dst)
        candidate = classify(protocol, required)
        key = (src, dst, port, protocol, username or "", candidate)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            (
                src,
                dst,
                port or 0,
                protocol,
                username or "",
                "" if required is None else int(required),
                int(candidate),
            )
        )
    return out
