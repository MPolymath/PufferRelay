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

"""Passive 802.11 / Wi-Fi analysis (epic #82, issues #72-#81).

Everything here reads a monitor-mode capture (radiotap + 802.11). PufferRelay
never sets monitor mode, never sends frames and never cracks a key. The output
answers three questions per network:

* what is *observed* (SSID, BSSID, security suite, PMF, EAP identity, WPS),
* what is *offline-crackable* (WEP IVs, a WPA2 handshake, a PMKID),
* what needs an *active* step (deauth, rogue AP, WPS PIN, DragonShift).

Proof levels are explicit: ``observed``, ``offline-crackable``,
``active-verification-required`` and ``reference-only``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from PufferRelay.core_imports import sqlite3
from PufferRelay.tshark_fields import fields, find_tshark

# --------------------------------------------------------------------------- #
# Field extraction
# --------------------------------------------------------------------------- #

WIFI_FIELDS = (
    "frame.time_epoch",
    "wlan.fc.type",
    "wlan.fc.type_subtype",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "wlan.ssid",
    "wlan.fixed.capabilities.privacy",
    "wlan.fixed.auth.alg",
    "wlan.rsn.akms.type",
    "wlan.rsn.pcs.type",
    "wlan.rsn.gcs.type",
    "wlan.rsn.capabilities.mfpc",
    "wlan.rsn.capabilities.mfpr",
    "wlan.rsn.ie.pmkid",
    "wlan.rsn.pmkid.list",
    "eapol.keydes.type",
    "wlan_rsna_eapol.keydes.msgnr",
    "wlan_rsna_eapol.keydes.key_info.key_ack",
    "wlan_rsna_eapol.keydes.key_info.key_mic",
    "wlan_rsna_eapol.keydes.key_info.secure",
    "eapol.keydes.replay_counter",
    "eap.code",
    "eap.type",
    "eap.identity",
    "wps.wifi_protected_setup_state",
    "wps.ap_setup_locked",
    "wps.selected_registrar",
    "wps.config_methods",
    "wps.manufacturer",
    "wps.model_name",
    "wps.device_name",
    "wps.version",
    "wlan.wep.iv",
    "wlan.wep.icv",
    "wlan.wep.weakiv",
    "wlan.fc.protected",
    "radiotap.channel.freq",
    "radiotap.dbm_antsignal",
    "arp.opcode",
    "wlan.fixed.sae_message_type",
)

# 802.11 management subtypes (wlan.fc.type_subtype). tshark prints these as
# hex (0x0008), so every comparison goes through _num().
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_ASSOC_RESP = 1
SUBTYPE_PROBE_REQ = 4
SUBTYPE_PROBE_RESP = 5
SUBTYPE_BEACON = 8
SUBTYPE_DISASSOC = 10
SUBTYPE_DEAUTH = 12

BEACON_SUBTYPES = {SUBTYPE_BEACON, SUBTYPE_PROBE_RESP}

AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SUITE-B",
    12: "802.1X-SUITE-B-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}

CIPHER_NAMES = {
    1: "WEP40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP104",
    8: "GCMP",
    9: "GCMP256",
}

EAP_METHODS = {
    1: "Identity",
    2: "Notification",
    3: "Nak",
    4: "MD5",
    5: "OTP",
    6: "GTC",
    13: "TLS",
    17: "LEAP",
    18: "SIM",
    21: "TTLS",
    23: "AKA",
    25: "PEAP",
    26: "MSCHAPv2",
    43: "EAP-FAST",
    46: "TEAP",
    47: "TEAP",
    50: "TEAP",
}

WPS_METHODS = {
    0x0001: "usba",
    0x0002: "ethernet",
    0x0004: "label",
    0x0008: "display",
    0x0010: "ext-nfc-token",
    0x0020: "int-nfc-token",
    0x0040: "nfc-interface",
    0x0080: "push-button",
    0x0100: "keypad",
}

WPS_STATES = {1: "unconfigured", 2: "configured"}

# Reference links used by the command pack when no local tool exists.
REFERENCES = {
    "wep": "https://www.thehacker.recipes/radio/wi-fi/wep/",
    "wpa2": "https://www.thehacker.recipes/radio/wi-fi/wpa2/",
    "wps": "https://www.thehacker.recipes/radio/wi-fi/wps/",
    "wpa3": "https://www.thehacker.recipes/radio/wi-fi/wpa3/",
    "synacktiv": (
        "https://www.synacktiv.com/publications/"
        "wireless-infidelity-pentest-wi-fi-en-2025.html"
    ),
    "dragonshift": "https://github.com/jabbaw0nky/DragonShift",
    "dragonblood": "https://wpa3.mathyvanhoef.com/",
    "ssidconfusion": "https://www.usenix.org/conference/usenixsecurity24/"
    "presentation/vanhoef",
    "krack": "https://www.krackattacks.com/",
    "fragattacks": "https://www.fragattacks.com/",
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _num(value):
    """Best-effort int from a tshark field (None when absent/non-numeric)."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text.split(",")[0].strip(), 0)
        except (ValueError, IndexError):
            return None


def _ints(value):
    """Expand an aggregated tshark field (``"2,8"``) into a set of ints.

    Also accepts an iterable of numbers, because the summariser passes sets
    into the name helpers.
    """
    if isinstance(value, (set, frozenset, list, tuple)):
        out = set()
        for item in value:
            number = _num(item)
            if number is not None:
                out.add(number)
        return out
    out = set()
    for item in str(value or "").split(","):
        number = _num(item)
        if number is not None:
            out.add(number)
    return out


def _truthy(value):
    return str(value or "").strip() in {"1", "True", "true", "yes"}


def _first(value):
    text = str(value or "").strip()
    return text.split(",")[0].strip() if text else ""


def _clean_hex(value):
    return re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()


def _mac_hex(value):
    return _clean_hex(value)[:12]


def _ssid(value):
    """Decode wlan.ssid: tshark prints FT_BYTES as bare hex."""
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        try:
            return bytes.fromhex(text).decode("utf-8", "replace")
        except ValueError:
            return text
    return text


def _iter_rows(pcap_file):
    """Yield one dict per 802.11 packet, or nothing on an Ethernet capture.

    ``occurrence="a"`` is required: AKM/EAP/cipher fields are lists, and the
    default "first occurrence" would hide SAE in a PSK+SAE transition beacon.
    """
    for row in fields(pcap_file, "wlan", WIFI_FIELDS, occurrence="a"):
        yield dict(zip(WIFI_FIELDS, row))


def has_wifi(pcap_file):
    """True when the capture contains 802.11 frames (radiotap link type)."""
    try:
        return bool(fields(pcap_file, "wlan", ("wlan.fc.type",)))
    except RuntimeError:
        return False


WIFI_HANDLERS = {
    "wifi",
    "wifiwep",
    "wifihs",
    "wifiwps",
    "wifieap",
    "wifiwpa3",
    "wifievents",
}

# Wireshark WTAP encapsulation types that carry 802.11: IEEE 802.11,
# PRISM, 802.11+radio, radiotap, PPI.
WIFI_ENCAP_TYPES = {"20", "21", "22", "23", "163"}


def is_wifi_capture(pcap_file):
    """Cheap link-type check: read one packet, no full-file scan.

    Used to keep the Wi-Fi handlers out of an Ethernet full run (they would
    each scan the whole capture and find nothing).
    """
    tshark = find_tshark()
    if not tshark:
        return False
    try:
        completed = subprocess.run(
            [
                tshark,
                "-r",
                pcap_file,
                "-c",
                "1",
                "-T",
                "fields",
                "-e",
                "frame.encap_type",
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    first = completed.stdout.decode("utf-8", "replace").strip().splitlines()
    return bool(first) and first[0].strip() in WIFI_ENCAP_TYPES


def akm_names(value):
    names = [AKM_NAMES.get(number, f"AKM-{number}") for number in sorted(_ints(value))]
    return names


def cipher_names(value):
    names = [CIPHER_NAMES.get(number, f"CIPHER-{number}") for number in sorted(_ints(value))]
    return names


def eap_method_names(value):
    names = [EAP_METHODS.get(number, f"EAP-{number}") for number in sorted(_ints(value))]
    return names


def wps_method_names(value):
    number = _num(value) or 0
    return [name for bit, name in WPS_METHODS.items() if number & bit]


def band_channel(freq):
    """Map a radiotap frequency to (band, channel)."""
    number = _num(freq)
    if number is None:
        return ("unknown", "")
    if 2400 <= number <= 2500:
        return ("2.4GHz", str((number - 2407) // 5))
    if 4900 <= number <= 5900:
        return ("5GHz", str((number - 5000) // 5))
    if 5925 <= number <= 7125:
        return ("6GHz", str((number - 5950) // 5))
    return ("unknown", "")


def classify_network(privacy, akms, mfpc, mfpr):
    """Return the security label advertised by a beacon/probe response.

    A beacon is a capability claim, not proof of enforcement. The label is
    deliberately conservative: transition mode is called out explicitly and
    PMF is recorded separately.
    """
    akm_set = akms if isinstance(akms, set) else _ints(akms)
    has_privacy = _truthy(privacy)
    if 18 in akm_set:
        return "OWE"
    if not has_privacy and not akm_set:
        return "OPEN"
    if has_privacy and not akm_set:
        return "WEP"
    sae = bool(akm_set & {8, 9, 24, 25})
    psk = bool(akm_set & {2, 4, 6, 19, 20})
    enterprise = bool(akm_set & {1, 3, 5, 11, 12, 13})
    if sae and psk:
        return "WPA3-TRANSITION"
    if sae:
        return "WPA3-SAE"
    if psk and enterprise:
        return "WPA2-MIXED"
    if enterprise:
        return "WPA2-ENTERPRISE"
    if psk:
        return "WPA2-PSK"
    return "WPA2-OTHER"


def pmf_label(mfpc, mfpr):
    if _truthy(mfpr):
        return "required"
    if _truthy(mfpc):
        return "capable"
    return "not-set"


def build_pmkid_line(pmkid, bssid, client, ssid):
    """Build a hashcat 22000 PMKID line when every field is complete.

    Format: ``WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***``. Returns an empty string
    when a field is missing rather than emitting a line hashcat would reject.
    """
    pmkid_hex = _clean_hex(pmkid)
    ap = _mac_hex(bssid)
    sta = _mac_hex(client)
    essid = str(ssid or "").encode("utf-8", "replace").hex()
    if len(pmkid_hex) != 32 or len(ap) != 12 or len(sta) != 12 or not essid:
        return ""
    return f"WPA*01*{pmkid_hex}*{ap}*{sta}*{essid}***"


def parse_eapol_message(key_ack, key_mic, secure):
    """Infer the 4-way message number from the key-info bits.

    M1: ACK set, MIC clear. M2: no ACK, MIC set, Secure clear. M3: ACK and
    MIC set. M4: no ACK, MIC set, Secure set. Returns 0 when ambiguous.
    """
    ack = _truthy(key_ack)
    mic = _truthy(key_mic)
    secured = _truthy(secure)
    if ack and not mic:
        return 1
    if ack and mic:
        return 3
    if not ack and mic:
        return 4 if secured else 2
    return 0


# --------------------------------------------------------------------------- #
# Inventory (issue #72)
# --------------------------------------------------------------------------- #


def summarize_rows(rows):
    """Group packet rows into networks and clients.

    ``rows`` is an iterable of dicts shaped like :data:`WIFI_FIELDS`. The
    function is pure so it can be tested without tshark.
    """
    networks = {}
    clients = {}
    ssid_by_bssid = {}
    channel_by_bssid = {}

    for row in rows:
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        subtype = _num(row.get("wlan.fc.type_subtype"))
        ssid = _ssid(row.get("wlan.ssid"))
        sa = (row.get("wlan.sa") or "").strip().lower()
        da = (row.get("wlan.da") or "").strip().lower()

        if subtype in BEACON_SUBTYPES and bssid:
            akms = _ints(row.get("wlan.rsn.akms.type"))
            security = classify_network(
                row.get("wlan.fixed.capabilities.privacy"),
                akms,
                row.get("wlan.rsn.capabilities.mfpc"),
                row.get("wlan.rsn.capabilities.mfpr"),
            )
            band, channel = band_channel(row.get("radiotap.channel.freq"))
            key = (bssid, ssid)
            entry = networks.get(key)
            timestamp = (row.get("frame.time_epoch") or "").strip()
            try:
                ts = float(timestamp)
            except ValueError:
                ts = 0.0
            if entry is None:
                entry = {
                    "bssid": bssid,
                    "ssid": ssid,
                    "band": band,
                    "channel": channel,
                    "security": security,
                    "akms": ",".join(akm_names(akms)),
                    "ciphers": ",".join(
                        dict.fromkeys(
                            cipher_names(row.get("wlan.rsn.pcs.type"))
                            + cipher_names(row.get("wlan.rsn.gcs.type"))
                        )
                    ),
                    "pmf": pmf_label(
                        row.get("wlan.rsn.capabilities.mfpc"),
                        row.get("wlan.rsn.capabilities.mfpr"),
                    ),
                    "first_seen": ts,
                    "last_seen": ts,
                    "beacons": 0,
                }
                networks[key] = entry
                ssid_by_bssid.setdefault(bssid, ssid)
                if channel:
                    channel_by_bssid.setdefault(bssid, channel)
            if ts:
                entry["first_seen"] = min(entry["first_seen"] or ts, ts)
                entry["last_seen"] = max(entry["last_seen"] or ts, ts)
            entry["beacons"] += 1

        if bssid and sa and sa != bssid:
            clients.setdefault(bssid, set()).add(sa)
        elif bssid and da and da != bssid and subtype not in BEACON_SUBTYPES:
            clients.setdefault(bssid, set()).add(da)

    out = []
    for (bssid, ssid), entry in sorted(networks.items()):
        row = dict(entry)
        row["clients"] = len(clients.get(bssid, ()))
        out.append(row)
    return {
        "networks": out,
        "clients": {bssid: sorted(values) for bssid, values in clients.items()},
        "ssid_by_bssid": ssid_by_bssid,
        "channel_by_bssid": channel_by_bssid,
    }


_SUMMARY_CACHE = {}


def _summary(pcap_file):
    try:
        stat = os.stat(pcap_file)
        key = (os.path.abspath(pcap_file), stat.st_size, stat.st_mtime_ns)
    except OSError:
        key = None
    if key is not None and key in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[key]
    summary = summarize_rows(_iter_rows(pcap_file))
    if key is not None:
        if len(_SUMMARY_CACHE) > 8:
            _SUMMARY_CACHE.clear()
        _SUMMARY_CACHE[key] = summary
    return summary


def process_wifi(pcap_file):
    """Inventory rows: (bssid, ssid, band, channel, security, akms, ciphers,
    pmf, first_seen, last_seen, beacons, clients)."""
    summary = _summary(pcap_file)
    return [
        (
            row["bssid"],
            row["ssid"],
            row["band"],
            row["channel"],
            row["security"],
            row["akms"],
            row["ciphers"],
            row["pmf"],
            f"{row['first_seen']:.0f}" if row["first_seen"] else "",
            f"{row['last_seen']:.0f}" if row["last_seen"] else "",
            row["beacons"],
            row["clients"],
        )
        for row in summary["networks"]
    ]


# --------------------------------------------------------------------------- #
# WEP (issue #73)
# --------------------------------------------------------------------------- #


def process_wifi_wep(pcap_file):
    """Per-BSSID WEP IV counts and offline-crack readiness."""
    summary = _summary(pcap_file)
    ivs = {}
    unique = {}
    weak = {}
    arp = {}
    seen_clients = {}
    for row in _iter_rows(pcap_file):
        iv = (row.get("wlan.wep.iv") or "").strip()
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        if not iv or not bssid:
            continue
        ivs[bssid] = ivs.get(bssid, 0) + 1
        unique.setdefault(bssid, set()).add(_clean_hex(iv))
        if _truthy(row.get("wlan.wep.weakiv")):
            weak[bssid] = weak.get(bssid, 0) + 1
        if (row.get("arp.opcode") or "").strip():
            arp[bssid] = arp.get(bssid, 0) + 1
        sa = (row.get("wlan.sa") or "").strip().lower()
        if sa and sa != bssid:
            seen_clients.setdefault(bssid, set()).add(sa)

    rows = []
    for bssid in sorted(ivs):
        unique_count = len(unique.get(bssid, ()))
        if unique_count >= 20000:
            readiness = "offline-crackable"
        elif unique_count >= 5000:
            readiness = "near-threshold (collect to ~20k unique IVs)"
        else:
            readiness = "active-required"
        rows.append(
            (
                bssid,
                summary["ssid_by_bssid"].get(bssid, ""),
                summary["channel_by_bssid"].get(bssid, ""),
                ivs[bssid],
                unique_count,
                weak.get(bssid, 0),
                arp.get(bssid, 0),
                len(seen_clients.get(bssid, ())),
                readiness,
                "offline-crackable" if unique_count >= 20000 else "observed",
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# WPA/WPA2 handshake and PMKID (issue #74)
# --------------------------------------------------------------------------- #


def process_wifi_hs(pcap_file):
    """Pair EAPOL M1-M4 per (BSSID, client) and capture PMKIDs."""
    summary = _summary(pcap_file)
    groups = {}
    for row in _iter_rows(pcap_file):
        if not (row.get("eapol.keydes.type") or "").strip():
            continue
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        sa = (row.get("wlan.sa") or "").strip().lower()
        da = (row.get("wlan.da") or "").strip().lower()
        client = sa if sa and sa != bssid else da
        if not bssid or not client:
            continue
        key = (bssid, client)
        group = groups.setdefault(key, {"messages": set(), "pmkid": ""})
        message = _num(row.get("wlan_rsna_eapol.keydes.msgnr"))
        if message not in (1, 2, 3, 4):
            message = parse_eapol_message(
                row.get("wlan_rsna_eapol.keydes.key_info.key_ack"),
                row.get("wlan_rsna_eapol.keydes.key_info.key_mic"),
                row.get("wlan_rsna_eapol.keydes.key_info.secure"),
            )
        if message:
            group["messages"].add(message)
        candidate = _first(row.get("wlan.rsn.ie.pmkid")) or _first(
            row.get("wlan.rsn.pmkid.list")
        )
        if candidate and not group["pmkid"]:
            group["pmkid"] = _clean_hex(candidate)

    rows = []
    for (bssid, client), group in sorted(groups.items()):
        messages = sorted(group["messages"])
        complete = 1 in messages and 2 in messages
        ssid = summary["ssid_by_bssid"].get(bssid, "")
        proof = (
            "offline-crackable"
            if complete or len(group["pmkid"]) == 32
            else "observed"
        )
        rows.append(
            (
                bssid,
                ssid,
                client,
                ",".join(str(number) for number in messages),
                int(complete),
                group["pmkid"],
                proof,
            )
        )
    return rows


def process_wifi_pmkid(pcap_file):
    """PMKID rows only, in hashcat 22000 form when constructible."""
    rows = []
    for bssid, ssid, client, _messages, _complete, pmkid, _proof in process_wifi_hs(
        pcap_file
    ):
        if len(pmkid) == 32:
            rows.append(
                (
                    bssid,
                    ssid,
                    client,
                    pmkid,
                    build_pmkid_line(pmkid, bssid, client, ssid),
                )
            )
    return rows


# --------------------------------------------------------------------------- #
# WPS (issue #75)
# --------------------------------------------------------------------------- #


def process_wifi_wps(pcap_file):
    """WPS state, lock, selected registrar, methods and vendor/model."""
    rows = {}
    for row in _iter_rows(pcap_file):
        subtype = _num(row.get("wlan.fc.type_subtype"))
        if subtype not in BEACON_SUBTYPES:
            continue
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        if not bssid:
            continue
        state = _num(row.get("wps.wifi_protected_setup_state"))
        manufacturer = (row.get("wps.manufacturer") or "").strip()
        if state is None and not manufacturer:
            continue
        entry = rows.setdefault(
            bssid,
            {
                "ssid": _ssid(row.get("wlan.ssid")),
                "state": "",
                "locked": 0,
                "selected_registrar": 0,
                "methods": "",
                "manufacturer": "",
                "model": "",
                "device": "",
                "version": "",
            },
        )
        if state is not None:
            entry["state"] = WPS_STATES.get(state, str(state))
        if (row.get("wps.ap_setup_locked") or "").strip():
            entry["locked"] = int(_truthy(row.get("wps.ap_setup_locked")))
        if (row.get("wps.selected_registrar") or "").strip():
            entry["selected_registrar"] = int(
                _truthy(row.get("wps.selected_registrar"))
            )
        methods = ",".join(wps_method_names(row.get("wps.config_methods")))
        if methods:
            entry["methods"] = methods
        for source, target in (
            ("wps.manufacturer", "manufacturer"),
            ("wps.model_name", "model"),
            ("wps.device_name", "device"),
            ("wps.version", "version"),
        ):
            value = (row.get(source) or "").strip()
            if value:
                entry[target] = value

    out = []
    for bssid, entry in sorted(rows.items()):
        locked = entry["locked"]
        if entry["state"] == "unconfigured":
            risk = "critical"
        elif locked:
            risk = "medium"
        else:
            risk = "high"
        out.append(
            (
                bssid,
                entry["ssid"],
                entry["state"],
                locked,
                entry["selected_registrar"],
                entry["methods"],
                entry["manufacturer"],
                entry["model"],
                entry["device"],
                entry["version"],
                risk,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Enterprise EAP (issue #76)
# --------------------------------------------------------------------------- #


def process_wifi_eap(pcap_file):
    """Observed EAP identities and methods per BSSID."""
    groups = {}
    for row in _iter_rows(pcap_file):
        identity = (row.get("eap.identity") or "").strip()
        methods = _ints(row.get("eap.type"))
        if not identity and not methods:
            continue
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        key = (bssid, identity or "anonymous")
        group = groups.setdefault(
            key,
            {
                "methods": set(),
                "src": (row.get("wlan.sa") or "").strip().lower(),
                "dst": (row.get("wlan.da") or "").strip().lower(),
                "frames": 0,
            },
        )
        group["methods"].update(methods)
        group["frames"] += 1
        if not group["src"]:
            group["src"] = (row.get("wlan.sa") or "").strip().lower()

    rows = []
    for (bssid, identity), group in sorted(groups.items()):
        rows.append(
            (
                bssid,
                identity,
                ",".join(eap_method_names(group["methods"])),
                group["src"],
                group["dst"],
                group["frames"],
                "observed",
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# WPA3 / SAE / PMF (issue #77)
# --------------------------------------------------------------------------- #


def process_wifi_wpa3(pcap_file):
    """WPA3-SAE and transition-mode classification with PMF state."""
    summary = _summary(pcap_file)
    sae_frames = {}
    for row in _iter_rows(pcap_file):
        if (row.get("wlan.fixed.sae_message_type") or "").strip():
            bssid = (row.get("wlan.bssid") or "").strip().lower()
            sae_frames[bssid] = sae_frames.get(bssid, 0) + 1

    rows = []
    for network in summary["networks"]:
        security = network["security"]
        if not security.startswith("WPA3"):
            continue
        transition = int(security.startswith("WPA3-TRANSITION"))
        downgrade = int(transition and network["pmf"] != "required")
        if downgrade:
            proof = "active-verification-required"
        else:
            proof = "observed"
        rows.append(
            (
                network["bssid"],
                network["ssid"],
                network["akms"],
                network["pmf"],
                sae_frames.get(network["bssid"], 0),
                transition,
                downgrade,
                proof,
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# Rogue AP / deauth analytics (issue #78)
# --------------------------------------------------------------------------- #


def process_wifi_events(pcap_file):
    """Deauth/disassoc bursts and duplicate-SSID (evil-twin) candidates."""
    summary = _summary(pcap_file)
    events = {}
    for row in _iter_rows(pcap_file):
        subtype = _num(row.get("wlan.fc.type_subtype"))
        if subtype not in {SUBTYPE_DEAUTH, SUBTYPE_DISASSOC}:
            continue
        bssid = (row.get("wlan.bssid") or "").strip().lower()
        sa = (row.get("wlan.sa") or "").strip().lower()
        da = (row.get("wlan.da") or "").strip().lower()
        client = da if da and da != bssid else sa
        key = ("deauth" if subtype == SUBTYPE_DEAUTH else "disassoc", bssid, client)
        events[key] = events.get(key, 0) + 1

    rows = []
    for (kind, bssid, client), count in sorted(events.items()):
        severity = "high" if count >= 5 else "low"
        detail = (
            f"{count} {kind} frame(s)"
            + (" (burst)" if count >= 5 else "")
        )
        rows.append(
            (
                kind,
                severity,
                bssid,
                summary["ssid_by_bssid"].get(bssid, ""),
                client,
                count,
                detail,
                json.dumps({"count": count}, sort_keys=True),
            )
        )

    by_ssid = {}
    for network in summary["networks"]:
        ssid = network["ssid"]
        if not ssid:
            continue
        by_ssid.setdefault(ssid, []).append(network)
    for ssid, networks in sorted(by_ssid.items()):
        if len(networks) < 2:
            continue
        securities = {network["security"] for network in networks}
        ouis = {network["bssid"][:8] for network in networks}
        if len(securities) == 1 and len(ouis) == 1:
            continue
        evidence = {
            "ssid": ssid,
            "bssids": [network["bssid"] for network in networks],
            "security": sorted(securities),
            "ouis": sorted(ouis),
        }
        for network in networks:
            rows.append(
                (
                    "evil-twin-candidate",
                    "medium",
                    network["bssid"],
                    ssid,
                    "",
                    len(networks),
                    "same SSID advertised by multiple BSSIDs with different "
                    "security or OUI; passive evidence only",
                    json.dumps(evidence, sort_keys=True),
                )
            )
    return rows


# --------------------------------------------------------------------------- #
# DB readers and the command pack (issue #79)
# --------------------------------------------------------------------------- #


WIFI_TABLES = {
    "networks": (
        "wifi_networks",
        [
            "bssid",
            "ssid",
            "band",
            "channel",
            "security",
            "akms",
            "ciphers",
            "pmf",
            "first_seen",
            "last_seen",
            "beacons",
            "clients",
        ],
    ),
    "wep": (
        "wifi_wep",
        [
            "bssid",
            "ssid",
            "channel",
            "iv_count",
            "unique_ivs",
            "weak_ivs",
            "arp_frames",
            "clients",
            "readiness",
            "proof",
        ],
    ),
    "handshakes": (
        "wifi_handshakes",
        ["bssid", "ssid", "client", "messages", "complete", "pmkid", "proof"],
    ),
    "wps": (
        "wifi_wps",
        [
            "bssid",
            "ssid",
            "state",
            "locked",
            "selected_registrar",
            "config_methods",
            "manufacturer",
            "model",
            "device_name",
            "version",
            "risk",
        ],
    ),
    "eap": (
        "wifi_eap",
        ["bssid", "identity", "methods", "src", "dst", "frames", "proof"],
    ),
    "wpa3": (
        "wifi_wpa3",
        [
            "bssid",
            "ssid",
            "akms",
            "pmf",
            "sae_frames",
            "transition",
            "downgrade_risk",
            "proof",
        ],
    ),
    "events": (
        "wifi_events",
        [
            "kind",
            "severity",
            "bssid",
            "ssid",
            "client",
            "count",
            "detail",
            "evidence",
        ],
    ),
}


def collect_wifi(conn):
    """Return the Wi-Fi tables as dicts for the export pack and leads."""
    out = {}
    for name, (table, columns) in WIFI_TABLES.items():
        try:
            cursor = conn.execute(f"SELECT {', '.join(columns)} FROM {table}")
        except sqlite3.Error:
            out[name] = []
            continue
        out[name] = [dict(zip(columns, row)) for row in cursor.fetchall()]
    return out


def _code(lines):
    return ["```bash", *lines, "```"]


def _network_table(networks):
    lines = [
        "| BSSID | SSID | Band | Ch | Security | PMF | Clients |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in networks:
        lines.append(
            f"| {row.get('bssid') or '-'} | {row.get('ssid') or '<hidden>'} "
            f"| {row.get('band') or '-'} | {row.get('channel') or '-'} "
            f"| {row.get('security') or '-'} | {row.get('pmf') or '-'} "
            f"| {row.get('clients') or 0} |"
        )
    return lines


def wifi_attacks_markdown(wifi, interface="wlan0mon", pcap_name=""):
    """Build the text-only Wi-Fi attack/next-step pack.

    ``wifi`` is the dict returned by :func:`collect_wifi`. Nothing here is
    executed by PufferRelay; every active command is marked and carries the
    reason, prerequisites and cleanup.
    """
    networks = wifi.get("networks") or []
    wep = wifi.get("wep") or []
    handshakes = wifi.get("handshakes") or []
    wps = wifi.get("wps") or []
    eap = wifi.get("eap") or []
    wpa3 = wifi.get("wpa3") or []
    events = wifi.get("events") or []

    lines = [
        f"# Wi-Fi attack pack{f' — {pcap_name}' if pcap_name else ''}",
        "",
        "> **WARNING — ACTIVE COMMANDS**",
        ">",
        "> Commands marked ACTIVE send 802.11 frames (deauth, rogue AP, WPS",
        "> PIN, DragonShift). Run them only inside an authorised engagement",
        "> with an agreed scope. Deauth and rogue APs can disrupt production.",
        "> PufferRelay never runs these commands.",
        "",
        "Proof levels: `observed` (capture shows the configuration),",
        "`offline-crackable` (material in the capture can be cracked offline),",
        "`active-verification-required` (needs a frame or a rogue AP),",
        "`reference-only` (no local tool; see the linked article).",
        "",
    ]

    if not any([networks, wep, handshakes, wps, eap, wpa3, events]):
        lines.append(
            "No 802.11 findings in the database. Run a monitor-mode capture "
            "through `-f capture.pcapng` first."
        )
        return "\n".join(lines) + "\n"

    if networks:
        lines += ["## Networks observed", ""]
        lines += _network_table(networks)
        lines.append("")

    if wep:
        lines += ["## WEP (offline-crackable)", ""]
        for row in wep:
            bssid = row.get("bssid") or "<BSSID>"
            channel = row.get("channel") or "<CH>"
            lines += [
                f"### {row.get('ssid') or bssid} — {bssid}",
                "",
                f"IVs: {row.get('iv_count')} total, {row.get('unique_ivs')} unique, "
                f"{row.get('weak_ivs')} weak; ARP frames: {row.get('arp_frames')}; "
                f"readiness: **{row.get('readiness')}**.",
                "",
                "OFFLINE (no traffic):",
            ]
            lines += _code([f"aircrack-ng -b {bssid} capture.pcap"])
            lines += [
                "",
                "ACTIVE — only if more IVs are needed (ARP replay / fake auth):",
            ]
            lines += _code(
                [
                    f"sudo airmon-ng start {interface}",
                    f"sudo airodump-ng -c {channel} --bssid {bssid} -w wep {interface}",
                    f"sudo aireplay-ng --fakeauth 0 -a {bssid} {interface}",
                    f"sudo aireplay-ng --arpreplay -b {bssid} {interface}",
                    "# alternatives: --fragment / --chopchop (same interface)",
                ]
            )
            lines += [
                "",
                "Cleanup: stop aireplay-ng, restore managed mode "
                f"(`sudo airmon-ng stop {interface}`).",
                f"Reference: {REFERENCES['wep']}",
                "",
            ]

    complete = [row for row in handshakes if row.get("complete")]
    pmkids = [row for row in handshakes if len(row.get("pmkid") or "") == 32]
    if complete or pmkids:
        lines += ["## WPA/WPA2 handshake and PMKID (offline-crackable)", ""]
    if complete:
        for row in complete:
            bssid = row.get("bssid") or "<BSSID>"
            lines += [
                f"### {row.get('ssid') or bssid} — {bssid} / {row.get('client')}",
                "",
                f"EAPOL messages: {row.get('messages')} (complete).",
                "",
                "OFFLINE (no traffic):",
            ]
            lines += _code(
                [
                    "hcxpcapngtool -o handshake.hc22000 handshake.pcap",
                    "hashcat -m 22000 handshake.hc22000 wordlist.txt",
                    f"aircrack-ng -b {bssid} -w wordlist.txt handshake.pcap",
                ]
            )
            lines.append("")
    for row in pmkids:
        line = build_pmkid_line(
            row.get("pmkid"), row.get("bssid"), row.get("client"), row.get("ssid")
        )
        lines += [
            f"### PMKID — {row.get('ssid') or row.get('bssid')}",
            "",
            "OFFLINE (no traffic):",
        ]
        lines += _code(
            [
                "hcxdumptool -i " + interface + " -w pmkid.pcapng --enable_status=1",
                "hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng",
                "hashcat -m 22000 pmkid.hc22000 wordlist.txt",
            ]
        )
        if line:
            lines += ["", "Captured PMKID line (hashcat 22000):", "", f"`{line}`"]
        lines += [
            "",
            f"Reference: {REFERENCES['wpa2']} · {REFERENCES['synacktiv']}",
            "",
        ]
    if handshakes and not complete:
        lines += [
            "## WPA/WPA2 handshake — not complete",
            "",
            "A partial handshake is not crackable. Capture more with an ACTIVE step:",
        ]
        lines += _code(
            [
                f"sudo hcxdumptool -i {interface} -o dump.pcapng --enable_status=1",
                "# or force a reconnect with a targeted deauth (ACTIVE, disruptive):",
                "sudo aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT> " + interface,
            ]
        )
        lines += ["", f"Reference: {REFERENCES['wpa2']}", ""]

    if wps:
        lines += ["## WPS (observed; active PIN/Pixie)", ""]
        for row in wps:
            bssid = row.get("bssid") or "<BSSID>"
            lines += [
                f"### {row.get('ssid') or bssid} — {bssid}",
                "",
                f"State: {row.get('state') or 'unknown'}; locked: "
                f"{row.get('locked')}; selected registrar: "
                f"{row.get('selected_registrar')}; methods: "
                f"{row.get('config_methods') or '-'}; vendor: "
                f"{row.get('manufacturer') or '-'} {row.get('model') or ''}; "
                f"risk: **{row.get('risk')}**.",
                "",
                "ACTIVE — monitor mode required; a lockout can delay the test:",
            ]
            lines += _code(
                [
                    f"sudo wash -i {interface}",
                    f"sudo reaver -i {interface} -b {bssid} -c <CH> -vv",
                    f"sudo bully {interface} -b {bssid} -c <CH> -S -F -B -v 3",
                    "# Pixie Dust (chipset-dependent):",
                    f"sudo reaver -i {interface} -b {bssid} -c <CH> -K 1 -N -vv",
                    "# NULL PIN (only when the AP accepts it):",
                    f"sudo reaver -i {interface} -b {bssid} -c <CH> -f -N -g 1 -vv -p ''",
                ]
            )
            lines += [
                "",
                "Cleanup: stop reaver/bully; restore managed mode.",
                f"Reference: {REFERENCES['wps']}",
                "",
            ]

    if eap:
        lines += ["## Enterprise EAP (observed; rogue AP/relay is active)", ""]
        for row in eap:
            lines += [
                f"### {row.get('bssid') or '<BSSID>'} — identity "
                f"`{row.get('identity')}`",
                "",
                f"Methods: {row.get('methods') or '-'}; frames: "
                f"{row.get('frames')}.",
                "",
                "ACTIVE — rogue authenticator / relay; certificates may be "
                "validated by the client:",
            ]
            lines += _code(
                [
                    "sudo eaphammer -i " + interface + " --auth wpa-eap "
                    "--identity <identity> --cert-wizard",
                    "# or relay PEAP-MSCHAPv2 with hostapd-mana + wpa_sycophant:",
                    "sudo hostapd-mana /etc/hostapd-mana.conf",
                    "sudo wpa_sycophant -i " + interface + " -c wpa_sycophant.conf",
                ]
            )
            lines += [
                "",
                f"Reference: {REFERENCES['synacktiv']}",
                "",
            ]

    if wpa3:
        lines += ["## WPA3-SAE / transition mode", ""]
        for row in wpa3:
            bssid = row.get("bssid") or "<BSSID>"
            lines += [
                f"### {row.get('ssid') or bssid} — {bssid}",
                "",
                f"AKMs: {row.get('akms')}; PMF: {row.get('pmf')}; "
                f"SAE auth frames: {row.get('sae_frames')}; transition: "
                f"{row.get('transition')}; downgrade risk: "
                f"**{row.get('downgrade_risk')}**; proof: "
                f"`{row.get('proof')}`.",
                "",
            ]
            if row.get("downgrade_risk"):
                lines += [
                    "ACTIVE — transition mode with PMF not required; "
                    "downgrade to WPA2 then capture the handshake:",
                ]
                lines += _code(
                    [
                        "python3 dragonshift.py -m " + interface + " -r <second-iface>",
                        "hcxpcapngtool -o dragon.hc22000 dragon.pcapng",
                        "hashcat -m 22000 dragon.hc22000 wordlist.txt",
                    ]
                )
                lines += ["", f"Reference: {REFERENCES['dragonshift']}"]
            else:
                lines += [
                    "SAE has no offline handshake/PMKID hash. Dragonblood "
                    "side channels and SSID Confusion need active verification:",
                    f"- {REFERENCES['dragonblood']}",
                    f"- {REFERENCES['ssidconfusion']}",
                ]
            lines += [
                "",
                "Also reference-only for WPA2/3 without PMF: KRACK "
                f"({REFERENCES['krack']}) and FragAttacks "
                f"({REFERENCES['fragattacks']}).",
                "",
            ]

    if events:
        lines += ["## Rogue AP / deauth observations", ""]
        for row in events:
            lines += [
                f"- **{row.get('kind')}** {row.get('severity')} — "
                f"{row.get('bssid') or '-'} / {row.get('ssid') or '-'} — "
                f"{row.get('detail')}",
            ]
        lines += [
            "",
            "ACTIVE — confirm a candidate before calling it an evil twin:",
        ]
        lines += _code(
            [
                "sudo bettercap -iface " + interface,
                "# wifi.recon on ; wifi.show ; wifi.deauth <BSSID>",
                "sudo mdk4 " + interface + " d -b <BSSID>  # deauth test",
            ]
        )
        lines += ["", f"Reference: {REFERENCES['synacktiv']}", ""]

    lines += [
        "## References",
        "",
        f"- WEP: {REFERENCES['wep']}",
        f"- WPA2: {REFERENCES['wpa2']}",
        f"- WPS: {REFERENCES['wps']}",
        f"- WPA3 (page may be empty): {REFERENCES['wpa3']}",
        f"- Synacktiv 2025: {REFERENCES['synacktiv']}",
        f"- DragonShift: {REFERENCES['dragonshift']}",
        f"- Dragonblood: {REFERENCES['dragonblood']}",
        f"- SSID Confusion: {REFERENCES['ssidconfusion']}",
        f"- KRACK: {REFERENCES['krack']}",
        f"- FragAttacks: {REFERENCES['fragattacks']}",
        "",
        "## Cleanup",
        "",
        "- stop aireplay-ng / reaver / bully / hostapd-mana / bettercap;",
        "- restore managed mode (`sudo airmon-ng stop " + interface + "`);",
        "- remove temporary captures, handshakes and PMKID files;",
        "- never upload captures, handshakes or derived hashes to third parties.",
        "",
    ]
    return "\n".join(lines) + "\n"


def write_wifi_attacks(conn, out_path, interface="wlan0mon", pcap_name=""):
    """Write the Wi-Fi attack pack and return its path."""
    wifi = collect_wifi(conn)
    directory = os.path.dirname(os.path.abspath(out_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(wifi_attacks_markdown(wifi, interface=interface, pcap_name=pcap_name))
    return out_path
