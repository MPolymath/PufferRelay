"""Passive Wi-Fi analysis (epic #82): classification, parsers, DB and outputs.

These tests are tshark-free: handlers are exercised by monkeypatching the row
iterator, so the suite stays fast and runs everywhere. An end-to-end 802.11
capture test belongs to the fixtures issue (#81).
"""

import json

import pytest

from PufferRelay.database.db_models import create_database
from PufferRelay.database.db_queries import (
    fetch_protocol,
    insert_into_database,
    protocol_headers,
)
from PufferRelay.export import build_leads
from PufferRelay.protocols import wifi


def make_row(**overrides):
    row = {field: "" for field in wifi.WIFI_FIELDS}
    row.update(overrides)
    return row


def beacon(bssid, ssid, **overrides):
    base = {
        "wlan.fc.type": "0",
        "wlan.fc.type_subtype": "8",
        "wlan.bssid": bssid,
        "wlan.sa": bssid,
        "wlan.ssid": ssid,
        "frame.time_epoch": "1700000000.0",
        "radiotap.channel.freq": "2412",
    }
    base.update(overrides)
    return make_row(**base)


# --------------------------------------------------------------------------- #
# Classification helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "privacy,akms,mfpc,mfpr,expected",
    [
        ("0", "", "", "", "OPEN"),
        ("1", "", "", "", "WEP"),
        ("1", "2", "1", "0", "WPA2-PSK"),
        ("1", "1", "1", "0", "WPA2-ENTERPRISE"),
        ("1", "1,2", "1", "0", "WPA2-MIXED"),
        ("1", "8", "1", "1", "WPA3-SAE"),
        ("1", "2,8", "1", "0", "WPA3-TRANSITION"),
        ("1", "18", "1", "1", "OWE"),
        ("1", "2,8", "1", "1", "WPA3-TRANSITION"),
        ("1", "8,9", "1", "1", "WPA3-SAE"),
    ],
)
def test_classify_network(privacy, akms, mfpc, mfpr, expected):
    assert wifi.classify_network(privacy, akms, mfpc, mfpr) == expected


def test_pmf_label():
    assert wifi.pmf_label("1", "1") == "required"
    assert wifi.pmf_label("1", "0") == "capable"
    assert wifi.pmf_label("0", "0") == "not-set"


@pytest.mark.parametrize(
    "freq,band,channel",
    [
        ("2412", "2.4GHz", "1"),
        ("2437", "2.4GHz", "6"),
        ("5180", "5GHz", "36"),
        ("5955", "6GHz", "1"),
        ("", "unknown", ""),
    ],
)
def test_band_channel(freq, band, channel):
    assert wifi.band_channel(freq) == (band, channel)


def test_akm_and_cipher_names():
    assert wifi.akm_names("2,8") == ["PSK", "SAE"]
    assert wifi.cipher_names("2,4") == ["TKIP", "CCMP"]


# --------------------------------------------------------------------------- #
# Row summarisation
# --------------------------------------------------------------------------- #


def test_summarize_rows_builds_networks_and_clients():
    rows = [
        beacon("aa:bb:cc:dd:ee:01", "corp", **{"wlan.rsn.akms.type": "2"}),
        beacon(
            "aa:bb:cc:dd:ee:02",
            "corp",
            **{
                "wlan.rsn.akms.type": "2,8",
                "wlan.rsn.capabilities.mfpc": "1",
                "wlan.rsn.capabilities.mfpr": "0",
                "radiotap.channel.freq": "5180",
            },
        ),
        make_row(**{
            "wlan.fc.type_subtype": "2",
            "wlan.bssid": "aa:bb:cc:dd:ee:01",
            "wlan.sa": "11:22:33:44:55:66",
        }),
    ]
    summary = wifi.summarize_rows(rows)
    networks = {row["bssid"]: row for row in summary["networks"]}
    assert networks["aa:bb:cc:dd:ee:01"]["security"] == "WPA2-PSK"
    assert networks["aa:bb:cc:dd:ee:01"]["clients"] == 1
    assert networks["aa:bb:cc:dd:ee:02"]["security"] == "WPA3-TRANSITION"
    assert networks["aa:bb:cc:dd:ee:02"]["band"] == "5GHz"
    assert networks["aa:bb:cc:dd:ee:02"]["pmf"] == "capable"


def test_summarize_rows_empty_on_ethernet():
    assert wifi.summarize_rows([])["networks"] == []


# --------------------------------------------------------------------------- #
# EAPOL / PMKID
# --------------------------------------------------------------------------- #


def test_parse_eapol_message():
    assert wifi.parse_eapol_message("1", "0", "0") == 1
    assert wifi.parse_eapol_message("0", "1", "0") == 2
    assert wifi.parse_eapol_message("1", "1", "0") == 3
    assert wifi.parse_eapol_message("0", "1", "1") == 4
    assert wifi.parse_eapol_message("0", "0", "0") == 0


def test_build_pmkid_line():
    line = wifi.build_pmkid_line(
        "00112233445566778899aabbccddeeff",
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "corp",
    )
    assert line == (
        "WPA*01*00112233445566778899aabbccddeeff"
        "*aabbccddeeff*112233445566*636f7270***"
    )
    assert wifi.build_pmkid_line("00", "aa", "bb", "corp") == ""
    assert wifi.build_pmkid_line("0" * 32, "aa:bb:cc:dd:ee:ff", "x", "") == ""


# --------------------------------------------------------------------------- #
# Handlers (tshark-free via monkeypatched rows)
# --------------------------------------------------------------------------- #


def test_process_wifi_wep(monkeypatch):
    rows = [
        beacon("aa:bb:cc:00:00:01", "wepnet"),
        make_row(**{
            "wlan.fc.type_subtype": "32",
            "wlan.bssid": "aa:bb:cc:00:00:01",
            "wlan.sa": "aa:bb:cc:00:00:01",
            "wlan.wep.iv": "0x0001",
            "wlan.fc.protected": "1",
            "arp.opcode": "1",
        }),
        make_row(**{
            "wlan.fc.type_subtype": "32",
            "wlan.bssid": "aa:bb:cc:00:00:01",
            "wlan.sa": "aa:bb:cc:00:00:01",
            "wlan.wep.iv": "0x0002",
            "wlan.fc.protected": "1",
        }),
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_wep("fake.pcap")
    assert len(result) == 1
    bssid, ssid, channel, count, unique, weak, arp, clients, readiness, proof = result[0]
    assert (bssid, ssid, channel) == ("aa:bb:cc:00:00:01", "wepnet", "1")
    assert count == 2 and unique == 2 and arp == 1
    assert readiness == "active-required"
    assert proof == "observed"


def test_process_wifi_handshake_and_pmkid(monkeypatch):
    rows = [
        beacon("aa:bb:cc:00:00:02", "wp2"),
        make_row(**{
            "wlan.bssid": "aa:bb:cc:00:00:02",
            "wlan.sa": "aa:bb:cc:00:00:02",
            "wlan.da": "11:22:33:44:55:66",
            "eapol.keydes.type": "2",
            "wlan_rsna_eapol.keydes.msgnr": "1",
            "wlan.rsn.ie.pmkid": "00112233445566778899aabbccddeeff",
        }),
        make_row(**{
            "wlan.bssid": "aa:bb:cc:00:00:02",
            "wlan.sa": "11:22:33:44:55:66",
            "wlan.da": "aa:bb:cc:00:00:02",
            "eapol.keydes.type": "2",
            "wlan_rsna_eapol.keydes.msgnr": "2",
        }),
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_hs("fake.pcap")
    assert len(result) == 1
    bssid, ssid, client, messages, complete, pmkid, proof = result[0]
    assert complete == 1
    assert messages == "1,2"
    assert pmkid == "00112233445566778899aabbccddeeff"
    assert proof == "offline-crackable"
    pmkid_rows = wifi.process_wifi_pmkid("fake.pcap")
    assert pmkid_rows[0][4].startswith("WPA*01*")


def test_process_wifi_wps(monkeypatch):
    rows = [
        beacon(
            "aa:bb:cc:00:00:03",
            "wpsnet",
            **{
                "wps.wifi_protected_setup_state": "2",
                "wps.ap_setup_locked": "0",
                "wps.selected_registrar": "1",
                "wps.config_methods": "392",
                "wps.manufacturer": "Acme",
                "wps.model_name": "AP-1",
            },
        )
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_wps("fake.pcap")
    assert len(result) == 1
    (
        bssid,
        ssid,
        state,
        locked,
        selected,
        methods,
        manufacturer,
        model,
        _device,
        _version,
        risk,
    ) = result[0]
    assert state == "configured" and locked == 0 and selected == 1
    assert "push-button" in methods and "keypad" in methods
    assert manufacturer == "Acme" and model == "AP-1"
    assert risk == "high"


def test_process_wifi_eap(monkeypatch):
    rows = [
        make_row(**{
            "wlan.bssid": "aa:bb:cc:00:00:04",
            "wlan.sa": "11:22:33:44:55:66",
            "wlan.da": "aa:bb:cc:00:00:04",
            "eap.code": "1",
            "eap.type": "25",
            "eap.identity": "alice",
        }),
        make_row(**{
            "wlan.bssid": "aa:bb:cc:00:00:04",
            "wlan.sa": "11:22:33:44:55:66",
            "wlan.da": "aa:bb:cc:00:00:04",
            "eap.code": "2",
            "eap.type": "26",
            "eap.identity": "alice",
        }),
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_eap("fake.pcap")
    assert result[0][1] == "alice"
    assert result[0][2] == "PEAP,MSCHAPv2"
    assert result[0][5] == 2


def test_process_wifi_wpa3_transition(monkeypatch):
    rows = [
        beacon(
            "aa:bb:cc:00:00:05",
            "wpa3net",
            **{
                "wlan.rsn.akms.type": "2,8",
                "wlan.rsn.capabilities.mfpc": "1",
                "wlan.rsn.capabilities.mfpr": "0",
            },
        ),
        make_row(**{
            "wlan.bssid": "aa:bb:cc:00:00:05",
            "wlan.fixed.sae_message_type": "1",
        }),
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_wpa3("fake.pcap")
    assert len(result) == 1
    bssid, ssid, akms, pmf, sae, transition, downgrade, proof = result[0]
    assert (bssid, ssid, pmf) == ("aa:bb:cc:00:00:05", "wpa3net", "capable")
    assert "SAE" in akms
    assert sae == 1 and transition == 1 and downgrade == 1
    assert proof == "active-verification-required"


def test_process_wifi_events(monkeypatch):
    rows = [
        beacon(
            "aa:bb:cc:00:00:06",
            "same",
            **{"wlan.rsn.akms.type": "2"},
        ),
        beacon(
            "aa:bb:cc:00:00:07",
            "same",
            **{"wlan.rsn.akms.type": "8"},
        ),
    ]
    rows += [
        make_row(**{
            "wlan.fc.type_subtype": "12",
            "wlan.bssid": "aa:bb:cc:00:00:06",
            "wlan.sa": "aa:bb:cc:00:00:06",
            "wlan.da": "11:22:33:44:55:66",
        })
        for _ in range(5)
    ]
    monkeypatch.setattr(wifi, "_iter_rows", lambda path: iter(rows))
    result = wifi.process_wifi_events("fake.pcap")
    kinds = {row[0] for row in result}
    assert "deauth" in kinds and "evil-twin-candidate" in kinds
    deauth = [row for row in result if row[0] == "deauth"][0]
    assert deauth[1] == "high" and deauth[5] == 5
    evidence = json.loads(result[-1][7])
    assert evidence["ssid"] == "same"


# --------------------------------------------------------------------------- #
# Database round-trip and raw protocol view
# --------------------------------------------------------------------------- #


def test_wifi_tables_roundtrip(tmp_path):
    db_path = str(tmp_path / "wifi.db")
    conn = create_database(db_path)
    assert conn is not None
    try:
        insert_into_database(
            "wifi",
            [("aa:bb:cc:dd:ee:ff", "corp", "2.4GHz", "6", "WPA2-PSK", "PSK",
              "CCMP", "capable", "1700000000", "1700000010", 10, 2)],
            db_path=db_path,
        )
        insert_into_database(
            "wifiwep",
            [("aa:bb:cc:dd:ee:01", "wep", "1", 100, 90, 3, 5, 1,
              "active-required", "observed")],
            db_path=db_path,
        )
        insert_into_database(
            "wifihs",
            [("aa:bb:cc:dd:ee:ff", "corp", "11:22:33:44:55:66", "1,2", 1,
              "0" * 32, "offline-crackable")],
            db_path=db_path,
        )
        insert_into_database(
            "wifiwps",
            [("aa:bb:cc:dd:ee:02", "wps", "configured", 0, 1,
              "push-button,keypad", "Acme", "AP-1", "lab", "1.0", "high")],
            db_path=db_path,
        )
        insert_into_database(
            "wifieap",
            [("aa:bb:cc:dd:ee:03", "alice", "PEAP,MSCHAPv2",
              "11:22:33:44:55:66", "aa:bb:cc:dd:ee:03", 2, "observed")],
            db_path=db_path,
        )
        insert_into_database(
            "wifiwpa3",
            [("aa:bb:cc:dd:ee:04", "wpa3", "PSK,SAE", "capable", 1, 1, 1,
              "active-verification-required")],
            db_path=db_path,
        )
        insert_into_database(
            "wifievents",
            [("deauth", "high", "aa:bb:cc:dd:ee:ff", "corp",
              "11:22:33:44:55:66", 5, "5 deauth frame(s) (burst)", "{}")],
            db_path=db_path,
        )

        # fetch_protocol prepends the protocol name, so every index shifts by 1.
        assert fetch_protocol(conn, "wifi")[0][2] == "corp"
        assert fetch_protocol(conn, "wifiwep")[0][4] == 100
        assert fetch_protocol(conn, "wifihs")[0][5] == 1
        assert fetch_protocol(conn, "wifiwps")[0][9] == "high"
        assert fetch_protocol(conn, "wifieap")[0][2] == "alice"
        assert fetch_protocol(conn, "wifiwpa3")[0][7] == 1
        assert fetch_protocol(conn, "wifievents")[0][1] == "deauth"
        assert protocol_headers("wifi")[1] == "Bssid"
        assert protocol_headers("wifiwep")[1] == "Bssid"
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Command pack and leads
# --------------------------------------------------------------------------- #


def _wifi_fixture():
    return {
        "networks": [
            {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "wepnet", "band": "2.4GHz",
             "channel": "1", "security": "WEP", "pmf": "not-set", "clients": 1},
            {"bssid": "aa:bb:cc:dd:ee:02", "ssid": "corp", "band": "5GHz",
             "channel": "36", "security": "WPA2-PSK", "pmf": "capable",
             "clients": 3},
        ],
        "wep": [
            {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "wepnet", "channel": "1",
             "iv_count": 100, "unique_ivs": 90, "weak_ivs": 1, "arp_frames": 2,
             "clients": 1, "readiness": "active-required", "proof": "observed"},
        ],
        "handshakes": [
            {"bssid": "aa:bb:cc:dd:ee:02", "ssid": "corp",
             "client": "11:22:33:44:55:66", "messages": "1,2", "complete": 1,
             "pmkid": "00112233445566778899aabbccddeeff",
             "proof": "offline-crackable"},
        ],
        "wps": [
            {"bssid": "aa:bb:cc:dd:ee:03", "ssid": "wpsnet",
             "state": "configured", "locked": 0, "selected_registrar": 1,
             "config_methods": "push-button,keypad", "manufacturer": "Acme",
             "model": "AP-1", "risk": "high"},
        ],
        "eap": [
            {"bssid": "aa:bb:cc:dd:ee:04", "identity": "alice",
             "methods": "PEAP,MSCHAPv2", "frames": 2, "proof": "observed"},
        ],
        "wpa3": [
            {"bssid": "aa:bb:cc:dd:ee:05", "ssid": "wpa3net",
             "akms": "PSK,SAE", "pmf": "capable", "sae_frames": 1,
             "transition": 1, "downgrade_risk": 1,
             "proof": "active-verification-required"},
        ],
        "events": [
            {"kind": "deauth", "severity": "high", "bssid": "aa:bb:cc:dd:ee:02",
             "ssid": "corp", "client": "11:22:33:44:55:66", "count": 5,
             "detail": "5 deauth frame(s) (burst)", "evidence": "{}"},
        ],
    }


def test_wifi_attacks_markdown_marks_active_and_links_references():
    text = wifi.wifi_attacks_markdown(_wifi_fixture(), interface="wlan0mon")
    assert "WARNING — ACTIVE COMMANDS" in text
    assert "aircrack-ng" in text
    assert "hashcat -m 22000" in text
    assert "reaver" in text
    assert "eaphammer" in text
    assert "dragonshift.py" in text
    assert "https://www.thehacker.recipes/radio/wi-fi/wep/" in text
    assert "https://wpa3.mathyvanhoef.com/" in text
    assert "Cleanup" in text
    # The pack is text only: no execution primitives.
    assert "subprocess" not in text


def test_wifi_attacks_markdown_empty_database():
    text = wifi.wifi_attacks_markdown({})
    assert "No 802.11 findings" in text
    assert "WARNING — ACTIVE COMMANDS" in text


def test_build_leads_includes_wifi_with_proof_levels():
    inventory = {
        "hosts": [],
        "users": [],
        "credentials": [],
        "hashes": [],
        "quick_wins": [],
        "wifi": _wifi_fixture(),
    }
    leads = {lead["id"]: lead for lead in build_leads(inventory)}
    assert leads["WIFI-WEP-aa:bb:cc:dd:ee:01"]["severity"] == "critical"
    assert leads["WIFI-WEP-aa:bb:cc:dd:ee:01"]["proof_level"] == "observed"
    handshake = leads["WIFI-HANDSHAKE-aa:bb:cc:dd:ee:02"]
    assert handshake["proof_level"] == "offline-crackable"
    assert leads["WIFI-PMKID-aa:bb:cc:dd:ee:02"]["proof_level"] == "offline-crackable"
    assert leads["WIFI-WPS-aa:bb:cc:dd:ee:03"]["severity"] == "high"
    assert leads["WIFI-EAP-aa:bb:cc:dd:ee:04-alice"]["severity"] == "medium"
    downgrade = leads["WIFI-WPA3-DOWNGRADE-aa:bb:cc:dd:ee:05"]
    assert downgrade["proof_level"] == "active-verification-required"
    assert leads["WIFI-DEAUTH-aa:bb:cc:dd:ee:02-11:22:33:44:55:66"]["severity"] == "high"
    assert all(lead.get("attck") for lead in leads.values() if lead["id"].startswith("WIFI"))
