"""End-to-end check of the committed Wi-Fi fixture generator (issue #81).

Skipped when scapy or tshark is unavailable; the unit tests in test_wifi.py
still cover the parsing logic without them.
"""

import importlib.util
import subprocess
import sys

import pytest

from PufferRelay.tshark_fields import find_tshark

ROOT = __file__.rsplit("PufferRelay", 1)[0].rstrip("\\/")
HAS_SCAPY = importlib.util.find_spec("scapy") is not None
HAS_TSHARK = bool(find_tshark())


@pytest.mark.skipif(not HAS_SCAPY, reason="scapy is not installed")
@pytest.mark.skipif(not HAS_TSHARK, reason="tshark is not installed")
def test_generated_fixture_exercises_every_handler(tmp_path):
    capture = tmp_path / "wifi-fixture.pcapng"
    subprocess.run(
        [sys.executable, "scripts/make_wifi_fixture.py", str(capture)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )

    from PufferRelay.protocols import wifi

    networks = wifi.process_wifi(str(capture))
    security = {row[4] for row in networks}
    assert {"OPEN", "WPA2-PSK", "WPA3-TRANSITION"} <= security
    assert len(networks) == 3

    wep = wifi.process_wifi_wep(str(capture))
    assert wep and wep[0][3] == 20 and wep[0][4] == 20

    handshakes = wifi.process_wifi_hs(str(capture))
    assert handshakes and handshakes[0][4] == 1
    assert handshakes[0][5] == "00112233445566778899aabbccddeeff"
    assert handshakes[0][6] == "offline-crackable"
    assert wifi.process_wifi_pmkid(str(capture))[0][4].startswith("WPA*01*")

    wps = wifi.process_wifi_wps(str(capture))
    assert wps and wps[0][2] == "configured" and wps[0][10] == "high"

    identities = {row[1] for row in wifi.process_wifi_eap(str(capture))}
    assert "alice" in identities

    wpa3 = wifi.process_wifi_wpa3(str(capture))
    assert wpa3 and wpa3[0][5] == 1 and wpa3[0][6] == 1
    assert wpa3[0][7] == "active-verification-required"

    events = wifi.process_wifi_events(str(capture))
    deauth = [row for row in events if row[0] == "deauth"]
    assert deauth and deauth[0][1] == "high" and deauth[0][5] == 5
