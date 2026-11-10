#!/usr/bin/env python3
"""Generate a deterministic 802.11 fixture for PufferRelay Wi-Fi tests.

This writes a small synthetic monitor-mode capture (radiotap + 802.11). It
contains no real traffic: three beacons (open, WPA2-PSK, WPA3 transition+WPS),
WEP data frames with incrementing IVs, an EAPOL M1 (with PMKID) + M2 pair, an
EAP identity exchange and a five-frame deauth burst.

Requires scapy (`pip install scapy`); tshark is only needed by the tests that
consume the output.

    python scripts/make_wifi_fixture.py /tmp/wifi-fixture.pcapng
"""

from __future__ import annotations

import argparse
import struct
import sys


def build(path):
    try:
        from scapy.all import (
            Dot11,
            Dot11Beacon,
            Dot11Deauth,
            Dot11Elt,
            Dot11EltVendorSpecific,
            Dot11WEP,
            EAPOL,
            LLC,
            RadioTap,
            SNAP,
            Raw,
            wrpcap,
        )
    except ImportError as error:  # pragma: no cover - depends on the dev env
        raise SystemExit(f"scapy is required: {error}")

    ap_open = "aa:bb:cc:dd:ee:01"
    ap_psk = "aa:bb:cc:dd:ee:02"
    ap_wpa3 = "aa:bb:cc:dd:ee:03"
    client = "11:22:33:44:55:66"

    def rsn_ie(akms, mfpc=True, mfpr=False):
        caps = (0x0080 if mfpc else 0) | (0x0040 if mfpr else 0)
        info = (
            b"\x01\x00"
            + b"\x00\x0f\xac\x04"  # group cipher: CCMP
            + b"\x01\x00"
            + b"\x00\x0f\xac\x04"  # pairwise: CCMP
            + struct.pack("!H", len(akms))
            + b"".join(b"\x00\x0f\xac" + bytes([akm]) for akm in akms)
            + struct.pack("<H", caps)
        )
        return Dot11Elt(ID=48, info=info)

    def beacon(bssid, ssid, rsn=None, vendor=None, privacy=True):
        frame = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=bssid,
                addr3=bssid,
            )
            / Dot11Beacon(cap="ESS+privacy" if privacy else "ESS")
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
        )
        if rsn is not None:
            frame = frame / rsn
        if vendor is not None:
            frame = frame / vendor
        return frame

    def wps_ie():
        def attr(kind, value):
            return struct.pack("!HH", kind, len(value)) + value

        info = b"\x04" + b"".join(
            [
                attr(0x1044, b"\x02"),  # configured
                attr(0x1057, b"\x00"),  # not locked
                attr(0x1041, b"\x01"),  # selected registrar
                attr(0x1008, b"\x01\x88"),  # keypad + push button + display
                attr(0x1021, b"Acme"),
                attr(0x1023, b"AP-1"),
                attr(0x1011, b"lab-ap"),
                attr(0x104a, b"\x10"),
            ]
        )
        return Dot11EltVendorSpecific(oui=0x0050F2, info=info)

    def data_frame(src, dst, bssid, fcfield=0):
        return RadioTap() / Dot11(
            type=2,
            subtype=0,
            FCfield=fcfield,
            addr1=dst,
            addr2=src,
            addr3=bssid,
        )

    def eapol_key(key_info, replay, nonce, keydata=b""):
        descriptor = (
            b"\x02"  # RSN key descriptor
            + struct.pack("!H", key_info)
            + struct.pack("!H", 0)
            + struct.pack("!Q", replay)
            + nonce
            + b"\x00" * 16  # key IV
            + b"\x00" * 8  # RSC
            + b"\x00" * 8  # key ID
            + b"\x00" * 16  # MIC
            + struct.pack("!H", len(keydata))
            + keydata
        )
        return EAPOL(version=2, type=3, len=len(descriptor)) / Raw(descriptor)

    def eap_identity(code, identifier, identity):
        body = b"\x01" + identity.encode()  # EAP type 1 = Identity
        packet = struct.pack("!BBH", code, identifier, 4 + len(body)) + body
        return EAPOL(version=2, type=0, len=len(packet)) / Raw(packet)

    packets = [
        beacon(ap_open, b"opennet", privacy=False),
        beacon(ap_psk, b"corp", rsn=rsn_ie([2])),
        beacon(ap_wpa3, b"wpa3net", rsn=rsn_ie([2, 8])),
        beacon(ap_wpa3, b"wpa3net", rsn=rsn_ie([2, 8]), vendor=wps_ie()),
    ]

    for index in range(1, 21):
        packets.append(
            data_frame(client, ap_open, ap_open, fcfield="protected")
            / Dot11WEP(
                iv=struct.pack("!I", index)[1:],
                keyid=0,
                wepdata=b"\xaa" * 24,
                icv=0,
            )
        )

    pmkid = bytes.fromhex("00112233445566778899aabbccddeeff")
    pmkid_kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid
    packets.append(
        data_frame(ap_psk, client, ap_psk)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / eapol_key(0x008A, 1, b"\x11" * 32, pmkid_kde)
    )
    packets.append(
        data_frame(client, ap_psk, ap_psk)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / eapol_key(0x010A, 1, b"\x22" * 32)
    )

    packets.append(
        data_frame(ap_wpa3, client, ap_wpa3)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / eap_identity(1, 1, "")
    )
    packets.append(
        data_frame(client, ap_wpa3, ap_wpa3)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / eap_identity(2, 1, "alice")
    )

    for _ in range(5):
        packets.append(
            RadioTap()
            / Dot11(type=0, subtype=12, addr1=client, addr2=ap_psk, addr3=ap_psk)
            / Dot11Deauth(reason=7)
        )

    wrpcap(path, packets)
    return len(packets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="output pcap path")
    args = parser.parse_args()
    count = build(args.output)
    print(f"wrote {args.output} ({count} frames)")


if __name__ == "__main__":
    sys.exit(main())
