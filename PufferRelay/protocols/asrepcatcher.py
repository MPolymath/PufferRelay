"""ASRepCatcher detection (passive).

ASRepCatcher (https://github.com/Yaxxine7/ASRepCatcher) harvests crackable
Kerberos AS-REP material on a VLAN. It either relays workstation AS-REQ
messages to the DC (forcing RC4 in relay mode) or ARP-poisons the gateway to
observe AS-REP responses (listen mode). It does not require pre-authentication
to be disabled.

The capture alone cannot prove intent, so the detector looks for the traffic
shape and reports confidence:

* the same account requests a TGT from two different source addresses
  (relayed AS-REQ / MITM);
* a crackable AS-REP (RC4/AES) is delivered to a host that never sent the
  matching AS-REQ, while another host did (reply diverted);
* ARP replies claim one IPv4 address with more than one MAC (spoofing), and
  the two signals overlap.

Every finding carries the upstream repository link so the operator can read
the technique before acting.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields

REFERENCE = "https://github.com/Yaxxine7/ASRepCatcher"
CRACKABLE_ETYPES = {"17", "18", "23"}
PREAUTH_PADATA = "2"


def _split(value):
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def detect(rows):
    """Turn (frame, src, dst, arp_op, arp_ip, arp_mac, arp_target, msg_type,
    user, realm, etypes, padata) rows into finding dicts (pure, unit-tested).
    """
    asreqs = []
    asreps = []
    arp_replies = []

    for row in rows:
        padded = tuple(row) + ("",) * (12 - len(row))
        (
            _frame,
            src,
            dst,
            arp_op,
            arp_src_ip,
            arp_src_mac,
            _arp_dst_ip,
            msg_type,
            user,
            realm,
            etypes,
            padata,
        ) = padded[:12]

        if str(arp_op).strip() == "2" and arp_src_ip:
            arp_replies.append(
                {"ip": arp_src_ip, "mac": (arp_src_mac or "").lower()}
            )

        message = _int(msg_type)
        if message not in (10, 11):
            continue
        entry = {
            "src": src or "",
            "dst": dst or "",
            "user": (user or "").strip(),
            "realm": (realm or "").strip(),
            "etypes": set(_split(etypes)),
            "padata": set(_split(padata)),
        }
        if message == 10:
            asreqs.append(entry)
        else:
            asreps.append(entry)

    by_user = {}
    for request in asreqs:
        if request["user"]:
            by_user.setdefault(request["user"], []).append(request)

    findings = []

    relayed = []
    for user, requests in by_user.items():
        sources = {request["src"] for request in requests if request["src"]}
        if len(sources) < 2:
            continue
        relayed.append(
            {
                "kind": "relayed-asreq",
                "severity": "high",
                "client_ip": sorted(sources)[0],
                "attacker_ip": "",
                "kdc_ip": requests[0]["dst"],
                "username": user,
                "realm": requests[0]["realm"],
                "summary": (
                    f"TGT request for {user} seen from {len(sources)} source "
                    "addresses — relay or on-path modification is plausible"
                ),
                "evidence": {
                    "sources": sorted(sources),
                    "realm": requests[0]["realm"],
                    "reference": REFERENCE,
                },
            }
        )

    diverted = []
    for reply in asreps:
        user = reply["user"]
        if not user or not (reply["etypes"] & CRACKABLE_ETYPES):
            continue
        if not reply["dst"] or reply["dst"] == reply["src"]:
            continue
        requesters = {
            request["src"]
            for request in by_user.get(user, [])
            if request["src"] and request["src"] != reply["src"]
        }
        if requesters and reply["dst"] not in requesters:
            diverted.append(
                {
                    "kind": "asrep-to-third-party",
                    "severity": "high",
                    "client_ip": sorted(requesters)[0],
                    "attacker_ip": reply["dst"],
                    "kdc_ip": reply["src"],
                    "username": user,
                    "realm": reply["realm"],
                    "summary": (
                        f"crackable AS-REP for {user} delivered to "
                        f"{reply['dst']}, which never requested it"
                    ),
                    "evidence": {
                        "requesters": sorted(requesters),
                        "reply_destination": reply["dst"],
                        "kdc": reply["src"],
                        "etype": sorted(reply["etypes"] & CRACKABLE_ETYPES),
                        "reference": REFERENCE,
                    },
                }
            )

    claims = {}
    for reply in arp_replies:
        if reply["mac"]:
            claims.setdefault(reply["ip"], set()).add(reply["mac"])
    impersonated = sorted(ip for ip, macs in claims.items() if len(macs) > 1)
    arp_finding = None
    if impersonated:
        arp_finding = {
            "kind": "arp-impersonation",
            "severity": "high",
            "client_ip": impersonated[0],
            "attacker_ip": "",
            "kdc_ip": "",
            "username": "",
            "realm": "",
            "summary": (
                "one IPv4 address is announced by multiple MAC addresses — "
                "ARP spoofing is present in the capture"
            ),
            "evidence": {
                "addresses": {
                    ip: sorted(macs) for ip, macs in claims.items() if len(macs) > 1
                },
                "reference": REFERENCE,
            },
        }

    combined_signals = [item for item in relayed + diverted if item["username"]]
    if arp_finding and combined_signals:
        usernames = sorted({item["username"] for item in combined_signals})
        findings.append(
            {
                "kind": "asrepcatcher",
                "severity": "critical",
                "client_ip": combined_signals[0]["client_ip"],
                "attacker_ip": impersonated[0] if impersonated else "",
                "kdc_ip": combined_signals[0]["kdc_ip"],
                "username": ",".join(usernames),
                "realm": combined_signals[0]["realm"],
                "summary": (
                    "ASRepCatcher-compatible pattern: ARP spoofing plus "
                    f"Kerberos relay/reply diversion for {len(usernames)} "
                    "account(s)"
                ),
                "evidence": {
                    "arp": arp_finding["evidence"]["addresses"],
                    "kerberos": [
                        {
                            "kind": item["kind"],
                            "username": item["username"],
                            "summary": item["summary"],
                        }
                        for item in combined_signals
                    ],
                    "reference": REFERENCE,
                },
            }
        )
    else:
        findings.extend(relayed)
        findings.extend(diverted)
        if arp_finding and asreps:
            findings.append(arp_finding)

    # Username enumeration burst from one host (AS-REQ without pre-auth).
    burst = {}
    for request in asreqs:
        if request["user"] and PREAUTH_PADATA not in request["padata"]:
            burst.setdefault(request["src"], set()).add(request["user"])
    for src, users in burst.items():
        if len(users) >= 5:
            findings.append(
                {
                    "kind": "asrep-enumeration",
                    "severity": "medium",
                    "client_ip": src,
                    "attacker_ip": "",
                    "kdc_ip": "",
                    "username": f"{len(users)} accounts",
                    "realm": "",
                    "summary": (
                        f"{len(users)} pre-auth-less TGT requests from {src} — "
                        "username enumeration or roasting sweep"
                    ),
                    "evidence": {
                        "accounts": sorted(users),
                        "reference": REFERENCE,
                    },
                }
            )

    return findings


def process_asrepcatcher(pcap_file):
    """Return DB rows for ASRepCatcher-compatible activity in the capture."""
    rows = fields(
        pcap_file,
        "kerberos || arp",
        [
            "frame.number",
            "ip.src",
            "ip.dst",
            "arp.opcode",
            "arp.src.proto_ipv4",
            "arp.src.hw_mac",
            "arp.dst.proto_ipv4",
            "kerberos.msg_type",
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.etype",
            "kerberos.padata_type",
        ],
        occurrence="a",
    )
    out = []
    for finding in detect(rows):
        out.append(
            (
                finding["kind"],
                finding["severity"],
                finding["client_ip"],
                finding["attacker_ip"],
                finding["kdc_ip"],
                finding["username"],
                finding["realm"],
                finding["summary"],
                json.dumps(finding["evidence"], sort_keys=True),
            )
        )
    return out
