"""DHCPv6 / IPv6 RA takeover and ADIDNS abuse (issue #66) — passive.

mitm6-style attacks answer DHCPv6 or send Router Advertisements with a rogue
DNS server. DNS dynamic updates (RFC 2136) can also create records such as
WPAD. All of it is visible in a capture.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields


def _ipv6_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "dhcpv6 || icmpv6.type == 134",
        [
            "ipv6.src",
            "ipv6.dst",
            "dhcpv6.msgtype",
            "dhcpv6.dns_server",
            "icmpv6.type",
            "icmpv6.opt.rdnss",
            "icmpv6.opt.dnssl",
        ],
    )
    for src, dst, msgtype, dns_server, icmp_type, rdnss, dnssl in rows:
        if (dns_server or "").strip():
            kind = "dhcpv6-dns"
            detail = f"DHCPv6 msgtype {msgtype or '?'} offers DNS {dns_server}"
            severity = "high"
        elif str(icmp_type).strip() == "134" and ((rdnss or "").strip() or (dnssl or "").strip()):
            kind = "ra-rdnss"
            detail = f"RA advertises RDNSS {rdnss or '-'} DNSSL {dnssl or '-'}"
            severity = "high"
        else:
            continue
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                detail,
                json.dumps(
                    {
                        "msgtype": msgtype or "",
                        "dns_server": dns_server or "",
                        "rdnss": rdnss or "",
                        "dnssl": dnssl or "",
                    },
                    sort_keys=True,
                ),
            )
        )
    return out


def _adidns_pass(pcap_file):
    out = []
    rows = fields(
        pcap_file,
        "dns.flags.opcode == 5",
        [
            "ip.src",
            "ip.dst",
            "dns.qry.name",
            "dns.count.updates",
            "dns.count.add_rr",
        ],
    )
    for src, dst, name, updates, additions in rows:
        detail = f"DNS UPDATE {name or '(zone)'} updates={updates or '?'} add={additions or '?'}"
        out.append(
            (
                "adidns-update",
                "medium",
                src or "",
                dst or "",
                detail,
                json.dumps(
                    {
                        "zone": name or "",
                        "updates": updates or "",
                        "additions": additions or "",
                    },
                    sort_keys=True,
                ),
            )
        )
    return out


def process_ipv6_adidns(pcap_file):
    events = _ipv6_pass(pcap_file) + _adidns_pass(pcap_file)

    # Same host offering DHCPv6/RA DNS and updating AD DNS is a strong
    # takeover signal; merge it into one critical finding.
    by_source = {}
    for event in events:
        by_source.setdefault(event[2], set()).add(event[0])
    combined = []
    for source, kinds in by_source.items():
        if {"dhcpv6-dns", "ra-rdnss"} & kinds and "adidns-update" in kinds:
            combined.append(
                (
                    "ipv6-dns-takeover",
                    "critical",
                    source,
                    "",
                    "DHCPv6/RA DNS plus ADIDNS update from one host",
                    json.dumps({"kinds": sorted(kinds)}, sort_keys=True),
                )
            )
    return combined + events
