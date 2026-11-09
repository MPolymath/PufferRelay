"""DNS visibility (issues #11 / #59) — passive.

Extracts queries and answers from the capture so the operator gets a network
map (names <-> IPs, lookups to suspicious domains) without sending a single
DNS packet. A/AAAA answers also enrich the host inventory with names.
"""

from __future__ import annotations

from PufferRelay.tshark_fields import fields

DNS_QTYPE = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}


def qtype_name(value):
    """Map a numeric dns.qry.type to its common name."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value or "").strip()
    return DNS_QTYPE.get(number, str(number))


def process_dns(pcap_file):
    """Return (src_ip, dst_ip, query_name, query_type, answer, is_response) rows."""
    rows = fields(
        pcap_file,
        "dns",
        [
            "ip.src",
            "ip.dst",
            "dns.qry.name",
            "dns.qry.type",
            "dns.flags.response",
            "dns.a",
            "dns.aaaa",
        ],
    )
    out = []
    for src_ip, dst_ip, name, qtype, response, answer_a, answer_aaaa in rows:
        name = (name or "").rstrip(".").strip()
        if not name:
            continue
        answer = (answer_a or answer_aaaa or "").rstrip(".").strip()
        flags = str(response or "").strip()
        is_response = 1 if flags in ("1", "True", "true") else 0
        out.append((src_ip or "", dst_ip or "", name, qtype_name(qtype), answer, is_response))
    return out
