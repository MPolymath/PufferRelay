"""Kerberoasting extraction (issue #64) — passive.

A TGS-REP for a service account is encrypted with that account's password
hash. Recovering it from a capture gives an offline crack (hashcat 13100 for
RC4, 19600 for AES-128, 19700 for AES-256) without sending anything.

The encrypted ticket lives inside the KDC-REP DER. tshark does not expose the
cipher as a field, so this module reassembles TCP and walks the DER until the
Ticket enc-part, then formats the hashcat line. When the DER cannot be parsed,
a "candidate" row is still emitted so the operator sees the roasting attempt.
"""

from __future__ import annotations

import logging
import re

from PufferRelay.protocols.kerberos_shared import rows as kerberos_rows

TGS_REQ = 12
TGS_REP = 13
CRACKABLE_ETYPES = {17: "19600", 18: "19700", 23: "13100"}


# --------------------------------------------------------------------------- #
# Minimal DER walker (definite lengths only, enough for KDC-REP)
# --------------------------------------------------------------------------- #
def _tlv(data, pos):
    """Return (tag, value_start, value_end, next_pos) or None."""
    if pos >= len(data):
        return None
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        return None
    first = data[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            return None
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    else:
        length = first
    end = pos + length
    if end > len(data):
        return None
    return tag, pos, end, end


def _children(data, start, end):
    pos = start
    while pos < end:
        item = _tlv(data, pos)
        if item is None:
            return
        yield item
        pos = item[3]


def _find(data, start, end, tag):
    for child in _children(data, start, end):
        if child[0] == tag:
            return child
    return None


def parse_tgs_rep(data):
    """Return (etype, cipher bytes) from a KDC-REP DER blob, or None."""
    if not data:
        return None
    try:
        root = _tlv(data, 0)
        if root is None or root[0] != 0x6B:  # [APPLICATION 11] KDC-REP
            return None
        ticket = _find(data, root[1], root[2], 0xA5)  # ticket [5]
        if ticket is None:
            return None
        app = _tlv(data, ticket[1])
        if app is None or app[0] != 0x61:  # [APPLICATION 1] Ticket
            return None
        enc = _find(data, app[1], app[2], 0xA3)  # enc-part [3]
        if enc is None:
            return None
        sequence = _find(data, enc[1], enc[2], 0x30)
        if sequence is None:
            return None
        etype = None
        cipher = b""
        for child in _children(data, sequence[1], sequence[2]):
            if child[0] == 0x02 and etype is None:
                etype = int.from_bytes(data[child[1] : child[2]], "big")
            elif child[0] == 0x04:
                cipher = data[child[1] : child[2]]
        if not etype or not cipher:
            return None
        return etype, cipher
    except (IndexError, ValueError):
        return None


def format_hash(user, realm, spn, etype, cipher):
    """hashcat 13100/19600/19700 line, or '' when the etype is unsupported."""
    if etype not in CRACKABLE_ETYPES or len(cipher) < 17:
        return ""
    checksum = cipher[:16].hex()
    data = cipher[16:].hex()
    return f"$krb5tgs${etype}$*{user}${realm}${spn}*${checksum}${data}"


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #
SPN_HINT = re.compile(r"^[A-Za-z0-9._/-]+$")


def process_kerberoast(pcap_file):
    rows = kerberos_rows(pcap_file)

    requests = {}
    out = []
    seen = set()

    def add(row):
        key = (row[0], row[2], row[6], row[7])
        if key in seen:
            return
        seen.add(key)
        out.append(row)

    for row in rows:
        src, dst, msg_type, user, realm, etype = row[:6]
        spn = row[8]
        reassembled, payload, udp = row[9], row[10], row[11]
        try:
            message = int(str(msg_type).strip())
        except (TypeError, ValueError):
            continue
        user = (user or "").strip()
        realm = (realm or "").strip()
        spn = (spn or "").strip()
        if message == TGS_REQ and user and spn:
            requests.setdefault((user, realm), set()).add(spn)
            continue
        if message != TGS_REP or not user or not spn:
            continue
        if spn.lower().startswith("krbtgt"):
            continue
        blob = None
        for candidate in (reassembled, payload, udp):
            text = (candidate or "").replace(":", "").strip()
            if not text or len(text) % 2:
                continue
            try:
                blob = bytes.fromhex(text)
                break
            except ValueError:
                continue
        parsed = parse_tgs_rep(blob) if blob else None
        chosen_etype = parsed[0] if parsed else _safe_int(etype)
        if chosen_etype not in CRACKABLE_ETYPES:
            continue
        digest = format_hash(user, realm, spn, chosen_etype, parsed[1]) if parsed else ""
        add((user, realm, spn, chosen_etype, digest, src, dst,
             "hash" if digest else "candidate"))
        logging.debug("kerberoast: %s %s etype=%s hash=%s", user, spn, chosen_etype, bool(digest))

    # Burst of distinct SPNs from one principal: roasting sweep even without
    # a parsed TGS-REP for every request.
    for (user, realm), spns in requests.items():
        if len(spns) < 5:
            continue
        for spn in sorted(spns):
            add((user, realm, spn, 0, "", "", "", "candidate"))

    return out


def _safe_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0
