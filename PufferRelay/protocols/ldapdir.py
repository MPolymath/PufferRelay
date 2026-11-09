"""LDAP directory extraction (step 2/5) — SPN-to-account and optional SIDs.

Kerberoasting is much more actionable when the capture also contains the LDAP
search result that maps an SPN to its account. SearchResultEntry attributes are
not exposed as paired fields, so this module pairs
``ldap.AttributeDescription`` with ``ldap.AttributeValue`` in packet order and
keeps the account/SID context per conversation.
"""

from __future__ import annotations

from PufferRelay.tshark_fields import fields

ACCOUNT_ATTRS = {"samaccountname", "sAMAccountName".lower()}
SID_ATTRS = {"objectsid", "objectSid".lower()}
SPN_ATTRS = {"serviceprincipalname", "servicePrincipalName".lower()}


def _split(value):
    return [part.strip() for part in (value or "").split(",")]


def _pairs(attrs, values):
    if len(attrs) == 1 and len(values) > 1:
        return [(attrs[0], value) for value in values]
    return list(zip(attrs, values))


def process_ldap_directory(pcap_file):
    rows = fields(
        pcap_file,
        "ldap.AttributeDescription || ldap.AttributeValue",
        [
            "ip.src",
            "ip.dst",
            "ldap.AttributeDescription",
            "ldap.AttributeValue",
        ],
        occurrence="a",
    )
    context = {}
    out = []
    seen = set()

    def flush(src, dst, state):
        account = state.get("account", "")
        sid = state.get("sid", "")
        for spn in state.get("spns", []):
            if not account or not spn:
                continue
            key = (account.lower(), spn.lower(), dst or "")
            if key in seen:
                continue
            seen.add(key)
            out.append((account, spn, sid, src or "", dst or ""))

    for src, dst, descriptions, values in rows:
        attrs = _split(descriptions)
        vals = _split(values)
        state = context.setdefault((src, dst), {"account": "", "sid": "", "spns": []})
        for attr, value in _pairs(attrs, vals):
            name = attr.lower().strip()
            value = value.strip()
            if not name or not value:
                continue
            if name in ACCOUNT_ATTRS:
                if state.get("account") and state.get("spns"):
                    flush(src, dst, state)
                    state = {"account": "", "sid": "", "spns": []}
                    context[(src, dst)] = state
                state["account"] = value
            elif name in SID_ATTRS:
                state["sid"] = value
            elif name in SPN_ATTRS:
                if value not in state["spns"]:
                    state["spns"].append(value)
    for (src, dst), state in context.items():
        flush(src, dst, state)
    return out
