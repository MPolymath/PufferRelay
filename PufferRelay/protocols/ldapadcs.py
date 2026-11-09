"""LDAP ADCS objects (step 2) — CA and certificate-template discovery.

AD-integrated PKI publishes `pKIEnrollmentService` (the CA) and
`pKICertificateTemplate` objects in the Configuration partition. A passive
capture of an LDAP search can reveal the CA host, published templates and the
SAN/enrollment flags that make ESC1-style abuse possible.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields

TEMPLATE_FLAG_SAN = 0x00000001  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT


def _split(value):
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _pairs(attrs, values):
    """Pair attribute names with values; a single attr may own many values."""
    if len(attrs) == 1 and len(values) > 1:
        return [(attrs[0], value) for value in values]
    return list(zip(attrs, values))


def _append(state, name, value):
    state.setdefault(name.lower(), []).append(value)


def _flush(state, src, dst, out):
    classes = {value.lower() for value in state.get("objectclass", [])}
    cn = (state.get("cn") or [""])[0]
    evidence = {
        "objectclass": sorted(classes),
        "cn": cn,
    }
    if "pkienrollmentservice" in classes:
        dns_name = (state.get("dnshostname") or [""])[0]
        templates = state.get("certificatetemplates", [])
        evidence["templates"] = templates
        evidence["dns_hostname"] = dns_name
        out.append(
            (
                "ca",
                "medium",
                cn,
                dns_name,
                "",
                f"ADCS CA {cn or '(unnamed)'} with {len(templates)} template(s)",
                json.dumps(evidence, sort_keys=True),
                src,
                dst,
            )
        )
    if "pkicertificatetemplate" in classes:
        flags_text = (state.get("mspki-certificate-name-flag") or ["0"])[0]
        try:
            flags = int(flags_text, 0)
        except ValueError:
            flags = 0
        eku = state.get("pkiextendedkeyusage", [])
        san = bool(flags & TEMPLATE_FLAG_SAN)
        evidence["name_flag"] = flags_text
        evidence["eku"] = eku
        evidence["san_supplied_by_requester"] = san
        out.append(
            (
                "template",
                "high" if san else "medium",
                cn,
                "",
                cn,
                (
                    f"template {cn or '(unnamed)'} allows requester-supplied "
                    "SAN (ESC1 indicator)"
                    if san
                    else f"template {cn or '(unnamed)'} published"
                ),
                json.dumps(evidence, sort_keys=True),
                src,
                dst,
            )
        )


def process_ldap_adcs(pcap_file):
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
    for src, dst, descriptions, values in rows:
        attrs = _split(descriptions)
        vals = _split(values)
        state = context.setdefault((src, dst), {})
        for attr, value in _pairs(attrs, vals):
            name = attr.strip().lower()
            value = value.strip()
            if not name or not value:
                continue
            if name == "objectclass" and state.get("objectclass"):
                _flush(state, src or "", dst or "", out)
                state.clear()
                context[(src, dst)] = state
            _append(state, name, value)
    for (src, dst), state in context.items():
        _flush(state, src or "", dst or "", out)

    deduped = []
    seen = set()
    for row in out:
        key = (row[0], row[2], row[3], row[4], row[7], row[8])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
