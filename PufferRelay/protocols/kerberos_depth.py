"""Kerberos depth (step 2) — delegation, S4U and UnPAC chains, passively.

AS-REP and Kerberoast are covered elsewhere. This module adds the signals that
explain *how* an account can be abused:

* S4U2Self/S4U2Proxy (`PA-FOR-USER` padata 129/130, additional tickets);
* delegation ticket flags (`forwarded`, `proxy`, `proxiable`, `ok-as-delegate`);
* UnPAC-the-hash: PKINIT (padata 16) followed by a user-to-user request from the
  same source, which is how a certificate is turned into an NT hash.
"""

from __future__ import annotations

import json

from PufferRelay.tshark_fields import fields

PKINIT = "16"
S4U_PADATA = {"129", "130"}


def _truthy(value):
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def process_kerberos_depth(pcap_file):
    rows = fields(
        pcap_file,
        "kerberos",
        [
            "ip.src",
            "ip.dst",
            "kerberos.msg_type",
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.SNameString",
            "kerberos.padata_type",
            "kerberos.additional_tickets",
            "kerberos.TicketFlags.ok.as.delegate",
            "kerberos.TicketFlags.forwarded",
            "kerberos.TicketFlags.proxy",
            "kerberos.TicketFlags.proxiable",
        ],
        occurrence="a",
    )
    pkinit_seen = set()
    out = []
    seen = set()

    def add(kind, severity, src, dst, user, realm, service, detail, evidence):
        key = (kind, src, dst, user.lower(), service)
        if key in seen:
            return
        seen.add(key)
        out.append(
            (
                kind,
                severity,
                user,
                realm,
                service,
                src or "",
                dst or "",
                detail,
                json.dumps(evidence, sort_keys=True),
            )
        )

    for row in rows:
        padded = tuple(row) + ("",) * (12 - len(row))
        (
            src,
            dst,
            msg_type,
            user,
            realm,
            service,
            padata,
            additional,
            ok_delegate,
            forwarded,
            proxy,
            proxiable,
        ) = padded[:12]
        user = (user or "").split(",", 1)[0].strip()
        realm = (realm or "").split(",", 1)[0].strip()
        service = (service or "").split(",", 1)[0].strip()
        padata_types = {
            part.strip() for part in (padata or "").split(",") if part.strip()
        }
        key = (src or "", dst or "", user.lower())
        if PKINIT in padata_types:
            pkinit_seen.add(key)

        if padata_types & S4U_PADATA:
            unpac = key in pkinit_seen
            add(
                "unpac-chain" if unpac else "s4u",
                "high",
                src,
                dst,
                user,
                realm,
                service,
                (
                    "PKINIT followed by a user-to-user request (UnPAC-the-hash)"
                    if unpac
                    else "S4U/PA-FOR-USER request (delegation abuse)"
                ),
                {
                    "padata": sorted(padata_types & S4U_PADATA),
                    "pkinit": unpac,
                    "service": service,
                },
            )

        if (additional or "").strip():
            add(
                "s4u2proxy",
                "high",
                src,
                dst,
                user,
                realm,
                service,
                "TGS request carries additional tickets (S4U2Proxy)",
                {"service": service},
            )

        flags = {
            "ok_as_delegate": _truthy(ok_delegate),
            "forwarded": _truthy(forwarded),
            "proxy": _truthy(proxy),
            "proxiable": _truthy(proxiable),
        }
        if str(msg_type).split(",", 1)[0].strip() == "11" and any(flags.values()):
            add(
                "delegation-ticket",
                "medium",
                src,
                dst,
                user,
                realm,
                service,
                "service ticket carries delegation-related flags",
                {"flags": [name for name, enabled in flags.items() if enabled]},
            )

    return out
