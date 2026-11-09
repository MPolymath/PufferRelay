"""Auto profile (step 6): choose handlers from the observed services.

A cheap services pass tells us which protocol families are in the capture;
running only their handlers cuts a ~33-pass full run to the handful that can
actually find something. Unknown/odd captures fall back to the full set.
"""

from __future__ import annotations

ALWAYS = {"services", "ips", "dns"}
PORT_HANDLERS = {
    21: {"ftp", "files"},
    23: {"telnet"},
    25: {"smtp"},
    53: {"dns", "ipv6"},
    67: {"ipv6"},
    88: {"kerberos", "kerberoast", "kerberosdepth", "asrepcatcher", "ldapdir"},
    110: {"pop3"},
    135: {"coercion", "adcs", "relays"},
    139: {"netbios", "ntlm", "smb", "relays", "coercion", "smbobjects", "sccm"},
    143: {"imap"},
    161: {"snmp"},
    389: {"ldap", "ldapdir", "relays"},
    443: {"http", "httptokens", "files", "adcs", "sccm", "llm"},
    445: {"ntlm", "smb", "relays", "coercion", "smbobjects", "sccm"},
    587: {"smtp"},
    636: {"ldap", "ldapdir", "relays"},
    2000: {"voip"},
    2375: {"cloudapi"},
    2376: {"cloudapi"},
    2379: {"cloudapi"},
    3268: {"ldap", "ldapdir", "relays"},
    3269: {"ldap", "ldapdir", "relays"},
    3306: {"dbcreds"},
    3389: {"rdp"},
    5060: {"voip"},
    5061: {"voip"},
    5432: {"dbcreds"},
    5985: {"ntlm", "httptokens"},
    5986: {"ntlm", "httptokens"},
    6379: {"dbcreds"},
    6443: {"cloudapi"},
    8080: {"http", "httptokens", "files", "llm", "sccm"},
    8200: {"cloudapi"},
    8443: {"http", "httptokens", "files", "adcs", "sccm", "llm"},
    8500: {"cloudapi"},
    9419: {"cloudapi"},
    10250: {"cloudapi"},
}


def select_profile(services):
    """Return a sorted handler list, or None when the capture is unknown.

    ``services`` rows are ``(ip, port, service, transport)`` from the services
    handler. Fewer than two recognised ports means the profile is too weak to
    trust, so the caller should run everything.
    """
    ports = set()
    for row in services or []:
        try:
            ports.add(int(str(row[1]).strip()))
        except (IndexError, TypeError, ValueError):
            continue
    selected = set(ALWAYS)
    recognised = 0
    for port, handlers in PORT_HANDLERS.items():
        if port in ports:
            recognised += 1
            selected |= handlers
    if recognised < 2:
        return None
    return sorted(selected)
