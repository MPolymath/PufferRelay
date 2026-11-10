# PufferRelay 1.2.0 — 2026-11-10

Passive Wi-Fi (802.11) coverage (epic #82, issues #72–#81). PufferRelay still
never sets monitor mode, injects frames or cracks a key; active Wi-Fi commands
are text only and marked ACTIVE.

- `wifi`: BSSID/SSID/band/channel, AKMs, ciphers, PMF, clients and a
  conservative security label (OPEN/WEP/WPA2-PSK/WPA2-ENTERPRISE/WPA2-MIXED/
  WPA3-SAE/WPA3-TRANSITION/OWE).
- `wifiwep`: IV/unique-IV/weak-IV/ARP counts and offline-crack readiness.
- `wifihs`: EAPOL 1–4 pairing per BSSID/client, complete-handshake flag and
  PMKID capture; `pmkid-hashes.txt` in hashcat 22000 form when complete.
- `wifiwps`: WPS state/lock/selected registrar/methods/vendor and risk.
- `wifieap`: EAP identities and methods (PEAP/TTLS/TLS/GTC/MSCHAPv2).
- `wifiwpa3`: SAE-only vs PSK+SAE transition mode, PMF capable/required and
  SAE auth frames; transition without required PMF is downgrade-exposed.
- `wifievents`: deauth/disassoc bursts and duplicate-SSID/security/OUI
  candidates.
- New tables (`wifi_networks`, `wifi_wep`, `wifi_handshakes`, `wifi_wps`,
  `wifi_eap`, `wifi_wpa3`, `wifi_events`), export TSVs, `WIFI-*` leads with
  `proof_level`, ATT&CK mapping (T1040/T1557/T1110) and `-r --protocol wifi...`.
- `--wifi-commands [FILE]` writes `wifi-attacks.md`: per-finding commands with
  prerequisites, warnings and cleanup, or article links when no local tool
  exists (WPA3/Dragonblood/SSID Confusion/KRACK/FragAttacks).
- `--auto` selects the Wi-Fi handlers for 802.11 captures and skips them on
  Ethernet; one union tshark pass feeds all handlers.
- Tests: 31 new Wi-Fi tests; full suite 181 passing offline.

# PufferRelay 1.1.2 — 2026-11-09

Packaging fix:

- The wheel now includes every subpackage (`database`, `protocols`, `utils`,
  `pcap_processing`) and ships `catalog_data.yaml`, so `--detections` works in
  an installed package. 1.1.1 was uploaded before this fix; use 1.1.2.
- `requires-python` is >=3.10, matching the tested interpreters.

# PufferRelay 1.1.1 — 2026-11-09

Coverage completion after 1.1.0:

- MSSQL SQL authentication (username/password from `tds.login`) is now part of
  the database pass and `db-creds.tsv`; Windows auth remains with NTLM.
- SIP digest parsing: username/realm/nonce plus a fingerprint of the response
  (never the raw response) in the VoIP evidence.
- SMB3 awareness: encrypted sessions and encryption capability are reported in
  `fingerprints.tsv` so a missing SMB carve is explained rather than silent.
- Tests: 150 passing.

# PufferRelay 1.1.0 — 2026-11-09

Passive capture analysis for authorised engagements. No client data leaves the
machine; active modes are opt-in and warned.

## Detection coverage

- Kerberoasting: TGS-REP DER walk, hashcat 13100/19600/19700, burst candidates.
- Kerberos depth: S4U, S4U2Proxy, delegation flags, PKINIT→U2U UnPAC chains.
- ASRepCatcher-compatible ARP/relay pattern with upstream link.
- HTTP bearer/JWT/Vault/GitLab/GitHub/AWS tokens (fingerprinted exports).
- RPC coercion (MS-EFSRPC/RPRN/DFSNM/FSRVP) with UNC extraction.
- ADCS: HTTP `/certsrv`, MS-WCCE DCOM, PKINIT, and LDAP CA/template objects.
- SCCM/MECM: MP/DP/AdminService, SMS shares, client-push SMB.
- Database auth: Redis clear text, MySQL `$mysqlna$` (11200), PostgreSQL MD5 (12).
- DHCPv6/RA DNS and ADIDNS dynamic updates.
- SMB object carving, DNS inventory, VoIP (SIP/Skinny), RDP identity,
  Docker/K8s/etcd/Consul/Vault/Veeam exposure, WPAD, SSH/TLS/VNC/TFTP
  fingerprints.
- Chain correlation (coercion + credential + relay; LDAP signing; ADCS),
  identity/credential graph, ATT&CK mapping, lead confidence.

## Interfaces

- `--auto` handler profile, `--jobs N`, `--chunk-packets N` (editcap chunks with
  resume), `--report` Markdown/HTML with metadata and cleanup checklist,
  `--diff DB`, loopback-only `--triage`, `--detections`, `--version`.
- Export pack adds kerberoast/tokens/coercions/ADCS/SCCM/IPv6/DB/VoIP/RDP/
  cloud/fingerprint/SPN files, `credential-matrix.tsv`, `identity-graph.json`,
  `report.md`/`.html`, `diff.md`, `triage.md`.

## Safety

- Passive by default. `--live`/`--proxy` are warned, authorised, and live
  captures are deleted unless kept. `--commands`/`--serveme` are text only.
- Client captures, databases, hashes, tokens and reports stay local.

## Quality

- 149 pytest tests, including benign and malformed corpora; CI matrix on
  Linux (3.11/3.13), Windows and macOS; generated wiki catalog checked in CI.
