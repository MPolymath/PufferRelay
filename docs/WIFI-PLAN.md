# Wi-Fi capability plan (802.11 / radiotap)

Status: **implemented** (2026-11-10). Epic #82, sub-issues #72–#81.
The passive handlers, tables, export files, leads and `--wifi-commands`
generator are in `PufferRelay/protocols/wifi.py`; tests are in
`PufferRelay/tests/test_wifi.py`. Implementation notes:

- one union `tshark` pass (field occurrence `a`) feeds all seven handlers;
- EAPOL message numbers use `wlan_rsna_eapol.keydes.msgnr` because Wireshark
  4.4 no longer exposes the `eapol.keydes.key_info.*` display fields;
- PMKID lines are emitted in hashcat 22000 form only when the PMKID, BSSID,
  client and SSID are all present; otherwise the command pack points at
  `hcxdumptool`/`hcxpcapngtool`;
- `--wifi-commands` is text only and marks every ACTIVE line.

## 1. Goal

PufferRelay currently assumes Ethernet/IP captures. This plan extends it to
**passive 802.11 captures** (monitor-mode pcap/pcapng with radiotap) so an
operator can answer:

1. What Wi-Fi networks and clients are in this capture?
2. What weakness is *observed* (WEP, WPS, open, enterprise EAP, WPA3
   transition, missing PMF, rogue/deauth activity)?
3. Is there material that is *offline-crackable* (WEP IVs, WPA2 handshake,
   PMKID)?
4. What needs an *active* step (deauth, rogue AP, WPS PIN, DragonShift,
   Dragonblood, KRACK/FragAttacks verification)?
5. Exactly which command or article should the operator use next?

PufferRelay remains passive: it never sets monitor mode, injects frames, starts
a rogue AP or cracks a key.

## 2. Non-goals

- Cracking, frame injection, deauth, rogue-AP execution, WPS PIN attacks.
- Monitor-mode/driver management (operator supplies the capture).
- WPA3 protocol research; we consume public results.
- Bluetooth/RFID/other radio (separate backlog; the library has adjacent
  references).
- Replacing aircrack-ng, hcxdumptool/hcxtools, reaver/bully, eaphammer,
  hostapd-mana, DragonShift, dragonslayer, bettercap or mdk4.

## 3. Proof-level model

Every Wi-Fi finding carries one:

| Level | Meaning |
|---|---|
| `observed` | The capture shows the configuration/identity/activity. No exploit proof. |
| `offline-crackable` | The capture contains material that can be cracked offline (WEP IVs, WPA2 handshake, PMKID). Still depends on a weak key. |
| `active-verification-required` | The attack needs deauth, a rogue AP, a side channel or another active step. PufferRelay only provides commands/references. |
| `reference-only` | No practical local tool/path from the capture; link the article/paper. |

This distinction is the core of the feature: a WPA2 handshake is not a password,
a WPA3 transition beacon is not a successful downgrade, and a duplicate SSID is
not a proven evil twin.

## 4. Attack / evidence matrix

| Attack | Passive evidence in capture | Proof level | Active step needed | Primary tools / references |
|---|---|---|---|---|
| Open network / OWE absent | beacon privacy/RSN absent | observed | none (sniff/evil twin are active) | Synacktiv 2025 |
| WEP crack | IV count, unique IVs, ARP traffic | offline-crackable at ~20k–60k IVs; otherwise active | ARP replay / fragmentation / chopchop | aircrack-ng, aireplay-ng |
| WPA/WPA2-PSK | 4-way EAPOL M1–M4 | offline-crackable | deauth/evil twin to force a handshake | aircrack-ng, hcxdumptool, hashcat 22000 |
| PMKID | PMKID in EAPOL M1 / RSN IE | offline-crackable | association attempt may be required | hcxdumptool, hashcat 22000 |
| WPS PIN / Pixie / NULL PIN | WPS IE, setup state, lock, config methods, vendor/model | observed (WPS presence); active for PIN | reaver/bully/wash | thacker WPS |
| WPA2-Enterprise EAP | EAP identity, method (PEAP/TTLS/TLS/GTC/MSCHAPv2) | observed; credentials active | rogue AP / relay | eaphammer, hostapd-mana, wpa_sycophant |
| WPA3-Enterprise | EAP method + mandatory 802.11w | observed; relay active | rogue AP + relay if cert validation absent | hostapd-mana/wpa_sycophant 2.11 (Synacktiv 2025) |
| WPA3-SAE | AKM SAE, SAE auth frames, PMF | observed; no offline hash | side channels/active probing | dragonslayer |
| WPA3 transition downgrade | AKMs PSK+SAE, MFPR=0 | observed (configuration); active for downgrade | deauth + WPA2-only rogue AP | DragonShift + hostapd-mana |
| SSID Confusion (CVE-2023-52424) | no beacon protection, credential reuse | reference/active | credential reuse + MitM | USENIX 2024 paper |
| Rogue AP / evil twin | duplicate SSID, different BSSID/security/OUI | candidate | active verification | bettercap, mdk4, eaphammer |
| Deauth/disassoc | subtype 12/10 frames, bursts | observed (frames); active to perform | aireplay-ng, bettercap, mdk4 |
| KRACK / FragAttacks | WPA2/3 without PMF; version-dependent | reference-only | active replay/verification | krackattacks.com, fragattacks.com |

## 5. Architecture

### Input

- Normal `-f capture.pcapng` path; tshark detects 802.11/radiotap.
- No new monitor-mode management. The operator captures with `airodump-ng`,
  `hcxdumptool`, Wireshark or `tcpdump -i mon0`.
- Validate the capture link type before running Wi-Fi handlers; Ethernet
  captures must not produce Wi-Fi tables.

### Fields (verified against the local tshark 4.x)

- 802.11: `wlan.fc.type`, `wlan.fc.subtype`, `wlan.fc.type_subtype`,
  `wlan.bssid`, `wlan.sa`, `wlan.da`, `wlan.ssid`,
  `wlan.fixed.capabilities.privacy`, `wlan.fixed.auth.alg`,
  `wlan.fixed.sae_message_type`, `wlan.ext_tag.sae.*`, `wlan.rsnx.sae_pk`
- RSN: `wlan.rsn.akms.type`, `wlan.rsn.pcs.type`, `wlan.rsn.gcs.type`,
  `wlan.rsn.capabilities.mfpc`, `wlan.rsn.capabilities.mfpr`,
  `wlan.rsn.ie.pmkid`, `wlan.rsn.pmkid.list`
- WEP: `wlan.wep.iv`, `wlan.wep.icv`, `wlan.wep.weakiv`, `wlan.fc.protected`
- EAPOL/EAP: `eapol.keydes.type`, `eapol.keydes.key_info.key_ack`,
  `eapol.keydes.key_info.key_mic`, `eapol.keydes.replay_counter`,
  `eap.code`, `eap.type`, `eap.identity`
- WPS: `wps.wifi_protected_setup_state`, `wps.ap_setup_locked`,
  `wps.selected_registrar`, `wps.config_methods`, `wps.manufacturer`,
  `wps.model_name`, `wps.device_name`, `wps.version`
- Radio: `radiotap.channel.freq`, `radiotap.dbm_antsignal`

Field availability varies by tshark version; each handler must degrade
gracefully (warn + skip) rather than return a misleading empty result.

### Handlers and tables (planned)

| Handler | Purpose | Tables |
|---|---|---|
| `wifi` | network/client inventory and security classification | `wifi_networks`, `wifi_clients` |
| `wifiwep` | IV/weak-IV/ARP counting and crack readiness | `wifi_wep` |
| `wifihs` | EAPOL M1–M4 and PMKID pairing | `wifi_handshakes`, `wifi_pmkid` |
| `wifiwps` | WPS state/lock/methods/vendor | `wifi_wps` |
| `wifieap` | Enterprise identities and EAP methods | `wifi_eap` |
| `wifiwpa3` | SAE/transition/PMF classification | `wifi_wpa3` |
| `wifievents` | deauth/disassoc/duplicate SSID/security downgrade | `wifi_events` |

One fields pass per handler (or one union pass where fields overlap), consistent
with the existing field-based architecture. Schema version bumps per table.

### CLI and outputs

- Passive: normal `-f`, `--only wifi,...`, `-r --protocol wifi`.
- `--wifi-commands` (new): text-only `wifi-attacks.md` with per-finding
  commands, prerequisites, risk, cleanup and article links. Mirrors
  `--commands`/`--serveme`; no `--run`.
- Files: `wifi-networks.tsv`, `wifi-clients.tsv`, `wep.txt`,
  `wifi-handshakes/`, `pmkid-hashes.txt`, `wifi-wps.tsv`, `wifi-eap.tsv`,
  `wifi-wpa3.tsv`, `wifi-events.tsv`, `wifi-attacks.md`.
- Leads: `WIFI-NET`, `WIFI-WEP`, `WIFI-HANDSHAKE`, `WIFI-PMKID`, `WIFI-WPS`,
  `WIFI-EAP`, `WIFI-WPA3-SAE`, `WIFI-WPA3-DOWNGRADE`, `WIFI-EVILTWIN`,
  `WIFI-DEAUTH`.
- Report/agent feed: Wi-Fi section, proof level, ATT&CK advisory mapping
  (T1040 sniffing, T1557 AiTM, T1110 brute for WPS).

## 6. Phases and issues

| Phase | Issue | Deliverable |
|---|---|---|
| 1 | #72 | Inventory + security classification (foundation) |
| 2 | #73 | WEP IV analysis and passive/active crack guidance |
| 3 | #74 | WPA2 handshake/PMKID export (pcap subset + 22000) |
| 4 | #75 | WPS detection and PIN/Pixie/NULL PIN guidance |
| 5 | #76 | Enterprise EAP inventory + rogue AP/relay guidance |
| 6 | #77 | WPA3-SAE/transition/PMF + DragonShift/Dragonblood/SSID Confusion guidance |
| 7 | #78 | Rogue AP/evil twin/deauth analytics |
| 8 | #79 | `--wifi-commands` command/reference pack |
| 9 | #80 | Leads/report/ATT&CK integration |
| 10 | #81 | Fixtures, public-capture validation, docs |

Epic: #82.

ROI order: #72 → #74 → #73 → #75 → #76 → #77 → #78 → #79 → #80 → #81.
Rationale: inventory is the prerequisite; WPA2 handshake/PMKID and WEP are the
fastest passive-to-offline wins; WPS and enterprise are common and cheap to
flag; WPA3 is mostly configuration/downgrade guidance; rogue/deauth analytics
benefit from the inventory; output/report last once the data model is stable.

## 7. Validation

- Synthetic scapy fixtures per attack class: radiotap/Dot11 beacons, probe
  responses, WEP data, EAPOL M1–M4, PMKID, WPS IEs, EAP identity/method, SAE
  and transition RSN, duplicate SSID/deauth bursts.
  `scripts/make_wifi_fixture.py` generates the committed fixture (no capture
  binary in git); `PufferRelay/tests/test_wifi_fixture.py` runs it through all
  seven handlers when scapy and tshark are available.
- Public captures (Wireshark samples) through `scripts/local_smoke.py` with
  aggregate counts only; never commit captures or hashes.
- CI: tshark version matrix (existing); `build_wiki.py --check`; no active
  commands run in tests.
- Each issue adds tests and a `wiki/detections.yaml` entry; generated
  `DETECTIONS.md`/`CHEATSHEET.md` stay current.

## 8. Privacy and safety

- Wi-Fi captures can contain third-party traffic and personal data. The same
  capture-confidentiality rules apply (`docs/PRIVACY.md`): no uploads, no
  commits, temporary outputs deleted.
- Handshakes, PMKIDs and derived hashes are secrets; they stay in the local
  engagement directory. Reports are confidential.
- Every active command is text-only, marked ACTIVE, with prerequisites,
  disruption warning and cleanup. PufferRelay never executes them.
- Deauth/rogue APs can disrupt production and third parties; scope and written
  authorization are the operator's responsibility.

## 9. Research notes and references

- thehacker.recipes WEP page: detailed WEP workflow (IV thresholds, fake auth,
  ARP replay, fragmentation, ChopChop). WPS page: PIN search space (~11,000),
  Pixie Dust chipsets, NULL PIN, wash/reaver/bully. WPA2 page: stub, only
  handshake capture/crack described. WPA3 page: currently has no body.
- Synacktiv "Wireless infidelity: pentest Wi-Fi in 2025": open/WEP/WPA2,
  PMKID, enterprise PEAP-MSCHAPv2, relay with hostapd-mana + wpa_sycophant,
  WPA3-Enterprise relay (2.11), WPA3 transition exposure.
- DragonShift: automates WPA3 transition-mode downgrade with hostapd-mana and
  captures the WPA2 handshake for hashcat 22000.
- Dragonblood: SAE side channels/timing/group downgrade; dragonslayer scripts.
- SSID Confusion CVE-2023-52424: SSID not bound to PMK; needs credential reuse
  and no beacon protection.
- KRACK and FragAttacks: reference-only; active verification.
- Attack library: the Wi-Fi entries above are already indexed; Bluetooth/RFID
  entries exist but are out of scope for this epic.

Links:
- https://www.thehacker.recipes/radio/wi-fi/wep/
- https://www.thehacker.recipes/radio/wi-fi/wpa2/
- https://www.thehacker.recipes/radio/wi-fi/wps/
- https://www.thehacker.recipes/radio/wi-fi/wpa3/
- https://www.synacktiv.com/publications/wireless-infidelity-pentest-wi-fi-en-2025.html
- https://github.com/jabbaw0nky/DragonShift
- https://wpa3.mathyvanhoef.com/
- https://www.krackattacks.com/
- https://www.fragattacks.com/
- https://www.usenix.org/conference/usenixsecurity24/presentation/vanhoef
- https://github.com/ZerBea/hcxdumptool ; https://github.com/ZerBea/hcxtools
- https://github.com/s0lst1c3/eaphammer ; https://github.com/sensepost/hostapd-mana ; https://github.com/sensepost/wpa_sycophant
- https://www.bettercap.org/ ; https://github.com/aircrack-ng/mdk4 ; https://github.com/derv82/wifite2

## 10. Open questions

- Exact hashcat 22000 PMKID/handshake line construction from tshark fields vs
  exporting a filtered pcap and letting `hcxpcapngtool` do it (preferred:
  filtered pcap + command, direct PMKID only when the fields are complete).
- Whether to parse `eapol.keydes.key_info` reliably across tshark versions or
  infer message numbers from key_ack/key_mic/secure bits.
- WPA3 transition detection needs both AKM list membership and PMF state; some
  APs advertise unusual combinations. Decide conservative labels.
- Should Wi-Fi handlers auto-run on 802.11 captures (yes) and be skippable on
  Ethernet (yes); `--auto` profile must include them only for radiotap input.
- Whether to include a small passive WPS "Pixie-likely" model list; the plan
  recommends reporting vendor/model and letting the operator decide.
