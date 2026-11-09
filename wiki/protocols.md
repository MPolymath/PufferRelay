# Protocols: what is parsed and what it proves

Each handler reads only fields from the capture. "Proves" is deliberately
narrow: a capture proves traffic, not intent.

## LDAP
- Filter: `ldap && ldap.protocolOp==bindRequest`; fields `ldap.name`, `ldap.simple`.
- Proves: a simple bind (often the DN) and, when present, the password.
- Limit: SASL binds do not expose a password; signing state is not in the packet.

## HTTP
- Filter: requests with a method or `Authorization`; fields host, URI,
  `Authorization`, `file_data`.
- Proves: Basic-auth credentials, POST form content (including credential-like
  fields), URLs visited.
- Limit: TLS is opaque; NTLM/SSO auth is handled by the NTLM handler.

## FTP / Telnet
- FTP: `USER`/`PASS` commands. Telnet: `telnet.data` text.
- Proves: cleartext credentials. Telnet credential detection is heuristic
  (login/password text).

## SMTP / IMAP / POP3
- SMTP: `smtp.auth.username/password`.
- IMAP: `LOGIN` parsed from the command line (tshark truncates its password
  field); `AUTHENTICATE` identity when exposed.
- POP3: `USER`/`PASS` pairing, `APOP` identity.
- Proves: mailbox credentials in clear text.

## NTLM
- Only packets carrying `NTLMSSP` (or HTTP NTLM headers) are read.
- Proves: NetNTLMv1/v2 challenge/response for an account. Format is hashcat 5600.

## Kerberos (AS-REP roasting)
- Pairs AS-REQ (`msg_type 10`) with AS-REP (`11`). No `PA-ENC-TIMESTAMP` in the
  AS-REQ means the KDC answered without pre-auth: the AS-REP is crackable
  offline (hashcat 18200).
- Limit: if the capture starts after the AS-REQ, the account is treated as
  roastable (assumed).

## SMB
- Fields: SMB2 command, tree connect, filename, SMB1 path/file.
- Proves: shares and file names that crossed the wire; printer shares.
- Limit: read/write frames reference FileIds, so names appear only when the
  capture contains the create/tree-connect.

## Relay scenarios
- Joins NTLMSSP authentications with destination protocol/port and SMB2
  `sec_mode.sign_required`.
- Proves: an authentication happened towards an endpoint; a candidate when SMB
  signing is not required or NTLM is used over LDAP/HTTP.
- Limit: LDAP/HTTP signing enforcement cannot be proven from the capture alone.

## NetBIOS
- `nbns` name/type frames; maps workstation, domain/browser and service names.

## SNMP
- `snmp.community` and version (v1/v2c) per packet.

## EAP / NAC
- `eapol`/`eap` frames and RADIUS `User-Name` attributes; EAP identities and
  MAB-style MAC usernames.
- Proves: 802.1X/MAB is present and which identities authenticate.
- Limit: no keys; spoofing suggestions stay active/Tier B.

## WSUS
- HTTP requests whose URI, host or User-Agent indicates Windows Update/WSUS.
- Proves: update infrastructure endpoints seen in traffic.
- Limit: WSUS approval state and content integrity are not visible.

## Files
- HTTP response bodies and FTP-DATA objects, sha256, size, safe name.
- Limit: objects split across many TCP segments depend on tshark reassembly.
