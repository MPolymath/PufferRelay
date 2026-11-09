# Protocols: what is parsed and what it proves

The canonical, machine-checked catalog is **[DETECTIONS.md](DETECTIONS.md)**
(generated from [detections.yaml](detections.yaml)); this page keeps the prose
detail per protocol.

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

## ASRepCatcher-compatible activity
- One pass over `kerberos || arp` frames: AS-REQ/AS-REP message type, account,
  realm, etype, padata types, plus ARP reply sender IP/MAC.
- Proves a traffic shape, not intent: the same account requesting a TGT from
  two source addresses (relayed AS-REQ), a crackable AS-REP delivered to a host
  that never requested it, an IPv4 address announced by two MACs (ARP
  spoofing), or a burst of pre-auth-less TGT requests.
- When ARP spoofing and a Kerberos relay/diversion signal overlap, the finding
  is raised to **critical** and links
  <https://github.com/Yaxxine7/ASRepCatcher>, the tool that uses this technique.
- Limit: partial captures (started after the request) cannot correlate a
  reply; the detector only reports a diverted reply when another host did send
  the matching AS-REQ.

## DNS
- `dns` frames: `dns.qry.name`, `dns.qry.type`, `dns.flags.response`, `dns.a`,
  `dns.aaaa`.
- Proves: which names were resolved and to which addresses (A/AAAA/PTR), a
  passive name-to-IP map. A/AAAA answers also enrich `hosts.tsv`.
- Limit: one answer per row when a response carries several records; DoH/DoT
  traffic is not DNS and is not parsed here.

## Kerberoasting
- TGS-REQ (msg 12) / TGS-REP (msg 13) fields: account, realm, SPN, etype.
  The encrypted ticket is not a tshark field, so the handler reassembles the
  TCP/UDP payload and walks the KDC-REP DER to the Ticket enc-part.
- Proves: a service ticket encrypted with the service account's password hash;
  format `$krb5tgs$23|17|18$…` for hashcat 13100/19600/19700. A burst of ≥5
  distinct SPNs from one principal is reported as a candidate even without a
  parsed reply.
- Limit: fragmented/segmented Kerberos with no reassembly, or a non-DER blob,
  yields a candidate row only.

## HTTP tokens
- Request/response headers and body: `Authorization: Bearer`, `X-Vault-Token`,
  `PRIVATE-TOKEN`, `X-Api-Key`, session cookies; JWT/GitHub/GitLab/AWS/Slack/
  Stripe patterns; JSON `access_token`/`api_key` keys.
- Proves: a reusable secret was sent. JWTs are decoded (claims only; signature
  is not verified). Exports carry a fingerprint by default; the full value
  stays in the local database.
- Limit: TLS is opaque; header values split across TCP segments may be missed.

## RPC coercion
- `dcerpc` binds and requests on the MS-EFSRPC, MS-RPRN, MS-DFSNM and MS-FSRVP
  interfaces, plus the `efsrpc`/`spoolss`/`netdfs` named pipes; UNC paths are
  extracted from the reassembled call data.
- Proves: a coercion attempt (the first half of an NTLM relay chain).
- Limit: only bind/request frames; encrypted RPC is opaque.

## ADCS / PKINIT
- HTTP `/certsrv`-style enrollment (NTLM or certificate auth) and Kerberos
  PKINIT AS-REQ (`padata_type == 16`), with the principal/realm.
- Proves: certificate enrollment or certificate logon was observed.
- Limit: template names/attributes are often not visible; DCOM-only enrollment
  is detected by bind, not by the requested template.

## IPv6 / DHCPv6 / ADIDNS
- DHCPv6 Advertise/Reply DNS servers, ICMPv6 RA RDNSS/DNSSL, and DNS UPDATE
  (opcode 5) records.
- Proves: a rogue DNS source on the segment and/or dynamic AD DNS updates; one
  host doing both is raised to critical.
- Limit: no baseline of the legitimate resolver, so the lead asks the operator
  to confirm.

## Database authentication
- Redis RESP `AUTH` (clear text), MySQL login user/response, PostgreSQL startup
  parameters, cleartext password auth and MD5/SASL mechanism.
- Proves: reusable database material or an offline-crackable response.
- Limit: `mysql_native_password` scrambles and SCRAM proofs need the matching
  hashcat mode; MSSQL stays with the NTLM handler.

## SMB objects
- tshark `--export-objects smb,<dir>` writes reassembled SMB file objects; the
  handler reads them into `captured_files` with sha256, type and size caps
  (8 MiB/object, 16 MiB/capture).
- Proves: the file content, not just the name seen in CREATE frames.

## SCCM / MECM
- HTTP markers `/SMS_MP`, `ccmhttp`, `/CCM_System`, `Content_*`, `SMSPKG`,
  `.pkg`; SMB trees `SMS_SITE`/`SMSPKG$`.
- Proves: management-point/distribution-point traffic; NTLM to an MP is
  flagged high (relay candidate). Package delivery alone is inventory.
- Limit: the SMS Provider DCOM interfaces are not resolved; client-push is
  inferred from SMB, not from a policy object.

## LLM / MCP / vector DB
- Hosts/ports (OpenAI, Anthropic, Google, Ollama 11434, Gradio 7860, Qdrant
  6333, Milvus 19530), paths (`/api/generate`, `/v1/chat/completions`, `/mcp`,
  `/sse`), and JSON bodies (`model`, `messages`, `tools`, `method`).
- Proves: which model/service is in use, whether an auth header was present,
  and MCP tool calls (method + tool names). Metadata only: prompts and answers
  are not exported.
- Limit: TLS is opaque; local services on ambiguous ports (8080/8000) are only
  recognised by path markers.

## Files
- HTTP response bodies and FTP-DATA objects, sha256, size, safe name.
- Limit: objects split across many TCP segments depend on tshark reassembly.
