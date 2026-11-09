# Decision guide — from capture to next action

Use this with [CHEATSHEET.md](CHEATSHEET.md). The catalog entries in
[DETECTIONS.md](DETECTIONS.md) carry the per-handler detail.

## Before anything

1. **Scope.** Confirm the capture's subnets/hosts are inside the authorization.
2. **Privacy.** The capture, database and exports stay on the engagement
   machine. No uploads, no AI services, no commits. See [privacy.md](privacy.md).
3. **No active step without confirmation.** Every command that sends traffic is
   marked ACTIVE and needs an agreed scope and a cleanup plan.

## Five passes

### 1. Map the battlefield

```bash
pufferrelay -f capture.pcapng --only services,ips,dns --dump out
```

Read `hosts.tsv`, `nmap-targets.txt`, `dns.txt`. Decide the capture type below.

### 2. Take reusable secrets

```bash
pufferrelay -f capture.pcapng --credentials-only --dump out
```

Or narrower: `--only httptokens,ldap,http,ftp,smtp,imap,pop3,snmp,dbcreds`.

Check `credentials.csv`, `tokens.tsv`, `db-creds.tsv`. A secret that still works
beats a clever chain.

### 3. Kerberos and offline material

```bash
pufferrelay -f capture.pcapng --only kerberos,kerberoast,asrepcatcher,ntlm --dump out
```

`asrep-hashes.txt`, `kerberoast-hashes.txt`, `ntlm-hashes.txt` are offline
work; crack first, then decide what to do with the password. `asrepcatcher.txt`
is the ASRepCatcher-compatible pattern (links the upstream repo).

### 4. Attack paths

```bash
pufferrelay -f capture.pcapng --only relays,coercion,adcs,sccm,ipv6,smb --dump out
```

- `relays.tsv` — candidate destinations and signing state.
- `coercions.tsv` — a UNC path in a coercion call; look for the matching NTLM.
- `adcs.tsv` — enrollment/PKINIT; ESC8/ESC1 review.
- `sccm.tsv` — management/distribution traffic; NTLM to an MP is high.
- `ipv6.tsv` — rogue DHCPv6/RA DNS or ADIDNS updates.
- `smb-shares.txt` / `smb-files.txt` — what was accessed.

### 5. Content and hand-off

```bash
pufferrelay -f capture.pcapng --only files,smbobjects,smb --dump out
pufferrelay -q capture.pcapng --dump out
```

`files/` + `files.tsv` hold the objects; `leads.md` is the human briefing,
`leads.json` + `agent-prompt.md` the agent feed. Never upload the output.

## Choose by capture type

### AD / Windows

Indicators: Kerberos (88), LDAP (389), SMB (445), RPC (135), WinRM (5985),
RDP (3389), NetBIOS names.

```bash
pufferrelay -f cap.pcapng --only services,ips,dns,kerberos,kerberoast,asrepcatcher,ntlm,relays,coercion,adcs,sccm,smb,smbobjects,nac --dump out
```

Order: secrets → crackable tickets → relay/coercion/ADCS → share content.
Do not poison ARP until you have a target and a cleanup plan; `--commands`
generates the text but never runs it.

### Web / HTTP

Indicators: HTTP/HTTPS hosts, web ports, JSON bodies.

```bash
pufferrelay -f cap.pcapng --only http,httptokens,files,dns,services --dump out
```

Credentials → tokens → carved objects. TLS traffic is opaque; note that the
capture cannot see it rather than guessing.

### Cloud / AI / containers

Indicators: LLM hosts/ports, MCP paths, Docker/Kubernetes/etcd ports, metadata
IPs.

```bash
pufferrelay -f cap.pcapng --only llm,httptokens,services,dns,files --dump out
```

An unauthenticated Ollama/Open WebUI endpoint is critical; MCP `tools/call`
shows tool use. Metadata only — prompts are not exported.

### Unknown / mixed

```bash
pufferrelay -f cap.pcapng --only services,ips,dns --dump out
pufferrelay -q cap.pcapng --dump out
```

Then pick the tree that matches the protocols you actually saw.

## Reading a lead

Each lead has: **id**, **severity**, **why**, **evidence**, **suggested
actions**. Read the catalog entry for its **proves** and **limits**:

- `proves` is what the traffic demonstrates.
- `limits` is what it cannot. A candidate is not a cracked password; a relay
  target is not a successful relay.
- An action with `"active": true` sends packets. Confirm scope; prefer the
  passive alternative when one exists.

## Verify, don't assume

| Capture finding | What it proves | What to verify (scope-gated) |
|---|---|---|
| NetNTLMv2 hash | an NTLM exchange happened | whether the password cracks; destination signing |
| AS-REP / TGS-REP hash | the KDC returned crackable material | the cracked password, then access |
| Relay candidate | signing was not required | a relay attempt against the destination |
| Coercion UNC | a victim was told to authenticate | the matching NTLM and the relay outcome |
| Token fingerprint | a secret crossed the wire | whether it is still valid |
| SMB file name | the client touched it | content (carve it) and permissions |
| DHCPv6/RA DNS | a host offered DNS | whether it is the legitimate resolver |
| LLM endpoint | the service was used | authentication and exposure |

## What not to do

- Do not call a capture "exploited". Say what it proves and what remains.
- Do not run an ACTIVE command because it appears in a lead; confirm scope.
- Do not upload the capture, database, hashes, tokens or exports to any online
  service or AI tool.
