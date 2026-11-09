# Outputs and the agent feed

Full reference: [`docs/OUTPUTS.md`](../docs/OUTPUTS.md).

## One command

```bash
pufferrelay -f capture.pcapng -q --dump out
```

## What you get

| File | Use |
|---|---|
| `leads.json` | machine feed: ranked leads + inventory + suggested actions |
| `leads.md` | human/agent briefing: severity, why, evidence, commands |
| `agent-prompt.md` | prompt to paste into an AI agent with the pack |
| `ips.txt`, `subnets.txt`, `hosts.tsv` | network map |
| `users.txt` | spraying/roasting candidates |
| `credentials.csv`, `ntlm-hashes.txt`, `asrep-hashes.txt`, `kerberoast-hashes.txt` | secrets for reuse/cracking |
| `tokens.tsv` | HTTP bearer/JWT/API token inventory (fingerprints; raw values stay in the DB) |
| `db-creds.tsv` | Redis/MySQL/PostgreSQL credentials and authentication responses |
| `relay-targets.txt`, `relays.tsv`, `coercions.tsv`, `adcs.tsv`, `sccm.tsv` | lateral movement / AD escalation leads |
| `asrepcatcher.txt` | ASRepCatcher-compatible ARP/Kerberos pattern (links the upstream repo) |
| `wsus.txt`, `nac.txt`, `dns.txt`, `ipv6.tsv` | update infrastructure, 802.1X/MAB, name map, DHCPv6/RA/ADIDNS |
| `llm.tsv` | LLM/MCP/vector-DB endpoints and tool calls (metadata only) |
| `kerberos-signals.tsv`, `ldap-spns.tsv`, `ldap-signing.tsv` | delegation/UnPAC signals, SPN→account/SID, signing inference |
| `voip.tsv`, `media.tsv` | SIP/Skinny call metadata; audio/video objects already carved |
| `report.md`, `triage.md` | engagement report; optional localhost-LLM ranking |
| `files.tsv` + `files/` | carved objects (client data — local only) |
| `bloodhound/` | Legacy JSON graph (users/computers/sessions) |
| `summary.json` | inventory + leads for dashboards |

## Lead prefixes

`CRED`, `HASH`, `ASREP`, `KERBEROAST`/`KERBEROASTCAND`, `TOKEN`, `RELAY`,
`COERCE`, `ADCS`, `SCCM`, `IPV6`, `DB`, `LLM`, `KERB`, `SPN`, `LDAPSIGN`,
`CHAIN`, `VOIP`, `SMB`, `SMBFILE`, `FILE`, `NAC`, `WSUS`, `ASREPCATCHER`, `QW`.
Each lead's `evidence` names the source file/row; the agent feed never needs
to re-parse the database. Leads carry `confidence` (`high` for hash/secret
evidence, `medium` for heuristics such as coercion and delegation flags).

## Lead shape

```json
{
  "id": "CRED-001",
  "severity": "high",
  "title": "Captured ftp credentials for 10.0.0.10",
  "why": "Valid credentials seen in traffic can be replayed...",
  "evidence": {"protocol": "ftp", "source_ip": "10.0.0.5", "username": "alice"},
  "suggested_actions": [
    {"intent": "...", "command": "ftp 10.0.0.10", "active": true,
     "warning": "Active: ... Confirm scope."}
  ],
  "passive": true
}
```

Rules for an agent: cite lead ids, never invent hosts, and never run an
`active: true` action without the operator's confirmation.
