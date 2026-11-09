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
| `credentials.csv`, `ntlm-hashes.txt`, `asrep-hashes.txt` | secrets for reuse/cracking |
| `relay-targets.txt`, `relays.tsv`, `smb-shares.txt`, `smb-files.txt` | lateral movement leads |
| `wsus.txt`, `nac.txt` | update infrastructure and 802.1X/MAB observations |
| `files.tsv` + `files/` | carved objects (client data — local only) |
| `bloodhound/` | Legacy JSON graph (users/computers/sessions) |
| `summary.json` | inventory + leads for dashboards |

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
