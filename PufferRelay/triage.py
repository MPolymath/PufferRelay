"""Optional local-LLM triage (issue #51) — localhost only, off by default.

The model receives *lead metadata* (id, severity, confidence, title) and
inventory counts, never credentials, hashes, tokens, commands or packet data.
The URL is forced to loopback so capture-derived text cannot leave the machine.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Dict, List

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3"


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url or "")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Ollama URL must be http(s)://HOST[:PORT]")
    if parsed.hostname.lower() not in LOOPBACK_HOSTS:
        raise ValueError(
            "Ollama URL must be loopback (127.0.0.1/localhost/::1) so capture "
            "data never leaves this machine"
        )
    return url.rstrip("/")


def build_prompt(inventory: Dict, leads: List[Dict]) -> str:
    counts = {}
    for lead in leads:
        counts[lead.get("severity", "low")] = counts.get(lead.get("severity", "low"), 0) + 1
    ranked = sorted(
        leads,
        key=lambda lead: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            lead.get("severity", "low"), 9
        ),
    )
    lines = [
        "You are assisting an authorised penetration test. The operator captured",
        "traffic passively and PufferRelay produced these leads. Use only this",
        "list; do not invent hosts or vulnerabilities.",
        "",
        f"Inventory: {len(inventory.get('hosts', []))} hosts, "
        f"{len(inventory.get('users', []))} users, "
        f"{len(inventory.get('credentials', []))} credentials, "
        f"{len(inventory.get('hashes', []))} hash items.",
        f"Leads: {counts}.",
        "",
        "Top leads:",
    ]
    for lead in ranked[:30]:
        lines.append(
            f"- {lead.get('id', '-')} | {lead.get('severity', 'low')} | "
            f"{lead.get('confidence', 'high')} | {lead.get('title', '')}"
        )
    lines.extend(
        [
            "",
            "Return Markdown with:",
            "1. The three highest-value verification steps, in order.",
            "2. One sentence per step explaining what it would prove.",
            "3. Anything that looks like a false positive or needs a capture check.",
            "Do not include credentials, hashes, IP addresses or commands.",
        ]
    )
    return "\n".join(lines)


def ask_ollama(prompt: str, url: str = DEFAULT_URL, model: str = DEFAULT_MODEL,
               timeout: int = 120, opener=urllib.request.urlopen) -> str:
    url = validate_url(url)
    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    request = urllib.request.Request(
        f"{url}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise RuntimeError("Ollama returned an unexpected payload")
    if payload.get("error"):
        raise RuntimeError(f"Ollama error: {payload['error']}")
    text = payload.get("response")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("Ollama returned an empty response")
    return text.strip()


def run_triage(inventory: Dict, leads: List[Dict], url: str = DEFAULT_URL,
               model: str = DEFAULT_MODEL, opener=urllib.request.urlopen) -> str:
    return ask_ollama(build_prompt(inventory, leads), url=url, model=model, opener=opener)


def write_triage(path: str, text: str, model: str, url: str) -> str:
    import os
    import time

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Local LLM triage\n\n")
        handle.write(f"- model: `{model}` at `{url}` (loopback only)\n")
        handle.write(f"- generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        handle.write(text.rstrip() + "\n")
    return path
