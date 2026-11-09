"""LLM / MCP / vector-DB traffic detection (issue #71) — passive.

Internal LLM stacks (Ollama, Open WebUI, LiteLLM), agent frameworks speaking
MCP over HTTP/SSE, and vector databases show up as distinctive hosts, ports,
paths and JSON bodies. Metadata only: prompts and answers are not exported.
"""

from __future__ import annotations

import json
import re

from PufferRelay.protocols.http_tokens import _header_block, _payload_text
from PufferRelay.tshark_fields import fields

FILTER = (
    'http.request && (http.host contains "openai" '
    '|| http.host contains "anthropic" '
    '|| http.host contains "generativelanguage" '
    '|| http.request.uri contains "/api/generate" '
    '|| http.request.uri contains "/api/chat" '
    '|| http.request.uri contains "/v1/chat/completions" '
    '|| http.request.uri contains "/v1/completions" '
    '|| http.request.uri contains "/v1/embeddings" '
    '|| http.request.uri contains "/mcp" '
    '|| http.request.uri contains "/sse" '
    '|| http.request.uri contains "jsonrpc" '
    '|| tcp.dstport == 11434 || tcp.dstport == 7860 '
    '|| tcp.dstport == 6333 || tcp.dstport == 19530)'
)
HOST_SERVICES = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
}
PORT_SERVICES = {
    11434: "ollama",
    7860: "gradio",
    6333: "qdrant",
    19530: "milvus",
}
PATH_MARKERS = [
    ("/api/generate", "ollama"),
    ("/api/chat", "ollama"),
    ("/v1/chat/completions", "openai-compatible"),
    ("/v1/completions", "openai-compatible"),
    ("/v1/embeddings", "embeddings"),
    ("jsonrpc", "mcp"),
    ("/mcp", "mcp"),
    ("/sse", "mcp"),
]
LOCAL_SERVICES = {"ollama", "gradio", "qdrant", "milvus", "openai-compatible"}


def service_for(host, port, path):
    host = (host or "").lower().split(":")[0]
    if host in HOST_SERVICES:
        return HOST_SERVICES[host]
    try:
        port_number = int(str(port).strip())
    except (TypeError, ValueError):
        port_number = 0
    if port_number in PORT_SERVICES:
        return PORT_SERVICES[port_number]
    for marker, name in PATH_MARKERS:
        if marker in (path or ""):
            return name
    return "llm"


def _json_body(body):
    start = body.find("{")
    if start == -1:
        return {}
    try:
        payload = json.loads(body[start:])
        return payload if isinstance(payload, dict) else {}
    except ValueError:
        return {}


def process_llm_traffic(pcap_file):
    rows = fields(
        pcap_file,
        FILTER,
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri",
            "http.user_agent",
            "tcp.dstport",
            "tcp.payload",
            "http.file_data",
        ],
    )
    out = []
    seen = set()
    for src, dst, host, uri, user_agent, port, payload, file_data in rows:
        text = _payload_text(payload)
        if not text:
            continue
        headers = _header_block(text)
        body = _payload_text(file_data)
        if not body:
            parts = text.split("\r\n\r\n", 1)
            body = parts[1] if len(parts) > 1 else ""
        service = service_for(host or headers.get("host"), port, uri)
        document = _json_body(body)
        model = str(document.get("model") or document.get("model_name") or "")[:80]
        method = str(document.get("method") or "")[:80]
        tools = document.get("tools")
        tool_names = []
        if isinstance(tools, list):
            for tool in tools[:10]:
                if isinstance(tool, dict):
                    name = tool.get("name") or (tool.get("function") or {}).get("name")
                    if name:
                        tool_names.append(str(name)[:60])
        auth = bool(headers.get("authorization") or headers.get("x-api-key"))
        is_mcp = service == "mcp" or method in {"tools/call", "tools/list"}
        if is_mcp:
            kind = "mcp-call"
            severity = "high"
            detail = f"MCP {method or 'request'} with {len(tool_names)} tool(s)"
        elif service in LOCAL_SERVICES and not auth:
            kind = "llm-unauthenticated"
            severity = "critical"
            detail = f"{service} inference endpoint answered without auth header"
        else:
            kind = "llm-endpoint"
            severity = "medium"
            detail = f"{service} request" + (f" model={model}" if model else "")
        key = (kind, src, dst, headers.get("host") or host or "", uri or "", method)
        if key in seen:
            continue
        seen.add(key)
        evidence = {
            "service": service,
            "host": headers.get("host") or host or "",
            "uri": uri or "",
            "model": model,
            "method": method,
            "tools": tool_names,
            "auth": auth,
            "user_agent": user_agent or headers.get("user-agent", ""),
        }
        out.append(
            (
                kind,
                severity,
                src or "",
                dst or "",
                service,
                headers.get("host") or host or "",
                uri or "",
                model,
                "yes" if auth else "no",
                detail,
                json.dumps(evidence, sort_keys=True),
            )
        )
    return out
