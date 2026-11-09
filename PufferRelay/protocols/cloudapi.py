"""Exposed infrastructure APIs (step 10) — Docker, Kubernetes, etcd, Consul,
Vault and Veeam, detected by port, path and the absence of auth headers.
"""

from __future__ import annotations

import json

from PufferRelay.protocols.http_tokens import _header_block, _payload_text
from PufferRelay.tshark_fields import fields

SERVICES = {
    2375: "docker",
    2376: "docker-tls",
    6443: "kubernetes",
    10250: "kubelet",
    2379: "etcd",
    8500: "consul",
    8200: "vault",
    9419: "veeam",
}
SENSITIVE = {
    "docker": ("/version", "/containers/json", "/images/json", "/exec", "/build"),
    "kubernetes": ("/api/", "/apis/", "/version"),
    "kubelet": ("/pods", "/run/", "/metrics"),
    "etcd": ("/v3/", "/v2/keys", "/version"),
    "consul": ("/v1/", "/ui/"),
    "vault": ("/v1/", "/ui/"),
    "veeam": ("/api/", "/swagger"),
}
AUTH_HEADERS = {"authorization", "x-vault-token", "x-consul-token"}


def _service_for(port):
    try:
        return SERVICES.get(int(str(port).strip()))
    except (TypeError, ValueError):
        return None


def process_cloudapi(pcap_file):
    filter_parts = " || ".join(f"tcp.dstport == {port}" for port in SERVICES)
    rows = fields(
        pcap_file,
        filter_parts,
        [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "http.request.uri",
            "http.host",
            "tcp.payload",
        ],
    )
    out = []
    seen = set()
    for src, dst, port, uri, host, payload in rows:
        service = _service_for(port)
        if not service:
            continue
        text = _payload_text(payload)
        headers = _header_block(text) if text else {}
        authenticated = any(name in headers for name in AUTH_HEADERS)
        path = (uri or "").strip()
        sensitive = any(marker in path for marker in SENSITIVE.get(service, ()))
        if not sensitive:
            continue
        if authenticated:
            kind, severity = f"{service}-exposure", "medium"
            detail = f"{service} API exposed with an auth header"
        else:
            kind, severity = f"{service}-unauthenticated", "critical"
            detail = f"{service} API path {path} requested without auth header"
        evidence = {
            "service": service,
            "host": host or headers.get("host", ""),
            "path": path,
            "authenticated": authenticated,
        }
        key = (kind, src, dst, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            (kind, severity, src or "", dst or "", host or "", detail,
             json.dumps(evidence, sort_keys=True))
        )
    return out
