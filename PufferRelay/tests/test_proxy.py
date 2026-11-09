"""Local recording TCP relay (issue #16), tested against a loopback echo."""

import base64
import json
import socket
import threading
import time

import pytest

from PufferRelay.proxy import ProxyError, ProxyServer, parse_target


def test_parse_target():
    assert parse_target("10.0.0.10:445") == ("10.0.0.10", 445)
    for bad in ("", "hostonly", "host:notaport", "host:0", "host:70000", ":445"):
        with pytest.raises(ProxyError):
            parse_target(bad)


def _echo_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        try:
            connection, _ = server.accept()
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                connection.sendall(data)
            connection.close()
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server.getsockname()[1], thread


def test_relay_forwards_and_records(tmp_path):
    echo_port, echo_thread = _echo_server()
    recording = tmp_path / "relay.jsonl"
    proxy = ProxyServer("127.0.0.1", echo_port, str(recording))

    # Point the relay at the echo server (target set in the constructor).
    host, port = proxy.start()
    assert host == "127.0.0.1" and port > 0

    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.sendall(b"ping")
    echoed = client.recv(4096)
    assert echoed == b"ping"
    client.close()

    # Wait until both directions were recorded, then stop and flush.
    deadline = time.time() + 3
    while time.time() < deadline and len(proxy._records) < 2:
        time.sleep(0.05)
    proxy.stop()

    echo_thread.join(timeout=3)

    records = [
        json.loads(line)
        for line in recording.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    directions = {record["direction"] for record in records}
    assert {"c2s", "s2c"} <= directions, records
    payloads = {base64.b64decode(record["b64"]) for record in records}
    assert b"ping" in payloads


def test_stop_is_idempotent(tmp_path):
    proxy = ProxyServer("127.0.0.1", 1, str(tmp_path / "none.jsonl"))
    host, port = proxy.start()
    proxy.stop()
    proxy.stop()
    assert host == "127.0.0.1"
