"""Local TCP relay that records traffic (issue #16) — ACTIVE network access.

Tier B: a relay that connects to a target and forwards bytes while recording
both directions to JSONL. It is a deliberate, scoped tool: the operator names
the listen port and the single target, confirms authorisation, and the relay
runs for a bounded duration.

Recording format: one JSON object per chunk with ts, direction (c2s/s2c),
peer, target and base64 payload. It is not a pcap; open it with any JSON tool
or convert it for Wireshark if needed.
"""

from __future__ import annotations

import base64
import json
import select
import socket
import threading
import time


class ProxyError(RuntimeError):
    pass


def parse_target(spec: str):
    """'host:port' -> (host, port)."""
    if not spec or ":" not in spec:
        raise ProxyError("target must be HOST:PORT")
    host, port_text = spec.rsplit(":", 1)
    host = host.strip()
    try:
        port = int(port_text)
    except ValueError:
        raise ProxyError("target port must be a number")
    if not host or not (1 <= port <= 65535):
        raise ProxyError("target must be HOST:PORT (1-65535)")
    return host, port


class ProxyServer:
    """Bounded TCP relay with a JSONL recording."""

    def __init__(self, target_host, target_port, output_path, host="127.0.0.1",
                 port=0, max_connections=10):
        self.target_host = target_host
        self.target_port = int(target_port)
        self.output_path = output_path
        self.host = host
        self.port = int(port)
        self.max_connections = max(1, int(max_connections))
        self._listener = None
        self._threads = []
        self._records = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # --- lifecycle -----------------------------------------------------
    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(self.max_connections)
        listener.settimeout(0.3)
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.host, self.port

    def stop(self):
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        for thread in list(self._threads):
            thread.join(timeout=2.0)
        self._write_recording()

    def wait(self, seconds):
        end = time.time() + max(0, float(seconds))
        while not self._stop.is_set() and time.time() < end:
            time.sleep(0.1)

    # --- internals -----------------------------------------------------
    def _accept_loop(self):
        while not self._stop.is_set() and self._listener is not None:
            try:
                client, peer = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle, args=(client, peer), daemon=True
            )
            self._threads.append(thread)
            thread.start()

    def _record(self, direction, peer, payload):
        with self._lock:
            self._records.append(
                {
                    "ts": round(time.time(), 3),
                    "direction": direction,
                    "peer": f"{peer[0]}:{peer[1]}",
                    "target": f"{self.target_host}:{self.target_port}",
                    "b64": base64.b64encode(payload).decode("ascii"),
                }
            )

    def _handle(self, client, peer):
        upstream = None
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=10
            )
            client.settimeout(0.3)
            upstream.settimeout(0.3)
            client.setblocking(False)
            upstream.setblocking(False)
            sockets = [client, upstream]
            while not self._stop.is_set():
                try:
                    ready, _, _ = select.select(sockets, [], [], 0.3)
                except OSError:
                    break
                if not ready:
                    continue
                done = False
                for source in ready:
                    try:
                        data = source.recv(65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        done = True
                        break
                    destination = upstream if source is client else client
                    try:
                        destination.sendall(data)
                    except OSError:
                        done = True
                        break
                    self._record(
                        "c2s" if source is client else "s2c", peer, data
                    )
                if done:
                    break
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _write_recording(self):
        with self._lock:
            records = list(self._records)
        with open(self.output_path, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")


def run_proxy(target_spec, output_path, listen_port=0, seconds=60, host="127.0.0.1"):
    """Convenience wrapper used by the CLI."""
    target_host, target_port = parse_target(target_spec)
    server = ProxyServer(target_host, target_port, output_path, host=host, port=listen_port)
    bind_host, bind_port = server.start()
    try:
        server.wait(seconds)
    finally:
        server.stop()
    return bind_host, bind_port
