"""CLI end-to-end: parse a capture, dump the pack, read machine JSON.

Runs PufferRelay in a subprocess so the cwd-based database behaves exactly as a
user would experience it.
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark is not installed"
)


def _env():
    env = os.environ.copy()
    env["PYTHONPATH"] = REPO_ROOT
    return env


def _run(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "PufferRelay", *args, "--log-level", "ERROR"],
        cwd=cwd,
        env=_env(),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_parse_dump_and_json():
    with tempfile.TemporaryDirectory() as tmp:
        from scapy.all import Ether, IP, Raw, TCP, wrpcap

        pcap = os.path.join(tmp, "cap.pcap")
        packets = [
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=40000, dport=21, flags="PA", seq=1, ack=1)
            / Raw(load=b"USER alice\r\n"),
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=40000, dport=21, flags="PA", seq=20, ack=1)
            / Raw(load=b"PASS s3cret\r\n"),
        ]
        wrpcap(pcap, packets)

        result = _run(["-f", pcap, "--dump", "out"], cwd=tmp)
        assert result.returncode == 0, result.stderr
        for name in ("leads.json", "leads.md", "agent-prompt.md", "credentials.csv"):
            assert os.path.exists(os.path.join(tmp, "out", name)), name

        result = _run(["-r", "--json"], cwd=tmp)
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert set(payload) == {"inventory", "leads"}
        assert payload["inventory"]["credentials"][0]["username"] == "alice"
        assert any(lead["severity"] == "high" for lead in payload["leads"])
