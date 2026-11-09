"""Tests for the tshark field helper (no tshark needed)."""

import subprocess

import PufferRelay.tshark_fields as helper


class _Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_fields_builds_command_and_parses(monkeypatch):
    captured = {}

    def fake_run(command, capture_output=True, timeout=None):
        captured["command"] = command
        return _Result(stdout=b"10.0.0.5\t21\n10.0.0.6\t445\n")

    monkeypatch.setattr(helper, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)

    rows = helper.fields("cap.pcap", "tcp", ["ip.src", "tcp.dstport"])
    assert rows == [("10.0.0.5", "21"), ("10.0.0.6", "445")]
    command = captured["command"]
    assert command[:5] == ["tshark", "-n", "-r", "cap.pcap", "-Y"]
    assert "separator=\t" in command
    assert "occurrence=f" in command
    assert command.count("-e") == 2


def test_fields_pads_missing_columns(monkeypatch):
    monkeypatch.setattr(helper, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(
        helper.subprocess, "run", lambda *a, **k: _Result(stdout=b"a\nb\tc\td\n")
    )
    assert helper.fields("c", "x", ["one", "two"]) == [("a", ""), ("b", "c")]


def test_fields_returns_empty_on_failure(monkeypatch):
    monkeypatch.setattr(helper, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(
        helper.subprocess, "run", lambda *a, **k: _Result(returncode=2, stderr=b"bad")
    )
    assert helper.fields("c", "x", ["one"]) == []


def test_fields_raises_without_tshark(monkeypatch):
    monkeypatch.setattr(helper, "find_tshark", lambda: "")
    try:
        helper.fields("c", "x", ["one"])
    except RuntimeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_find_tshark_prefers_path(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/tshark")
    assert helper.find_tshark() == "/usr/bin/tshark"
