"""Live capture gating and command construction (issue #27)."""

import os

import pytest

from PufferRelay import live


class Completed:
    def __init__(self, returncode=0, stderr=b""):
        self.returncode = returncode
        self.stderr = stderr


def test_build_capture_command_is_explicit():
    command = live.build_capture_command(
        "tshark", "eth0", "port 445", 30, "out.pcap"
    )
    assert command[0] == "tshark"
    assert "-i" in command and command[command.index("-i") + 1] == "eth0"
    assert "-f" in command and command[command.index("-f") + 1] == "port 445"
    assert "-a" in command and command[command.index("-a") + 1] == "duration:30"
    assert "-w" in command and command[command.index("-w") + 1] == "out.pcap"


@pytest.mark.parametrize(
    "interface,bpf,seconds",
    [
        ("", "port 445", 30),
        ("eth0", "", 30),
        ("eth0", "port 445", 0),
        ("eth0", "port 445", 90000),
        ("eth0", "port 445", "soon"),
    ],
)
def test_build_capture_command_rejects_unsafe_input(interface, bpf, seconds):
    with pytest.raises(live.LiveCaptureError):
        live.build_capture_command("tshark", interface, bpf, seconds, "out.pcap")


def test_capture_returns_temp_path_and_runner_is_used(tmp_path, monkeypatch):
    path = tmp_path / "capture.pcap"
    monkeypatch.setattr(
        live.tempfile,
        "mkstemp",
        lambda **kwargs: (os.open(str(path), os.O_CREAT | os.O_WRONLY), str(path)),
    )

    def runner(command, capture_output, timeout):
        with open(command[command.index("-w") + 1], "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
        assert timeout == 40
        return Completed()

    result = live.capture("eth0", "port 445", 10, tshark="tshark", runner=runner)
    assert result == str(path)
    assert os.path.getsize(result) > 0


def test_capture_failure_removes_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "capture.pcap"
    monkeypatch.setattr(
        live.tempfile,
        "mkstemp",
        lambda **kwargs: (os.open(str(path), os.O_CREAT | os.O_WRONLY), str(path)),
    )

    def runner(command, capture_output, timeout):
        return Completed(returncode=1, stderr=b"no such device\n")

    with pytest.raises(live.LiveCaptureError):
        live.capture("eth0", "port 445", 10, tshark="tshark", runner=runner)
    assert not path.exists()


def test_capture_with_no_packets_is_an_error(tmp_path, monkeypatch):
    path = tmp_path / "capture.pcap"
    monkeypatch.setattr(
        live.tempfile,
        "mkstemp",
        lambda **kwargs: (os.open(str(path), os.O_CREAT | os.O_WRONLY), str(path)),
    )

    def runner(command, capture_output, timeout):
        return Completed()

    with pytest.raises(live.LiveCaptureError):
        live.capture("eth0", "port 445", 10, tshark="tshark", runner=runner)


def test_confirm_authorization_never_assumes():
    assert live.confirm_authorization(True, stdin_isatty=False) is True
    assert live.confirm_authorization(False, stdin_isatty=False) is False
    assert (
        live.confirm_authorization(False, True, prompt=lambda _: "authorized")
        is True
    )
    assert live.confirm_authorization(False, True, prompt=lambda _: "yes") is False

    def boom(_):
        raise EOFError

    assert live.confirm_authorization(False, True, prompt=boom) is False
