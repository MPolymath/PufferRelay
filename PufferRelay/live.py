"""Live capture wrapper (issue #27) — ACTIVE network access.

Tier B: this reads packets from an interface. It is never automatic: the CLI
requires an explicit interface, a mandatory BPF filter, and an operator
confirmation (interactive "authorized" or --confirm-authorized). The capture is
written to a temporary pcap, analysed with the normal passive pipeline, and
deleted afterwards unless the operator asks to keep it.

The module itself does not prompt; the CLI owns the warning and confirmation.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from PufferRelay.tshark_fields import find_tshark


class LiveCaptureError(RuntimeError):
    """Invalid parameters or tshark failure."""


def build_capture_command(tshark, interface, bpf_filter, seconds, output_path):
    if not interface or not str(interface).strip():
        raise LiveCaptureError("an interface is required for live capture")
    if not bpf_filter or not str(bpf_filter).strip():
        raise LiveCaptureError("a BPF filter is mandatory for live capture")
    try:
        duration = int(seconds)
    except (TypeError, ValueError):
        raise LiveCaptureError("duration must be an integer number of seconds")
    if duration < 1 or duration > 86400:
        raise LiveCaptureError("duration must be between 1 and 86400 seconds")
    if not output_path:
        raise LiveCaptureError("an output path is required")
    return [
        tshark,
        "-n",
        "-i",
        str(interface),
        "-f",
        str(bpf_filter),
        "-a",
        f"duration:{duration}",
        "-w",
        output_path,
        "-q",
    ]


def capture(interface, bpf_filter, seconds, tshark=None, runner=subprocess.run):
    """Capture to a temporary pcap and return its path. Caller deletes it."""
    tshark = tshark or find_tshark()
    if not tshark:
        raise LiveCaptureError("tshark is not installed")

    handle, path = tempfile.mkstemp(prefix="pufferrelay-live-", suffix=".pcap")
    os.close(handle)
    os.unlink(path)  # tshark wants to create it

    command = build_capture_command(tshark, interface, bpf_filter, seconds, path)
    try:
        completed = runner(command, capture_output=True, timeout=int(seconds) + 30)
    except subprocess.TimeoutExpired:
        _remove(path)
        raise LiveCaptureError("capture timed out")
    except OSError as e:
        _remove(path)
        raise LiveCaptureError(f"capture failed: {e}")

    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        _remove(path)
        raise LiveCaptureError(
            f"tshark capture failed: {error[-1] if error else completed.returncode}"
        )
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        _remove(path)
        raise LiveCaptureError("capture produced no packets")
    return path


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def confirm_authorization(confirm_flag, stdin_isatty, prompt=input):
    """Require explicit authorisation; never assume it."""
    if confirm_flag:
        return True
    if not stdin_isatty:
        return False
    try:
        answer = prompt("Type 'authorized' to continue: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return (answer or "").strip().lower() == "authorized"
