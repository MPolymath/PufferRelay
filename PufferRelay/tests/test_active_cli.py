"""Active CLI modes are opt-in and refuse to run without authorisation."""

import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "PufferRelay", *args, "--log-level", "ERROR"],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": REPO_ROOT},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


def test_live_requires_bpf(tmp_path):
    result = _run(["--live", "eth0"], cwd=str(tmp_path))
    assert result.returncode == 2
    assert "--bpf" in result.stderr
    assert "LIVE CAPTURE" in (result.stdout + result.stderr)


def test_live_refuses_without_authorisation(tmp_path):
    result = _run(["--live", "eth0", "--bpf", "port 445"], cwd=str(tmp_path))
    assert result.returncode == 2
    assert "refusing live capture" in result.stderr


def test_proxy_requires_target(tmp_path):
    result = _run(["--proxy"], cwd=str(tmp_path))
    assert result.returncode == 2
    assert "--proxy-target" in result.stderr


def test_proxy_refuses_without_authorisation(tmp_path):
    result = _run(
        ["--proxy", "--proxy-target", "127.0.0.1:9"], cwd=str(tmp_path)
    )
    assert result.returncode == 2
    assert "refusing proxy" in result.stderr
