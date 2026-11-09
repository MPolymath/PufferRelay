"""Shared pytest fixtures.

Adds Wireshark's directory to PATH when tshark is installed outside PATH so
the pyshark-based end-to-end tests can run on a developer machine. CI installs
tshark normally.
"""

import os
import shutil

import pytest

WIRESHARK_DIRS = [
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
    "/usr/bin",
    "/usr/local/bin",
]


def _ensure_tshark_on_path():
    if shutil.which("tshark"):
        return
    for directory in WIRESHARK_DIRS:
        candidate = os.path.join(directory, "tshark.exe" if os.name == "nt" else "tshark")
        if os.path.exists(candidate):
            os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")
            return


_ensure_tshark_on_path()


@pytest.fixture(scope="session")
def tshark_available():
    return shutil.which("tshark") is not None
