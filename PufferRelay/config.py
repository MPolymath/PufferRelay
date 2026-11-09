# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

"""Runtime settings (issue #19).

Precedence: CLI flags > environment variables > config file > defaults.

Config file: JSON (no extra dependency), searched in this order:
  1. the path passed with --config / PUFFERRELAY_CONFIG
  2. %APPDATA%\\pufferrelay\\config.json (Windows)
  3. $XDG_CONFIG_HOME/pufferrelay/config.json or ~/.config/pufferrelay/config.json

Supported keys:
  db_path       SQLite path                  (default ./extracted_data.db)
  log_level     DEBUG|INFO|WARNING|ERROR|CRITICAL
  output_dir    default directory for --dump (default ./out)
  default_pcap  capture to use when -f/-q is omitted

Invalid JSON, wrong types and bad values raise ConfigError with a message the
CLI prints before exiting; unknown keys only warn.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from PufferRelay.core_imports import dotenv

CURRENT_DIR = Path.cwd()

# Kept for backwards compatibility; use get_db_name() at runtime.
DB_NAME = str(CURRENT_DIR / "extracted_data.db")

LOG_LEVEL = "INFO"
PCAP_STORAGE_FILE = str(CURRENT_DIR / "pcap_storage.txt")

dotenv.load_dotenv()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_TYPE = "sqlite"
LOG_FILE = os.getenv("LOG_FILE", os.path.join(PROJECT_ROOT, "app.log"))
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
KNOWN_KEYS = {"db_path", "log_level", "output_dir", "default_pcap"}

_settings = {
    "db_path": str(CURRENT_DIR / "extracted_data.db"),
    "log_level": "INFO",
    "output_dir": str(CURRENT_DIR / "out"),
    "default_pcap": "",
}


class ConfigError(Exception):
    """Raised when the config file cannot be used."""


def config_candidates() -> list:
    """Config paths to try, in order (explicit/env path first)."""
    candidates = []
    explicit = os.getenv("PUFFERRELAY_CONFIG")
    if explicit:
        candidates.append(Path(explicit).expanduser())
    appdata = os.getenv("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "pufferrelay" / "config.json")
    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    candidates.append(base / "pufferrelay" / "config.json")
    return candidates


def _read_config(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON ({e})")
    except OSError as e:
        raise ConfigError(f"{path}: cannot read ({e})")
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: expected a JSON object")
    for key in payload:
        if key not in KNOWN_KEYS:
            logging.warning("Config: unknown key %r ignored", key)
    return payload


def configure(config_path: str = None) -> dict:
    """Load settings and return the resolved dict. Raises ConfigError."""
    if config_path:
        path = Path(config_path).expanduser()
        if not path.exists():
            raise ConfigError(f"config file not found: {path}")
        payload = _read_config(path)
    else:
        payload = {}
        for candidate in config_candidates():
            if candidate.exists():
                payload = _read_config(candidate)
                break

    resolved = dict(_settings)

    db_path = payload.get("db_path", os.getenv("PUFFERRELAY_DB"))
    if db_path is not None:
        if not isinstance(db_path, str) or not db_path.strip():
            raise ConfigError("db_path must be a non-empty string")
        resolved["db_path"] = str(Path(db_path).expanduser())

    log_level = payload.get("log_level", os.getenv("PUFFERRELAY_LOG_LEVEL"))
    if log_level is not None:
        if not isinstance(log_level, str) or log_level.upper() not in VALID_LOG_LEVELS:
            raise ConfigError(
                f"log_level must be one of {', '.join(sorted(VALID_LOG_LEVELS))}"
            )
        resolved["log_level"] = log_level.upper()

    output_dir = payload.get("output_dir", os.getenv("PUFFERRELAY_OUTPUT_DIR"))
    if output_dir is not None:
        if not isinstance(output_dir, str) or not output_dir.strip():
            raise ConfigError("output_dir must be a non-empty string")
        resolved["output_dir"] = str(Path(output_dir).expanduser())

    default_pcap = payload.get("default_pcap", os.getenv("PUFFERRELAY_DEFAULT_PCAP"))
    if default_pcap is not None:
        if not isinstance(default_pcap, str):
            raise ConfigError("default_pcap must be a string")
        resolved["default_pcap"] = str(Path(default_pcap).expanduser())

    _settings.update(resolved)
    return dict(_settings)


def set_db_path(path: str) -> None:
    if not path or not str(path).strip():
        raise ConfigError("db path must not be empty")
    _settings["db_path"] = str(Path(path).expanduser())


def get_db_name() -> str:
    """Current database path (config/CLI overrides applied)."""
    return _settings["db_path"]


def get_output_dir() -> str:
    return _settings["output_dir"]


def get_default_pcap() -> str:
    return _settings["default_pcap"]


def get_log_level() -> str:
    return _settings["log_level"]
