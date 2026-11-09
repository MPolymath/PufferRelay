"""Config file and CLI override tests (issue #19)."""

import json
import os
import tempfile

import pytest

import PufferRelay.config as config


@pytest.fixture(autouse=True)
def _restore_settings():
    saved = dict(config._settings)
    env = {k: os.environ.get(k) for k in (
        "PUFFERRELAY_CONFIG", "PUFFERRELAY_DB", "PUFFERRELAY_OUTPUT_DIR",
        "PUFFERRELAY_LOG_LEVEL", "PUFFERRELAY_DEFAULT_PCAP")}
    yield
    config._settings.clear()
    config._settings.update(saved)
    for key, value in env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _write_config(tmp, payload):
    path = os.path.join(tmp, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        if isinstance(payload, str):
            handle.write(payload)
        else:
            json.dump(payload, handle)
    return path


def test_config_file_sets_values():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_config(
            tmp,
            {
                "db_path": os.path.join(tmp, "custom.db"),
                "log_level": "warning",
                "output_dir": os.path.join(tmp, "exports"),
                "default_pcap": os.path.join(tmp, "default.pcapng"),
            },
        )
        settings = config.configure(path)
        assert settings["log_level"] == "WARNING"
        assert config.get_db_name() == os.path.join(tmp, "custom.db")
        assert config.get_output_dir() == os.path.join(tmp, "exports")
        assert config.get_default_pcap().endswith("default.pcapng")


def test_invalid_json_and_values_raise():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_config(tmp, "{not json")
        with pytest.raises(config.ConfigError):
            config.configure(path)

        path = _write_config(tmp, {"log_level": "LOUD"})
        with pytest.raises(config.ConfigError):
            config.configure(path)

        path = _write_config(tmp, {"db_path": 42})
        with pytest.raises(config.ConfigError):
            config.configure(path)

        with pytest.raises(config.ConfigError):
            config.configure(os.path.join(tmp, "missing.json"))


def test_unknown_keys_warn(caplog):
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_config(tmp, {"mystery": True})
        with caplog.at_level("WARNING"):
            config.configure(path)
        assert "unknown key" in caplog.text


def test_environment_overrides(monkeypatch):
    monkeypatch.setenv("PUFFERRELAY_DB", "/tmp/env.db")
    monkeypatch.setenv("PUFFERRELAY_LOG_LEVEL", "debug")
    settings = config.configure()
    assert settings["db_path"].endswith("env.db")
    assert settings["log_level"] == "DEBUG"


def test_set_db_path_rejects_empty():
    with pytest.raises(config.ConfigError):
        config.set_db_path("")
