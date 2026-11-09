"""Handler-selection tests for --only / --credentials-only (no tshark needed)."""

import logging

import PufferRelay.pcap_processing.pcap_parser as parser


def test_selected_handlers_default_is_everything():
    names = parser.selected_handlers()
    assert names == list(parser.HANDLERS)


def test_selected_handlers_only_filter():
    names = parser.selected_handlers(only=["ftp", "http", "services"])
    assert names == ["http", "ftp", "services"]


def test_selected_handlers_credentials_only():
    names = parser.selected_handlers(credentials_only=True)
    assert set(names) == parser.CREDENTIAL_HANDLERS
    assert "ips" not in names and "services" not in names


def test_selected_handlers_ignores_unknown(caplog):
    with caplog.at_level(logging.WARNING):
        names = parser.selected_handlers(only=["ftp", "nope"])
    assert names == ["ftp"]
    assert "Unknown protocol 'nope'" in caplog.text


def test_parse_pcap_runs_only_selected_handlers(monkeypatch):
    calls = []

    def fake(name):
        def run(pcap_file):
            calls.append(name)
            return [("x",)]

        return run

    monkeypatch.setattr(parser, "HANDLERS", {"ftp": fake("ftp"), "http": fake("http")})
    # Avoid the loading animation thread.
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        data = parser.parse_pcap("ignored.pcap", only=["ftp"])
    finally:
        logging.getLogger().setLevel(logging.INFO)
    assert calls == ["ftp"]
    assert data == {"ftp": [("x",)]}
