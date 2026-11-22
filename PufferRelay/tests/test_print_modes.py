"""Tests for copy-paste print modes (IPs, subnets, hashes)."""

from PufferRelay.export import (
    clean_hash,
    format_hash_list,
    format_ip_list,
    format_subnet_list,
    format_values,
)

INVENTORY = {
    "hosts": [
        {"ip": "10.0.0.5"},
        {"ip": "10.0.0.10"},
        {"ip": "8.8.8.8"},
    ],
    "hashes": [
        {"hash": "NTLMv2 complete hash is: user::DOMAIN:0011223344556677:aabbccddeeff00112233445566778899:0000", "hashcat_mode": 5600},
        {"hash": "$krb5asrep$23$user@DOMAIN:aaaa$bbbb", "hashcat_mode": 18200},
        {"hash": "$krb5asrep$18$user@DOMAIN:aaaa$bbbb", "hashcat_mode": 19900},
    ],
    "kerberoast": [
        {"hash": "$krb5tgs$23$*svc$DOMAIN$aaaa$bbbb"},
    ],
}


def test_clean_hash_strips_label():
    assert clean_hash("NTLMv2 complete hash is: user::D:aa:bb:cc") == "user::D:aa:bb:cc"
    assert clean_hash("$krb5asrep$23$u@R:aa$bb") == "$krb5asrep$23$u@R:aa$bb"


def test_ip_list_and_private_filter():
    assert format_ip_list(INVENTORY) == ["8.8.8.8", "10.0.0.5", "10.0.0.10"]
    assert format_ip_list(INVENTORY, private_only=True) == ["10.0.0.5", "10.0.0.10"]


def test_subnet_list_and_private_filter():
    assert format_subnet_list(INVENTORY) == ["8.8.8.0/24", "10.0.0.0/24"]
    assert format_subnet_list(INVENTORY, private_only=True) == ["10.0.0.0/24"]


def test_hash_list_filters_and_cleans():
    all_hashes = format_hash_list(INVENTORY)
    assert "user::DOMAIN:0011223344556677:aabbccddeeff00112233445566778899:0000" in all_hashes
    assert "$krb5asrep$23$user@DOMAIN:aaaa$bbbb" in all_hashes
    assert "$krb5asrep$18$user@DOMAIN:aaaa$bbbb" in all_hashes
    assert "$krb5tgs$23$*svc$DOMAIN$aaaa$bbbb" in all_hashes

    assert format_hash_list(INVENTORY, "ntlmv2") == [
        "user::DOMAIN:0011223344556677:aabbccddeeff00112233445566778899:0000"
    ]
    assert format_hash_list(INVENTORY, "asrep") == [
        "$krb5asrep$18$user@DOMAIN:aaaa$bbbb",
        "$krb5asrep$23$user@DOMAIN:aaaa$bbbb",
    ]
    assert format_hash_list(INVENTORY, "kerberoast") == [
        "$krb5tgs$23$*svc$DOMAIN$aaaa$bbbb"
    ]


def test_join_modes():
    assert format_values(["10.0.0.5", "10.0.0.10"], "lines") == "10.0.0.5\n10.0.0.10"
    assert format_values(["10.0.0.5", "10.0.0.10"], "comma") == "10.0.0.5,10.0.0.10"
    assert format_values(["10.0.0.5", "10.0.0.10"], "space") == "10.0.0.5 10.0.0.10"
