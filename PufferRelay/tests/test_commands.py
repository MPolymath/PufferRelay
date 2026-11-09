"""Offline command generators (issues #13 and #60)."""

import os

from PufferRelay import commands


def _inventory():
    return {
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostnames": [],
                "macs": [],
                "services": [],
            },
            {
                "ip": "10.0.0.5",
                "hostnames": ["FS01"],
                "macs": [],
                "services": [{"port": 445, "service": "smb"}],
            },
            {
                "ip": "10.0.0.6",
                "hostnames": [],
                "macs": [],
                "services": [{"port": 80, "service": "http"}],
            },
        ],
        "users": [],
        "credentials": [
            {
                "protocol": "ftp",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.10",
                "username": "alice",
                "secret": "s3cret",
                "context": "cleartext FTP",
            }
        ],
        "hashes": [
            {
                "username": "bob@CORP",
                "hash": "$krb5asrep$...",
                "kind": "AS-REP (etype 23)",
                "hashcat_mode": 18200,
            }
        ],
        "relays": [
            {
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.40",
                "destination_port": 445,
                "protocol": "SMB",
                "username": "alice",
                "signing_required": False,
                "candidate": True,
            }
        ],
        "wsus": [
            {
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.20",
                "host": "wsus.corp",
                "uri": "/SelfUpdate/",
                "user_agent": "",
                "indicator": "wsus",
            }
        ],
        "quick_wins": [],
        "smb": {"shares": [], "files": []},
        "files": [],
        "nac": [],
    }


def test_arp_plan_targets_relay_relevant_hosts_only():
    plan = commands.arp_spoof_plan(_inventory(), interface="eth0")
    assert plan["gateway"] == "10.0.0.1"
    assert plan["targets"] == ["10.0.0.5"]
    assert any("-t 10.0.0.5 10.0.0.1" in item["command"] for item in plan["commands"])
    assert plan["cleanup"]


def test_arp_plan_uses_explicit_gateway():
    plan = commands.arp_spoof_plan(_inventory(), interface="ens33", gateway="10.0.0.254")
    assert plan["gateway"] == "10.0.0.254"
    assert "ens33" in plan["commands"][0]["command"]


def test_render_arp_plan_carries_warning():
    plan = commands.arp_spoof_plan(_inventory())
    text = commands.render_arp_plan(plan)
    assert "ACTIVE NETWORK TRAFFIC" in text
    assert "arpspoof" in text
    assert "sudo pkill arpspoof" in text


def test_serve_me_suggestions_cover_each_source():
    suggestions = commands.serve_me_suggestions(_inventory())
    joined = "\n".join(item["command"] for item in suggestions)
    assert "curl -sSk -D- http://10.0.0.6:80/" in joined
    assert "nxc smb 10.0.0.5" in joined
    assert "impacket-ntlmrelayx -t smb://10.0.0.40" in joined
    assert "hashcat -m 18200" in joined
    assert "http://10.0.0.20/SelfUpdate/" in joined

    offline = [item for item in suggestions if not item["active"]]
    assert offline and all("hashcat" in item["command"] for item in offline)


def test_write_command_pack_respects_include(tmp_path):
    inventory = _inventory()

    arp_only = commands.write_command_pack(
        inventory, str(tmp_path), include=("arp",)
    )
    assert set(arp_only) == {"active_commands"}
    assert os.path.exists(arp_only["active_commands"])
    assert not os.path.exists(os.path.join(tmp_path, "serveme.md"))

    both = commands.write_command_pack(inventory, str(tmp_path))
    assert set(both) == {"active_commands", "serveme"}
    with open(both["serveme"], encoding="utf-8") as handle:
        assert "ACTIVE NETWORK TRAFFIC" in handle.read()


def test_empty_inventory_is_safe():
    plan = commands.arp_spoof_plan({"hosts": []})
    assert plan["targets"] == []
    assert plan["gateway"] == "<GATEWAY>"
    assert "No relay-relevant target" in commands.render_arp_plan(plan)
    assert "inventory is empty" in commands.render_serve_me(
        commands.serve_me_suggestions({})
    )
