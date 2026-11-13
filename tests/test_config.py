import json

import pytest

from vpntui import appconfig, globalconfig, paths

CANDIDATE = {
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                            "users": [{"id": "uuid", "encryption": "none"}]}]},
    "streamSettings": {"network": "tcp", "security": "none"},
}


@pytest.fixture()
def config(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CANDS", tmp_path / "candidates.json")
    monkeypatch.setattr(paths, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(paths, "RULES", tmp_path / "rules.json")
    monkeypatch.setattr(paths, "SUBS", tmp_path / "subscription.json")
    monkeypatch.setattr(paths, "GLOBAL_CONFIG", tmp_path / "config.json")
    monkeypatch.setattr(globalconfig.paths, "CANDS", paths.CANDS)
    monkeypatch.setattr(globalconfig.paths, "STATE", paths.STATE)
    monkeypatch.setattr(globalconfig.paths, "GLOBAL_CONFIG", paths.GLOBAL_CONFIG)
    (tmp_path / "candidates.json").write_text(json.dumps([CANDIDATE]))
    (tmp_path / "rules.json").write_text(json.dumps({
        "default": "proxy",
        "rules": [{"type": "DOMAIN-SUFFIX", "value": "example.com", "target": "direct"}],
    }))
    return tmp_path


def test_app_config(config, monkeypatch):
    monkeypatch.setattr(appconfig, "CANDS", paths.CANDS)
    monkeypatch.setattr(appconfig, "STATE", paths.STATE)
    monkeypatch.setattr(appconfig, "RULES", paths.RULES)
    payload = appconfig.build(0)
    assert payload["config"]["inbounds"][0]["protocol"] == "tun"
    assert payload["server"]["host"] == "127.0.0.1"
    assert payload["rules"]["count"] == 1
    assert payload["config"]["routing"]["rules"][-1]["outboundTag"] == "proxy"
    assert payload["config"]["outbounds"][0]["streamSettings"]["sockopt"]["mark"] == appconfig.MARK


def test_global_config(config, monkeypatch):
    monkeypatch.setattr(paths, "GLOBAL_CONFIG", config / "config.json")
    globalconfig.write("proxy", 0)
    data = json.loads((config / "config.json").read_text())
    assert [i["tag"] for i in data["inbounds"]] == ["socks", "http"]
    assert data["outbounds"][0]["tag"] == "proxy"
    assert json.loads((config / "state.json").read_text()) == {"mode": "proxy", "server_index": 0}


def test_server_name_matches_by_content(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "SUBS", tmp_path / "subscription.json")
    cands = [
        {"protocol": "vless", "tag": "proxy-0", "settings": {"vnext": [{"address": "a"}]}},
        {"protocol": "vless", "tag": "proxy-1", "settings": {"vnext": [{"address": "b"}]}},
    ]
    subs = [{"remarks": "A", "outbounds": [cands[0]]},
            {"remarks": "B", "outbounds": [cands[1]]}]
    (tmp_path / "subscription.json").write_text(json.dumps(subs))
    assert appconfig.server_name(cands, 1) == "B"
    # extra entries at the end do not shift names
    (tmp_path / "subscription.json").write_text(json.dumps(subs + [subs[1]]))
    assert appconfig.server_name(cands, 0) == "A"
    # an unknown outbound falls back to the tag
    (tmp_path / "subscription.json").write_text(json.dumps([subs[1]]))
    assert appconfig.server_name(cands, 0) == "proxy-0"
