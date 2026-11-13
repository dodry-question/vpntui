import base64
import json

import pytest

from vpntui import paths, subscription


VLESS = ("vless://11111111-1111-1111-1111-111111111111@example.com:443"
         "?type=tcp&security=reality&sni=cdn.example.com&fp=chrome&pbk=KEY&sid=ab"
         "&flow=xtls-rprx-vision#DE%20Frankfurt")
TROJAN = "trojan://secret@example.org:8443?sni=example.org#Trojan"
SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.net:8388#SS"
HY2 = "hysteria2://token@example.io:443?sni=example.io&insecure=1#HY2"


def test_parse_vless():
    name, out = subscription.parse_link(VLESS)
    assert name == "DE Frankfurt"
    assert out["protocol"] == "vless"
    assert out["settings"]["vnext"][0]["address"] == "example.com"
    assert out["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert out["streamSettings"]["security"] == "reality"
    assert out["streamSettings"]["realitySettings"]["publicKey"] == "KEY"


def test_parse_trojan_ss_hy2():
    assert subscription.parse_link(TROJAN)[1]["protocol"] == "trojan"
    ss = subscription.parse_link(SS)[1]
    assert ss["protocol"] == "shadowsocks"
    assert ss["settings"]["servers"][0]["method"] == "aes-256-gcm"
    hy = subscription.parse_link(HY2)[1]
    assert hy["protocol"] == "hysteria"
    assert hy["streamSettings"]["hysteriaSettings"]["auth"] == "token"


def test_base64_list():
    raw = base64.b64encode("\n".join([VLESS, TROJAN]).encode()).decode()
    items = subscription.parse_text(raw)
    assert [name for name, _ in items] == ["DE Frankfurt", "Trojan"]


def test_json_candidates():
    config = {"outbounds": [
        json.loads(json.dumps(subscription.parse_link(VLESS)[1])),
        {"protocol": "freedom", "tag": "direct"},
    ]}
    items = subscription.parse_text(json.dumps(config))
    assert len(items) == 1
    assert items[0][1]["protocol"] == "vless"


def test_reject_clash():
    with pytest.raises(subscription.SubscriptionError):
        subscription.parse_text("proxies:\n  - name: x\n")


def test_apply_writes_and_keeps_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CANDS", tmp_path / "candidates.json")
    monkeypatch.setattr(paths, "SUBS", tmp_path / "subscription.json")
    monkeypatch.setattr(paths, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(paths, "SOURCE", tmp_path / "source.json")
    items = subscription.parse_text("\n".join([VLESS, TROJAN, SS]))
    assert subscription.apply(items, "https://example/sub") == 3
    assert len(json.loads((tmp_path / "candidates.json").read_text())) == 3
    assert len(json.loads((tmp_path / "subscription.json").read_text())) == 3

    # choosing the second server and re-importing must keep it selected
    (tmp_path / "state.json").write_text('{"server_index": 1}')
    assert subscription.apply(items) == 3
    assert json.loads((tmp_path / "state.json").read_text())["server_index"] == 1

    names = [row["name"] for row in subscription.summary()]
    assert names == ["DE Frankfurt", "Trojan", "SS"]


def test_duplicates_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CANDS", tmp_path / "candidates.json")
    monkeypatch.setattr(paths, "SUBS", tmp_path / "subscription.json")
    monkeypatch.setattr(paths, "STATE", tmp_path / "state.json")
    items = subscription.parse_text("\n".join([VLESS, VLESS]))
    assert subscription.apply(items) == 1
