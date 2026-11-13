"""Generate the global Xray config (system proxy or TUN)."""
from __future__ import annotations

import json

from . import paths
from .util import load_json, save_json

TUN_ADDR = "198.18.0.1/30"


def load_state() -> dict:
    state = load_json(paths.STATE, {})
    if not isinstance(state, dict):
        state = {}
    state.setdefault("mode", "proxy")
    state.setdefault("server_index", 0)
    return state


def save_state(state: dict) -> None:
    save_json(paths.STATE, state)


def pick_outbound(index: int) -> dict:
    candidates = load_json(paths.CANDS, [])
    if not candidates:
        raise RuntimeError(f"нет серверов: {paths.CANDS}; импортируй подписку (vpntui sub import)")
    if not 0 <= index < len(candidates):
        raise RuntimeError(f"сервер #{index} вне диапазона (всего {len(candidates)})")
    outbound = json.loads(json.dumps(candidates[index]))
    outbound["tag"] = "proxy"
    outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 255
    return outbound


def routing_rules() -> list[dict]:
    return [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"},
        {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
    ]


def build(mode: str, index: int) -> dict:
    proxy = pick_outbound(index)
    direct = {"protocol": "freedom", "tag": "direct",
              "settings": {"domainStrategy": "UseIP"}}
    inbounds = []
    if mode == "vpn":
        inbounds.append({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "address": [TUN_ADDR],
                "mtu": 1500,
                "stack": "system",
                "strictRoute": True,
                "sniff": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
        })
    inbounds += [
        {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
         "settings": {"udp": True}},
        {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
    ]
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": inbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules()},
        "outbounds": [proxy, direct],
    }


def write(mode: str, index: int) -> tuple[str, int]:
    state = load_state()
    state["mode"] = mode
    state["server_index"] = index
    save_state(state)
    save_json(paths.GLOBAL_CONFIG, build(mode, index))
    return mode, index
