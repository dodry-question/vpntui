"""Generate the global Xray config (system proxy or TUN)."""
from __future__ import annotations

import json

from . import paths
from .util import load_json, port_free, save_json

TUN_ADDR = "198.18.0.1/30"
TUN_NAME = "vpntui0"

DEFAULT_SOCKS = 10808
DEFAULT_HTTP = 10809


def load_state() -> dict:
    state = load_json(paths.STATE, {})
    if not isinstance(state, dict):
        state = {}
    state.setdefault("mode", "proxy")
    state.setdefault("server_index", 0)
    return state


def save_state(state: dict) -> None:
    save_json(paths.STATE, state)


def state_ports(state: dict | None = None) -> dict:
    """Proxy ports from the state file, with sane defaults."""
    state = state if state is not None else load_state()
    ports = state.get("ports") if isinstance(state, dict) else None
    result = {"socks": DEFAULT_SOCKS, "http": DEFAULT_HTTP}
    if isinstance(ports, dict):
        for key in result:
            value = ports.get(key)
            if isinstance(value, int) and 0 < value < 65536:
                result[key] = value
    return result


def free_pair(start: int = DEFAULT_SOCKS) -> tuple[int, int]:
    """First two free 127.0.0.1 ports at or above ``start``."""
    chosen: list[int] = []
    for candidate in range(start, start + 200):
        if port_free(candidate):
            chosen.append(candidate)
            if len(chosen) == 2:
                return chosen[0], chosen[1]
    return DEFAULT_SOCKS, DEFAULT_HTTP


def ensure_ports(state: dict | None = None, running: bool = False) -> dict:
    """Keep the current ports while they are free, otherwise move them.

    ``running`` means our own service owns the ports right now, so a busy
    port is expected: never reshuffle in that case.
    """
    state = state if state is not None else load_state()
    ports = state_ports(state)
    if running:
        state["ports"] = ports
        return ports
    if port_free(ports["socks"]) and port_free(ports["http"]):
        state["ports"] = ports
        return ports
    socks, http = free_pair(DEFAULT_SOCKS)
    state["ports"] = {"socks": socks, "http": http}
    return state["ports"]


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


def build(mode: str, index: int, ports: dict | None = None) -> dict:
    proxy = pick_outbound(index)
    ports = ports or {"socks": DEFAULT_SOCKS, "http": DEFAULT_HTTP}
    direct = {"protocol": "freedom", "tag": "direct",
              "settings": {}, "sockopt": {"domainStrategy": "UseIP"}}
    inbounds = []
    if mode == "vpn":
        inbounds.append({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_NAME,
                "address": [TUN_ADDR],
                "mtu": 1500,
                "stack": "system",
                "strictRoute": True,
                # Xray installs and removes the default route itself.
                "autoSystemRoutingTable": ["0.0.0.0/0"],
                "sniff": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
        })
    inbounds += [
        {"tag": "socks", "listen": "127.0.0.1", "port": int(ports["socks"]),
         "protocol": "socks", "settings": {"udp": True}},
        {"tag": "http", "listen": "127.0.0.1", "port": int(ports["http"]),
         "protocol": "http"},
    ]
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": inbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules()},
        "outbounds": [proxy, direct],
    }


def write(mode: str, index: int, running: bool = False) -> tuple[str, int]:
    state = load_state()
    ports = ensure_ports(state, running=running)
    state["mode"] = mode
    state["server_index"] = index
    save_state(state)
    save_json(paths.GLOBAL_CONFIG, build(mode, index, ports))
    return mode, index
