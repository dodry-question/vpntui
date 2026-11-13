#!/usr/bin/env python3
"""Генератор конфига Xray для per-app VPN (TUN-инбаунд + правила по доменам).

Правила лежат в ~/.config/xray/rules.json (как в Clash):

  {"default": "proxy",
   "rules": [
     {"type": "DOMAIN-SUFFIX", "value": "roblox.com", "target": "proxy"},
     {"type": "DOMAIN",        "value": "example.com", "target": "direct"},
     {"type": "DOMAIN-KEYWORD","value": "rbxcdn",     "target": "srv:13"}
   ]}

target:
  proxy   — сервер, с которым запущено приложение (по умолчанию)
  direct  — напрямую, мимо VPN
  srv:N   — конкретный сервер из подписки (см. `run-vpn -l`)

Печатает JSON:
  {"config": {...}, "server": {...}, "tun": {...}, "rules": {...}}

Используется скриптом run-vpn. Ничего не пишет на диск.
"""
import json
import socket
import sys

from . import paths

CANDS = paths.CANDS
STATE = paths.STATE
RULES = paths.RULES
SUBS = paths.SUBS
# Шаблон стандартных правил (его же использует vpntui для «Сбросить»).
RULES_TEMPLATE = paths.RULES_TEMPLATE

# Тот же mark, что zapret использует для «не трогать этот трафик»
# (nfqws --dpi-desync-fwmark=0x40000000). Заодно он выводит сокеты xray
# из-под правил TUN (loopback-защита: fwmark -> table main).
MARK = 0x40000000

TUN_NAME = "appvpn0"
TUN_ADDR = "198.18.0.1/30"
TUN_TABLE = 100
GATEWAY_IP = "10.0.2.2"  # slirp4netns: шлюз наружу

DEFAULT_RULES = {
    "default": "proxy",
    "rules": [
        {"type": "DOMAIN-SUFFIX", "value": "roblox.com", "target": "proxy",
         "note": "Roblox: игра, чат, API"},
        {"type": "DOMAIN-SUFFIX", "value": "rbxcdn.com", "target": "proxy",
         "note": "Roblox CDN: картинки и ассеты"},
        {"type": "DOMAIN-SUFFIX", "value": "rbxcdn.net", "target": "proxy",
         "note": "Roblox CDN (резервный домен)"},
        {"type": "DOMAIN-SUFFIX", "value": "robloxlabs.com", "target": "proxy",
         "note": "Roblox: капча и антибот"},
    ],
}

# DOMAIN-SUFFIX -> domain:, DOMAIN -> full:, DOMAIN-KEYWORD -> keyword:
TYPE_PREFIX = {
    "DOMAIN": "full",
    "DOMAIN-SUFFIX": "domain",
    "DOMAIN-KEYWORD": "keyword",
}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def state_index():
    try:
        return int(json.loads(STATE.read_text()).get("server_index", 0))
    except Exception:
        return 0


def server_name(cands, index):
    """Человекочитаемое имя: из subscription.json, иначе tag кандидата."""
    try:
        subs = json.loads(SUBS.read_text())
        names = []
        seen = set()
        for cfg in subs:
            remark = (cfg.get("remarks") or "").strip()
            for o in cfg.get("outbounds", []):
                if o.get("protocol") in ("freedom", "block", "dns", "blackhole", None):
                    continue
                key = json.dumps(o.get("settings", {}), sort_keys=True) + \
                    json.dumps(o.get("streamSettings", {}), sort_keys=True)
                if key in seen:
                    continue
                seen.add(key)
                names.append(remark)
        if len(names) == len(cands):
            return names[index]
    except Exception:
        pass
    candidate = cands[index] if 0 <= index < len(cands) else {}
    return str(candidate.get("remarks") or candidate.get("tag") or "?")


def host_port(o):
    s = o.get("settings", {})
    if o.get("protocol") == "hysteria":
        return s.get("address"), s.get("port")
    v = (s.get("vnext") or [{}])[0]
    return v.get("address"), v.get("port")


def resolve_ips(host):
    """Все A-записи (для bypass-маршрутов и подстановки адреса)."""
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def use_ip(proxy, ips):
    """Подставляем IP вместо домена.

    Внутри network namespace у xray нет DNS (127.0.0.53 недоступен), поэтому
    домен сервера резолвим заранее на хосте. SNI/REALITY-домен при этом
    остаётся в streamSettings — TLS работает как обычно.
    """
    host, _ = host_port(proxy)
    if not host or host.replace(".", "").isdigit():
        return host
    if not ips:
        die(f"не удалось разрезолвить сервер {host}")
    ip = ips[0]
    if proxy.get("protocol") == "hysteria":
        proxy["settings"]["address"] = ip
    else:
        proxy["settings"]["vnext"][0]["address"] = ip
    return host


def norm_target(raw):
    """proxy | direct | srv:N (регистр и пробелы не важны)."""
    t = str(raw or "proxy").strip().lower()
    if t in ("", "proxy", "vpn", "default"):
        return "proxy"
    if t in ("direct", "dir", "off"):
        return "direct"
    if t.startswith("srv:") or t.startswith("server:"):
        num = t.split(":", 1)[1].strip()
        if num.isdigit():
            return f"srv:{int(num)}"
    return None


def default_rules():
    """Стандартные правила: шаблон из scripts/vpn, иначе встроенный минимум."""
    try:
        raw = json.loads(RULES_TEMPLATE.read_text())
        if isinstance(raw, dict) and isinstance(raw.get("rules"), list):
            return raw
    except Exception:
        pass
    return json.loads(json.dumps(DEFAULT_RULES))


def load_rules():
    """Читаем rules.json; битые/отсутствующие правила — стандартные."""
    try:
        data = json.loads(RULES.read_text())
    except Exception:
        return default_rules()
    if not isinstance(data, dict):
        return default_rules()
    rules = []
    for r in data.get("rules") or []:
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("type") or "").strip().upper()
        if rtype not in TYPE_PREFIX:
            continue
        value = str(r.get("value") or "").strip().strip(".")
        if not value:
            continue
        target = norm_target(r.get("target"))
        if not target:
            continue
        item = {"type": rtype, "value": value, "target": target}
        if r.get("note"):
            item["note"] = str(r["note"])
        rules.append(item)
    default = norm_target(data.get("default")) or "proxy"
    return {"default": default, "rules": rules}


def make_outbound(cands, index, tag):
    """Копия кандидата с тегом, fwmark и подставленным IP сервера."""
    if not 0 <= index < len(cands):
        die(f"сервер #{index} вне диапазона (всего {len(cands)})")
    proxy = json.loads(json.dumps(cands[index]))
    proxy["tag"] = tag
    sock = proxy.setdefault("streamSettings", {}).setdefault("sockopt", {})
    sock["mark"] = MARK
    host, port = host_port(proxy)
    ips = resolve_ips(host) if host else []
    use_ip(proxy, ips)
    return proxy, host, port, ips


def build(index):
    if not CANDS.exists():
        die(f"нет файла подписки: {CANDS}")
    cands = json.loads(CANDS.read_text())
    if not 0 <= index < len(cands):
        die(f"сервер #{index} вне диапазона (всего {len(cands)})")

    rules_cfg = load_rules()
    proxy, host, port, ips = make_outbound(cands, index, "proxy")

    outbounds = {"proxy": proxy,
                 "direct": {"protocol": "freedom", "tag": "direct",
                            "settings": {"domainStrategy": "UseIP"},
                            "streamSettings": {"sockopt": {"mark": MARK}}}}
    bypass_ips = set(ips)
    used_servers = {index}

    def outbound_tag(target):
        """Возвращает тег outbound'а для цели правила, создавая его при нужде."""
        if target == "direct":
            return "direct"
        if target == "proxy":
            return "proxy"
        if not target.startswith("srv:"):
            return "proxy"
        srv = int(target.split(":", 1)[1])
        tag = f"srv{srv}"
        if tag not in outbounds:
            ob, _h, _p, srv_ips = make_outbound(cands, srv, tag)
            outbounds[tag] = ob
            bypass_ips.update(srv_ips)
            used_servers.add(srv)
        return tag

    default_tag = outbound_tag(rules_cfg["default"])

    route = [
        # Локальные адреса — всегда напрямую.
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
    ]
    active_rules = []
    for r in rules_cfg["rules"]:
        tag = outbound_tag(r["target"])
        route.append({
            "type": "field",
            "domain": [f"{TYPE_PREFIX[r['type']]}:{r['value']}"],
            "outboundTag": tag,
        })
        active_rules.append({**r, "tag": tag})
    route.append({"type": "field", "network": "tcp,udp", "outboundTag": default_tag})

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {"name": TUN_NAME, "mtu": 1500},
            "sniffing": {"enabled": True, "routeOnly": True,
                         "destOverride": ["http", "tls", "quic"]},
        }],
        "routing": {"domainStrategy": "AsIs", "rules": route},
        "outbounds": list(outbounds.values()),
    }

    return {
        "config": cfg,
        "server": {
            "index": index,
            "name": server_name(cands, index),
            "host": host,
            "port": port,
            "protocol": proxy.get("protocol"),
            "ip": (ips[0] if ips else host),
            # IP-адреса всех задействованных серверов: root-хелпер прокладывает
            # к ним bypass-маршрут, чтобы туннель не ушёл сам в себя.
            "ips": sorted(bypass_ips),
        },
        "tun": {
            "name": TUN_NAME,
            "addr": TUN_ADDR,
            "table": TUN_TABLE,
            "gateway": GATEWAY_IP,
            "mark": MARK,
        },
        "rules": {
            "default": rules_cfg["default"],
            "default_tag": default_tag,
            "count": len(active_rules),
            "items": active_rules,
            "servers": sorted(used_servers),
        },
    }


def main():
    args = sys.argv[1:]
    index = state_index()
    if args:
        if args[0] in ("-h", "--help"):
            print(__doc__)
            return
        try:
            index = int(args[0])
        except ValueError:
            die(f"не индекс сервера: {args[0]}")
    print(json.dumps(build(index), ensure_ascii=False))


if __name__ == "__main__":
    main()
