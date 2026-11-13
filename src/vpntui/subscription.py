"""Subscription import: base64 lists, share links and Xray JSON.

Supported inputs
----------------
* ``vless://``, ``vmess://``, ``trojan://``, ``ss://``, ``hysteria2://``
  share links (one per line, optionally base64-encoded as a whole);
* a raw Xray ``outbounds`` array (the old ``candidates.json`` format);
* a list of Xray configs (the old ``subscription.json`` format);
* a single Xray config object containing ``outbounds``.

Clash/sing-box YAML is intentionally rejected with a clear message instead of
being half-imported.
"""
from __future__ import annotations

import base64
import binascii
import json
import pathlib
import re
import socket
import time
import urllib.parse
import urllib.request
from typing import Iterable

from . import paths
from .util import load_json, save_json

USER_AGENT = "vpntui/1.0 (+https://github.com/dodry-question/vpntui)"


class SubscriptionError(RuntimeError):
    pass


def _b64decode(value: str) -> bytes | None:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def _maybe_base64(text: str) -> str:
    stripped = re.sub(r"\s+", "", text)
    if "://" in stripped or stripped.startswith(("{", "[")):
        return text
    decoded = _b64decode(stripped)
    if decoded:
        try:
            candidate = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return text
        if "://" in candidate or candidate.lstrip().startswith(("{", "[")):
            return candidate
    return text


def _alpn(query: dict) -> list[str] | None:
    raw = query.get("alpn") or query.get("alpn") or ""
    if isinstance(raw, list):
        return [str(x) for x in raw if x]
    values = [x for x in re.split(r"[,;]", str(raw)) if x]
    return values or None


def _tls(host: str, query: dict) -> tuple[dict, dict]:
    """Return (streamSettings parts, tls/reality settings)."""
    security = (query.get("security") or "none").lower()
    sni = query.get("sni") or query.get("serverName") or host
    fp = query.get("fp") or query.get("fingerprint")
    if security == "reality":
        reality = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": query.get("pbk") or query.get("public-key") or "",
            "shortId": query.get("sid") or query.get("short-id") or "",
            "spiderX": query.get("spx") or query.get("spiderX") or "/",
        }
        return {"security": "reality", "realitySettings": reality}, reality
    if security in ("tls", "xtls"):
        tls = {"serverName": sni}
        if fp:
            tls["fingerprint"] = fp
        alpn = _alpn(query)
        if alpn:
            tls["alpn"] = alpn
        if str(query.get("allowInsecure") or query.get("insecure") or "").lower() in ("1", "true"):
            tls["allowInsecure"] = True
        return {"security": "tls", "tlsSettings": tls}, tls
    return {"security": "none"}, {}


def _transport(host: str, query: dict) -> dict:
    network = (query.get("type") or query.get("network") or "tcp").lower()
    header = (query.get("headerType") or "").lower()
    path = query.get("path") or "/"
    host_header = query.get("host") or host
    if network == "ws":
        return {"network": "ws", "wsSettings": {"path": path,
                                                "headers": {"Host": host_header}}}
    if network == "grpc":
        return {"network": "grpc", "grpcSettings": {
            "serviceName": query.get("serviceName") or query.get("path") or ""}}
    if network == "httpupgrade":
        return {"network": "httpupgrade", "httpupgradeSettings": {
            "path": path, "host": host_header}}
    if network in ("xhttp", "splithttp"):
        return {"network": "xhttp", "xhttpSettings": {
            "path": path, "host": host_header}}
    if network == "tcp" and header == "http":
        return {"network": "tcp", "tcpSettings": {"header": {"type": "http",
                "request": {"path": [path], "headers": {"Host": [host_header]}}}}}
    return {"network": "tcp"}


def _parse_vless(uri: urllib.parse.SplitResult) -> dict:
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(uri.query).items()}
    host = uri.hostname or ""
    port = uri.port or 443
    user = urllib.parse.unquote(uri.username or "")
    if not user or not host:
        raise SubscriptionError("vless: нет id или адреса")
    stream, _ = _tls(host, query)
    stream.update(_transport(host, query))
    user_obj = {"id": user, "encryption": "none"}
    flow = query.get("flow")
    if flow:
        user_obj["flow"] = flow
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user_obj]}]},
        "streamSettings": stream,
    }


def _parse_vmess(uri: urllib.parse.SplitResult) -> dict:
    raw = (uri.netloc + uri.path).rstrip("/")
    decoded = _b64decode(raw)
    if not decoded:
        raise SubscriptionError("vmess: некорректная base64-строка")
    data = json.loads(decoded.decode("utf-8"))
    host = str(data.get("add") or "")
    port = int(data.get("port") or 443)
    if not host or not data.get("id"):
        raise SubscriptionError("vmess: нет id или адреса")
    query = {
        "security": "tls" if str(data.get("tls") or "") in ("tls", "reality") else "none",
        "sni": str(data.get("sni") or data.get("host") or host),
        "fp": str(data.get("fp") or ""),
        "type": str(data.get("net") or "tcp"),
        "path": str(data.get("path") or "/"),
        "host": str(data.get("host") or host),
        "serviceName": str(data.get("path") or ""),
        "headerType": str(data.get("type") or ""),
        "alpn": ",".join(data.get("alpn") or []) if isinstance(data.get("alpn"), list) else str(data.get("alpn") or ""),
    }
    stream, _ = _tls(host, query)
    stream.update(_transport(host, query))
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{
            "id": str(data["id"]),
            "alterId": int(data.get("aid") or 0),
            "security": str(data.get("scy") or "auto"),
        }]}]},
        "streamSettings": stream,
    }


def _parse_trojan(uri: urllib.parse.SplitResult) -> dict:
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(uri.query).items()}
    host = uri.hostname or ""
    port = uri.port or 443
    password = urllib.parse.unquote(uri.username or "")
    if not password or not host:
        raise SubscriptionError("trojan: нет пароля или адреса")
    query.setdefault("security", "tls")
    stream, _ = _tls(host, query)
    stream.update(_transport(host, query))
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": stream,
    }


def _parse_ss(uri: urllib.parse.SplitResult) -> dict:
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(uri.query).items()}
    netloc = uri.netloc
    if "@" not in netloc:
        decoded = _b64decode(netloc)
        if not decoded:
            raise SubscriptionError("ss: некорректная ссылка")
        netloc = decoded.decode("utf-8")
    userinfo, _, address = netloc.rpartition("@")
    decoded = _b64decode(userinfo)
    if decoded:
        userinfo = decoded.decode("utf-8")
    if ":" not in userinfo or ":" not in address:
        raise SubscriptionError("ss: нет метода/пароля или адреса")
    method, password = userinfo.split(":", 1)
    host, _, port = address.rpartition(":")
    if not host:
        raise SubscriptionError("ss: нет адреса")
    out = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host.strip("[]"), "port": int(port),
            "method": method, "password": urllib.parse.unquote(password),
        }]},
        "streamSettings": {"network": "tcp"},
    }
    plugin = query.get("plugin")
    if plugin:
        parts = [p for p in plugin.split(";") if p]
        if parts:
            out["settings"]["servers"][0]["plugin"] = parts[0]
            opts = {}
            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    opts[k] = v
            if opts:
                out["settings"]["servers"][0]["pluginOpts"] = opts
    return out


def _parse_hysteria2(uri: urllib.parse.SplitResult) -> dict:
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(uri.query).items()}
    host = uri.hostname or ""
    port = uri.port or 443
    auth = urllib.parse.unquote(uri.username or query.get("auth") or "")
    if not host:
        raise SubscriptionError("hysteria2: нет адреса")
    tls = {
        "serverName": query.get("sni") or host,
        "fingerprint": query.get("fp") or "firefox",
        "alpn": ["h3"],
    }
    if str(query.get("insecure") or "").lower() in ("1", "true"):
        tls["allowInsecure"] = True
    return {
        "protocol": "hysteria",
        "settings": {"address": host, "port": port, "version": 2},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls,
            "hysteriaSettings": {"version": 2, "auth": auth},
        },
    }


PARSERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "trojan": _parse_trojan,
    "ss": _parse_ss,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
}


def parse_link(link: str) -> tuple[str, dict]:
    link = link.strip()
    uri = urllib.parse.urlsplit(link)
    scheme = uri.scheme.lower()
    parser = PARSERS.get(scheme)
    if not parser:
        raise SubscriptionError(f"неизвестный протокол: {scheme or link[:20]}")
    name = urllib.parse.unquote(uri.fragment).strip() or f"{scheme}-{uri.hostname or 'server'}"
    return name, parser(uri)


def _is_outbound(item: dict) -> bool:
    return isinstance(item, dict) and "protocol" in item and (
        "settings" in item or item.get("protocol") in ("freedom", "blackhole", "dns", "block"))


def _proxy_outbounds(config: dict) -> Iterable[dict]:
    for out in config.get("outbounds") or []:
        if not _is_outbound(out):
            continue
        if out.get("protocol") in ("freedom", "blackhole", "dns", "block"):
            continue
        yield out


def _from_json(text: str) -> list[tuple[str, dict]]:
    data = json.loads(text)
    items: list[tuple[str, dict]] = []
    if isinstance(data, list):
        for i, item in enumerate(data):
            if _is_outbound(item):
                items.append((str(item.get("remarks") or item.get("tag") or f"server-{i}"), item))
            elif isinstance(item, dict):
                for out in _proxy_outbounds(item):
                    items.append((str(item.get("remarks") or item.get("name") or out.get("tag") or f"server-{i}"), out))
    elif isinstance(data, dict):
        for out in _proxy_outbounds(data):
            items.append((str(data.get("remarks") or data.get("name") or out.get("tag") or "server"), out))
    if not items:
        raise SubscriptionError("в JSON нет ни одного proxy-outbound")
    return items


def parse_text(text: str) -> list[tuple[str, dict]]:
    if not text or not text.strip():
        raise SubscriptionError("пустой ответ подписки")
    text = text.strip()
    if text.lstrip().startswith(("{", "[")):
        return _from_json(text)
    text = _maybe_base64(text)
    links = [line.strip() for line in re.split(r"[\r\n]+", text) if line.strip()]
    items, errors = [], []
    for link in links:
        if link.startswith("#"):
            continue
        if "://" not in link:
            continue
        try:
            items.append(parse_link(link))
        except SubscriptionError as exc:
            errors.append(str(exc))
    if not items:
        if "proxies:" in text or "proxy-groups:" in text:
            raise SubscriptionError("это Clash YAML; нужна ссылка на подписку или список vless/vmess/trojan")
        raise SubscriptionError("не найдено ни одной поддерживаемой ссылки" +
                                (f" ({errors[0]})" if errors else ""))
    return items


def fetch(url: str, headers: dict | None = None, timeout: float = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            charset = response.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
    except Exception as exc:
        raise SubscriptionError(f"не удалось скачать подписку: {exc}") from exc


def _key(out: dict) -> tuple:
    settings = out.get("settings") or {}
    vnext = (settings.get("vnext") or [{}])[0]
    server = (settings.get("servers") or [{}])[0]
    user = (vnext.get("users") or [{}])[0]
    return (
        out.get("protocol"), vnext.get("address") or settings.get("address") or server.get("address"),
        vnext.get("port") or settings.get("port") or server.get("port"),
        user.get("id") or server.get("password") or settings.get("auth"),
    )


OUTBOUND_KEYS = {
    "tag", "protocol", "settings", "streamSettings", "proxySettings",
    "sendThrough", "mux", "multiplex",
}


def _normalise(out: dict, index: int) -> dict:
    result = {k: json.loads(json.dumps(v)) for k, v in out.items() if k in OUTBOUND_KEYS}
    if "protocol" not in result:
        raise SubscriptionError("outbound без protocol")
    result["tag"] = f"proxy-{index}"
    return result


def apply(items: list[tuple[str, dict]], source: str | None = None,
          headers: dict | None = None) -> int:
    """Write candidates/subscription and keep the selected server when possible."""
    seen, clean_items = set(), []
    for name, out in items:
        key = _key(out)
        if key in seen:
            continue
        seen.add(key)
        clean_items.append((name.strip() or f"server-{len(clean_items)}", out))
    if not clean_items:
        raise SubscriptionError("после удаления дублей не осталось серверов")

    old_candidates = load_json(paths.CANDS, [])
    old_index = 0
    try:
        old_index = int((load_json(paths.STATE, {}) or {}).get("server_index", 0))
    except (TypeError, ValueError):
        pass
    old_key = _key(old_candidates[old_index]) if 0 <= old_index < len(old_candidates) else None

    candidates, configs, new_index = [], [], 0
    for i, (name, out) in enumerate(clean_items):
        candidate = _normalise(out, i)
        candidates.append(candidate)
        configs.append({"remarks": name, "outbounds": [json.loads(json.dumps(candidate))]})
        if old_key is not None and _key(candidate) == old_key:
            new_index = i

    save_json(paths.CANDS, candidates)
    save_json(paths.SUBS, configs, mode=0o600)
    state = load_json(paths.STATE, {}) or {}
    state["server_index"] = new_index
    save_json(paths.STATE, state)
    if source:
        meta = {"url": source, "updated": int(time.time()), "count": len(candidates)}
        if headers:
            meta["headers"] = headers
        save_json(paths.SOURCE, meta, mode=0o600)
    return len(candidates)


def import_source(source: str, headers: dict | None = None) -> int:
    if source.startswith(("http://", "https://")):
        text = fetch(source, headers)
        origin = source
    elif source == "-":
        import sys
        text = sys.stdin.read()
        origin = "stdin"
    else:
        path = pathlib.Path(source).expanduser()
        if not path.exists() or path.is_dir():
            raise SubscriptionError(f"файл не найден: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        origin = str(path)
    return apply(parse_text(text), origin, headers)


def update() -> int:
    meta = load_json(paths.SOURCE, {}) or {}
    url = meta.get("url")
    if not url:
        raise SubscriptionError("источник подписки не сохранён; используй: vpntui sub import <url|file>")
    return apply(parse_text(fetch(url, meta.get("headers"))), url)


def summary() -> list[dict]:
    candidates = load_json(paths.CANDS, []) or []
    configs = load_json(paths.SUBS, []) or []
    names = []
    for cfg in configs:
        if isinstance(cfg, dict):
            names.append(str(cfg.get("remarks") or ""))
    out = []
    for i, candidate in enumerate(candidates):
        settings = candidate.get("settings") or {}
        vnext = (settings.get("vnext") or [{}])[0]
        server = (settings.get("servers") or [{}])[0]
        host = vnext.get("address") or settings.get("address") or server.get("address") or "?"
        port = vnext.get("port") or settings.get("port") or server.get("port") or "?"
        out.append({"index": i, "name": names[i] if i < len(names) else f"server-{i}",
                    "host": host, "port": port, "protocol": candidate.get("protocol")})
    return out


def resolve(name: str) -> list[str]:
    ips = []
    try:
        ips = sorted({entry[4][0] for entry in socket.getaddrinfo(name, None, socket.AF_INET)})
    except OSError:
        pass
    return ips
