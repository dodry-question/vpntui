#!/usr/bin/env python3
"""vpntui — панель VPN в духе Koala Clash (Textual TUI).

Каркас: слева постоянная боковая навигация + быстрые переключатели,
справа содержимое раздела, внизу строка состояния:
  Главная · Профили · Прокси · Подключения · Правила · Логи ·
  Настройки · Приложения

Управление: 1–8 — разделы, r — обновить, q — выход; в разделах —
клавиши из подсказки в заголовке (Enter, p, k, a, d, s, l, [ ], /, c).

Глобальный режим xray (proxy / TUN) переключается на «Главной»
и в боковой панели. Отдельные приложения запускаются в своей сети
через vpntui runvpn; правила «всегда через VPN» — в «Приложениях».

CLI:
  vpntui --status
  vpntui --launch <id>
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time

from rich.markup import escape
from rich.text import Text
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.theme import Theme
from textual.widgets import DataTable, Input, RichLog, Static

from . import __version__
from . import apps as app_rules
from . import paths as P

HOME = P.HOME
RUN_DIR = P.RUNTIME_DIR
SESS_DIR = P.SESSIONS
LAST_LOG = P.LAST_LOG

XDIR = P.CONFIG_DIR
CANDS = P.CANDS
SUBS = P.SUBS
STATE = P.STATE
RULES = P.RULES
RULES_TEMPLATE = P.RULES_TEMPLATE

CFG = P.CONFIG_DIR
APPS = P.APPS
SETTINGS = P.SETTINGS
STATE_DIR = P.LOG_DIR

AUTOSTART = P.AUTOSTART

SERVICE = P.SERVICE
APP_VERSION = __version__


def manager(*args) -> subprocess.CompletedProcess:
    return sh(sys.executable, "-m", "vpntui.manager", *args)

# палитра «коала»: тёмный фон + зелёный акцент
C_OK = "#4cd98f"
C_BAD = "#f0716a"
C_WARN = "#e6b455"
C_BLUE = "#6cb2f5"
C_DIM = "#8494a5"

RULE_TYPES = [
    ("DOMAIN-SUFFIX", "DOMAIN-SUFFIX"),
    ("DOMAIN-KEYWORD", "DOMAIN-KEYWORD"),
    ("DOMAIN", "DOMAIN"),
]

COUNTRIES = {
    "": "Любая зарубежная",
    "DE": "Германия",
    "SE": "Швеция",
    "FI": "Финляндия",
    "FR": "Франция",
    "PL": "Польша",
    "NL": "Нидерланды",
    "LT": "Литва",
    "GB": "Великобритания",
    "US": "США",
    "JP": "Япония",
    "TR": "Турция",
}

HOST_CC = {
    "ger": "DE",
    "se": "SE",
    "lt": "LT",
    "ru": "RU",
}

_EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002190-\U000021FF"
    "\U0000FE00-\U0000FE0F\U0000200D\U000020E3\U00002B00-\U00002BFF]+"
)


# ---------------------------------------------------------------- утилиты

def clean(text: str | None) -> str:
    return re.sub(r"\s+", " ", _EMOJI.sub(" ", text or "")).strip(" -—·|")


def sh(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def load_json(p, default):
    try:
        return json.loads(pathlib.Path(p).read_text())
    except Exception:
        return default


def save_json(p, data) -> None:
    p = pathlib.Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    os.replace(tmp, p)


def fmt_dur(sec: float) -> str:
    sec = max(0, int(sec))
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_ago(ts: float) -> str:
    if not ts:
        return "никогда"
    d = time.time() - ts
    if d < 60:
        return "только что"
    if d < 3600:
        return f"{int(d // 60)} мин назад"
    if d < 86400:
        return f"{int(d // 3600)} ч назад"
    return time.strftime("%d.%m.%Y", time.localtime(ts))


def fit(text: str, width: int) -> str:
    if width <= 0:
        return text
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


# ---------------------------------------------------------------- xray

def flag_cc(remark: str) -> str:
    """Страна из флаг-эмодзи в названии группы подписки."""
    out = []
    for ch in remark:
        o = ord(ch)
        if 0x1F1E6 <= o <= 0x1F1FF:
            out.append(chr(o - 0x1F1E6 + 65))
    return "".join(out) if len(out) == 2 else ""


def server_names() -> list[tuple[str, str]]:
    def key(outbound: dict) -> str:
        return json.dumps([outbound.get("protocol"), outbound.get("settings", {}),
                           outbound.get("streamSettings", {})], sort_keys=True)

    names: dict[str, tuple[str, str]] = {}
    individual: set[str] = set()
    for cfg in load_json(SUBS, []):
        raw = str(cfg.get("remarks") or "")
        remark = clean(raw) or "Сервер"
        cc = flag_cc(raw)
        usable = [o for o in cfg.get("outbounds", [])
                  if o.get("protocol") not in ("freedom", "block", "dns", "blackhole", None)]
        for n, outbound in enumerate(usable, 1):
            ident = key(outbound)
            if len(usable) == 1 and ident not in individual:
                names[ident] = (remark, cc)
                individual.add(ident)
            elif ident not in names:
                names[ident] = (f"{remark} #{n}", cc)
    return [names.get(key(c), ("", "")) for c in load_json(CANDS, [])]


def server_host(c: dict) -> str:
    if not isinstance(c, dict):
        return "?"
    if c.get("protocol") == "hysteria":
        s = c.get("settings", {})
        return f"{s.get('address')}:{s.get('port')}"
    v = (c.get("settings", {}).get("vnext") or [{}])[0]
    return f"{v.get('address')}:{v.get('port')}"


def split_host(host: str) -> tuple[str, int]:
    h, _, p = host.rpartition(":")
    if not h:
        return host, 443
    try:
        return h, int(p)
    except ValueError:
        return host, 443


def host_country(host: str) -> str:
    h = host.split(":")[0].lower()
    for prefix, cc in HOST_CC.items():
        if h.startswith(prefix + ".") or h == prefix:
            return cc
    return ""


def load_servers() -> list[dict]:
    cands = load_json(CANDS, [])
    names = server_names()
    out = []
    for i, c in enumerate(cands):
        host = server_host(c)
        tag = str(c.get("tag") or "")
        cc = host_country(host)
        name, cc_flag = names[i] if i < len(names) else ("Сервер", "")
        if not name or name.startswith("? "):
            name = tag or "Сервер"
        if not cc:
            cc = cc_flag if cc_flag != "EU" else ""
        out.append({
            "index": i,
            "host": host,
            "hostname": split_host(host)[0],
            "port": split_host(host)[1],
            "protocol": str(c.get("protocol") or "?"),
            "tag": tag,
            "cc": cc,
            "name": name,
            "label": f"{cc + ' · ' if cc else ''}{name}",
        })
    return out


def state() -> dict:
    d = load_json(STATE, {"mode": "proxy", "server_index": 0})
    return d if isinstance(d, dict) else {"mode": "proxy", "server_index": 0}


def server_index() -> int:
    try:
        return int(state().get("server_index", 0))
    except Exception:
        return 0


def settings() -> dict:
    d = load_json(SETTINGS, {})
    return d if isinstance(d, dict) else {}


def is_active() -> bool:
    return sh("systemctl", "--user", "is-active", SERVICE).stdout.strip() == "active"


def service_mono() -> float:
    r = sh("systemctl", "--user", "show", SERVICE,
           "-p", "ActiveEnterTimestampMonotonic", "--value")
    try:
        return int(r.stdout.strip()) / 1_000_000
    except Exception:
        return 0.0


def host_uptime() -> float:
    try:
        return float(pathlib.Path("/proc/uptime").read_text().split()[0])
    except Exception:
        return time.monotonic()


# ---------------------------------------------------------------- правила

def rules_data() -> dict:
    d = load_json(RULES, None)
    if not isinstance(d, dict) or not isinstance(d.get("rules"), list):
        d = load_json(RULES_TEMPLATE, {"default": "proxy", "rules": []})
    if not isinstance(d, dict):
        d = {"default": "proxy", "rules": []}
    d.setdefault("default", "proxy")
    d.setdefault("rules", [])
    return d


def target_short(target: str) -> str:
    t = str(target or "proxy")
    if t == "proxy":
        return "PROXY"
    if t == "direct":
        return "DIRECT"
    if t.startswith("srv:"):
        return "#" + t.split(":", 1)[1]
    return t


def target_label(target: str, servers: list[dict] | None = None) -> str:
    target = str(target or "proxy")
    if target == "direct":
        return "DIRECT"
    if target == "proxy":
        return "по умолчанию"
    if target.startswith("srv:"):
        n = target.split(":", 1)[1]
        if n.isdigit():
            servers = servers or load_servers()
            i = int(n)
            if i < len(servers):
                return f"#{i} {servers[i]['label']}"
        return target
    return target


# ---------------------------------------------------------------- приложения

def load_apps() -> list[dict]:
    return app_rules.load_apps()


# ---------------------------------------------------------------- сессии

def read_sessions() -> list[dict]:
    out = []
    if not SESS_DIR.is_dir():
        return out
    for f in sorted(SESS_DIR.glob("*.json")):
        d = load_json(f, None)
        if not isinstance(d, dict):
            continue
        pid, ns = d.get("app_pid"), d.get("ns") or ""
        if not isinstance(pid, int) or not pathlib.Path(f"/proc/{pid}").exists():
            continue
        if ns and not pathlib.Path("/run/netns", ns).exists():
            continue
        d["_file"] = str(f)
        out.append(d)
    out.sort(key=lambda d: d.get("started") or 0)
    return out


def _hex_ip4(h: str) -> str:
    return ".".join(str(int(h[i:i + 2], 16)) for i in (6, 4, 2, 0))


def _hex_ip6(h: str) -> str:
    try:
        raw = bytes.fromhex(h)
        if len(raw) != 16:
            return h
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return h


def conn_stats(pid: int) -> tuple[list[tuple[str, int]], int]:
    tcp, udp, seen = [], 0, set()
    for fn, v6 in (("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)):
        try:
            lines = pathlib.Path(f"/proc/{pid}/net/{fn}").read_text().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            p = ln.split()
            if len(p) < 4:
                continue
            if fn.startswith("tcp") and p[3] != "01":
                continue
            try:
                h, pv = p[2].split(":")
                port = int(pv, 16)
            except ValueError:
                continue
            if port == 0 or set(h) <= {"0"}:
                continue
            ip = _hex_ip6(h) if v6 else _hex_ip4(h)
            if fn.startswith("tcp"):
                if (ip, port) not in seen:
                    seen.add((ip, port))
                    tcp.append((ip, port))
            else:
                udp += 1
    return tcp, udp


def session_conns(s: dict) -> tuple[list[tuple[str, int]], int]:
    pid = s.get("app_pid")
    if not isinstance(pid, int):
        return [], 0
    tcp, udp = conn_stats(pid)
    srv_ip = (s.get("server") or {}).get("ip")
    if srv_ip:
        tcp = [c for c in tcp if c[0] != srv_ip]
    return tcp, udp


def session_title(s: dict) -> str:
    srv = s.get("server") or {}
    return clean(f"{s.get('app') or '?'} · #{srv.get('index')} {srv.get('name') or ''}")


def kill_session(s: dict) -> bool:
    pid = s.get("app_pid")
    if not isinstance(pid, int) or not pathlib.Path(f"/proc/{pid}").exists():
        return True
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.time() + 8
    while time.time() < deadline:
        if not pathlib.Path(f"/proc/{pid}").exists():
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    time.sleep(0.4)
    return not pathlib.Path(f"/proc/{pid}").exists()


def start_app(app: dict, server: int | None = None, country: str = "") -> tuple[subprocess.Popen, pathlib.Path]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path = STATE_DIR / f"launch-{int(time.time())}-{os.getpid()}.log"
    cmd = [sys.executable, "-m", "vpntui.runvpn"]
    if server is not None:
        cmd += ["-s", str(server)]
    if country:
        cmd += ["-c", country]
    cmd += ["--"] + list(app["cmd"])
    env = os.environ.copy()
    env.pop("SUDO_ASKPASS", None)
    for k, v in (app.get("env") or {}).items():
        if isinstance(k, str) and isinstance(v, str):
            env[k] = v
    if app.get("name"):
        env["VPN_APP_NAME"] = str(app.get("name"))
    logf = open(log_path, "w")
    p = subprocess.Popen(cmd, cwd=str(HOME), stdin=subprocess.DEVNULL,
                         stdout=logf, stderr=logf, env=env,
                         start_new_session=True)
    return p, log_path


def tail(path, n: int = 40) -> str:
    try:
        lines = pathlib.Path(path).read_text(errors="replace").strip().splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return ""


def net_bytes() -> tuple[int, int]:
    """Суммарный трафик всех активных VPN-сессий (по namespace, без дублей)."""
    rx = tx = 0
    seen = set()
    for s in read_sessions():
        ns = s.get("ns") or str(s.get("app_pid"))
        if ns in seen:
            continue
        seen.add(ns)
        pid = s.get("app_pid")
        try:
            lines = pathlib.Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
        except OSError:
            continue
        for ln in lines:
            if ":" not in ln:
                continue
            parts = ln.split(":", 1)[1].split()
            if len(parts) < 9:
                continue
            rx += int(parts[0])
            tx += int(parts[8])
    return rx, tx


# ---------------------------------------------------------------- автозапуск

def auto_vpn_apps() -> list[dict]:
    return [a for a in app_rules.load_apps() if a.get("always_vpn")]


def autostart_enabled() -> bool:
    return AUTOSTART.exists()


def terminal_command() -> str:
    executable = shlex.join(P.entry_command())
    if shutil.which("foot"):
        return f"foot -W 140x42 -T VPN -e {executable}"
    if shutil.which("kitty"):
        return f"kitty --title VPN {executable}"
    if shutil.which("alacritty"):
        return f"alacritty -t VPN -e {executable}"
    if shutil.which("gnome-terminal"):
        return f"gnome-terminal --title=VPN -- {executable}"
    if shutil.which("konsole"):
        return f"konsole -p tabtitle=VPN -e {executable}"
    return executable


def set_autostart(enabled: bool) -> bool:
    if enabled:
        AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
        AUTOSTART.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=VPN (vpntui)\n"
            "Comment=Панель VPN при входе в систему\n"
            f"Exec={terminal_command()}\n"
            "Icon=network-vpn\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n"
        )
    else:
        try:
            AUTOSTART.unlink()
        except OSError:
            pass
    return True


# ---------------------------------------------------------------- снимок

_SNAP = {"t": 0.0, "d": None}


def snapshot(force: bool = False) -> dict:
    if not force and _SNAP["d"] is not None and time.monotonic() - _SNAP["t"] < 2.5:
        return _SNAP["d"]
    st = state()
    servers = load_servers()
    sessions = read_sessions()
    rd = rules_data()
    active = is_active()
    data = {
        "state": st,
        "mode": str(st.get("mode") or "proxy"),
        "index": server_index(),
        "servers": servers,
        "sessions": sessions,
        "rules": rd,
        "active": active,
        "mono": service_mono() if active else 0.0,
        "country": settings().get("require_country") or "",
        "auto_apps": auto_vpn_apps(),
    }
    _SNAP.update(t=time.monotonic(), d=data)
    return data


def current_server(servers: list[dict]) -> dict | None:
    i = server_index()
    return servers[i] if 0 <= i < len(servers) else None


def server_text(servers: list[dict]) -> str:
    s = current_server(servers)
    if not s:
        return "сервер не выбран"
    return f"#{s['index']} {s['label']} — {s['host']} [{s['protocol']}]"


# ---------------------------------------------------------------- тема

KOALA = Theme(
    name="koala",
    primary=C_OK,
    secondary=C_BLUE,
    accent=C_OK,
    warning=C_WARN,
    error=C_BAD,
    success=C_OK,
    foreground="#d7e0ea",
    background="#0c1117",
    surface="#121821",
    panel="#18202b",
    boost="#1d2733",
    dark=True,
    variables={"border": "#263140"},
)


# ---------------------------------------------------------------- виджеты TUI

class NavItem(Static):
    can_focus = True
    BINDINGS = [("enter", "activate", "Открыть")]

    def action_activate(self) -> None:
        self.app.show_view(self.key)

    def __init__(self, key: str, label: str, **kw) -> None:
        self.key = key
        self.label = label
        super().__init__(f"  {label}", **kw)

    def set_active(self, active: bool) -> None:
        self.set_class(active, "active")
        self.update(f"{'▌ ' if active else '  '}{self.label}")

    def on_click(self, event) -> None:
        self.app.show_view(self.key)


class QuickRow(Static):
    can_focus = True
    BINDINGS = [("enter", "activate", "Применить")]

    def on_click(self, event) -> None:
        self.action_activate()

    def action_activate(self) -> None:
        app = self.app
        if self.id == "quick-mode":
            app.cycle_mode()
        elif self.id == "quick-xray":
            app.toggle_global()
        elif self.id == "quit":
            app.exit()


class ActionRow(Static):
    can_focus = True
    BINDINGS = [("enter", "activate", "Выполнить")]

    def action_activate(self) -> None:
        getattr(self.app, self._handler)()

    def __init__(self, handler: str, *content, **kw) -> None:
        self._handler = handler
        super().__init__(*content, **kw)

    def on_click(self, event) -> None:
        fn = getattr(self.app, self._handler, None)
        if callable(fn):
            fn()


class OptionRow(Static):
    """«Метка  ◀ значение ▸» — цикл по вариантам: ←/→, клик, Enter."""

    can_focus = True
    BINDINGS = [
        ("left", "prev", "назад"),
        ("right", "next", "вперёд"),
        ("enter", "confirm", "применить"),
    ]

    class Changed(Message):
        def __init__(self, row: "OptionRow") -> None:
            self.row = row
            super().__init__()

        @property
        def control(self) -> "OptionRow":
            return self.row

    class Confirmed(Message):
        def __init__(self, row: "OptionRow") -> None:
            self.row = row
            super().__init__()

        @property
        def control(self) -> "OptionRow":
            return self.row

    def __init__(self, label: str, options, value=None, **kw) -> None:
        self.row_label = label
        self._opts = [(str(d), v) for d, v in options]
        if value is None and self._opts:
            value = self._opts[0][1]
        self._value = value
        super().__init__(**kw)

    @property
    def value(self):
        return self._value

    def _display(self):
        for d, v in self._opts:
            if v == self._value:
                return d
        return "—"

    def _redraw(self) -> None:
        width = self.content_size.width or 80
        label = fit(self.row_label, max(1, width // 2 - 4))
        value = fit(self._display(), max(1, width - len(label) - 6))
        self.update(f"{escape(label)}  [dim]◀[/] [bold]{escape(value)}[/] [dim]▶[/]")

    def on_resize(self) -> None:
        self._redraw()

    def on_mount(self) -> None:
        self._redraw()

    def set_options(self, options, value=None) -> None:
        self._opts = [(str(d), v) for d, v in options]
        if value is not None:
            self._value = value
        elif self._value not in [v for _, v in self._opts]:
            self._value = self._opts[0][1] if self._opts else None
        self._redraw()

    def set_value(self, value) -> None:
        self._value = value
        self._redraw()

    def _set(self, value) -> None:
        if value == self._value:
            return
        self._value = value
        self._redraw()
        self.post_message(self.Changed(self))

    def action_prev(self) -> None:
        if not self._opts:
            return
        vals = [v for _, v in self._opts]
        try:
            i = vals.index(self._value)
        except ValueError:
            i = 0
        self._set(vals[(i - 1) % len(vals)])

    def action_next(self) -> None:
        if not self._opts:
            return
        vals = [v for _, v in self._opts]
        try:
            i = vals.index(self._value)
        except ValueError:
            i = -1
        self._set(vals[(i + 1) % len(vals)])

    def action_confirm(self) -> None:
        self.post_message(self.Confirmed(self))

    def on_click(self, event) -> None:
        self.action_next()


class ToggleRow(Static):
    """«Метка  ● вкл / ○ выкл» — тумблер: клик, Enter, пробел."""

    can_focus = True
    BINDINGS = [
        ("enter", "toggle", "переключить"),
        ("space", "toggle", "переключить"),
    ]

    class Toggled(Message):
        def __init__(self, row: "ToggleRow", value: bool) -> None:
            self.row = row
            self.value = value
            super().__init__()

        @property
        def control(self) -> "ToggleRow":
            return self.row

    def __init__(self, label: str, value: bool = False, **kw) -> None:
        self.row_label = label
        self._value = bool(value)
        super().__init__(**kw)

    @property
    def value(self) -> bool:
        return self._value

    def _redraw(self) -> None:
        label = escape(fit(self.row_label, max(1, (self.content_size.width or 80) - 8)))
        if self._value:
            self.update(f"{label}  [bold {C_OK}]● вкл[/]")
        else:
            self.update(f"{label}  [dim]○ выкл[/]")

    def on_resize(self) -> None:
        self._redraw()

    def set_value(self, value: bool) -> None:
        self._value = bool(value)
        self._redraw()

    def on_mount(self) -> None:
        self._redraw()

    def action_toggle(self) -> None:
        self._value = not self._value
        self._redraw()
        self.post_message(self.Toggled(self, self._value))

    def on_click(self, event) -> None:
        self.action_toggle()


class DashToggle(Static):
    """Большая кнопка включения/выключения глобального xray."""

    can_focus = True
    BINDINGS = [
        ("enter", "toggle", "переключить"),
        ("space", "toggle", "переключить"),
    ]

    def on_click(self, event) -> None:
        self.app.toggle_global()

    def action_toggle(self) -> None:
        self.app.toggle_global()


# ---------------------------------------------------------------- CSS

CSS = """
Screen { background: $background; }

#root { height: 1fr; }

#sidebar {
    width: 18;
    background: $surface;
    border-right: solid $border;
    padding: 0 1;
}

#brand { height: 2; color: $text; }

NavItem { width: 100%; height: 1; color: $text-muted; }
NavItem:hover, NavItem:focus { background: $boost; color: $text; }
NavItem.active { background: $boost; color: $accent; text-style: bold; }
NavItem:focus { background: $accent; color: $background; text-style: bold; }

#sidebar-gap { height: 1fr; }

QuickRow { width: 100%; height: 1; color: $text-muted; }
QuickRow:hover, QuickRow:focus { background: $boost; color: $text; }
ActionRow { height: auto; }
ActionRow:hover, ActionRow:focus { background: $boost; color: $accent; }
#quit:hover { color: $error; }

#main { width: 1fr; height: 1fr; }

#page-title {
    height: 1;
    padding: 0 1;
    background: $panel;
    color: $text-muted;
}

#views { height: 1fr; }
.view { height: 1fr; padding: 0 1; }
.hidden { display: none; }

#statusbar {
    height: 1;
    padding: 0 1;
    background: $panel;
    color: $text-muted;
}

.card {
    background: $panel;
    border: round $border;
    padding: 0 1;
    margin-bottom: 1;
    height: auto;
}

.hintbar { height: 1; color: $text-muted; margin-top: 1; }
.dim { color: $text-muted; }
.bar-row { height: 1; margin-top: 1; }
.grow { width: 1fr; }

#dash-stats { height: 3; margin-bottom: 1; }
.stat {
    width: 1fr;
    height: 3;
    background: $panel;
    border: round $border;
    margin-right: 1;
    content-align: center middle;
}

#dash-hero {
    height: 4;
    border: round $success;
    content-align: center middle;
    margin-bottom: 1;
    background: $panel;
}
#dash-hero.off { border: round $error; }

#dash-toggle {
    height: 3;
    border: round $success;
    color: $success;
    text-style: bold;
    content-align: center middle;
    margin-bottom: 1;
}
#dash-toggle.off { border: round $error; color: $error; }
#dash-toggle:hover, #dash-toggle:focus { background: $boost; }

.action:hover { background: $boost; }
#dash-server { height: 2; padding: 0 1; margin-bottom: 1; }
#dash-server:hover { background: $boost; }

DataTable { height: 1fr; background: $surface; border: round $border; scrollbar-gutter: stable; }

Input {
    height: 1;
    border: none;
    background: $panel;
    padding: 0 1;
}
Input:focus { background: $boost; border-left: tall $accent; }

OptionRow { height: 1; padding: 0 1; }
OptionRow:hover { background: $boost; }
OptionRow:focus { background: $boost; border-left: tall $accent; }

ToggleRow { height: 1; padding: 0 1; }
ToggleRow:hover { background: $boost; }
ToggleRow:focus { background: $boost; border-left: tall $accent; }

RichLog { height: 1fr; background: $surface; border: round $border; }

.detail { height: 7; }
#settings-scroll { height: 1fr; }
#proxy-hint { margin-top: 1; }
"""


# ---------------------------------------------------------------- Главная

class DashboardView(VerticalScroll):
    def compose(self) -> ComposeResult:
        yield Static(id="dash-profile", classes="card")
        with Horizontal(id="dash-stats"):
            yield Static(id="stat-servers", classes="stat")
            yield Static(id="stat-sessions", classes="stat")
            yield Static(id="stat-rules", classes="stat")
        yield Static(id="dash-hero")
        yield DashToggle(id="dash-toggle")
        yield ActionRow("goto_proxies", id="dash-server")
        yield Static(id="dash-sessions", classes="card")
        with Vertical(classes="card"):
            yield Static(id="apps-state")
            yield ActionRow("goto_apps", "  ▸ настроить в «Приложениях»",
                            id="apps-goto")

    def on_mount(self) -> None:
        self.update_view(self.app.snap)

    def update_view(self, snap: dict) -> None:
        servers = snap["servers"]
        sessions = snap["sessions"]
        rules = snap["rules"].get("rules") or []
        active = snap["active"]
        mode = snap["mode"]

        srv = current_server(servers)
        self.query_one("#dash-profile", Static).update(
            "◈ [bold]nosok-top[/]  [dim]· per-app профиль[/]\n"
            f"[dim]{len(servers)} серверов · {len(rules)} правил · "
            f"страна выхода: {COUNTRIES.get(snap['country'], snap['country']) or 'любая'}[/]")

        self.query_one("#stat-servers", Static).update(
            f"[bold]{len(servers)}[/] [dim]узлов[/]")
        self.query_one("#stat-sessions", Static).update(
            f"[bold]{len(sessions)}[/] [dim]сессий[/]")
        self.query_one("#stat-rules", Static).update(
            f"[bold]{len(rules)}[/] [dim]правил[/]")

        hero = self.query_one("#dash-hero", Static)
        hero.set_class(not active, "off")
        if active:
            hero.update(f"[bold {C_OK}]●  ПОДКЛЮЧЕНО[/]\n"
                        f"[dim]глобальный xray активен[/]")
        else:
            hero.update(f"[bold {C_BAD}]○  ОТКЛЮЧЕНО[/]\n"
                        f"[dim]глобальный xray выключен[/]")

        up = 0.0
        if active and snap["mono"]:
            up = max(0.0, host_uptime() - snap["mono"])
        rx, tx = net_bytes()
        self._speed = getattr(self, "_speed", None)
        now = time.monotonic()
        speed_txt = "↑ —  ↓ —"
        if self._speed:
            pt, prx, ptx = self._speed
            dt = max(0.001, now - pt)
            speed_txt = (f"↑ {fmt_bytes(max(0, tx - ptx) / dt)}/s  "
                         f"↓ {fmt_bytes(max(0, rx - prx) / dt)}/s")
        self._speed = (now, rx, tx)

        toggle = self.query_one("#dash-toggle", DashToggle)
        toggle.set_class(active, "off")
        toggle.update("[bold]ОТКЛЮЧИТЬ[/]" if active else "[bold]ПОДКЛЮЧИТЬ[/]")

        self.query_one("#dash-server", ActionRow).update(
            f"Сервер  ▸  [bold]{escape(srv['label']) if srv else 'не выбран'}[/]"
            f"  [dim]{srv['host'] if srv else ''} · {srv['protocol'] if srv else ''}[/]\n"
            f"[dim]  режим: {'TUN / VPN' if mode == 'vpn' else 'системный прокси'} · "
            f"время: {fmt_dur(up) if active else '—'} · {speed_txt}  ▸ сменить[/]")

        if sessions:
            lines = ["[bold]Активные VPN-сессии[/]"]
            for s in sessions[:5]:
                tcp, udp = session_conns(s)
                up_s = fmt_dur(time.time() - (s.get("started") or time.time()))
                lines.append(
                    f"  • [bold]{clean(str(s.get('app') or '?'))}[/] · {up_s} · "
                    f"TCP {len(tcp)} · UDP {udp} · "
                    f"{s.get('exit_ip') or '—'} ({s.get('country') or '?'})")
            if len(sessions) > 5:
                lines.append(f"  … ещё {len(sessions) - 5}")
            self.query_one("#dash-sessions", Static).update("\n".join(lines))
        else:
            self.query_one("#dash-sessions", Static).update(
                "[bold]Активные VPN-сессии[/]\n"
                "[dim]Нет. Запусти приложение во вкладке «Подключения» (4).[/]")

        auto = snap.get("auto_apps") or []
        box = self.query_one("#apps-state", Static)
        if auto:
            names = ", ".join(str(a.get("name") or a["id"]) for a in auto[:4])
            more = f" и ещё {len(auto) - 4}" if len(auto) > 4 else ""
            box.update(f"[bold]Приложения через VPN[/]  "
                       f"[bold {C_OK}]● {len(auto)}[/]\n"
                       f"[dim]  {names}{more} · ярлыки запускаются в своей сети[/]")
        else:
            box.update("[bold]Приложения через VPN[/]  [dim]○ нет[/]\n"
                       "[dim]  включи правило для любой установленной программы[/]")


# ---------------------------------------------------------------- Профили

class ProfilesView(VerticalScroll):
    def compose(self) -> ComposeResult:
        yield Static(id="profile-card", classes="card")
        yield ActionRow("prof_reload", "▸ Перечитать конфиги  [r]", id="prof-reload")
        yield ActionRow("prof_check", "▸ Проверить серверы (пинг)", id="prof-check")
        yield ActionRow("prof_open", "▸ Открыть папку конфигов", id="prof-open")
        yield Static(id="profile-details", classes="card")

    def on_mount(self) -> None:
        self.update_view(self.app.snap)

    def update_view(self, snap: dict) -> None:
        try:
            mt = SUBS.stat().st_mtime
        except OSError:
            mt = 0
        try:
            cm = CANDS.stat().st_mtime
        except OSError:
            cm = 0
        servers = snap["servers"]
        self.query_one("#profile-card", Static).update(
            "[bold]Основная подписка[/]\n"
            f"[dim]ID:[/] nosok-top  [dim]·[/] серверов: [bold]{len(servers)}[/]\n"
            f"[dim]Кандидаты обновлены {fmt_ago(cm)} · источник {fmt_ago(mt)}[/]")
        rules = snap["rules"].get("rules") or []
        groups: dict[str, int] = {}
        for s in servers:
            groups[s["tag"] or "—"] = groups.get(s["tag"] or "—", 0) + 1
        glines = [f"  • {k}: {v}" for k, v in sorted(groups.items())]
        self.query_one("#profile-details", Static).update(
            "[bold]Состав[/]\n"
            f"[dim]Правил маршрутизации:[/] {len(rules)}  [dim]·[/]  "
            f"[dim]по умолчанию:[/] {target_label(snap['rules'].get('default'), servers)}\n"
            + "\n".join(glines[:20])
            + (f"\n  … ещё {len(glines) - 20} групп" if len(glines) > 20 else "")
        )


# ---------------------------------------------------------------- Прокси

class ProxiesView(Vertical):
    def compose(self) -> ComposeResult:
        yield Input(placeholder="Поиск: страна, хост, протокол…  [/]",
                    id="proxy-search")
        yield DataTable(id="proxy-table")
        yield Static(id="proxy-hint", classes="hintbar")

    def on_mount(self) -> None:
        self.ping_map: dict[int, float | None] = {}
        self.selected = server_index()
        self._last_w = 0
        table = self.query_one("#proxy-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._setup_columns(table, 0)
        self.rebuild()
        self.query_one("#proxy-hint", Static).update(
            "[dim]Enter — выбрать сервер · [p] пинг всех · [/] поиск[/]")

    def on_resize(self, event: events.Resize) -> None:
        self.rebuild()

    def on_show(self) -> None:
        self.rebuild()

    def _setup_columns(self, t: DataTable, width: int) -> None:
        t.clear(columns=True)
        name_w = max(12, width - 15) if width else 30
        self._col_name = t.add_column("Сервер", key="name", width=name_w)
        self._col_ping = t.add_column("Пинг", key="ping", width=8)
        self._col_cur = t.add_column("", key="cur", width=1)

    def rebuild(self) -> None:
        snap = self.app.snap
        q = self.query_one("#proxy-search", Input).value.strip().lower()
        t = self.query_one("#proxy-table", DataTable)
        selected = (t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
                    if t.row_count else str(self.selected))
        w = t.scrollable_content_region.width
        if w and w != self._last_w:
            self._last_w = w
            self._setup_columns(t, w)
        t.clear()
        cur = snap["index"]
        name_w = max(12, (self._last_w or 30) - 15)
        for s in snap["servers"]:
            hay = f"{s['label']} {s['host']} {s['protocol']} {s['tag']}".lower()
            if q and q not in hay:
                continue
            ping = self.ping_map.get(s["index"])
            if s["index"] not in self.ping_map:
                p = "[dim]—[/]"
            elif ping is None or ping < 0:
                p = f"[{C_BAD}]таймаут[/]"
            elif ping < 150:
                p = f"[{C_OK}]{int(ping)} ms[/]"
            elif ping < 350:
                p = f"[{C_WARN}]{int(ping)} ms[/]"
            else:
                p = f"[{C_BAD}]{int(ping)} ms[/]"
            t.add_row(
                Text(fit(f"{s['index']}  {s['label']}", name_w)), p,
                f"[{C_OK}]●[/]" if s["index"] == cur else "",
                key=str(s["index"]),
            )
        if selected in t.rows:
            t.move_cursor(row=t.get_row_index(selected))

    def _apply_index(self, idx: int) -> None:
        self.app.run_worker(self._apply_worker(idx), thread=True, group="server")

    def _apply_worker(self, idx: int):
        def run():
            ok = True
            if is_active():
                result = manager("set-server", str(idx))
                ok = result.returncode == 0 and result.stdout.strip() == "OK" and is_active()
            else:
                st = state()
                st["server_index"] = idx
                save_json(STATE, st)
            self.app.call_from_thread(self.app.refresh_all, True)
            self.app.call_from_thread(
                self.app.notify, f"Сервер #{idx} выбран" if ok else "Не удалось сменить сервер; смотри логи",
                severity="information" if ok else "error")
        return run

    def set_ping(self, idx: int, ms: float | None) -> None:
        self.ping_map[idx] = ms
        try:
            t = self.query_one("#proxy-table", DataTable)
            if ms is None:
                val = f"[{C_BAD}]таймаут[/]"
            elif ms < 150:
                val = f"[{C_OK}]{int(ms)} ms[/]"
            elif ms < 350:
                val = f"[{C_WARN}]{int(ms)} ms[/]"
            else:
                val = f"[{C_BAD}]{int(ms)} ms[/]"
            t.update_cell(str(idx), self._col_ping, val)
        except Exception:
            pass

    @work(thread=True, exclusive=True, group="ping")
    def ping_all(self) -> None:
        servers = list(self.app.snap["servers"])
        self.app.call_from_thread(self.app.notify, "Пингую серверы…")

        def one(s: dict) -> float | None:
            try:
                t0 = time.perf_counter()
                sock = socket.create_connection((s["hostname"], s["port"]), timeout=2.0)
                sock.close()
                return (time.perf_counter() - t0) * 1000
            except Exception:
                return None

        with cf.ThreadPoolExecutor(max_workers=24) as ex:
            for s, ms in zip(servers, ex.map(one, servers)):
                self.app.call_from_thread(self.set_ping, s["index"], ms)
        self.app.call_from_thread(self.app.notify, "Пинг завершён")


# ---------------------------------------------------------------- Приложения

class AppsView(Vertical):
    """Installed applications and their always-VPN rules."""

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Фильтр по названию или команде…", id="apps-filter")
        yield DataTable(id="apps-table")
        yield Static(
            "Enter — всегда через VPN · s — сервер · l — запустить · d — убрать",
            markup=False, classes="hintbar")
        yield Static(id="apps-summary")

    def on_mount(self) -> None:
        table = self.query_one("#apps-table", DataTable)
        table.add_column("Приложение", key="name")
        table.add_column("VPN", key="vpn", width=3)
        table.add_column("Сервер", key="server", width=9)
        table.cursor_type = "row"
        self.rebuild()

    def on_show(self) -> None:
        self.rebuild()

    def _entries(self) -> list[dict]:
        configured = app_rules.load_apps()
        by_id = {a["id"]: a for a in configured}
        by_desktop = {str(a.get("desktop")): a for a in configured if a.get("desktop")}
        rows, used = [], set()
        for info in app_rules.discover_installed():
            entry = by_id.get(info["id"]) or by_desktop.get(str(info["desktop"]))
            if entry:
                used.add(entry["id"])
                rows.append({**info, **entry})
            else:
                rows.append(dict(info))
        for entry in configured:
            if entry["id"] not in used:
                rows.append(dict(entry))
        return sorted(rows, key=lambda a: str(a.get("name") or a["id"]).lower())

    def rebuild(self) -> None:
        table = self.query_one("#apps-table", DataTable)
        query = self.query_one("#apps-filter", Input).value.strip().lower()
        selected = (table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
                    if table.row_count else None)
        table.clear()
        count = auto = 0
        width = max(18, (table.scrollable_content_region.width or 78) - 18)
        for entry in self._entries():
            haystack = f"{entry.get('name','')} {' '.join(entry.get('cmd') or [])}".lower()
            if query and query not in haystack:
                continue
            count += 1
            enabled = bool(entry.get("always_vpn"))
            auto += int(enabled)
            server = entry.get("server", "auto")
            server_txt = "Авто" if server in (None, "", "auto") else f"#{server}"
            table.add_row(
                Text(fit(clean(str(entry.get("name") or entry["id"])), width)),
                f"[{C_OK}]●[/]" if enabled else "[dim]○[/]",
                server_txt, key=entry["id"])
        if selected in table.rows:
            table.move_cursor(row=table.get_row_index(selected))
        self.query_one("#apps-summary", Static).update(
            f"[bold]Установлено: {count}[/]  [dim]· через VPN: {auto} · "
            f"стрелка + Enter переключает правило[/]")

    @on(DataTable.RowSelected, "#apps-table")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        self.toggle()

    @on(Input.Changed, "#apps-filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self.rebuild()

    def selected(self) -> dict | None:
        table = self.query_one("#apps-table", DataTable)
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return next((e for e in self._entries() if e["id"] == key), None)

    def toggle(self) -> None:
        entry = self.selected()
        if not entry:
            self.app.notify("Нет приложений", severity="warning")
            return
        enabled = not bool(entry.get("always_vpn"))
        try:
            entry = app_rules.enable_always(entry, enabled)
        except (app_rules.DesktopError, OSError) as exc:
            self.app.notify(f"{entry.get('name') or entry['id']}: {exc}", severity="error")
            return
        self.app.refresh_all(True)
        self.rebuild()
        self.app.notify(f"{entry.get('name') or entry['id']}: "
                        + ("всегда через VPN" if enabled else "обычный запуск"))

    def cycle_server(self) -> None:
        entry = self.selected()
        if not entry:
            return
        values = ["auto"] + [i for i in range(len(self.app.snap.get("servers") or []))]
        current = entry.get("server", "auto")
        try:
            pos = values.index(current)
        except ValueError:
            pos = 0
        entry["server"] = values[(pos + 1) % len(values)]
        app_rules.add_app(entry)
        self.rebuild()
        self.app.notify(f"{entry.get('name') or entry['id']}: сервер "
                        + ("Авто" if entry["server"] == "auto" else f"#{entry['server']}"))

    def remove(self) -> None:
        entry = self.selected()
        if not entry:
            return
        if entry["id"] not in {a["id"] for a in app_rules.load_apps()}:
            self.app.notify("Это приложение ещё не добавлено", severity="warning")
            return
        app_rules.remove_app(entry["id"])
        self.app.refresh_all(True)
        self.rebuild()
        self.app.notify(f"{entry.get('name') or entry['id']}: правило убрано")

    def launch(self) -> None:
        entry = self.selected()
        if not entry:
            return
        self.app.notify(f"Запускаю «{entry.get('name')}» через VPN…")
        self.app.run_worker(self._launch_worker(entry), thread=True, group="launch")

    def _launch_worker(self, entry: dict):
        def run():
            code = app_rules.run_entry(entry)
            self.app.call_from_thread(
                self.app.notify,
                f"{entry.get('name')}: запущено" if code == 0 else
                f"{entry.get('name')}: ошибка запуска ({code})",
                severity="information" if code == 0 else "error")
        return run


# ---------------------------------------------------------------- Подключения

class ConnectionsView(Vertical):
    def compose(self) -> ComposeResult:
        yield Static(id="conn-summary", classes="hintbar")
        yield DataTable(id="conn-table")
        with VerticalScroll(id="conn-detail", classes="card detail"):
            yield Static(id="conn-detail-text")
        yield OptionRow("Запустить", [], id="conn-app")
        yield Input(placeholder="Своя команда через VPN… Enter — запуск",
                    id="conn-cmd")

    def on_mount(self) -> None:
        self.selected_file: str | None = None
        t = self.query_one("#conn-table", DataTable)
        t.cursor_type = "row"
        t.zebra_stripes = True
        self._last_w = 0
        self._setup_columns(t, 0)
        row = self.query_one("#conn-app", OptionRow)
        row.set_options([(a.get("name") or a["id"], a["id"]) for a in load_apps()])
        self.refresh_view()

    def on_resize(self, event: events.Resize) -> None:
        self.refresh_view()

    def on_show(self) -> None:
        self.refresh_view()

    def _setup_columns(self, t: DataTable, width: int) -> None:
        t.clear(columns=True)
        self._app_w = 10 if width < 48 else 13
        self._srv_w = max(1, width - self._app_w - 19) if width else 18
        self._col_app = t.add_column("Приложение", key="app", width=self._app_w)
        self._col_srv = t.add_column("Сервер", key="srv", width=self._srv_w)
        self._col_up = t.add_column("Аптайм", key="up", width=8)
        self._col_tcp = t.add_column("TCP", key="tcp", width=3)

    def refresh_view(self, force: bool = False) -> None:
        snap = self.app.snap if not force else snapshot(force=True)
        sessions = snap["sessions"]
        t = self.query_one("#conn-table", DataTable)
        selected = (t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
                    if t.row_count else self.selected_file)
        w = t.scrollable_content_region.width
        if w and w != self._last_w:
            self._last_w = w
            self._setup_columns(t, w)
        t.clear()
        self._sessions = {s["_file"]: s for s in sessions}
        for s in sessions:
            tcp, udp = session_conns(s)
            up = fmt_dur(time.time() - (s.get("started") or time.time()))
            srv = s.get("server") or {}
            t.add_row(
                fit(clean(str(s.get("app") or "?")), self._app_w),
                fit(f"#{srv.get('index')} {clean(str(srv.get('name') or ''))}", self._srv_w),
                up, str(len(tcp)),
                key=s["_file"],
            )
        self.query_one("#conn-summary", Static).update(
            f"[bold]Сессий: {len(sessions)}[/]  [dim]· стрелки — детали сессии[/]")
        self.selected_file = selected if selected in self._sessions else None
        if self.selected_file is not None:
            t.move_cursor(row=t.get_row_index(self.selected_file))
            self.show_detail(self._sessions[self.selected_file])
        else:
            self.query_one("#conn-detail-text", Static).update(
                "[dim]Выбери сессию, чтобы увидеть её соединения.[/]")

    def show_detail(self, s: dict) -> None:
        tcp, udp = session_conns(s)
        srv = s.get("server") or {}
        started = s.get("started") or 0
        lines = [
            f"[bold]{clean(str(s.get('app') or '?'))}[/]  ·  "
            f"PID {s.get('app_pid')}  ·  namespace {s.get('ns')}",
            f"Сервер: #{srv.get('index')} {clean(str(srv.get('name') or ''))} — "
            f"{srv.get('host')}:{srv.get('port')} [{srv.get('protocol')}]",
            f"Запущено: {time.strftime('%d.%m %H:%M', time.localtime(started))} "
            f"({fmt_dur(time.time() - started)})  ·  "
            f"IP выхода: {s.get('exit_ip') or '—'} ({s.get('country') or '?'})",
            f"TCP: {len(tcp)}  ·  UDP: {udp}  ·  лог: {s.get('log')}",
        ]
        for ip, port in tcp[:8]:
            lines.append(f"  • {ip}:{port}")
        if len(tcp) > 8:
            lines.append(f"  … ещё {len(tcp) - 8}")
        self.query_one("#conn-detail-text", Static).update("\n".join(lines))

    def _launch(self, app: dict, server: int | None = None) -> None:
        country = settings().get("require_country") or ""
        self.app.notify(f"Запускаю «{app.get('name')}» через VPN…")
        self.app.run_worker(
            self._launch_worker(app, server, country), thread=True, group="launch")

    def _launch_worker(self, app: dict, server: int | None, country: str):
        def run():
            before = {s["_file"] for s in read_sessions()}
            p, log_path = start_app(app, server, country)
            deadline = time.time() + 65
            while time.time() < deadline:
                for s in read_sessions():
                    if s["_file"] not in before and (
                            s.get("exit_ip") or s.get("state") == "running"):
                        srv = s.get("server") or {}
                        self.app.call_from_thread(
                            self.app.notify,
                            f"{app.get('name')}: {s.get('exit_ip') or '—'} "
                            f"({s.get('country') or '?'}), "
                            f"сервер #{srv.get('index')}",
                            severity="information")
                        self.app.call_from_thread(self.app.refresh_all, True)
                        return
                if p.poll() is not None:
                    err = tail(log_path, 12) or "run-vpn завершился с ошибкой"
                    self.app.call_from_thread(
                        self.app.notify, f"{app.get('name')}: {err}",
                        severity="error", timeout=12)
                    return
                time.sleep(0.8)
            self.app.call_from_thread(
                self.app.notify,
                f"{app.get('name')}: подключение дольше обычного, смотри «Логи»",
                severity="warning", timeout=10)
        return run

    def _kill(self) -> None:
        if not self.selected_file or self.selected_file not in getattr(self, "_sessions", {}):
            self.app.notify("Сначала выбери сессию", severity="warning")
            return
        s = self._sessions[self.selected_file]
        self.app.run_worker(self._kill_worker(s), thread=True, group="kill")

    def _kill_worker(self, s: dict):
        def run():
            ok = kill_session(s)
            self.app.call_from_thread(
                self.app.notify,
                "Сессия завершена" if ok else "Процесс не завершился",
                severity="information" if ok else "error")
            self.app.call_from_thread(self.app.refresh_all, True)
        return run


# ---------------------------------------------------------------- Правила

class RulesView(Vertical):
    def compose(self) -> ComposeResult:
        yield Input(placeholder="Фильтр по домену, типу, цели…", id="rules-filter")
        yield DataTable(id="rules-table")
        yield OptionRow("Тип", RULE_TYPES, "DOMAIN-SUFFIX", id="rules-type")
        yield OptionRow("Цель", [], "proxy", id="rules-target")
        yield Input(placeholder="Домен (Enter — добавить)", id="rules-value")
        yield OptionRow("Умолч.", [], "proxy", id="rules-default")
        yield Static("a:+ d:− [ ]:порядок s:умолч.", markup=False, classes="hintbar")

    def on_mount(self) -> None:
        self.selected_row: int | None = None
        t = self.query_one("#rules-table", DataTable)
        t.cursor_type = "row"
        t.zebra_stripes = True
        self._last_w = 0
        self._setup_columns(t, 0)
        self._fill_targets()
        self.query_one("#rules-default", OptionRow).set_value(
            self.app.snap["rules"].get("default", "proxy"))
        self.rebuild()

    def on_resize(self, event: events.Resize) -> None:
        self.rebuild()

    def on_show(self) -> None:
        self._fill_targets()
        self.rebuild()

    def _setup_columns(self, t: DataTable, width: int) -> None:
        t.clear(columns=True)
        self._type_w = 7 if width < 48 else 14
        self._val_w = max(1, width - self._type_w - 17) if width else 16
        self._col_num = t.add_column("№", key="num", width=3)
        self._col_type = t.add_column("Тип", key="type", width=self._type_w)
        self._col_val = t.add_column("Значение", key="val", width=self._val_w)
        self._col_tgt = t.add_column("Цель", key="tgt", width=6)

    def _fill_targets(self) -> None:
        servers = self.app.snap["servers"]
        opts = [("по умолчанию", "proxy"), ("DIRECT", "direct")]
        opts += [(fit(f"#{s['index']} {s['label']}", 24), f"srv:{s['index']}")
                 for s in servers]
        self.query_one("#rules-target", OptionRow).set_options(opts)
        dsel = self.query_one("#rules-default", OptionRow)
        cur = dsel.value
        dsel.set_options(opts)
        if cur is not None and cur in [v for _, v in opts]:
            dsel.set_value(cur)

    def rebuild(self, selected: str | None = None) -> None:
        snap = self.app.snap
        q = self.query_one("#rules-filter", Input).value.strip().lower()
        t = self.query_one("#rules-table", DataTable)
        if selected is None:
            selected = (t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
                        if t.row_count else str(self.selected_row))
        w = t.scrollable_content_region.width
        if w and w != self._last_w:
            self._last_w = w
            self._setup_columns(t, w)
        t.clear()
        rules = snap["rules"].get("rules") or []
        self._rules = rules
        for i, r in enumerate(rules):
            tl = target_short(str(r.get("target") or "proxy"))
            hay = f"{r.get('type')} {r.get('value')} {tl} {r.get('note') or ''}".lower()
            if q and q not in hay:
                continue
            t.add_row(
                str(i + 1),
                fit(str(r.get("type") or "").replace("DOMAIN-", "")
                    if self._type_w < 14 else str(r.get("type") or ""), self._type_w),
                fit(str(r.get("value") or ""), self._val_w),
                fit(tl, 6),
                key=str(i),
            )
        if selected in t.rows:
            t.move_cursor(row=t.get_row_index(selected))
        elif not t.row_count:
            self.selected_row = None

    def _save(self, d: dict) -> None:
        save_json(RULES, d)
        snapshot(force=True)
        self.app.refresh_all(True)
        self.app.notify("Правила сохранены для новых per-app сессий")

    def _add(self) -> None:
        value = self.query_one("#rules-value", Input).value.strip().strip(".").lower()
        if not value or any(ch.isspace() for ch in value):
            self.app.notify("Домен не должен быть пустым или содержать пробелы",
                            severity="warning")
            return
        d = rules_data()
        d["rules"].append({
            "type": self.query_one("#rules-type", OptionRow).value,
            "value": value,
            "target": self.query_one("#rules-target", OptionRow).value,
        })
        self.query_one("#rules-value", Input).value = ""
        self._save(d)
        self.rebuild()

    def _delete(self) -> None:
        if self.selected_row is None:
            self.app.notify("Сначала выбери правило", severity="warning")
            return
        d = rules_data()
        if 0 <= self.selected_row < len(d["rules"]):
            d["rules"].pop(self.selected_row)
            self._save(d)
            self.selected_row = None
            self.rebuild()

    def _move(self, delta: int) -> None:
        if self.selected_row is None:
            return
        d = rules_data()
        i = self.selected_row
        j = i + delta
        if not (0 <= i < len(d["rules"]) and 0 <= j < len(d["rules"])):
            return
        d["rules"][i], d["rules"][j] = d["rules"][j], d["rules"][i]
        self._save(d)
        self.selected_row = j
        self.rebuild(selected=str(j))


# ---------------------------------------------------------------- Логи

class LogsView(Vertical):
    SOURCES = [
        ("last.log", "last"),
        ("сессия", "session"),
        ("journal xray", "journal"),
    ]

    def compose(self) -> ComposeResult:
        yield OptionRow("Источник", self.SOURCES, "last", id="log-source")
        yield OptionRow("Сессия", [], None, id="log-session")
        yield Input(placeholder="Фильтр…", id="log-filter")
        with Horizontal(classes="bar-row"):
            yield ToggleRow("Прокрутка", True, id="log-auto", classes="grow")
            yield ActionRow("log_clear", "Очистить (c)", id="log-clear", classes="grow")
        yield RichLog(id="log-view", max_lines=3000, markup=False, wrap=True)

    def on_mount(self) -> None:
        self._pos = 0
        self._source = "last"
        self._jbuf: list[str] = []
        self._jproc: asyncio.subprocess.Process | None = None
        self._sess_opts: list[tuple[str, str]] = []
        self._no_file_written = False
        self.set_interval(1.5, self.maybe_refresh)
        self.refresh_source(reset=True)

    def on_unmount(self) -> None:
        self._stop_journal()

    def on_show(self) -> None:
        self.refresh_source(reset=True)

    def _sessions(self) -> list[dict]:
        return read_sessions()

    def _session_path(self) -> pathlib.Path | None:
        sel = self.query_one("#log-session", OptionRow)
        val = sel.value
        for s in self._sessions():
            if s["_file"] == val:
                return pathlib.Path(s.get("log") or "")
        return None

    def refresh_source(self, reset: bool = False) -> None:
        src = self.query_one("#log-source", OptionRow).value or "last"
        if reset or src != self._source:
            self._source = src
            self._pos = 0
            self._no_file_written = False
            log = self.query_one("#log-view", RichLog)
            log.clear()
            if src == "journal":
                self._start_journal()
            else:
                self._stop_journal()
        # сессии могли измениться
        sel = self.query_one("#log-session", OptionRow)
        sessions = self._sessions()
        opts = [(clean(str(s.get("app") or "?")), s["_file"]) for s in sessions]
        if opts != self._sess_opts:
            self._sess_opts = opts
            cur = sel.value
            sel.set_options(opts)
            if opts:
                sel.set_value(cur if cur in [v for _, v in opts] else opts[0][1])
        self._load_delta()

    # --- живой стрим journalctl

    def _start_journal(self) -> None:
        self._stop_journal()
        self._jbuf = []
        self._journal_worker()

    def _stop_journal(self) -> None:
        self.workers.cancel_group(self, "jstream")

    @work(exclusive=True, group="jstream")
    async def _journal_worker(self) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "journalctl", "--user", "-u", SERVICE, "-n", "250",
                "--no-pager", "-o", "short-iso", "-f",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except OSError as exc:
            self.app.notify(f"Не удалось открыть журнал: {exc}", severity="error")
            return
        self._jproc = proc
        try:
            while line := await proc.stdout.readline():
                self._push_journal(line.decode(errors="replace").rstrip("\n"))
        finally:
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), 2)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if self._jproc is proc:
                self._jproc = None

    def _push_journal(self, ln: str) -> None:
        self._jbuf.append(ln)
        if len(self._jbuf) > 3000:
            del self._jbuf[: len(self._jbuf) - 3000]
        q = self.query_one("#log-filter", Input).value.strip().lower()
        if not q or q in ln.lower():
            self.query_one("#log-view", RichLog).write(ln)

    def _render_journal_buf(self) -> None:
        q = self.query_one("#log-filter", Input).value.strip().lower()
        log = self.query_one("#log-view", RichLog)
        log.clear()
        for ln in self._jbuf:
            if not q or q in ln.lower():
                log.write(ln)

    # --- файловые источники

    def _load_delta(self) -> None:
        if self._source == "journal":
            return
        log = self.query_one("#log-view", RichLog)
        q = self.query_one("#log-filter", Input).value.strip().lower()
        path = LAST_LOG if self._source == "last" else self._session_path()
        if not path or not pathlib.Path(path).exists():
            if not self._no_file_written:
                log.write("[нет файла лога]")
                self._no_file_written = True
            return
        self._no_file_written = False
        p = pathlib.Path(path)
        try:
            size = p.stat().st_size
        except OSError:
            return
        if size < self._pos:
            self._pos = 0
        try:
            with p.open("r", errors="replace") as f:
                if self._pos == 0:
                    # при первом чтении показываем хвост
                    data = f.read()
                    start = max(0, len(data) - 12000)
                    for ln in data[start:].splitlines():
                        if not q or q in ln.lower():
                            log.write(ln)
                    self._pos = f.tell()
                    return
                f.seek(self._pos)
                data = f.read()
                self._pos = f.tell()
        except OSError:
            return
        for ln in data.splitlines():
            if not q or q in ln.lower():
                log.write(ln)

    def maybe_refresh(self) -> None:
        if not self.display:
            return
        if self._source == "journal":
            return
        self._load_delta()

    def clear_log(self) -> None:
        self.query_one("#log-view", RichLog).clear()
        if self._source == "journal":
            self._jbuf = []


# ---------------------------------------------------------------- Настройки

class SettingsView(VerticalScroll):
    def compose(self) -> ComposeResult:
        with Vertical(classes="card"):
            yield Static("[bold]Глобальный режим xray[/]")
            yield Static(
                "[dim]TUN/VPN заворачивает весь трафик хоста. Системный прокси "
                "даёт SOCKS/HTTP. Per-app сессии работают независимо. "
                "Enter — применить.[/]", classes="dim")
            yield OptionRow("Режим", [("Системный прокси", "proxy"),
                                      ("VPN / TUN", "vpn")],
                            "proxy", id="set-mode")

        with Vertical(classes="card"):
            yield Static("[bold]Приложения через VPN[/]")
            yield Static(
                "[dim]Правила «всегда через VPN» для установленных программ — "
                "в разделе «Приложения» (8). Qoder сохраняет свой прежний "
                "способ запуска.[/]", classes="dim")
            yield ActionRow("goto_apps", "▸ Открыть «Приложения»", id="set-apps")

        with Vertical(classes="card"):
            yield ToggleRow("Автозапуск панели при входе", False, id="set-autostart")
            yield OptionRow("Страна выхода",
                            [(v, k) for k, v in COUNTRIES.items()],
                            "", id="set-country")
            yield OptionRow("Тема", [], None, id="set-theme")

        with Vertical(classes="card"):
            yield ActionRow("restart_xray", "▸ Перезапустить xray", id="set-restart")
            yield ActionRow("goto_logs", "▸ Диагностика / логи", id="set-logs")
            yield ActionRow("exit_app", "▸ Выход", id="set-quit")

        yield Static(id="set-info", classes="card")

    def on_mount(self) -> None:
        snap = self.app.snap
        self.query_one("#set-mode", OptionRow).set_value(snap["mode"])
        self.query_one("#set-autostart", ToggleRow).set_value(autostart_enabled())
        self.query_one("#set-country", OptionRow).set_value(snap["country"])
        tsel = self.query_one("#set-theme", OptionRow)
        tsel.set_options([(t, t) for t in sorted(self.app.available_themes)])
        tsel.set_value(self.app.theme)
        self.update_info(snap)

    def on_show(self) -> None:
        self.update_info(self.app.snap)

    def update_info(self, snap: dict) -> None:
        svc = f"[{C_OK}]активен[/]" if snap["active"] else "[dim]остановлен[/]"
        self.query_one("#set-info", Static).update(
            f"[dim]vpntui {APP_VERSION} · Textual · xray per-app[/]\n"
            f"[dim]Конфиги:[/] {XDIR}\n"
            f"[dim]Сессии:[/] {SESS_DIR}\n"
            f"[dim]Сервис:[/] {svc}  [dim]· режим:[/] {snap['mode']}  "
            f"[dim]· сервер:[/] #{snap['index']}"
        )


# ---------------------------------------------------------------- приложение

class VpnTuiApp(App):
    TITLE = "vpntui"
    CSS = CSS
    BINDINGS = [
        Binding("up", "focus_vertical(-1)", "Выше", show=False, priority=True),
        Binding("down", "focus_vertical(1)", "Ниже", show=False, priority=True),
        Binding("left", "focus_sidebar", "Меню", show=False, priority=True),
        Binding("right", "enter_section", "В раздел", show=False, priority=True),
        ("escape", "leave_input", "Назад / меню"),
        ("q", "quit", "Выход"),
        ("r", "refresh", "Обновить"),
        ("1", "view('dashboard')", "Главная"),
        ("2", "view('profiles')", "Профили"),
        ("3", "view('proxies')", "Прокси"),
        ("4", "view('connections')", "Подключения"),
        ("5", "view('rules')", "Правила"),
        ("6", "view('logs')", "Логи"),
        ("7", "view('settings')", "Настройки"),
        ("8", "view('apps')", "Приложения"),
        ("/", "focus_search", "Поиск"),
        ("p", "ping_all", "Пинг всех"),
        ("k", "kill_session", "Завершить сессию"),
        ("a", "rule_add", "Добавить правило"),
        ("d", "rule_delete", "Удалить правило"),
        ("s", "rule_save", "Сохранить / сменить сервер"),
        ("l", "launch_app", "Запустить приложение"),
        ("[", "rule_move(-1)", "Правило выше"),
        ("]", "rule_move(1)", "Правило ниже"),
        ("c", "clear_log", "Очистить лог"),
    ]

    NAV = [
        ("dashboard", "Главная"),
        ("profiles", "Профили"),
        ("proxies", "Прокси"),
        ("connections", "Подключения"),
        ("rules", "Правила"),
        ("logs", "Логи"),
        ("settings", "Настройки"),
        ("apps", "Приложения"),
    ]

    HINTS = {
        "dashboard": "↑↓ — действие · Enter — выполнить · ← — меню",
        "profiles": "↑↓ — действие · Enter — выполнить · ← — меню",
        "proxies": "Enter — выбрать сервер · p — пинг всех · / — поиск",
        "connections": "Enter — запустить приложение · k — завершить сессию",
        "rules": "a — добавить · d — удалить · [ ] — порядок · s — сохранить",
        "logs": "c — очистить · фильтр — подстрока",
        "settings": "↑↓ — поле · ←→ — значение · Esc — меню",
        "apps": "Enter — всегда через VPN · s — сервер · l — запуск · d — убрать",
    }

    def __init__(self) -> None:
        super().__init__()
        P.ensure_layout()
        self.register_theme(KOALA)
        self.theme = "koala"
        self.snap = snapshot(force=True)
        self._tick = 0
        self.current = "dashboard"

    def compose(self) -> ComposeResult:
        with Horizontal(id="root"):
            with Vertical(id="sidebar"):
                yield Static("◈ [bold]vpntui[/]\n[dim]koala edition[/]", id="brand")
                for number, (key, label) in enumerate(self.NAV, 1):
                    yield NavItem(key, f"{number} {label}", id=f"nav-{key}")
                yield Static(id="sidebar-gap")
                yield QuickRow(id="quick-mode")
                yield QuickRow(id="quick-xray")
                yield QuickRow("Выход", id="quit")
            with Vertical(id="main"):
                yield Static("Главная", id="page-title")
                with Vertical(id="views"):
                    yield DashboardView(id="dashboard", classes="view")
                    yield ProfilesView(id="profiles", classes="view hidden")
                    yield ProxiesView(id="proxies", classes="view hidden")
                    yield ConnectionsView(id="connections", classes="view hidden")
                    yield RulesView(id="rules", classes="view hidden")
                    yield LogsView(id="logs", classes="view hidden")
                    yield SettingsView(id="settings", classes="view hidden")
                    yield AppsView(id="apps", classes="view hidden")
                yield Static(id="statusbar")

    def on_mount(self) -> None:
        self.set_interval(1.0, self.tick)
        self.show_view(os.environ.get("VPNTUI_VIEW") or "dashboard")
        self.refresh_all(True)

    # ---------- навигация

    def show_view(self, name: str) -> None:
        if name not in dict(self.NAV):
            return
        self.current = name
        for key, label in self.NAV:
            self.query_one(f"#{key}").set_class(key != name, "hidden")
            self.query_one(f"#nav-{key}", NavItem).set_active(key == name)
        self.query_one("#page-title", Static).update(
            f"[bold]{dict(self.NAV)[name]}[/]  [dim]·  {self.HINTS.get(name, '')}[/]")
        view = self.query_one(f"#{name}")
        on_show = getattr(view, "on_show", None)
        if callable(on_show):
            on_show()
        self.focus_section()
        self.refresh_statusbar()

    def focus_section(self) -> None:
        target = {
            "dashboard": "dash-toggle", "profiles": "prof-reload",
            "proxies": "proxy-table", "connections": "conn-app",
            "rules": "rules-table", "logs": "log-source", "settings": "set-mode",
            "apps": "apps-table",
        }[self.current]
        self.query_one(f"#{target}").focus()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action not in ("focus_vertical", "focus_sidebar", "enter_section"):
            return super().check_action(action, parameters)
        focused = self.focused
        if focused is None or not any(node.id == "root" for node in focused.ancestors):
            return False
        sidebar = isinstance(focused, (NavItem, QuickRow))
        if action == "focus_sidebar":
            return not sidebar and not isinstance(focused, (Input, OptionRow))
        if action == "enter_section":
            return sidebar or isinstance(focused, DataTable)
        delta = parameters[0]
        if isinstance(focused, DataTable):
            return (not focused.row_count or
                    (delta < 0 and focused.cursor_row == 0) or
                    (delta > 0 and focused.cursor_row == focused.row_count - 1))
        if isinstance(focused, (VerticalScroll, RichLog)):
            return (focused.scroll_y <= 0 if delta < 0
                    else focused.scroll_y >= focused.max_scroll_y)
        return True

    def action_focus_vertical(self, delta: int) -> None:
        focused = self.focused
        pane = self.query_one("#sidebar" if isinstance(focused, (NavItem, QuickRow))
                              else f"#{self.current}")
        controls = [widget for widget in self.screen.focus_chain if pane in widget.ancestors]
        if focused in controls:
            index = controls.index(focused)
            controls[max(0, min(len(controls) - 1, index + delta))].focus()
        elif controls:
            controls[0 if delta > 0 else -1].focus()

    def action_focus_sidebar(self) -> None:
        self.query_one(f"#nav-{self.current}", NavItem).focus()

    def action_enter_section(self) -> None:
        focused = self.focused
        if isinstance(focused, NavItem):
            self.show_view(focused.key)
        elif isinstance(focused, QuickRow):
            self.focus_section()
        elif isinstance(focused, DataTable):
            self.action_focus_vertical(1)

    def action_leave_input(self) -> None:
        if isinstance(self.focused, Input):
            self.focus_section()
        else:
            self.action_focus_sidebar()

    def action_view(self, name: str) -> None:
        self.show_view(name)

    def action_refresh(self) -> None:
        self.refresh_all(True)

    def action_focus_search(self) -> None:
        target = {"proxies": "proxy-search", "rules": "rules-filter", "logs": "log-filter"}
        if self.current in target:
            self.query_one(f"#{target[self.current]}", Input).focus()

    # ---------- обновление

    def tick(self) -> None:
        if not self.is_running:
            return
        self._tick += 1
        if self._tick % 3 == 0:
            self.snap = snapshot(force=False)
            self.refresh_all(False)
        else:
            self.refresh_dynamic()
            self.refresh_statusbar()

    def refresh_all(self, force: bool = False) -> None:
        if not self.is_running:
            return
        self.snap = snapshot(force=force)
        self.refresh_dynamic()
        self.refresh_statusbar()
        self.query_one(ProfilesView).update_view(self.snap)
        self.query_one(SettingsView).update_info(self.snap)
        if self.current == "proxies":
            self.query_one(ProxiesView).rebuild()
        if self.current == "connections":
            self.query_one(ConnectionsView).refresh_view()
        if self.current == "rules":
            self.query_one(RulesView).rebuild()
        if self.current == "apps":
            self.query_one(AppsView).rebuild()

    def refresh_dynamic(self) -> None:
        self.query_one(DashboardView).update_view(self.snap)

    def refresh_statusbar(self) -> None:
        snap = self.snap
        srv = current_server(snap["servers"])
        mode = "TUN" if snap["mode"] == "vpn" else "PROXY"
        svc = "вкл" if snap["active"] else "выкл"
        suffix = f" · {mode} · xray:{svc} · {len(snap['sessions'])} сес."
        bar = self.query_one("#statusbar", Static)
        width = max(1, (bar.content_size.width or 80) - len(suffix))
        left = f"#{srv['index']} {srv['name']}" if srv else "—"
        bar.update(escape(fit(left, width) + suffix))
        self.query_one("#quick-mode", QuickRow).update(
            f"Режим    [bold]{mode}[/]")
        xray_row = self.query_one("#quick-xray", QuickRow)
        if snap["active"]:
            xray_row.update(f"Xray     [{C_OK}]● вкл[/]")
        else:
            xray_row.update("Xray     [dim]○ выкл[/]")

    # ---------- действия (клики и клавиши)

    def goto_proxies(self) -> None:
        self.show_view("proxies")

    def goto_settings(self) -> None:
        self.show_view("settings")

    def goto_apps(self) -> None:
        self.show_view("apps")

    def launch_app(self) -> None:
        if self.current == "apps":
            self.query_one(AppsView).launch()

    def app_toggle(self) -> None:
        if self.current == "apps":
            self.query_one(AppsView).toggle()

    def app_cycle_server(self) -> None:
        if self.current == "apps":
            self.query_one(AppsView).cycle_server()

    def app_remove(self) -> None:
        if self.current == "apps":
            self.query_one(AppsView).remove()

    def goto_logs(self) -> None:
        self.show_view("logs")

    def exit_app(self) -> None:
        self.exit()

    def cycle_mode(self) -> None:
        self.apply_mode("proxy" if self.snap["mode"] == "vpn" else "vpn")

    def toggle_global(self) -> None:
        self.run_worker(self._toggle_worker(), thread=True, group="svc")

    def apply_mode(self, mode: str) -> None:
        if mode not in ("proxy", "vpn"):
            return
        self.run_worker(self._mode_worker(mode), thread=True, group="svc")

    def restart_xray(self) -> None:
        self.run_worker(self._restart_worker(), thread=True, group="svc")

    def prof_reload(self) -> None:
        self.refresh_all(True)
        self.notify("Конфиги перечитаны")

    def prof_check(self) -> None:
        self.show_view("proxies")
        self.query_one(ProxiesView).ping_all()

    def prof_open(self) -> None:
        sh("xdg-open", str(XDIR))

    def proxy_ping(self) -> None:
        if self.current == "proxies":
            self.query_one(ProxiesView).ping_all()

    def log_clear(self) -> None:
        if self.current == "logs":
            self.query_one(LogsView).clear_log()

    def conn_launch_selected(self) -> None:
        cv = self.query_one(ConnectionsView)
        app_id = cv.query_one("#conn-app", OptionRow).value
        app = next((a for a in load_apps() if a["id"] == app_id), None)
        if app:
            cv._launch(app, server_index())

    def conn_launch_cmd(self) -> None:
        cv = self.query_one(ConnectionsView)
        line = cv.query_one("#conn-cmd", Input).value.strip()
        if not line:
            self.notify("Введи команду", severity="warning")
            return
        try:
            cmd = shlex.split(line)
        except ValueError as e:
            self.notify(f"Не разобрать команду: {e}", severity="error")
            return
        cv.query_one("#conn-cmd", Input).value = ""
        cv._launch({"id": "custom", "name": line, "cmd": cmd}, server_index())

    def conn_kill(self) -> None:
        self.query_one(ConnectionsView)._kill()

    def rules_add(self) -> None:
        self.query_one(RulesView)._add()

    def rules_delete(self) -> None:
        self.query_one(RulesView)._delete()

    def rules_save(self) -> None:
        d = rules_data()
        d["default"] = self.query_one("#rules-default", OptionRow).value
        self.query_one(RulesView)._save(d)

    def rules_move(self, delta: int) -> None:
        self.query_one(RulesView)._move(delta)

    def action_kill_session(self) -> None:
        if self.current == "connections":
            self.conn_kill()

    def action_ping_all(self) -> None:
        if self.current == "proxies":
            self.proxy_ping()

    def action_rule_add(self) -> None:
        if self.current == "rules":
            self.query_one("#rules-value", Input).focus()

    def action_rule_delete(self) -> None:
        if self.current == "rules":
            self.rules_delete()
        elif self.current == "apps":
            self.app_remove()

    def action_rule_save(self) -> None:
        if self.current == "rules":
            self.rules_save()
        elif self.current == "apps":
            self.app_cycle_server()

    def action_rule_move(self, delta: int) -> None:
        if self.current == "rules":
            self.rules_move(delta)

    def action_clear_log(self) -> None:
        if self.current == "logs":
            self.log_clear()

    # ---------- события таблиц и полей

    @on(DataTable.RowHighlighted, "#proxy-table")
    def _proxy_hl(self, event: DataTable.RowHighlighted) -> None:
        try:
            idx = int(event.row_key.value)
            pv = self.query_one(ProxiesView)
            pv.selected = idx
            servers = self.snap["servers"]
            if 0 <= idx < len(servers):
                srv = servers[idx]
                pv.query_one("#proxy-hint", Static).update(
                    f"[dim]#{idx} {srv['host']} · {srv['protocol']} · "
                    f"Enter — выбрать[/]")
        except Exception:
            pass

    @on(DataTable.RowSelected, "#proxy-table")
    def _proxy_sel(self, event: DataTable.RowSelected) -> None:
        try:
            idx = int(event.row_key.value)
        except Exception:
            return
        self.query_one(ProxiesView)._apply_index(idx)

    @on(DataTable.RowHighlighted, "#conn-table")
    def _conn_hl(self, event: DataTable.RowHighlighted) -> None:
        try:
            cv = self.query_one(ConnectionsView)
            cv.selected_file = event.row_key.value
            if cv.selected_file in getattr(cv, "_sessions", {}):
                cv.show_detail(cv._sessions[cv.selected_file])
        except Exception:
            pass

    @on(DataTable.RowHighlighted, "#rules-table")
    def _rules_hl(self, event: DataTable.RowHighlighted) -> None:
        try:
            self.query_one(RulesView).selected_row = int(event.row_key.value)
        except Exception:
            pass

    @on(Input.Changed, "#proxy-search")
    def _proxy_search_changed(self) -> None:
        self.query_one(ProxiesView).rebuild()

    @on(Input.Submitted, "#proxy-search")
    def _proxy_search_submit(self) -> None:
        self.query_one("#proxy-table", DataTable).focus()

    @on(Input.Changed, "#rules-filter")
    def _rules_filter(self) -> None:
        self.query_one(RulesView).rebuild()

    @on(Input.Submitted, "#rules-value")
    def _rules_submit(self) -> None:
        self.query_one(RulesView)._add()

    @on(Input.Submitted, "#conn-cmd")
    def _conn_cmd_submit(self) -> None:
        self.conn_launch_cmd()

    @on(Input.Changed, "#log-filter")
    def _log_filter(self) -> None:
        lv = self.query_one(LogsView)
        if lv._source == "journal":
            lv._render_journal_buf()
        else:
            lv.refresh_source(reset=True)

    @on(ToggleRow.Toggled, "#log-auto")
    def _log_auto(self, event: ToggleRow.Toggled) -> None:
        log = self.query_one("#log-view", RichLog)
        log.auto_scroll = event.value
        if event.value:
            log.scroll_end(animate=False)

    @on(OptionRow.Changed, "#log-source")
    def _log_source(self, event: OptionRow.Changed) -> None:
        self.query_one(LogsView).refresh_source(reset=True)

    @on(OptionRow.Changed, "#log-session")
    def _log_session(self, event: OptionRow.Changed) -> None:
        if self.query_one("#log-source", OptionRow).value == "session":
            self.query_one(LogsView).refresh_source(reset=True)

    @on(OptionRow.Confirmed, "#conn-app")
    def _conn_app_confirm(self, event: OptionRow.Confirmed) -> None:
        self.conn_launch_selected()

    @on(OptionRow.Confirmed, "#set-mode")
    def _set_mode_confirm(self, event: OptionRow.Confirmed) -> None:
        self.apply_mode(str(event.row.value))

    @on(OptionRow.Changed, "#set-country")
    def _set_country(self, event: OptionRow.Changed) -> None:
        val = str(event.row.value or "")
        if val == (settings().get("require_country") or ""):
            return
        st = settings()
        st["require_country"] = val
        save_json(SETTINGS, st)
        snapshot(force=True)
        self.notify(f"Страна выхода: {COUNTRIES.get(val, 'любая')}")

    @on(OptionRow.Changed, "#set-theme")
    def _set_theme(self, event: OptionRow.Changed) -> None:
        val = str(event.row.value or "")
        if val and val != self.theme:
            self.theme = val

    @on(ToggleRow.Toggled, "#set-autostart")
    def _set_autostart(self, event: ToggleRow.Toggled) -> None:
        if event.value == autostart_enabled():
            return
        set_autostart(event.value)
        self.notify("Автозапуск включён" if event.value else "Автозапуск выключен")

    # ---------- глобальный режим

    def _toggle_worker(self):
        def run():
            active = is_active()
            if active:
                r = sh("systemctl", "--user", "stop", SERVICE)
                ok = r.returncode == 0 and not is_active()
                msg = "Глобальный xray остановлен" if ok else "Не удалось остановить xray"
            else:
                mode = state().get("mode", "proxy")
                r = manager("set-mode", mode)
                ok = r.returncode == 0 and r.stdout.strip() == "OK" and is_active()
                msg = "Глобальный xray включён" if ok else "Не удалось включить xray; смотри логи"
            self.call_from_thread(self.refresh_all, True)
            self.call_from_thread(self.notify, msg, severity="information" if ok else "error")
        return run

    def _mode_worker(self, mode: str):
        def run():
            if is_active():
                r = manager("set-mode", mode)
                ok = r.returncode == 0 and r.stdout.strip() == "OK" and is_active()
            else:
                st = state()
                st["mode"] = mode
                save_json(STATE, st)
                ok = True
            self.call_from_thread(self.refresh_all, True)
            self.call_from_thread(
                self.query_one("#set-mode", OptionRow).set_value, state().get("mode", "proxy"))
            self.call_from_thread(
                self.notify,
                f"Режим: {'TUN / VPN' if mode == 'vpn' else 'системный прокси'}"
                if ok else "Не удалось сменить режим; смотри логи",
                severity="information" if ok else "error")
        return run

    def _restart_worker(self):
        def run():
            r = manager("set-mode", state().get("mode", "proxy"))
            ok = r.returncode == 0 and r.stdout.strip() == "OK" and is_active()
            self.call_from_thread(self.refresh_all, True)
            self.call_from_thread(self.notify,
                                  "xray перезапущен" if ok else "Не удалось перезапустить xray; смотри логи",
                                  severity="information" if ok else "error")
        return run


# ---------------------------------------------------------------- CLI

def cmd_status() -> int:
    snap = snapshot(force=True)
    print("Режим:   ", "VPN / TUN" if snap["mode"] == "vpn" else "системный прокси")
    print("Сервис:  ", "активен" if snap["active"] else "остановлен")
    print("Сервер:  ", server_text(snap["servers"]))
    print("Сессии:  ", len(snap["sessions"]))
    for s in snap["sessions"]:
        print("  •", session_title(s))
    auto = snap.get("auto_apps") or []
    print("Авто-VPN:", f"{len(auto)} прил. — " + ", ".join(
        str(a.get("name") or a["id"]) for a in auto) if auto else "нет")
    return 0


def cmd_launch(argv: list[str]) -> int:
    if not argv:
        return 2
    ident, extra = argv[0], argv[1:]
    entry = app_rules.get_app(ident)
    if entry is None:
        entry = {"id": ident, "name": ident, "cmd": [ident]}
    return app_rules.run_entry(entry, extra)


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--status":
        return cmd_status()
    if argv and argv[0] == "--launch":
        return cmd_launch(argv[1:])
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    VpnTuiApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
