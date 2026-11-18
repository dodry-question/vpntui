"""Preflight checks: software on the machine that fights with vpntui.

The global mode takes over the default route while it runs.  On a typical
Linux desktop other tools do the same thing in their own way: Cloudflare WARP
installs policy routing for the whole host, zapret rewrites the TLS
ClientHello of every outbound packet, Tailscale can carry an exit node, and a
second Xray/Clash instance can already own the local proxy ports.

The result is either "VPN says connected, traffic still goes direct" or a dead
network.  This module finds such tools **without root** and explains what to
do.  Fixes that change the system are applied by the privileged helper
(``run-vpn global repair``) or by the user explicitly (``vpntui doctor --fix``).
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import shutil
import subprocess

from . import paths
from .util import load_json, port_free

SEVERITY = {"ok": 0, "info": 1, "warn": 2, "critical": 3}
MARKS = {"ok": "[ok]", "info": "[..]", "warn": "[!!]", "critical": "[XX]"}

DEFAULT_SOCKS = 10808
DEFAULT_HTTP = 10809
# Ports other proxies commonly squat on.  Only our own two are critical.
COMMON_PROXY_PORTS = (1080, 1081, 7890, 7891, 8080, 8888, 9090, 10808, 10809)


@dataclasses.dataclass
class Finding:
    """One check result.  ``auto`` means vpntui can fix it without asking."""

    id: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""
    auto: bool = False

    @property
    def level(self) -> int:
        return SEVERITY.get(self.severity, 3)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)

    def lines(self) -> list[str]:
        out = [f"{MARKS.get(self.severity, '[??]')} {self.title}"]
        if self.detail:
            out.append(f"       {self.detail}")
        if self.fix:
            out.append(f"       -> {self.fix}")
        return out


def _run(cmd: list[str], timeout: float = 5) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (result.stdout or "") + (result.stderr or "")


def _active(unit: str) -> bool:
    return _run(["systemctl", "is-active", unit], 3).strip() == "active"


def _enabled(unit: str) -> str:
    return _run(["systemctl", "is-enabled", unit], 3).strip()


def _pgrep(*names: str) -> bool:
    for name in names:
        if _run(["pgrep", "-x", name], 3).strip():
            return True
    return False


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


# --------------------------------------------------------------- detectors

def warp_state() -> str:
    """``Connected`` / ``Connecting`` / ``Disconnected`` / ``""`` (no daemon)."""
    if not shutil.which("warp-cli"):
        return ""
    text = _run(["warp-cli", "--accept-tos", "status"], 6)
    match = re.search(r"Status(?: update)?:\s*(\w+)", text)
    return match.group(1) if match else ""


def default_routes() -> list[tuple[str, str]]:
    """``[(device, full line), ...]`` for every default route."""
    out = []
    for line in _run(["ip", "route", "show", "default"]).splitlines():
        match = re.search(r"\bdev\s+(\S+)", line)
        if match:
            out.append((match.group(1), line.strip()))
    return out


def policy_tables() -> list[int]:
    """Routing tables other than local/main/default that hold a default route.

    Cloudflare WARP and some kill-switches install ``ip rule`` entries like
    ``5209: from all lookup 65743``.  Such a rule is evaluated before the
    ``main`` table where vpntui's route lives, so it silently steals traffic.
    """
    tables = []
    for line in _run(["ip", "rule", "show"]).splitlines():
        match = re.search(r"lookup\s+(\d+)\s*$", line.strip())
        if not match:
            continue
        number = int(match.group(1))
        if number in (0, 253, 254, 255) or number in tables:
            continue
        if "default" in _run(["ip", "route", "show", "table", str(number)]):
            tables.append(number)
    return tables


def listening_ports() -> set[int]:
    ports: set[int] = set()
    for line in _run(["ss", "-lntH"]).splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        tail = fields[3].rsplit(":", 1)[-1]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


def _tailscale_exit_node() -> bool:
    if not shutil.which("tailscale"):
        return False
    raw = _run(["tailscale", "status", "--json"], 6)
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    return bool(data.get("ExitNodeStatus"))


# ------------------------------------------------------------------ checks

def scan(running: bool = False) -> list[Finding]:
    """Return every finding, sorted from most to least severe."""
    found: list[Finding] = []

    # --- Cloudflare WARP ------------------------------------------------
    warp_bin = shutil.which("warp-cli")
    state = warp_state()
    if state in ("Connected", "Connecting"):
        found.append(Finding(
            "warp", "critical", "WARP подключён",
            "WARP забирает весь трафик через policy-routing и спорит с TUN "
            "vpntui за default-маршрут.",
            "warp-cli --accept-tos disconnect", auto=True))
    elif state:
        found.append(Finding("warp", "ok", "WARP выключен", f"статус: {state}"))
    elif warp_bin:
        found.append(Finding(
            "warp", "ok", "WARP не запущен",
            "клиент установлен, демон выключен — конфликта нет"))
    if _active("warp-svc") and state not in ("Connected", "Connecting"):
        found.append(Finding(
            "warp", "info", "служба WARP запущена, но туннель WARP выключен",
            "в таком виде она безвредна; WARP включится только по команде"))

    # --- zapret ---------------------------------------------------------
    zapret_running = _active("zapret") or _pgrep("nfqws", "tpws")
    zapret_installed = bool(shutil.which("nfqws") or shutil.which("tpws")
                            or pathlib.Path("/opt/zapret").exists())
    if zapret_running:
        found.append(Finding(
            "zapret", "warn", "zapret (DPI-desync) активен",
            "zapret обрабатывает исходящий TCP/443 и портит TLS внутри "
            "туннеля: сайты из его хостелистов падают с TLS EOF.",
            "vpntui исключает свой TUN автоматически при запуске", auto=True))
    elif zapret_installed:
        found.append(Finding("zapret", "ok", "zapret установлен и выключен",
                             "конфликта нет"))

    # --- Tailscale ------------------------------------------------------
    if _active("tailscaled"):
        if _tailscale_exit_node():
            found.append(Finding(
                "tailscale", "critical", "Tailscale работает как exit-node",
                "весь трафик уходит в Tailscale раньше, чем в TUN vpntui.",
                "tailscale set --exit-node=", auto=False))
        else:
            found.append(Finding(
                "tailscale", "info", "Tailscale активен (без exit-node)",
                "совместим: туннель vpntui его не затрагивает"))

    # --- other tunnels / proxies ---------------------------------------
    for unit in ("openvpn-client@client", "wg-quick@wg0"):
        if _active(unit):
            found.append(Finding(
                unit, "warn", f"активен {unit}",
                "два туннеля одновременно делят default-маршрут.",
                f"systemctl stop {unit}", auto=False))
    for proc, label in (("mihomo", "Clash/Mihomo"), ("clash", "Clash"),
                        ("sing-box", "sing-box"), ("tun2socks", "tun2socks")):
        if _pgrep(proc):
            found.append(Finding(
                f"proxy-{proc}", "warn", f"запущен {label}",
                "может уже держать TUN и локальные прокси-порты.",
                "останови его или выбери другой режим", auto=False))

    # --- Telegram WS proxy ---------------------------------------------
    if _pgrep("TgWsProxy_linux", "tgwsproxy", "mtg"):
        found.append(Finding(
            "tgws", "info", "Telegram WS-прокси запущен",
            "совместим: это обычный клиент, его трафик просто пойдёт через "
            "туннель (Telegram при этом продолжит работать)"))

    # --- ports ----------------------------------------------------------
    ours = set(_state_ports().values()) or {DEFAULT_SOCKS, DEFAULT_HTTP}
    used = listening_ports()
    busy = sorted(ours & used)
    if busy and not running:
        found.append(Finding(
            "ports", "warn", "прокси-порты заняты: " + ", ".join(map(str, busy)),
            "другая программа уже слушает эти порты; vpntui сдвинет свои.",
            "новые порты выбираются автоматически", auto=True))
    elif busy and running:
        found.append(Finding("ports", "ok", "прокси-порты слушает сам vpntui"))
    elif not busy:
        found.append(Finding("ports", "ok", "прокси-порты свободны: "
                             + ", ".join(map(str, sorted(ours)))))
    foreign = sorted((used & set(COMMON_PROXY_PORTS)) - ours)
    if foreign:
        found.append(Finding(
            "ports-foreign", "info",
            "другие прокси слушают: " + ", ".join(map(str, foreign)),
            "на работу vpntui не влияет, но не запускай два прокси на одном порту"))

    # --- policy routing -------------------------------------------------
    tables = policy_tables()
    if tables:
        found.append(Finding(
            "policy", "warn",
            "policy-routing перехватывает трафик: таблица "
            + ", ".join(map(str, tables)),
            "правило ip rule с default-маршрутом срабатывает раньше main — "
            "так делает WARP или kill-switch другого VPN.",
            "выключи тот VPN или удали его правила", auto=False))

    # --- legacy user service -------------------------------------------
    if _run(["systemctl", "--user", "is-active", "xray.service"], 3).strip() == "active":
        found.append(Finding(
            "legacy-xray", "warn", "запущен старый xray.service (user)",
            "он занимает те же порты, что и vpntui.",
            "systemctl --user disable --now xray.service", auto=False))

    # --- legacy launcher -------------------------------------------------
    # Команда `vpntui` может указывать на старую установку (~/scripts/vpn):
    # её TUN-режим молча не работает — xray под юзером не может заменить
    # маршрут по умолчанию, сайты показывают реальный IP при «включённом» VPN.
    launcher = shutil.which("vpntui")
    if launcher:
        try:
            resolved = str(pathlib.Path(launcher).resolve())
        except OSError:
            resolved = ""
        if resolved.startswith(str(paths.LEGACY_VPN)):
            found.append(Finding(
                "legacy-launcher", "warn",
                f"команда vpntui запускает старую версию ({launcher})",
                "TUN-режим старой версии молча не работает: трафик идёт напрямую "
                "при статусе «ПОДКЛЮЧЕНО».",
                "vpntui setup — перепривяжет команду на эту установку", auto=False))

    # --- DNS ------------------------------------------------------------
    resolv = ""
    try:
        resolv = pathlib.Path("/etc/resolv.conf").read_text(errors="replace")
    except OSError:
        pass
    if "127.0.0.53" in resolv and not _active("systemd-resolved"):
        found.append(Finding(
            "dns", "warn", "resolv.conf указывает на systemd-resolved, а он выключен",
            "DNS не будет работать ни напрямую, ни через туннель.",
            "systemctl enable --now systemd-resolved", auto=False))

    # --- IPv6 -----------------------------------------------------------
    if _run(["ip", "-6", "route", "show", "default"]).strip():
        disabled = _run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"]).strip()
        if disabled != "1":
            found.append(Finding(
                "ipv6", "warn", "включён IPv6, а туннель только IPv4",
                "сайты с AAAA-записью могут пойти мимо VPN (утечка).",
                "отключи IPv6 или используй сервер с IPv6", auto=False))

    found.sort(key=lambda f: (-f.level, f.id))
    return found


def worst(findings: list[Finding]) -> str:
    if not findings:
        return "ok"
    return max(findings, key=lambda f: f.level).severity


def blockers(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity == "critical"]


def report(findings: list[Finding]) -> str:
    return "\n".join(line for finding in findings for line in finding.lines())


def _state_ports() -> dict:
    state = load_json(paths.STATE, {}) or {}
    ports = state.get("ports") if isinstance(state, dict) else None
    if not isinstance(ports, dict):
        return {}
    out = {}
    for key in ("socks", "http"):
        value = ports.get(key)
        if isinstance(value, int) and 0 < value < 65536:
            out[key] = value
    return out


def state_ports() -> tuple[int, int]:
    """Proxy ports the global service is configured to use."""
    ports = _state_ports()
    return (ports.get("socks", DEFAULT_SOCKS), ports.get("http", DEFAULT_HTTP))


def free_ports(start: int = DEFAULT_SOCKS, count: int = 2) -> list[int]:
    """First ``count`` free ports at or above ``start`` (127.0.0.1)."""
    out: list[int] = []
    candidate = start
    while len(out) < count and candidate < start + 200:
        if port_free(candidate):
            out.append(candidate)
        candidate += 1
    return out
