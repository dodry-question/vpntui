#!/usr/bin/env python3
"""run-vpn — запуск приложения в отдельной сети через Xray (per-app VPN).

Вся сеть процесса (TCP, UDP, DNS) идёт через сервер из твоей подписки.
Хост и остальные программы при этом ходят напрямую, как обычно.

Примеры:
  run-vpn brave                      # Brave целиком через VPN
  run-vpn roblox                     # Roblox (Sober/Vinegar) через VPN
  run-vpn -c DE roblox               # требовать зарубежный выход (DE/JP/…)
  run-vpn -- curl -s https://api.ipify.org
  run-vpn -s 13 steam                # конкретный сервер (13 = Германия [Игровой])
  run-vpn -l                         # список серверов
  run-vpn --server 3 -- bash         # интерактивный шелл внутри VPN

Требует установленного хелпера (см. install.sh).
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

from . import paths
from .appconfig import build as build_app_config
from .core import find_xray

HELPER = str(paths.HELPER)

QUIET = False

ENV_ALLOW = {
    "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TERM", "COLORTERM",
    "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE", "XDG_SESSION_DESKTOP", "XDG_CURRENT_DESKTOP",
    "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
    "XDG_DATA_HOME", "XDG_STATE_HOME", "DBUS_SESSION_BUS_ADDRESS", "SWAYSOCK",
    "I3SOCK", "HYPRLAND_INSTANCE_SIGNATURE", "PULSE_SERVER", "PULSE_COOKIE",
    "PIPEWIRE_REMOTE", "SSH_AUTH_SOCK", "TMPDIR", "LANG", "LANGUAGE",
    "MOZ_ENABLE_WAYLAND", "QT_QPA_PLATFORM", "GDK_BACKEND", "GTK_THEME",
    "BROWSER", "EDITOR", "VISUAL", "GTK_USE_PORTAL", "VPN_APP_NAME",
}
ENV_PREFIX = ("LC_", "QT_", "GTK_", "GDK_")


def collect_env():
    out = {}
    for k, v in os.environ.items():
        if k in ENV_ALLOW or k.startswith(ENV_PREFIX):
            out[k] = v
    return out


def notify(title, body, urgency="normal"):
    if QUIET or not shutil.which("notify-send"):
        return
    subprocess.Popen(
        ["notify-send", "-a", "app-vpn", "-u", urgency,
         "-i", "network-vpn", title, body],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF"      # эмодзи, флаги (regional indicators), пиктограммы
    "\U00002600-\U000027BF"       # разное (⚡, ✅ и т.п.)
    "\U00002190-\U000021FF"       # стрелки
    "\U0000FE00-\U0000FE0F"       # variation selectors
    "\U0000200D"                  # zero-width joiner
    "\U000020E3\U00002B00-\U00002BFF"
    "]+"
)


def clean_text(text, default="сервер"):
    """Убираем эмодзи/флаги: в шрифте уведомлений они превращаются в «тофу»."""
    if not text:
        return default
    text = EMOJI_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip(" -—·|")
    return text or default


def gen_config(index):
    try:
        return build_app_config(index)
    except SystemExit:
        raise
    except Exception as exc:
        sys.exit(f"run-vpn: {exc}")


def warp_exclude(ips):
    """IP серверов VPN — в исключения WARP, чтобы не было двойного туннеля.

    WARP живёт на хосте, а Xray в namespace выходит наружу через slirp.
    Без этого его соединение к серверу завернулось бы в WARP.
    """
    exe = shutil.which("warp-cli")
    if not exe:
        return
    for ip in ips or []:
        try:
            subprocess.run(
                [exe, "--accept-tos", "tunnel", "ip", "add", str(ip)],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass


def list_servers():
    subprocess.run([sys.executable, "-m", "vpntui.manager", "servers"])


def brave_running():
    for pattern in ("brave-browser-stable", "brave"):
        r = subprocess.run(["pgrep", "-u", str(os.getuid()), "-x", pattern],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return True
    return False


def resolve_alias(name):
    name = name.lower()
    if name in ("brave", "brave-browser", "browser"):
        exe = shutil.which("brave-browser-stable") or shutil.which("brave-browser")
        if not exe:
            sys.exit("run-vpn: не найден Brave (brave-browser-stable)")
        return [exe]
    if name in ("brave-vpn", "brave-alt", "brave2"):
        exe = shutil.which("brave-browser-stable") or shutil.which("brave-browser")
        if not exe:
            sys.exit("run-vpn: не найден Brave (brave-browser-stable)")
        # Отдельный профиль: можно держать обычный Brave открытым параллельно.
        return [exe, f"--user-data-dir={pathlib.Path.home() / '.config' / 'brave-vpn-profile'}"]
    if name in ("roblox", "sober"):
        if subprocess.run(["flatpak", "info", "org.vinegarhq.Sober"],
                          capture_output=True).returncode == 0:
            return ["flatpak", "run", "org.vinegarhq.Sober"]
        if shutil.which("vinegar"):
            return ["vinegar"]
        sys.exit("run-vpn: не найден ни Sober (flatpak org.vinegarhq.Sober), "
                 "ни Vinegar. Установи лаунчер, потом повтори.")
    if name == "steam" and shutil.which("flatpak") and \
            subprocess.run(["flatpak", "info", "com.valvesoftware.Steam"],
                           capture_output=True).returncode == 0:
        return ["flatpak", "run", "com.valvesoftware.Steam"]
    if name in ("shell", "bash"):
        return ["bash", "-i"]
    return None


def main():
    p = argparse.ArgumentParser(
        add_help=False,
        usage="run-vpn [опции] [brave|roblox|steam|shell] [--] команда [аргументы...]",
    )
    p.add_argument("-s", "--server", type=int, help="индекс сервера (см. -l)")
    p.add_argument("-c", "--country", metavar="XX",
                   help="требовать страну выхода, напр. DE (RU блокируется всегда)")
    p.add_argument("-l", "--list", action="store_true", help="список серверов")
    p.add_argument("-n", "--no-check", action="store_true",
                   help="не проверять связь перед запуском")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="без уведомлений (для тестов из vpntui)")
    p.add_argument("-v", "--debug", action="store_true",
                   help="подробный лог xray (/run/vpntui/last.log)")
    p.add_argument("-d", "--dry-run", action="store_true",
                   help="показать конфиг и выйти")
    p.add_argument("-h", "--help", action="store_true", help="эта справка")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    a = p.parse_args()
    global QUIET
    QUIET = bool(a.quiet)

    if a.help:
        print(__doc__)
        return 0
    if a.list:
        list_servers()
        return 0
    if a.country and not re.fullmatch(r"[A-Za-z]{2}", a.country):
        sys.exit("run-vpn: страна задаётся двумя буквами, например -c DE")

    rest = list(a.rest)
    while rest and rest[0] == "--":
        rest.pop(0)
    if not rest:
        print(__doc__)
        return 2

    alias = resolve_alias(rest[0])
    cmd = (alias + rest[1:]) if alias else rest
    first = rest[0].lower()

    if first in ("brave", "brave-browser", "browser") and brave_running():
        text = ("Brave уже запущен вне VPN — новый запуск открыл бы вкладку в старом\n"
                "окне БЕЗ VPN. Закрой Brave или запусти `run-vpn brave-vpn`\n"
                "(отдельный профиль, можно держать оба сразу).")
        print("run-vpn: [!] " + text, file=sys.stderr)
        notify("VPN: Brave уже открыт",
               "Закрой Brave или запусти run-vpn brave-vpn (отдельный профиль)")
        return 3

    index = a.server
    if index is None:
        try:
            index = int(json.loads(paths.STATE.read_text()).get("server_index", 0))
        except Exception:
            index = 0

    payload = gen_config(index)
    if a.debug:
        payload["config"].setdefault("log", {})["loglevel"] = "debug"
    if a.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=1))
        return 0

    if not pathlib.Path(HELPER).exists():
        sys.exit("run-vpn: не установлен root-хелпер.\n"
                 "Запусти: vpntui setup")
    allowed = subprocess.run(["sudo", "-n", "-l", HELPER],
                             capture_output=True).returncode == 0
    if not allowed:
        sys.exit("run-vpn: нет разрешения sudo для хелпера.\n"
                 "Запусти: vpntui setup")

    warp_exclude(payload.get("server", {}).get("ips"))
    srv = payload["server"]
    if os.environ.get("VPN_APP_NAME"):
        app_label = os.environ["VPN_APP_NAME"]
    elif alias:
        app_label = {"brave": "Brave", "brave-vpn": "Brave (свой профиль)",
                     "roblox": "Roblox", "steam": "Steam",
                     "shell": "Терминал", "bash": "Терминал"}.get(
                         rest[0].lower(), pathlib.Path(cmd[0]).name)
    else:
        app_label = pathlib.Path(cmd[0]).name
    desc = clean_text(f"{srv.get('name')} — {srv.get('host')}")
    notify(f"VPN: {app_label}", f"Подключаюсь… {desc}")

    xray = find_xray()
    if not xray:
        sys.exit("run-vpn: Xray не найден. Установи: vpntui core install")
    req = {
        "xray": str(xray),
        "config": payload["config"],
        "tun": payload["tun"],
        "server": srv,
        "cmd": cmd,
        "app": app_label,
        "cwd": os.getcwd(),
        "env": collect_env(),
        "no_check": bool(a.no_check),
        "require_country": (a.country or "").upper(),
        "notify": not a.quiet,
    }
    proc = subprocess.run(["sudo", "-n", HELPER],
                          input=json.dumps(req, ensure_ascii=False), text=True)
    if proc.returncode == 100:
        notify("VPN: ошибка", f"Не удалось поднять туннель ({desc})", "critical")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
