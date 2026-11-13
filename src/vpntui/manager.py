"""Global Xray mode and the ``vpntui-xray`` user service."""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

from . import core, globalconfig, paths
from .util import load_json, notify, save_json

UNIT = pathlib.Path.home() / ".config" / "systemd" / "user" / f"{paths.SERVICE}"
LEGACY_SERVICE = "xray.service"


def sh(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def is_active() -> bool:
    return sh("systemctl", "--user", "is-active", paths.SERVICE).stdout.strip() == "active"


def legacy_active() -> bool:
    return sh("systemctl", "--user", "is-active", LEGACY_SERVICE).stdout.strip() == "active"


def _xray() -> pathlib.Path:
    binary = core.find_xray()
    if not binary:
        raise RuntimeError("Xray не найден. Установи: vpntui core install")
    return binary


def validate() -> bool:
    if not paths.GLOBAL_CONFIG.is_file():
        return False
    try:
        result = sh(str(_xray()), "run", "-test", "-c", str(paths.GLOBAL_CONFIG))
    except OSError:
        return False
    return "Configuration OK" in (result.stdout + result.stderr)


def ensure_service() -> pathlib.Path:
    """Write/refresh the systemd user unit (idempotent)."""
    binary = _xray()
    UNIT.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "[Unit]\n"
        "Description=vpntui global Xray\n"
        "Documentation=https://github.com/dodry-question/vpntui\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={binary} run -c {paths.GLOBAL_CONFIG}\n"
        "Restart=on-failure\n"
        "RestartSec=3\n"
        "NoNewPrivileges=true\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    if not UNIT.is_file() or UNIT.read_text() != content:
        UNIT.write_text(content)
        sh("systemctl", "--user", "daemon-reload")
    return UNIT


# ---------------------------------------------------------------- WARP guard

def warp_state() -> str:
    if not shutil.which("warp-cli"):
        return ""
    result = sh("warp-cli", "--accept-tos", "status")
    import re
    match = re.search(r"Status(?: update)?:\s*(\w+)", (result.stdout or "") + (result.stderr or ""))
    return match.group(1) if match else ""


def ensure_warp_off(reason: str) -> bool:
    if warp_state() not in ("Connected", "Connecting"):
        return True
    if sh("warp-cli", "--accept-tos", "disconnect").returncode == 0:
        notify("vpntui", f"WARP выключен: {reason}")
        return True
    notify("vpntui", "WARP включён и не выключается — запуск VPN отменён", "critical")
    return False


# ---------------------------------------------------------------- operations

def _regenerate(mode: str | None = None, index: int | None = None) -> tuple[str, int]:
    state = globalconfig.load_state()
    mode = mode or str(state.get("mode") or "proxy")
    index = state.get("server_index", 0) if index is None else index
    if mode not in ("proxy", "vpn"):
        raise RuntimeError(f"неизвестный режим: {mode}")
    if mode == "vpn" and not ensure_warp_off("два TUN одновременно конфликтуют"):
        raise RuntimeError("WARP активен")
    return globalconfig.write(mode, int(index))


def _previous() -> tuple[str, int]:
    state = load_json(paths.STATE, {}) or {}
    return str(state.get("mode") or "proxy"), int(state.get("server_index", 0))


def set_mode(mode: str, restart: bool = True) -> bool:
    was_active, previous = is_active(), _previous()
    try:
        _regenerate(mode=mode)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return False
    if not validate():
        print("конфиг невалиден, откат", file=sys.stderr)
        globalconfig.write(*previous)
        return False
    if was_active and restart:
        ensure_service()
        sh("systemctl", "--user", "restart", paths.SERVICE)
    return True


def set_server(index: int, restart: bool = True) -> bool:
    was_active, previous = is_active(), _previous()
    try:
        _regenerate(index=index)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return False
    if not validate():
        print("конфиг невалиден, откат", file=sys.stderr)
        globalconfig.write(*previous)
        return False
    if was_active and restart:
        ensure_service()
        sh("systemctl", "--user", "restart", paths.SERVICE)
    return True


def start() -> bool:
    if legacy_active():
        print("Сначала останови старый сервис: systemctl --user disable --now xray.service",
              file=sys.stderr)
        return False
    state = globalconfig.load_state()
    if not validate() or not paths.GLOBAL_CONFIG.is_file():
        if not _regenerate():
            return False
    ensure_service()
    sh("systemctl", "--user", "enable", paths.SERVICE)
    result = sh("systemctl", "--user", "start", paths.SERVICE)
    return result.returncode == 0 and is_active()


def stop() -> bool:
    sh("systemctl", "--user", "stop", paths.SERVICE)
    return not is_active()


def restart() -> bool:
    _regenerate()
    if not validate():
        return False
    ensure_service()
    sh("systemctl", "--user", "restart", paths.SERVICE)
    return is_active()


def server_rows() -> list[dict]:
    from .subscription import summary
    return summary()


def cmd_servers(as_json: bool = False) -> int:
    rows = server_rows()
    if as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return 0
    state = globalconfig.load_state()
    current = int(state.get("server_index", 0))
    for row in rows:
        mark = "*" if row["index"] == current else " "
        print(f"{mark} {row['index']:>2}  {row['name']}  {row['host']}:{row['port']} [{row['protocol']}]")
    return 0


def cmd_status() -> int:
    state = globalconfig.load_state()
    print("Режим:   ", "VPN / TUN" if state.get("mode") == "vpn" else "системный прокси")
    print("Сервис:  ", "активен" if is_active() else "остановлен")
    if legacy_active():
        print("Внимание:  запущен старый xray.service — останови его, чтобы не конфликтовали порты")
    print("Ядро:    ", core.find_xray() or "не найдено", core.xray_version() or "")
    rows = server_rows()
    index = int(state.get("server_index", 0))
    if 0 <= index < len(rows):
        row = rows[index]
        print("Сервер:  ", f"#{index} {row['name']} — {row['host']}:{row['port']}")
    else:
        print("Сервер:   не выбран")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpntui manager")
    parser.add_argument("command", choices=[
        "status", "servers", "set-mode", "set-server", "start", "stop", "restart", "install-service"])
    parser.add_argument("value", nargs="?")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    paths.ensure_layout()

    if args.command == "status":
        return cmd_status()
    if args.command == "servers":
        return cmd_servers(args.json)
    if args.command == "set-mode":
        ok = set_mode(str(args.value or "proxy"))
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    if args.command == "set-server":
        try:
            index = int(args.value or 0)
        except ValueError:
            print("нужен номер сервера", file=sys.stderr)
            return 2
        ok = set_server(index)
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    if args.command == "start":
        ok = start()
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    if args.command == "stop":
        ok = stop()
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    if args.command == "restart":
        ok = restart()
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    if args.command == "install-service":
        print(ensure_service())
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
