"""Global Xray mode: a system TUN service managed by the root helper.

Global mode needs CAP_NET_ADMIN (TUN device + default route), so it cannot run
as a systemd *user* service.  The privileged helper writes a validated config
to /etc/vpntui, installs ``vpntui-xray.service`` and controls it over sudo.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

from . import core, conflicts, globalconfig, paths

SERVICE = "vpntui-xray.service"
LEGACY_SERVICE = "xray.service"
USER_UNIT = pathlib.Path.home() / ".config" / "systemd" / "user" / SERVICE


def sh(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def is_active() -> bool:
    return sh("systemctl", "is-active", SERVICE).stdout.strip() == "active"


def legacy_active() -> bool:
    return sh("systemctl", "--user", "is-active", LEGACY_SERVICE).stdout.strip() == "active"


def _helper() -> str:
    return str(paths.HELPER)


def _global(action: str, payload: dict | None = None, watchdog: int = 0):
    argv = ["sudo", "-n", _helper(), "global", action]
    if watchdog:
        argv += ["--watchdog", str(watchdog)]
    if not pathlib.Path(_helper()).exists():
        print(f"Хелпер не установлен: {_helper()}. Запусти: vpntui setup", file=sys.stderr)
        return None
    try:
        return subprocess.run(
            argv,
            input=json.dumps(payload) if payload is not None else "",
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("sudo не найден", file=sys.stderr)
        return None


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


def drop_user_unit() -> None:
    """Remove the old unprivileged unit from earlier versions."""
    if not USER_UNIT.is_file():
        return
    sh("systemctl", "--user", "disable", "--now", SERVICE)
    try:
        USER_UNIT.unlink()
    except OSError:
        return
    sh("systemctl", "--user", "daemon-reload")


# ---------------------------------------------------------------- WARP guard

def warp_state() -> str:
    return conflicts.warp_state()


def ensure_warp_off(reason: str) -> bool:
    if warp_state() not in ("Connected", "Connecting"):
        return True
    if sh("warp-cli", "--accept-tos", "disconnect").returncode == 0:
        from .util import notify
        notify("vpntui", f"WARP выключен: {reason}")
        return True
    from .util import notify
    notify("vpntui", "WARP включён и не выключается — запуск VPN отменён", "critical")
    return False


# ------------------------------------------------------------ conflict guard

def preflight(running: bool | None = None) -> list:
    """Scan the host for tools that fight with the tunnel (no root needed)."""
    if running is None:
        running = is_active()
    return conflicts.scan(running=running)


def guard(findings: list) -> bool:
    """Auto-fix what is safe, refuse to start on a real blocker."""
    for finding in conflicts.blockers(findings):
        if finding.id == "warp" and ensure_warp_off("он забирает трафик у TUN"):
            continue
        print(f"vpntui: {finding.title}", file=sys.stderr)
        if finding.detail:
            print(f"        {finding.detail}", file=sys.stderr)
        if finding.fix:
            print(f"        исправление: {finding.fix}", file=sys.stderr)
        return False
    for finding in findings:
        if finding.severity == "warn":
            print(f"vpntui: [!] {finding.title}", file=sys.stderr)
    return True


def repair() -> bool:
    """Apply root-only conflict fixes (zapret exclusion) without starting."""
    result = _global("repair")
    return bool(result and result.returncode == 0)


# ---------------------------------------------------------------- operations

def _regenerate(mode: str | None = None, index: int | None = None) -> tuple[str, int]:
    state = globalconfig.load_state()
    mode = mode or str(state.get("mode") or "proxy")
    index = state.get("server_index", 0) if index is None else index
    if mode not in ("proxy", "vpn"):
        raise RuntimeError(f"неизвестный режим: {mode}")
    # Пока сервис работает, порты заняты им самим — не двигаем их.
    return globalconfig.write(mode, int(index), running=is_active())


def _start(watchdog: int = 0) -> bool:
    drop_user_unit()
    if legacy_active():
        print("Сначала останови старый сервис: systemctl --user disable --now xray.service",
              file=sys.stderr)
        return False
    try:
        mode, index = _regenerate()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return False
    if mode == "vpn" and not guard(preflight(running=is_active())):
        return False
    if not validate():
        print("конфиг невалиден", file=sys.stderr)
        return False
    try:
        payload = json.loads(paths.GLOBAL_CONFIG.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"не читается {paths.GLOBAL_CONFIG}: {exc}", file=sys.stderr)
        return False
    result = _global("start", payload, watchdog)
    if result is None:
        return False
    if result.returncode != 0:
        print((result.stderr or result.stdout).strip(), file=sys.stderr)
        return False
    info = {}
    for line in reversed((result.stdout or "").strip().splitlines()):
        try:
            info = json.loads(line)
            break
        except ValueError:
            continue
    if info.get("verified"):
        print(f"vpntui: трафик идёт через туннель, внешний IP "
              f"{info.get('exit_ip') or '?'}", file=sys.stderr)
    return is_active()


def start() -> bool:
    return _start()


def restart() -> bool:
    return _start()


def stop() -> bool:
    result = _global("stop")
    if result is None:
        return False
    return result.returncode == 0 and not is_active()


def status() -> bool:
    mode = globalconfig.load_state().get("mode", "proxy")
    active = is_active()
    ports = globalconfig.state_ports()
    print("Режим:   ", "VPN / TUN" if mode == "vpn" else "системный прокси")
    print("Сервис:  ", "активен" if active else "остановлен")
    print("Прокси:  ", f"SOCKS 127.0.0.1:{ports['socks']} · "
                      f"HTTP 127.0.0.1:{ports['http']}")
    print("Конфиг:  ", paths.GLOBAL_CONFIG if mode else "-")
    print("Ядро:    ", core.find_xray() or "не найдено")
    if legacy_active():
        print("Внимание: запущен старый xray.service — останови его, чтобы не конфликтовали порты")
    return active


def set_mode(mode: str, restart: bool = True) -> bool:
    state = globalconfig.load_state()
    index = int(state.get("server_index", 0))
    try:
        _regenerate(mode=mode, index=index)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return False
    if not validate():
        print("конфиг невалиден", file=sys.stderr)
        return False
    if is_active() and restart:
        return _start()
    return True


def set_server(index: int, restart: bool = True) -> bool:
    state = globalconfig.load_state()
    mode = str(state.get("mode") or "proxy")
    try:
        _regenerate(mode=mode, index=index)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return False
    if not validate():
        print("конфиг невалиден", file=sys.stderr)
        return False
    if is_active() and restart:
        return _start()
    return True


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
    status()
    rows = server_rows()
    index = int(globalconfig.load_state().get("server_index", 0))
    if 0 <= index < len(rows):
        row = rows[index]
        print("Сервер:  ", f"#{index} {row['name']} — {row['host']}:{row['port']}")
    else:
        print("Сервер:   не выбран")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpntui manager")
    parser.add_argument("command", choices=[
        "status", "servers", "set-mode", "set-server", "start", "stop", "restart"])
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
    return 2


if __name__ == "__main__":
    sys.exit(main())
