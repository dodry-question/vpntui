"""Command line interface for vpntui."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import __version__, apps, core, paths, setup, subscription
from .util import load_json, save_json


def _prepare() -> None:
    paths.ensure_layout()
    apps.migrate_legacy()


def cmd_tui() -> int:
    from .app import main as app_main
    return app_main(["--tui"])


def cmd_status() -> int:
    from .app import cmd_status
    return cmd_status()


def cmd_launch(app_id: str, extra: list[str]) -> int:
    from .app import cmd_launch
    return cmd_launch([app_id, *extra])


def cmd_sub(args) -> int:
    try:
        if args.action == "import":
            count = subscription.import_source(args.source, _headers(args.header))
            print(f"Импортировано серверов: {count}")
            print(f"Серверы: {paths.CANDS}")
            print(f"Подписка: {paths.SUBS}")
        elif args.action == "update":
            count = subscription.update()
            print(f"Обновлено серверов: {count}")
        elif args.action == "list":
            for row in subscription.summary():
                mark = "*" if row["index"] == _current_index() else " "
                print(f"{mark} {row['index']:>2}  {row['name']}  "
                      f"{row['host']}:{row['port']} [{row['protocol']}]")
    except subscription.SubscriptionError as exc:
        print(f"Ошибка подписки: {exc}", file=sys.stderr)
        return 1
    return 0


def _headers(values: list[str] | None) -> dict:
    result = {}
    for value in values or []:
        if ":" in value:
            key, val = value.split(":", 1)
            result[key.strip()] = val.strip()
    return result


def _current_index() -> int:
    try:
        return int((load_json(paths.STATE, {}) or {}).get("server_index", 0))
    except (TypeError, ValueError):
        return 0


def cmd_core(args) -> int:
    if args.action == "install":
        try:
            if args.system:
                target = core.install_system(args.version, args.yes)
            else:
                target = core.install(args.version, args.yes)
        except core.CoreError as exc:
            print(f"Ошибка ядра: {exc}", file=sys.stderr)
            return 1
        print(target)
    elif args.action == "update":
        try:
            target = core.install("latest", args.yes)
        except core.CoreError as exc:
            print(f"Ошибка ядра: {exc}", file=sys.stderr)
            return 1
        print(f"Обновлено: {target}")
    elif args.action == "list":
        rows = core.installed()
        if not rows:
            print("Ядро не установлено")
        for row in rows:
            print(f"{'*' if row['current'] else ' '} {row['version']}  {row['path']}")
    elif args.action == "remove":
        print("удалено" if core.remove(args.version or "") else "не найдено")
    elif args.action == "path":
        print(core.find_xray() or "не найдено")
    return 0


def cmd_apps(args) -> int:
    _prepare()
    if args.action == "list":
        configured = apps.load_apps()
        if args.json:
            print(json.dumps(configured, ensure_ascii=False, indent=1))
            return 0
        for entry in configured:
            flag = "VPN" if entry.get("always_vpn") else "   "
            print(f"{flag}  {entry['id']:<28} {entry.get('name','')}")
        return 0
    if args.action == "installed":
        for info in apps.discover_installed():
            print(f"{info['id']:<36} {info['name']}")
        return 0
    if args.action == "add":
        if args.cmd:
            entry = {"id": args.id or "custom", "name": args.name or args.id or "custom",
                     "cmd": args.cmd}
        else:
            infos = apps.discover_installed()
            needle = (args.id or "").lower()
            entry = next((i for i in infos if i["id"].lower() == needle), None) or \
                next((i for i in infos if needle and needle in i["name"].lower()), None)
            if not entry:
                print(f"Не найдено приложение: {args.id}", file=sys.stderr)
                return 1
        if args.always:
            entry["always_vpn"] = True
        try:
            entry = apps.enable_always(entry, bool(entry.get("always_vpn")),
                                       write_desktop=bool(entry.get("desktop")))
        except apps.DesktopError as exc:
            print(f"Ошибка ярлыка: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(entry, ensure_ascii=False, indent=1))
        return 0
    if args.action == "remove":
        print("удалено" if apps.remove_app(args.id) else "не найдено")
        return 0
    if args.action == "always":
        entry = apps.get_app(args.id)
        if not entry:
            print("не найдено", file=sys.stderr)
            return 1
        try:
            apps.enable_always(entry, args.value == "on")
        except apps.DesktopError as exc:
            print(f"Ошибка ярлыка: {exc}", file=sys.stderr)
            return 1
        print(f"{args.id}: {'always VPN' if args.value == 'on' else 'direct'}")
        return 0
    if args.action == "server":
        entry = apps.get_app(args.id)
        if not entry:
            print("не найдено", file=sys.stderr)
            return 1
        entry["server"] = "auto" if args.value == "auto" else int(args.value)
        apps.add_app(entry)
        print(f"{args.id}: сервер {entry['server']}")
        return 0
    if args.action == "launch":
        entry = apps.get_app(args.id)
        if not entry:
            print("не найдено", file=sys.stderr)
            return 1
        return apps.run_entry(entry)
    return 2


def cmd_server(args) -> int:
    from . import manager
    _prepare()
    if args.action == "list":
        return manager.cmd_servers(False)
    if args.action == "set":
        ok = manager.set_server(int(args.value))
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    return 2


def cmd_mode(args) -> int:
    from . import manager
    _prepare()
    ok = manager.set_mode(args.value)
    print("OK" if ok else "FAIL")
    return 0 if ok else 1


def cmd_service(args) -> int:
    from . import manager
    _prepare()
    result = getattr(manager, args.action)()
    print("OK" if result else "FAIL")
    return 0 if result else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpntui",
        description="Per-application VPN control panel built on Xray",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vpntui                         open the TUI\n"
            "  vpntui sub import <url|file>   import a subscription\n"
            "  vpntui apps add brave --always toggle Brave's desktop rule\n"
            "  vpntui core install            download Xray with SHA-256 check\n"
            "  vpntui setup                   install the root helper\n"
        ))
    parser.add_argument("--version", action="version", version=f"vpntui {__version__}")
    parser.add_argument("--status", action="store_true", help="short status (legacy)")
    parser.add_argument("--launch", metavar="APP", help="launch an app through VPN (legacy)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("tui", help="open the terminal UI")

    p = sub.add_parser("status", help="print status")
    p.set_defaults(func=lambda a: cmd_status())

    p = sub.add_parser("launch", help="launch an application through VPN")
    p.add_argument("app")
    p.add_argument("extra", nargs=argparse.REMAINDER)

    p = sub.add_parser("launch-desktop", help="desktop-entry shim")
    p.add_argument("app")
    p.add_argument("extra", nargs=argparse.REMAINDER)

    p = sub.add_parser("sub", help="subscription management")
    sp = p.add_subparsers(dest="action", required=True)
    q = sp.add_parser("import", help="import URL or file")
    q.add_argument("source")
    q.add_argument("--header", action="append", help="HTTP header, e.g. 'User-Agent: ...'")
    sp.add_parser("update", help="refresh the saved URL")
    sp.add_parser("list", help="list servers")

    p = sub.add_parser("core", help="Xray core management")
    sp = p.add_subparsers(dest="action", required=True)
    q = sp.add_parser("install")
    q.add_argument("version", nargs="?", default="latest")
    q.add_argument("--yes", action="store_true")
    q.add_argument("--system", action="store_true", help="install root-owned into /usr/local/lib/vpntui")
    q = sp.add_parser("update")
    q.add_argument("--yes", action="store_true")
    sp.add_parser("list")
    q = sp.add_parser("remove")
    q.add_argument("version")
    sp.add_parser("path")

    p = sub.add_parser("apps", help="installed applications and rules")
    sp = p.add_subparsers(dest="action", required=True)
    q = sp.add_parser("list")
    q.add_argument("--json", action="store_true")
    sp.add_parser("installed")
    q = sp.add_parser("add")
    q.add_argument("id", nargs="?")
    q.add_argument("--name")
    q.add_argument("--cmd", nargs=argparse.REMAINDER)
    q.add_argument("--always", action="store_true")
    q = sp.add_parser("remove")
    q.add_argument("id")
    q = sp.add_parser("always")
    q.add_argument("id")
    q.add_argument("value", choices=["on", "off"])
    q = sp.add_parser("server")
    q.add_argument("id")
    q.add_argument("value")
    q = sp.add_parser("launch")
    q.add_argument("id")

    p = sub.add_parser("server", help="select the default server")
    sp = p.add_subparsers(dest="action", required=True)
    sp.add_parser("list")
    q = sp.add_parser("set")
    q.add_argument("value")

    p = sub.add_parser("mode", help="global Xray mode")
    p.add_argument("value", choices=["proxy", "vpn"])

    p = sub.add_parser("service", help="global Xray user service")
    p.add_argument("action", choices=["start", "stop", "restart", "status"])

    p = sub.add_parser("setup", help="install helper and desktop entry")
    p.add_argument("--no-helper", action="store_true")
    p.add_argument("--no-desktop", action="store_true")
    p.add_argument("--with-core", action="store_true")
    p.add_argument("--yes", action="store_true")

    p = sub.add_parser("uninstall", help="remove helper and desktop entry")
    p.add_argument("--purge", action="store_true", help="also delete configs and installed core")

    sub.add_parser("doctor", help="diagnose the installation")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        _prepare()
        return cmd_tui()
    if argv[0] == "--status":
        _prepare()
        return cmd_status()
    if argv[0] == "--launch":
        _prepare()
        return cmd_launch(argv[1], argv[2:])
    if argv[0] in ("-h", "--help"):
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.command in ("status", "tui", "doctor"):
        _prepare()
    if args.command == "launch":
        _prepare()
        return cmd_launch(args.app, args.extra)
    if args.command == "launch-desktop":
        _prepare()
        return apps.launch_desktop(args.app, list(args.extra))
    if args.command == "sub":
        _prepare()
        return cmd_sub(args)
    if args.command == "core":
        return cmd_core(args)
    if args.command == "apps":
        return cmd_apps(args)
    if args.command == "server":
        return cmd_server(args)
    if args.command == "mode":
        return cmd_mode(args)
    if args.command == "service":
        return cmd_service(args)
    if args.command == "setup":
        return setup.setup(not args.no_helper, not args.no_desktop, args.with_core, args.yes)
    if args.command == "uninstall":
        return setup.uninstall(args.purge)
    if args.command == "doctor":
        return setup.doctor()
    parser.print_help()
    return 0
