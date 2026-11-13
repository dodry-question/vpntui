"""Installed applications and their per-app VPN rules.

An application entry is a small dict stored in ``apps.json``:

    {
      "id": "qoder",
      "name": "Qoder",
      "cmd": ["/opt/Qoder/qoder", "--ozone-platform=x11"],
      "desktop": "/home/u/.local/share/applications/qoder.desktop",
      "always_vpn": true,
      "server": "auto",          # "auto" = server selected in the Proxy section
      "country": "",
      "managed": false,           # desktop Exec is owned by vpntui
      "original_exec": "...",     # for restoring the desktop file
      "legacy_launcher": "..."    # optional existing wrapper, kept as-is
    }
"""
from __future__ import annotations

import configparser
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys

from . import paths
from .util import load_json, save_json

PLACEHOLDERS = re.compile(r"%[fFuUdDnNickvm]")


def _application_dirs() -> list[pathlib.Path]:
    dirs = [paths.APPLICATIONS]
    value = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    dirs += [pathlib.Path(p) / "applications" for p in value.split(":") if p]
    return [d for d in dirs if d.is_dir()]


def _desktop_id(path: pathlib.Path, root: pathlib.Path) -> str:
    return str(path.relative_to(root)).replace(os.sep, "-")


def parse_exec(value: str) -> list[str]:
    value = PLACEHOLDERS.sub("", value or "").replace("%%", "%").strip()
    try:
        return shlex.split(value)
    except ValueError:
        return []


def desktop_info(path: pathlib.Path, root: pathlib.Path) -> dict | None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return None
    if not parser.has_section("Desktop Entry"):
        return None
    sec = parser["Desktop Entry"]
    if sec.get("Type", "Application") != "Application":
        return None
    if sec.getboolean("Hidden", fallback=False) or sec.getboolean("NoDisplay", fallback=False):
        return None
    exec_line = sec.get("Exec", "").strip()
    cmd = parse_exec(exec_line)
    if not cmd:
        return None
    name = (sec.get("Name") or path.stem).strip()
    return {
        "id": _desktop_id(path, root),
        "name": name,
        "cmd": cmd,
        "icon": sec.get("Icon", ""),
        "desktop": str(path),
        "terminal": sec.getboolean("Terminal", fallback=False),
    }


def discover_installed() -> list[dict]:
    found: dict[str, dict] = {}
    for root in _application_dirs():
        for path in sorted(root.glob("*.desktop")):
            info = desktop_info(path, root)
            if info and info["id"] not in found:
                found[info["id"]] = info
    return sorted(found.values(), key=lambda a: a["name"].lower())


def load_apps() -> list[dict]:
    data = load_json(paths.APPS, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("cmd"), list) or not item["cmd"]:
            continue
        item.setdefault("id", re.sub(r"\W+", "-", str(item.get("name") or "app").lower()).strip("-"))
        item.setdefault("name", item["id"])
        item.setdefault("always_vpn", False)
        item.setdefault("server", "auto")
        item.setdefault("country", "")
        out.append(item)
    return out


def save_apps(apps: list[dict]) -> None:
    save_json(paths.APPS, apps)


def get_app(app_id: str) -> dict | None:
    return next((a for a in load_apps() if a["id"] == app_id), None)


def add_app(entry: dict) -> dict:
    apps = load_apps()
    for i, current in enumerate(apps):
        if current["id"] == entry["id"]:
            apps[i] = {**current, **entry}
            save_apps(apps)
            return apps[i]
    apps.append(entry)
    save_apps(apps)
    return entry


def remove_app(app_id: str, restore_desktop: bool = True) -> bool:
    apps = load_apps()
    entry = next((a for a in apps if a["id"] == app_id), None)
    if not entry:
        return False
    if restore_desktop and entry.get("managed"):
        _write_desktop(entry, enabled=False)
    save_apps([a for a in apps if a["id"] != app_id])
    return True


def _desktop_path(entry: dict) -> pathlib.Path | None:
    raw = entry.get("desktop")
    return pathlib.Path(raw) if raw else None


def _backup(entry: dict, text: str) -> None:
    path = _desktop_path(entry)
    if not path or not path.is_file():
        return
    paths.DESKTOP_BACKUPS.mkdir(parents=True, exist_ok=True)
    backup = paths.DESKTOP_BACKUPS / f"{entry['id']}.desktop"
    if not backup.exists():
        backup.write_text(text)


def _exec_line(entry: dict, enabled: bool) -> str:
    if enabled:
        shim = shlex.join([sys.executable, "-m", "vpntui", "launch-desktop", entry["id"]])
        return f"Exec={shim} %U\n"
    original = entry.get("restore_exec") or entry.get("original_exec") or ""
    if original and not original.startswith("Exec="):
        original = "Exec=" + original
    return f"{original or 'Exec=false'}\n"


def _write_desktop(entry: dict, enabled: bool) -> bool:
    path = _desktop_path(entry)
    if not path or not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    _backup(entry, text)
    lines, replaced = [], False
    for line in text.splitlines(keepends=True):
        if line.startswith("Exec=") and not replaced:
            lines.append(_exec_line(entry, enabled))
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(_exec_line(entry, enabled))
    tmp = path.with_name(path.name + ".tmp-vpntui")
    tmp.write_text("".join(lines), encoding="utf-8")
    os.replace(tmp, path)
    return True


def enable_always(entry: dict, enabled: bool, write_desktop: bool = True) -> dict:
    """Mark an app as always-VPN and optionally rewrite its .desktop Exec."""
    entry = dict(entry)
    entry["always_vpn"] = bool(enabled)
    if write_desktop and entry.get("desktop"):
        path = pathlib.Path(entry["desktop"])
        if path.is_file():
            if "original_exec" not in entry:
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                try:
                    parser.read(path, encoding="utf-8")
                    entry["original_exec"] = parser["Desktop Entry"].get("Exec", "")
                except Exception:
                    entry["original_exec"] = ""
            if _write_desktop(entry, enabled):
                entry["managed"] = True
    add_app(entry)
    return entry


def auto_server() -> int:
    state = load_json(paths.STATE, {}) or {}
    try:
        return int(state.get("server_index", 0))
    except (TypeError, ValueError):
        return 0


def entry_server(entry: dict) -> int:
    value = entry.get("server", "auto")
    if value in (None, "", "auto"):
        return auto_server()
    try:
        return int(value)
    except (TypeError, ValueError):
        return auto_server()


def run_entry(entry: dict, args: list[str] | None = None,
              server: int | None = None, country: str = "") -> int:
    """Launch an app through per-app VPN, keeping any legacy wrapper."""
    args = [a for a in (args or []) if a]
    if args and entry.get("open_file_flag"):
        args = [str(entry["open_file_flag"]), *args]
    legacy = entry.get("legacy_launcher")
    if legacy and pathlib.Path(legacy).is_file() and not args:
        return subprocess.call([legacy])
    env = os.environ.copy()
    for key, value in (entry.get("env") or {}).items():
        if isinstance(key, str) and isinstance(value, str):
            env[key] = value
    env["VPN_APP_NAME"] = str(entry.get("name") or entry["id"])
    cmd = [sys.executable, "-m", "vpntui.runvpn", "-q"]
    index = entry_server(entry) if server is None else server
    cmd += ["-s", str(index)]
    if country or entry.get("country"):
        cmd += ["-c", country or entry["country"]]
    cmd += ["--"] + list(entry["cmd"]) + args
    return subprocess.call(cmd, env=env)


def launch_desktop(app_id: str, args: list[str]) -> int:
    entry = get_app(app_id)
    if not entry:
        return 3
    return run_entry(entry, args)


def migrate_legacy() -> None:
    """Import the old Qoder special case without changing its launcher.

    The old setup rewrote ``qoder.desktop`` to call ``~/.local/bin/qoder-vpn``.
    We keep that file and its Exec line untouched, register Qoder as an
    always-VPN application, and only start managing the desktop file if the
    user toggles the rule later.
    """
    desktop = paths.LEGACY_QODER_DESKTOP
    if not desktop.is_file():
        return
    apps = load_apps()
    qoder = next((a for a in apps if a["id"] == "qoder"), None)
    if qoder and qoder.get("managed"):
        return
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(desktop, encoding="utf-8")
        exec_line = parser["Desktop Entry"].get("Exec", "")
    except Exception:
        return
    cmd = parse_exec(exec_line)
    if not cmd:
        return
    wrapper = cmd[0] if "vpn" in pathlib.Path(cmd[0]).name.lower() else ""
    entry = dict(qoder or {})
    entry.setdefault("id", "qoder")
    entry.setdefault("name", "Qoder")
    entry["desktop"] = str(desktop)
    entry["original_exec"] = exec_line
    # Keep Qoder's real parameters from the existing wrapper (scale factor,
    # --open-file).  The wrapper itself stays untouched unless the user
    # toggles the rule in the new UI.
    wrapper_file = pathlib.Path(wrapper).expanduser() if wrapper else None
    if wrapper_file and wrapper_file.is_file():
        text = wrapper_file.read_text(errors="replace")
        app_match = re.search(r"^APP=(.+)$", text, re.M)
        args_match = re.search(r"^args=\(([^)]*)\)", text, re.M)
        if app_match:
            cmd = [app_match.group(1).strip()]
            if args_match:
                try:
                    cmd += shlex.split(args_match.group(1))
                except ValueError:
                    pass
            entry["cmd"] = cmd
            if "--open-file" in text:
                entry["open_file_flag"] = "--open-file"
    entry.setdefault("cmd", ["/opt/Qoder/qoder", "--ozone-platform=x11"])
    if wrapper:
        entry["always_vpn"] = True
        entry["managed"] = False
        entry["legacy_launcher"] = str(wrapper_file)
        entry.setdefault("restore_exec", shlex.join(entry["cmd"]) + " %U")
    elif "always_vpn" not in entry:
        entry["always_vpn"] = False
    browser = paths.DATA_DIR / "bin" / "browser-vpn"
    if browser.is_file():
        env = dict(entry.get("env") or {})
        env["BROWSER"] = str(browser)
        entry["env"] = env
    add_app(entry)
