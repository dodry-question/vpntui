"""Filesystem layout for vpntui.

Everything lives in XDG directories.  ``VPNTUI_CONFIG_DIR``,
``VPNTUI_DATA_DIR``, ``VPNTUI_STATE_DIR`` and ``VPNTUI_RUNTIME_DIR`` can
override individual locations (handy for tests and for NixOS modules).

The old, hard-coded layout (``~/.config/xray`` and ``~/scripts/vpn``) is
only read for a one-time migration; the application never writes there.
"""
from __future__ import annotations

import os
import pathlib
import shutil

APP = "vpntui"


def _xdg(var: str, default: str) -> pathlib.Path:
    value = os.environ.get(var)
    base = pathlib.Path(value).expanduser() if value else pathlib.Path.home() / default
    return base


def _override(var: str, fallback: pathlib.Path) -> pathlib.Path:
    value = os.environ.get(var)
    return pathlib.Path(value).expanduser() if value else fallback


HOME = pathlib.Path.home()

CONFIG_DIR = _override("VPNTUI_CONFIG_DIR", _xdg("XDG_CONFIG_HOME", ".config") / APP)
DATA_DIR = _override("VPNTUI_DATA_DIR", _xdg("XDG_DATA_HOME", ".local/share") / APP)
STATE_DIR = _override("VPNTUI_STATE_DIR", _xdg("XDG_STATE_HOME", ".local/state") / APP)
CACHE_DIR = _override("VPNTUI_CACHE_DIR", _xdg("XDG_CACHE_HOME", ".cache") / APP)
RUNTIME_DIR = _override("VPNTUI_RUNTIME_DIR", pathlib.Path("/run/vpntui"))

# --- configuration ---------------------------------------------------------
CANDS = CONFIG_DIR / "candidates.json"
SUBS = CONFIG_DIR / "subscription.json"
STATE = CONFIG_DIR / "state.json"
RULES = CONFIG_DIR / "rules.json"
SETTINGS = CONFIG_DIR / "settings.json"
APPS = CONFIG_DIR / "apps.json"
GLOBAL_CONFIG = CONFIG_DIR / "config.json"
SOURCE = CONFIG_DIR / "subscription-source.json"  # url, update time (0600 if it contains a token)

# --- installed data --------------------------------------------------------
CORE_DIR = DATA_DIR / "core"
CORE_CURRENT = CORE_DIR / "current"
DESKTOP_BACKUPS = DATA_DIR / "desktop-backups"

# --- state / logs ----------------------------------------------------------
SESSIONS = RUNTIME_DIR / "sessions"
LAST_LOG = RUNTIME_DIR / "last.log"
LOG_DIR = STATE_DIR / "logs"

# --- package data ----------------------------------------------------------
PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
RULES_TEMPLATE = PACKAGE_DIR / "data" / "rules.default.json"
BROWSER_WRAPPER = PACKAGE_DIR / "data" / "browser-vpn.sh"

# --- system integration ----------------------------------------------------
SERVICE = "vpntui-xray.service"
HELPER = pathlib.Path(os.environ.get("VPNTUI_HELPER", "/usr/local/lib/vpntui/run-vpn"))
SUDOERS = pathlib.Path("/etc/sudoers.d/vpntui")
AUTOSTART = _xdg("XDG_CONFIG_HOME", ".config") / "autostart" / "vpntui.desktop"
APPLICATIONS = _xdg("XDG_DATA_HOME", ".local/share") / "applications"

# --- legacy layout (read-only) --------------------------------------------
LEGACY_CONFIG = HOME / ".config" / "xray"
LEGACY_VPN_CONFIG = HOME / ".config" / "vpn"
LEGACY_VPN = HOME / "scripts" / "vpn"
LEGACY_XRAY = HOME / ".local" / "opt" / "xray" / "xray"
LEGACY_QODER_DESKTOP = APPLICATIONS / "qoder.desktop"

FILE_MAP = {
    LEGACY_CONFIG / "candidates.json": CANDS,
    LEGACY_CONFIG / "subscription.json": SUBS,
    LEGACY_CONFIG / "state.json": STATE,
    LEGACY_CONFIG / "rules.json": RULES,
    LEGACY_CONFIG / "config.json": GLOBAL_CONFIG,
    LEGACY_VPN_CONFIG / "settings.json": SETTINGS,
    LEGACY_VPN_CONFIG / "apps.json": APPS,
}


def ensure_layout() -> None:
    """Create the XDG directories and migrate the old layout once."""
    for path in (CONFIG_DIR, DATA_DIR, STATE_DIR, CACHE_DIR, CORE_DIR,
                 DESKTOP_BACKUPS, LOG_DIR):
        path.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        try:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    for source, target in FILE_MAP.items():
        if target.exists() or not source.is_file():
            continue
        try:
            shutil.copy2(source, target)
        except OSError:
            continue
    if not RULES.exists() and RULES_TEMPLATE.is_file():
        shutil.copy2(RULES_TEMPLATE, RULES)
    for secret in (SUBS, SOURCE):
        try:
            if secret.exists():
                secret.chmod(0o600)
        except OSError:
            pass
