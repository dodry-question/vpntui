"""``vpntui setup``: dependencies, root helper, desktop entry."""
from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile

from . import core, paths

HELPER_SOURCE = paths.PACKAGE_DIR / "privileged" / "run-vpn"
BROWSER_SOURCE = paths.PACKAGE_DIR / "data" / "browser-vpn.sh"

DEPENDENCIES = {
    "ip": "iproute2",
    "unshare": "util-linux",
    "setpriv": "util-linux",
    "slirp4netns": "slirp4netns",
    "curl": "curl",
    "notify-send": "libnotify",
    "systemctl": "systemd",
}


def missing_dependencies() -> dict[str, str]:
    return {cmd: package for cmd, package in DEPENDENCIES.items() if not shutil.which(cmd)}


def _run_sudo(script: str) -> int:
    """Run a root script, letting sudo ask for a password on the terminal."""
    with tempfile.NamedTemporaryFile("w", delete=False, prefix="vpntui-setup-", suffix=".sh") as fh:
        fh.write("set -e\n" + script)
        name = fh.name
    os.chmod(name, 0o700)
    try:
        return subprocess.call(["sudo", "bash", name])
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def helper_script() -> str:
    helper = str(paths.HELPER)
    sudoers = str(paths.SUDOERS)
    user = os.environ.get("USER") or pathlib.Path.home().name
    return f"""
install -D -m 0755 {str(HELPER_SOURCE)!r} {helper!r}
printf '%s\\n' {f'{user} ALL=(root) NOPASSWD: {helper}'!r} > {sudoers!r}
chmod 0440 {sudoers!r}
visudo -cf {sudoers!r} >/dev/null
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F {sudoers!r} {helper!r} >/dev/null 2>&1 || true
fi
echo "helper: $(ls -l {helper!r})"
"""


def install_helper() -> bool:
    print(f"Устанавливаю root-хелпер в {paths.HELPER}")
    print(f"и правило sudo в {paths.SUDOERS}")
    result = _run_sudo(helper_script())
    if result != 0:
        print("Не удалось установить хелпер", file=sys.stderr)
        return False
    check = subprocess.run(["sudo", "-n", "-l", str(paths.HELPER)],
                           capture_output=True, text=True)
    if check.returncode != 0:
        print("sudo -n не работает; проверь /etc/sudoers.d/vpntui", file=sys.stderr)
        return False
    return True


def install_browser_wrapper() -> pathlib.Path:
    target = paths.DATA_DIR / "bin" / "browser-vpn"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BROWSER_SOURCE, target)
    target.chmod(0o755)
    return target


def desktop_entry() -> pathlib.Path:
    executable = shlex.join(paths.entry_command())
    content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=VPN (vpntui)\n"
        "GenericName=Per-app VPN\n"
        "Comment=Run selected applications through Xray, manage servers and rules\n"
        f"Exec={executable}\n"
        "Icon=network-vpn\n"
        "Terminal=true\n"
        "Categories=Network;System;\n"
        "Keywords=vpn;proxy;xray;vpntui;\n"
    )
    target = paths.APPLICATIONS / "vpntui.desktop"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    subprocess.run(["update-desktop-database", str(paths.APPLICATIONS)],
                   capture_output=True)
    return target


def setup(install_helper_flag: bool = True, install_desktop: bool = True,
          install_core: bool = False, assume_yes: bool = False) -> int:
    paths.ensure_layout()
    missing = missing_dependencies()
    if missing:
        packages = " ".join(sorted(set(missing.values())))
        print("Не хватает программ: " + ", ".join(missing))
        print("Fedora:  sudo dnf install " + packages)
        print("Debian:  sudo apt install iproute2 util-linux slirp4netns curl libnotify-bin")
        print("Arch:    sudo pacman -S iproute2 util-linux slirp4netns curl libnotify")
        print("NixOS:   используй nix/module.nix (зависимости ставит Nix)")
        return 1

    install_browser_wrapper()
    print(f"Браузерный wrapper: {paths.DATA_DIR / 'bin' / 'browser-vpn'}")

    if install_core and not core.find_xray():
        print("Ядро Xray не найдено — устанавливаю официальный релиз")
        try:
            core.install("latest", assume_yes=assume_yes)
        except core.CoreError as exc:
            print(f"Не удалось установить ядро: {exc}", file=sys.stderr)
            return 1

    if install_helper_flag:
        if not install_helper():
            return 1
    if install_desktop:
        print(f"Ярлык: {desktop_entry()}")
    print("Готово. Запусти: vpntui")
    return 0


def uninstall(remove_config: bool = False) -> int:
    helper = str(paths.HELPER)
    sudoers = str(paths.SUDOERS)
    script = (
        f"rm -f {sudoers!r} {helper!r}\n"
        f"rmdir --ignore-fail-on-non-empty {str(paths.HELPER.parent)!r} 2>/dev/null || true\n"
    )
    if _run_sudo(script) != 0:
        print("Не удалось удалить root-хелпер", file=sys.stderr)
        return 1
    for path in (paths.APPLICATIONS / "vpntui.desktop",):
        path.unlink(missing_ok=True)
    if remove_config:
        shutil.rmtree(paths.CONFIG_DIR, ignore_errors=True)
        shutil.rmtree(paths.DATA_DIR, ignore_errors=True)
    print("Удалено")
    return 0


def doctor() -> int:
    print(f"vpntui:      {shutil.which('vpntui') or sys.argv[0]}")
    print(f"python:      {sys.version.split()[0]}")
    print(f"config:      {paths.CONFIG_DIR}")
    print(f"data:        {paths.DATA_DIR}")
    print(f"runtime:     {paths.RUNTIME_DIR}")
    xray = core.find_xray()
    print(f"xray:        {xray or 'НЕ НАЙДЕН'}")
    if xray:
        print(f"xray версия: {core.xray_version(xray) or '?'}")
    print(f"хелпер:      {paths.HELPER} {'OK' if paths.HELPER.is_file() else 'НЕ УСТАНОВЛЕН'}")
    if paths.HELPER.is_file():
        check = subprocess.run(["sudo", "-n", "-l", str(paths.HELPER)], capture_output=True)
        print(f"sudo:        {'OK' if check.returncode == 0 else 'нет NOPASSWD-правила'}")
    missing = missing_dependencies()
    print(f"зависимости: {'OK' if not missing else 'не хватает: ' + ', '.join(missing)}")
    print(f"серверов:    {len(__import__('vpntui.subscription', fromlist=['summary']).summary())}")
    return 0
