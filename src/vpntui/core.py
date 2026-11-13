"""Locate or install the Xray-core binary.

The core is deliberately *not* embedded in vpntui: Xray has its own release
cycle and security advisories.  Resolution order:

1. ``VPNTUI_XRAY`` environment variable;
2. ``$XDG_DATA_HOME/vpntui/core/current/xray`` (installed by ``vpntui core``);
3. ``xray`` in ``$PATH`` (distribution package);
4. the legacy ``~/.local/opt/xray/xray``.

``vpntui core install`` downloads an official XTLS/Xray-core release and
verifies its SHA-256 digest before installing it into the XDG data directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shutil
import stat
import tempfile
import urllib.request
import zipfile

from . import paths

API = "https://api.github.com/repos/XTLS/Xray-core/releases"
CORE_FILES = ("xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md")
SYSTEM_CORE = pathlib.Path("/usr/local/lib/vpntui/core")
USER_AGENT = "vpntui/1.0"


class CoreError(RuntimeError):
    pass


def find_xray() -> pathlib.Path | None:
    override = os.environ.get("VPNTUI_XRAY")
    if override:
        path = pathlib.Path(override).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return path
    current = paths.CORE_CURRENT / "xray"
    if current.is_file() and os.access(current, os.X_OK):
        return current
    system = SYSTEM_CORE / "current" / "xray"
    if system.is_file() and os.access(system, os.X_OK):
        return system
    found = shutil.which("xray")
    if found:
        return pathlib.Path(found)
    if paths.LEGACY_XRAY.is_file() and os.access(paths.LEGACY_XRAY, os.X_OK):
        return paths.LEGACY_XRAY
    return None


def xray_version(binary: pathlib.Path | None = None) -> str | None:
    binary = binary or find_xray()
    if not binary:
        return None
    import subprocess
    try:
        result = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    first = (result.stdout or result.stderr).splitlines()
    return first[0].strip() if first else None


def asset_name() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "64", "amd64": "64",
        "aarch64": "arm64-v8a", "arm64": "arm64-v8a",
        "armv7l": "arm32-v7a", "armv7": "arm32-v7a",
        "armv6l": "arm32-v6", "i686": "32", "i386": "32",
    }
    arch = mapping.get(machine)
    if not arch:
        raise CoreError(f"неизвестная архитектура: {machine}")
    return f"Xray-linux-{arch}.zip"


def _release(version: str | None) -> dict:
    url = f"{API}/latest" if not version or version == "latest" else f"{API}/tags/{version}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except Exception as exc:
        raise CoreError(f"GitHub API недоступен: {exc}") from exc


def _download(url: str, target: pathlib.Path, expected: str | None) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=120) as response, target.open("wb") as fh:
            while True:
                chunk = response.read(1024 * 512)
                if not chunk:
                    break
                fh.write(chunk)
                digest.update(chunk)
    except Exception as exc:
        raise CoreError(f"не удалось скачать {url}: {exc}") from exc
    actual = digest.hexdigest()
    if expected and actual != expected:
        target.unlink(missing_ok=True)
        raise CoreError(f"SHA256 не совпал: ожидался {expected}, получен {actual}")


def _safe_extract(archive: pathlib.Path, target: pathlib.Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            name = member.filename
            if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                raise CoreError(f"небезопасный путь в архиве: {name}")
            if pathlib.PurePosixPath(name).name not in CORE_FILES:
                continue
            destination = target / pathlib.PurePosixPath(name).name
            with zf.open(member) as source, destination.open("wb") as dest:
                shutil.copyfileobj(source, dest)
            if destination.name == "xray":
                destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install(version: str = "latest", assume_yes: bool = False) -> pathlib.Path:
    release = _release(version)
    tag = str(release.get("tag_name") or version)
    asset = next((a for a in release.get("assets", []) if a.get("name") == asset_name()), None)
    if not asset:
        raise CoreError(f"в релизе {tag} нет {asset_name()}")
    expected = str(asset.get("digest") or "")
    expected = expected.split(":", 1)[1] if expected.startswith("sha256:") else (expected or None)
    target = paths.CORE_DIR / tag
    if target.is_dir() and (target / "xray").is_file():
        _activate(target)
        return target
    if not assume_yes:
        print(f"Будет установлен Xray {tag} ({asset_name()}, {asset.get('size', 0) // 1024 // 1024} МБ)")
        print(f"в {target}")
        answer = input("Продолжить? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes", "д", "да"):
            raise CoreError("установка отменена")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vpntui-core-") as tmp:
        archive = pathlib.Path(tmp) / asset_name()
        print(f"Скачиваю {asset['browser_download_url']}")
        _download(str(asset["browser_download_url"]), archive, expected)
        staging = pathlib.Path(tmp) / "staging"
        staging.mkdir()
        _safe_extract(archive, staging)
        if not (staging / "xray").is_file():
            raise CoreError("в архиве нет бинарника xray")
        staging.chmod(0o755)
        if target.exists():
            shutil.rmtree(target)
        staging.rename(target)
    _activate(target)
    print(f"Xray {tag} установлен: {target}")
    return target


def install_system(version: str = "latest", assume_yes: bool = False) -> pathlib.Path:
    """Install a root-owned copy under /usr/local/lib/vpntui/core.

    The root helper refuses to execute user-owned binaries as root; a system
    core avoids that problem while keeping the normal XDG install untouched.
    """
    import subprocess
    stage = install(version, assume_yes=assume_yes)
    tag = stage.name
    target = SYSTEM_CORE / tag
    script = (
        "set -e\n"
        f"install -d -m 0755 {SYSTEM_CORE}\n"
        f"rm -rf {target}\n"
        f"cp -a {stage} {target}\n"
        f"chown -R root:root {target}\n"
        f"chmod 0755 {target} {target}/xray\n"
        f"ln -sfn {target} {SYSTEM_CORE}/current\n"
    )
    result = subprocess.call(["sudo", "bash", "-c", script])
    if result != 0:
        raise CoreError("не удалось установить системное ядро (sudo)")
    return target


def _activate(target: pathlib.Path) -> None:
    tmp = paths.CORE_CURRENT.with_name("current.tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(target)
    os.replace(tmp, paths.CORE_CURRENT)


def installed() -> list[dict]:
    result = []
    if not paths.CORE_DIR.is_dir():
        return result
    for path in sorted(paths.CORE_DIR.iterdir()):
        if path.is_dir() and (path / "xray").is_file():
            result.append({"version": path.name, "path": str(path),
                           "current": path == paths.CORE_CURRENT.resolve()})
    return result


def remove(version: str) -> bool:
    target = paths.CORE_DIR / version
    if not target.is_dir():
        return False
    if paths.CORE_CURRENT.resolve() == target.resolve():
        paths.CORE_CURRENT.unlink(missing_ok=True)
    shutil.rmtree(target)
    return True
