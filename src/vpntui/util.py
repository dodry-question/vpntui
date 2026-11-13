"""Small shared helpers."""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess

EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002190-\U000021FF"
    "\U0000FE00-\U0000FE0F\U0000200D\U000020E3\U00002B00-\U00002BFF]+"
)


def clean(text: str | None) -> str:
    return re.sub(r"\s+", " ", EMOJI.sub(" ", text or "")).strip(" -—·|")


def sh(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def load_json(path, default):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except Exception:
        return default


def save_json(path, data, mode: int | None = None) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    if mode is not None:
        tmp.chmod(mode)
    os.replace(tmp, path)


def notify(title: str, body: str, urgency: str = "normal", quiet: bool = False) -> None:
    if quiet or not shutil.which("notify-send"):
        return
    subprocess.Popen(
        ["notify-send", "-a", "vpntui", "-u", urgency, "-i", "network-vpn", title, body],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def which(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None
