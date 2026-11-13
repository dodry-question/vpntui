import platform

import pytest

from vpntui import core


def test_asset_name_matches_architecture():
    name = core.asset_name()
    assert name.startswith("Xray-linux-")
    assert name.endswith(".zip")


def test_find_xray_env(tmp_path, monkeypatch):
    binary = tmp_path / "xray"
    binary.write_text("#!/bin/sh\necho 'Xray test'\n")
    binary.chmod(0o755)
    monkeypatch.setenv("VPNTUI_XRAY", str(binary))
    assert core.find_xray() == binary


def test_find_xray_none(tmp_path, monkeypatch):
    monkeypatch.delenv("VPNTUI_XRAY", raising=False)
    monkeypatch.setattr(core.paths, "CORE_CURRENT", tmp_path / "core" / "current")
    monkeypatch.setattr(core.paths, "LEGACY_XRAY", tmp_path / "missing")
    monkeypatch.setattr(core.shutil, "which", lambda name: None)
    assert core.find_xray() is None
