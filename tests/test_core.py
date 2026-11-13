import shutil
import sys

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


def test_entry_command_ignores_foreign_launcher(tmp_path, monkeypatch):
    from vpntui import paths

    foreign = tmp_path / "bin" / "vpntui"
    foreign.parent.mkdir()
    foreign.write_text("#!/bin/sh\n")
    monkeypatch.setattr(shutil, "which", lambda name: str(foreign))
    monkeypatch.setattr(sys, "executable", str(tmp_path / "other" / "python"))
    assert paths.entry_command() == [str(tmp_path / "other" / "python"), "-m", "vpntui"]

    venv = tmp_path / "venv" / "bin" / "vpntui"
    venv.parent.mkdir(parents=True)
    venv.write_text("")
    monkeypatch.setattr(shutil, "which", lambda name: str(venv))
    monkeypatch.setattr(sys, "executable", str(venv.parent / "python"))
    assert paths.entry_command() == [str(venv)]
