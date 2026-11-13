import json

from vpntui import apps, paths


DESKTOP = """[Desktop Entry]
Type=Application
Name=Fake App
Exec=/bin/true %U
"""


def test_discover_and_toggle(tmp_path, monkeypatch):
    root = tmp_path / "applications"
    root.mkdir()
    desktop = root / "fake.desktop"
    desktop.write_text(DESKTOP)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path))
    monkeypatch.setattr(paths, "APPLICATIONS", root)
    monkeypatch.setattr(paths, "APPS", tmp_path / "apps.json")
    monkeypatch.setattr(paths, "DESKTOP_BACKUPS", tmp_path / "backups")

    found = apps.discover_installed()
    assert [a["name"] for a in found] == ["Fake App"]

    entry = apps.enable_always(found[0], True)
    assert entry["always_vpn"] is True
    text = desktop.read_text()
    assert "launch-desktop" in text and "fake.desktop" in text
    assert (tmp_path / "backups" / "fake.desktop.desktop").read_text() == DESKTOP

    apps.enable_always(apps.get_app("fake.desktop"), False)
    assert desktop.read_text() == DESKTOP


def test_remove_restores_desktop(tmp_path, monkeypatch):
    root = tmp_path / "applications"
    root.mkdir()
    desktop = root / "fake.desktop"
    desktop.write_text(DESKTOP)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path))
    monkeypatch.setattr(paths, "APPLICATIONS", root)
    monkeypatch.setattr(paths, "APPS", tmp_path / "apps.json")
    monkeypatch.setattr(paths, "DESKTOP_BACKUPS", tmp_path / "backups")

    entry = apps.discover_installed()[0]
    apps.enable_always(entry, True)
    assert apps.remove_app("fake.desktop")
    assert desktop.read_text() == DESKTOP
    assert json.loads((tmp_path / "apps.json").read_text()) == []


def test_entry_server_auto(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "STATE", tmp_path / "state.json")
    (tmp_path / "state.json").write_text(json.dumps({"server_index": 7}))
    assert apps.entry_server({"server": "auto"}) == 7
    assert apps.entry_server({"server": 2}) == 2
    assert apps.entry_server({"server": "bad"}) == 7


def test_qoder_migration_keeps_existing_launcher(tmp_path, monkeypatch):
    desktop = tmp_path / "qoder.desktop"
    desktop.write_text("[Desktop Entry]\nType=Application\nName=Qoder\n"
                       "Exec=/home/u/.local/bin/qoder-vpn %U\n")
    wrapper = tmp_path / "qoder-vpn"
    wrapper.write_text("#!/bin/sh\nAPP=/opt/Qoder/qoder\n"
                       "args=(--ozone-platform=x11 --force-device-scale-factor=1.25)\n"
                       "exec run-vpn -- \"$APP\" \"${args[@]}\" --open-file \"$@\"\n")
    monkeypatch.setattr(paths, "LEGACY_QODER_DESKTOP", desktop)
    monkeypatch.setattr(paths, "APPS", tmp_path / "apps.json")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data" / "bin").mkdir(parents=True)
    (tmp_path / "data" / "bin" / "browser-vpn").write_text("#!/bin/sh\n")

    apps.migrate_legacy()
    entry = apps.get_app("qoder")
    assert entry["always_vpn"] is True
    assert entry["managed"] is False
    assert entry["legacy_launcher"].endswith("qoder-vpn")
    assert entry["cmd"][0] == "/opt/Qoder/qoder"
    assert desktop.read_text().splitlines()[3] == "Exec=/home/u/.local/bin/qoder-vpn %U"
    # idempotent
    apps.migrate_legacy()
    assert len([a for a in apps.load_apps() if a["id"] == "qoder"]) == 1
