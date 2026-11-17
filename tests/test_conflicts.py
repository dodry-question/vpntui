import json

from vpntui import apps, conflicts, globalconfig, paths


def _quiet(monkeypatch):
    """Silence every host probe so tests never depend on the test machine."""
    monkeypatch.setattr(conflicts, "_run", lambda *a, **k: "")
    monkeypatch.setattr(conflicts, "_active", lambda unit: False)
    monkeypatch.setattr(conflicts, "_pgrep", lambda *names: False)
    monkeypatch.setattr(conflicts, "listening_ports", lambda: set())
    monkeypatch.setattr(conflicts, "policy_tables", lambda: [])
    monkeypatch.setattr(conflicts, "default_routes", lambda: [])
    monkeypatch.setattr(conflicts.shutil, "which", lambda name: None)


def test_warp_connected_is_a_blocker(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(conflicts, "warp_state", lambda: "Connected")
    monkeypatch.setattr(conflicts.shutil, "which",
                        lambda name: "/usr/bin/warp-cli" if name == "warp-cli" else None)

    findings = conflicts.scan()
    warp = next(f for f in findings if f.id == "warp")
    assert warp.severity == "critical"
    assert warp.auto is True
    assert conflicts.worst(findings) == "critical"
    assert any(f.id == "warp" for f in conflicts.blockers(findings))


def test_zapret_is_reported_and_auto_fixed(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(conflicts, "warp_state", lambda: "")
    monkeypatch.setattr(conflicts, "_active", lambda unit: unit == "zapret")
    monkeypatch.setattr(conflicts, "listening_ports",
                        lambda: {globalconfig.DEFAULT_SOCKS, globalconfig.DEFAULT_HTTP})

    findings = conflicts.scan(running=True)
    zapret = next(f for f in findings if f.id == "zapret")
    assert zapret.severity == "warn"
    assert zapret.auto is True
    # our own ports busy while running are not a conflict
    assert not any(f.id == "ports" and f.severity == "warn" for f in findings)
    assert conflicts.worst(findings) == "warn"


def test_busy_ports_are_reported_when_stopped(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(conflicts, "warp_state", lambda: "")
    monkeypatch.setattr(conflicts, "listening_ports",
                        lambda: {globalconfig.DEFAULT_SOCKS})

    findings = conflicts.scan(running=False)
    ports = next(f for f in findings if f.id == "ports")
    assert ports.severity == "warn"
    assert ports.auto is True


def test_ensure_ports_keeps_free_ports(monkeypatch, tmp_path):
    monkeypatch.setattr(globalconfig, "port_free", lambda port, host="127.0.0.1": True)
    state = {"mode": "vpn", "server_index": 0}
    ports = globalconfig.ensure_ports(state)
    assert ports == {"socks": globalconfig.DEFAULT_SOCKS,
                     "http": globalconfig.DEFAULT_HTTP}
    assert state["ports"]["socks"] == globalconfig.DEFAULT_SOCKS


def test_ensure_ports_moves_when_busy(monkeypatch):
    busy = {globalconfig.DEFAULT_SOCKS, globalconfig.DEFAULT_HTTP}
    monkeypatch.setattr(globalconfig, "port_free",
                        lambda port, host="127.0.0.1": port not in busy)
    state = {"mode": "vpn", "server_index": 0}
    ports = globalconfig.ensure_ports(state)
    assert ports["socks"] not in busy and ports["http"] not in busy
    assert ports["socks"] != ports["http"]


def test_ensure_ports_never_moves_while_running(monkeypatch):
    monkeypatch.setattr(globalconfig, "port_free", lambda *a, **k: False)
    state = {"mode": "vpn", "server_index": 0,
             "ports": {"socks": 10820, "http": 10821}}
    ports = globalconfig.ensure_ports(state, running=True)
    assert ports == {"socks": 10820, "http": 10821}


def test_custom_command_gets_launcher(tmp_path, monkeypatch):
    root = tmp_path / "applications"
    root.mkdir()
    monkeypatch.setattr(paths, "APPLICATIONS", root)
    monkeypatch.setattr(paths, "APPS", tmp_path / "apps.json")
    monkeypatch.setattr(paths, "DESKTOP_BACKUPS", tmp_path / "backups")

    entry = apps.enable_always(
        {"id": "mycmd", "name": "My Cmd", "cmd": ["/bin/true", "--x"]}, True)

    assert entry["always_vpn"] is True
    launcher = root / "vpntui-mycmd.desktop"
    assert launcher.is_file()
    text = launcher.read_text()
    assert "launch-desktop" in text and "mycmd" in text
    assert json.loads((tmp_path / "apps.json").read_text())[0]["id"] == "mycmd"

    assert apps.remove_app("mycmd")
    assert not launcher.exists()
    assert json.loads((tmp_path / "apps.json").read_text()) == []


def test_ensure_launcher_keeps_existing_desktop(tmp_path, monkeypatch):
    root = tmp_path / "applications"
    root.mkdir()
    desktop = root / "real.desktop"
    desktop.write_text("[Desktop Entry]\nType=Application\nName=Real\nExec=/bin/true\n")
    monkeypatch.setattr(paths, "APPLICATIONS", root)

    entry = apps.ensure_launcher({"id": "real", "name": "Real", "cmd": ["/bin/true"],
                                  "desktop": str(desktop)})
    assert entry["desktop"] == str(desktop)
    assert not entry.get("synthetic")
    assert sorted(p.name for p in root.iterdir()) == ["real.desktop"]
