"""Headless TUI smoke test.

Run in a subprocess so XDG paths are read at import time exactly like in a real
installation, and so no real network/root command can leak into the test.
"""
import os
import subprocess
import sys
import textwrap

SCRIPT = textwrap.dedent("""
    import asyncio
    from textual.widgets import DataTable
    from vpntui import app as ui

    async def main():
        ui.is_active = lambda: False
        ui.service_mono = lambda: 0.0
        ui.read_sessions = lambda: []
        ui.net_bytes = lambda: (0, 0)
        app = ui.VpnTuiApp()
        async with app.run_test(size=(100, 30)) as pilot:
            for width, height in ((100, 30), (72, 22), (60, 20), (80, 24)):
                await pilot.resize_terminal(width, height)
                for number, (page, _) in enumerate(app.NAV, 1):
                    await pilot.press("escape", str(number))
                    await pilot.pause()
                    assert app.current == page, (page, app.current)
                    view = app.query_one(f"#{page}")
                    assert not view.has_class("hidden")
                assert app.current == "apps"
            # toggle a rules-free fake app and verify the desktop rewrite
            app.show_view("apps")
            await pilot.pause()
            table = app.query_one("#apps-table", DataTable)
            assert table.row_count >= 1
            print("OK", len(app.NAV))

    asyncio.run(main())
""")


def test_tui_layout(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "candidates.json").write_text(
        '[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1",'
        '"port":443,"users":[{"id":"u","encryption":"none"}]}]},'
        '"streamSettings":{"network":"tcp","security":"none"}}]')
    (config / "subscription.json").write_text(
        '[{"remarks":"Test","outbounds":[{"protocol":"vless","settings":'
        '{"vnext":[{"address":"127.0.0.1","port":443,"users":'
        '[{"id":"u","encryption":"none"}]}]},"streamSettings":'
        '{"network":"tcp","security":"none"}}]}]')
    (config / "state.json").write_text('{"mode":"proxy","server_index":0}')
    (config / "apps.json").write_text("[]")
    (config / "rules.json").write_text('{"default":"proxy","rules":[]}')

    data = tmp_path / "data"
    (data / "applications").mkdir(parents=True)
    (data / "applications" / "fake.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Fake App\nExec=/bin/true %U\n")

    env = {
        **os.environ,
        "PYTHONPATH": str((__import__("pathlib").Path(__file__).parents[1] / "src")),
        "VPNTUI_CONFIG_DIR": str(config),
        "VPNTUI_DATA_DIR": str(data),
        "VPNTUI_STATE_DIR": str(tmp_path / "state"),
        "VPNTUI_RUNTIME_DIR": str(tmp_path / "run"),
        "VPNTUI_XRAY": "/bin/true",
        "XDG_DATA_HOME": str(data),
        "XDG_DATA_DIRS": str(data),
    }
    result = subprocess.run([sys.executable, "-c", SCRIPT], env=env,
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK 8" in result.stdout
