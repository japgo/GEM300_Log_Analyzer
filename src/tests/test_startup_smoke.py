from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import desktop_app


class _Root:
    def __init__(self) -> None:
        self.updated = False
        self.destroyed = False

    def update_idletasks(self) -> None:
        self.updated = True

    def destroy(self) -> None:
        self.destroyed = True


class _App:
    def __init__(self) -> None:
        self.root = _Root()
        self.run_called = False

    def run(self) -> None:
        self.run_called = True


def test_main_startup_smoke_writes_marker_and_exits(monkeypatch, tmp_path: Path) -> None:
    app = _App()
    marker = tmp_path / "startup-ok.txt"
    monkeypatch.setattr(desktop_app, "Gem300DesktopApp", lambda: app)
    monkeypatch.setenv(desktop_app.STARTUP_SMOKE_MARKER_ENV, str(marker))

    desktop_app.main()

    assert marker.read_text(encoding="utf-8") == (
        f"GEM300 Log Analyzer v{desktop_app.__version__} startup OK"
    )
    assert app.root.updated is True
    assert app.root.destroyed is True
    assert app.run_called is False
