from __future__ import annotations

import os
import tomllib
from pathlib import Path
from unittest.mock import patch

from gem300_log_analyzer import __version__
from gem300_log_analyzer.__main__ import main
from gem300_log_analyzer.parsers.mmi_parser import load_level_map


ROOT = Path(__file__).resolve().parents[1]


def test_project_metadata_uses_package_version_as_single_source() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        project = tomllib.load(file)

    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "gem300_log_analyzer.__version__"
    }
    assert project["tool"]["setuptools"]["packages"]["find"]["include"] == [
        "gem300_log_analyzer*"
    ]
    assert f"v{__version__}" in (ROOT / "FEATURE_SPEC.md").read_text(encoding="utf-8")


def test_packaged_level_map_is_used() -> None:
    levels = load_level_map()

    assert levels[2] == "Warning"
    assert levels[31] == "Alarm"


def test_macos_launcher_is_executable_and_documented() -> None:
    launcher = ROOT.parent / "run_desktop_mac.command"

    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    assert "run_desktop_mac.command" in (ROOT / "README.md").read_text(
        encoding="utf-8"
    )


def test_windows_build_publishes_exe_to_release_without_committing_it() -> None:
    workflow = (ROOT.parent / ".github/workflows/windows-build.yml").read_text(
        encoding="utf-8"
    )

    assert "gh release upload" in workflow
    assert '$ErrorActionPreference = "Continue"' in workflow
    assert "if (-not $releaseExists)" in workflow
    assert "git add -f src/dist" not in workflow
    assert "git push" not in workflow


def test_cli_launches_streamlit_app_from_source_root() -> None:
    with patch("gem300_log_analyzer.__main__.subprocess.run") as run:
        main()

    command = run.call_args.args[0]
    assert command[1:3] == ["-m", "streamlit"]
    assert Path(command[4]) == ROOT / "app.py"
