"""CLI entry: launch Streamlit app."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    app = Path(__file__).resolve().parents[1] / "app.py"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app), *sys.argv[1:]],
        check=False,
    )


if __name__ == "__main__":
    main()
