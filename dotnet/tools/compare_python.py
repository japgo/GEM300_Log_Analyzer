"""Compare C# ordering/message semantics against the existing Python parser."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "src"))
from gem300_log_analyzer.parsers.log_loader import parse_paths
from gem300_log_analyzer.analysis.keyword_search import normalize_sxfy_w

paths = sys.argv[1:]
entries, _, _ = parse_paths(paths, max_workers=1)
digest = hashlib.sha256()
for entry in entries:
    kind = "Mmi" if entry.log_type.value == "MMI" else "Secs"
    value = f"{entry.display_time}|{kind}|{entry.source_file}|{entry.line_no}|{normalize_sxfy_w(entry.message)}\n"
    digest.update(value.encode("utf-8"))
expected = f"count={len(entries)} sha256={digest.hexdigest()}"
dotnet = os.environ.get("GEM300_DOTNET", "dotnet")
actual = subprocess.check_output(
    [dotnet, str(root / "dotnet/Gem300.Checks/bin/Release/net10.0/Gem300.Checks.dll"), "--digest", *paths],
    text=True,
).strip()
assert actual == expected, f"C#: {actual}\nPython: {expected}"
print(f"PASS Python / C# parity: {expected}")
