"""Verify parsing against sample machine backup logs."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from gem300_log_analyzer.analysis.gem300_trace import extract_gem300_events
from gem300_log_analyzer.analysis.keyword_search import search_keywords
from gem300_log_analyzer.export.report_export import generate_report
from gem300_log_analyzer.parsers.log_loader import parse_paths

SAMPLE_MMI = Path(r"d:\01_Project\02_BOC_COB\80_MachineBackup\20260619\2026_06_19.log")
SAMPLE_SECS = Path(r"d:\01_Project\02_BOC_COB\80_MachineBackup\20260619\2026-06-19 18.log")
FIXTURE_MMI = ROOT / "tests" / "fixtures" / "mmi_sample.log"
FIXTURE_SECS = ROOT / "tests" / "fixtures" / "secs_sample.log"


def main() -> int:
    paths = [p for p in [SAMPLE_MMI, SAMPLE_SECS] if p.exists()]
    use_full = bool(paths)
    if not paths:
        paths = [p for p in [FIXTURE_MMI, FIXTURE_SECS] if p.exists()]
    if not paths:
        print("No sample or fixture log files found.")
        return 1

    entries, skipped, file_types = parse_paths(paths, skip_setup_dump=True)
    gem300 = extract_gem300_events(entries)
    matches = search_keywords(entries, "CarrierObject::StateChange")
    report = generate_report(
        entries,
        gem300,
        [],
        matches,
        keyword="CarrierObject::StateChange",
        skipped_setup_lines=skipped,
        file_summary={k: v.value for k, v in file_types.items()},
    )

    print(f"Parsed entries: {len(entries)}")
    print(f"Skipped setup lines: {skipped}")
    print(f"File types: {file_types}")
    print(f"GEM300 events: {len(gem300)}")
    print(f"Keyword matches: {len(matches)}")
    print(f"Using {'full backup' if use_full else 'fixture'} logs")

    assert len(entries) > 0, "Expected parsed entries"
    assert entries == sorted(
        entries, key=lambda e: (e.timestamp, e.source_file, e.line_no)
    ), "Expected entries to be sorted as one combined timeline"
    assert any(e.log_type.value == "MMI" for e in entries), "Expected MMI entries"
    assert any(e.log_type.value == "SECS" for e in entries), "Expected SECS entries"
    assert len(gem300) > 0, "Expected GEM300 events"
    assert len(matches) > 0, "Expected keyword matches"
    assert "GEM300 State Timeline" in report

    event_types = {e.event_type for e in gem300}
    if SAMPLE_MMI.exists():
        expected = {
            "CarrierObject::StateChange",
            "LoadPortObject::StateChange",
            "SubstrateObject::Initialize",
            "[CMS]",
        }
        found = expected & event_types
        print(f"GEM300 event types found: {sorted(event_types)}")
        assert found, f"Expected at least some of {expected}"
    else:
        print(f"GEM300 event types (fixture): {sorted(event_types)}")

    print("All verification checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
