from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from gem300_log_analyzer.analysis.s6f11_variables import annotate_s6f11_variables
from gem300_log_analyzer.models import LogEntry, LogType
from gem300_log_analyzer.parsers.log_loader import apply_reference_data


S6F11_MESSAGE = """S6F11 W
<L [3]>
  <U4 [1] 0>
  <U4 [1] 777>
  <L [1]>
    <L [2]>
      <U4 [1] 10>
      <L [1]>
        <A [3] ABC>
"""


def test_annotate_s6f11_adds_ceid_event_name_and_vid_comments() -> None:
    text = annotate_s6f11_variables(
        S6F11_MESSAGE,
        {10: [SimpleNamespace(vid=1001, name="CarrierID")]},
        {777: "Carrier Arrived"},
    )

    assert "<U4 [1] 777> // (CEID 777) Carrier Arrived" in text
    assert "<A [3] ABC> // (1001) CarrierID" in text


def test_annotate_s6f11_adds_ceid_event_name_without_report_variables() -> None:
    text = annotate_s6f11_variables(S6F11_MESSAGE, event_names={777: "Carrier Arrived"})

    assert "<U4 [1] 777> // (CEID 777) Carrier Arrived" in text


def test_reference_enrichment_preserves_raw_message() -> None:
    entry = LogEntry(
        timestamp=datetime(2026, 8, 28, 10, 0),
        log_type=LogType.SECS,
        source_file="2026-08-28 10.log",
        message=S6F11_MESSAGE,
        line_no=1,
        ceid=777,
    )

    apply_reference_data(
        [entry],
        {777: "Carrier Arrived"},
        {10: [SimpleNamespace(vid=1001, name="CarrierID")]},
    )

    assert entry.message == S6F11_MESSAGE
    assert entry.event_name == "Carrier Arrived"
    assert entry.annotated_message is not None
    assert "Carrier Arrived" in entry.display_message
    assert "CarrierID" in entry.display_message


if __name__ == "__main__":
    test_annotate_s6f11_adds_ceid_event_name_and_vid_comments()
    test_annotate_s6f11_adds_ceid_event_name_without_report_variables()
