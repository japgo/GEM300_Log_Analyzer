from __future__ import annotations

from gem300_log_analyzer.analysis.s6f11_variables import annotate_s6f11_variables
from types import SimpleNamespace


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


if __name__ == "__main__":
    test_annotate_s6f11_adds_ceid_event_name_and_vid_comments()
    test_annotate_s6f11_adds_ceid_event_name_without_report_variables()