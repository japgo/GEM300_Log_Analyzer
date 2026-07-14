from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desktop_app import Gem300DesktopApp, _calculate_flow_positions


class _Widget:
    def __init__(self, width: int, height: int = 24) -> None:
        self.width = width
        self.height = height
        self.position: tuple[int, int] | None = None
        self.placed_width: int | None = None

    def winfo_reqwidth(self) -> int:
        return self.width

    def winfo_reqheight(self) -> int:
        return self.height

    def grid_forget(self) -> None:
        pass

    def place_forget(self) -> None:
        self.position = None

    def place(self, *, x: int, y: int, width: int | None = None) -> None:
        self.position = (x, y)
        self.placed_width = width


class _Frame:
    def __init__(self) -> None:
        self.height = 0

    def configure(self, *, height: int) -> None:
        self.height = height


class _AppShim:
    _layout_responsive_flow = Gem300DesktopApp._layout_responsive_flow

    def __init__(
        self,
        frame: _Frame,
        widgets: list[_Widget],
        gap: int = 10,
        stretch_index: int | None = None,
    ) -> None:
        self._responsive_flows = {
            frame: {
                "widgets": tuple(widgets),
                "horizontal_padding": 0,
                "gap": gap,
                "stretch_index": stretch_index,
                "layout_signature": None,
            }
        }


def test_flow_uses_one_row_when_width_is_sufficient() -> None:
    assert _calculate_flow_positions([100, 100, 100], 320, gap=10) == [
        (0, 0),
        (0, 1),
        (0, 2),
    ]


def test_flow_moves_only_overflowing_items_when_width_shrinks() -> None:
    assert _calculate_flow_positions([100, 100, 100], 250, gap=10) == [
        (0, 0),
        (0, 1),
        (1, 0),
    ]


def test_responsive_layout_returns_to_one_row_after_expanding() -> None:
    frame = _Frame()
    widgets = [_Widget(100), _Widget(100), _Widget(100)]
    app = _AppShim(frame, widgets)

    app._layout_responsive_flow(frame, 320)
    assert [widget.position for widget in widgets] == [(0, 0), (110, 0), (220, 0)]
    assert frame.height == 24

    app._layout_responsive_flow(frame, 250)
    assert [widget.position for widget in widgets] == [(0, 0), (110, 0), (0, 28)]
    assert frame.height == 52

    app._layout_responsive_flow(frame, 320)
    assert [widget.position for widget in widgets] == [(0, 0), (110, 0), (220, 0)]
    assert frame.height == 24


def test_stretched_item_restores_right_aligned_wide_layout() -> None:
    frame = _Frame()
    widgets = [_Widget(100), _Widget(50), _Widget(50)]
    app = _AppShim(frame, widgets, stretch_index=0)

    app._layout_responsive_flow(frame, 300)

    assert widgets[0].placed_width == 180
    assert [widget.position for widget in widgets] == [(0, 0), (190, 0), (250, 0)]

if __name__ == "__main__":
    test_flow_uses_one_row_when_width_is_sufficient()
    test_flow_moves_only_overflowing_items_when_width_shrinks()
    test_responsive_layout_returns_to_one_row_after_expanding()
    test_stretched_item_restores_right_aligned_wide_layout()