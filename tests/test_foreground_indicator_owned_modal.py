"""Regression for losing all borders while the selected window owns a modal."""
import unittest
from unittest.mock import patch
from contextlib import ExitStack
from flower_control.drivers.computer_native import WindowIdentity
from flower_control.drivers.foreground_indicator import ForegroundIndicator


class OwnedModalLayoutTests(unittest.TestCase):
    def layout(self, *, owner=123, pid=456, visible=True, minimized=False,
               same_process=False, hud_foreground=False, prepare=True):
        identity = WindowIdentity(123, 456, "2026-10-06T00:00:00", 789)
        base = "flower_control.drivers.foreground_indicator."
        with ExitStack() as stack:
            for name, value in (("assert_window", None), ("win32gui.IsIconic", minimized),
               ("win32gui.GetForegroundWindow", 999), ("win32gui.GetAncestor", 999),
               ("win32gui.IsWindow", True), ("win32gui.IsWindowVisible", visible),
               ("win32gui.GetWindow", owner), ("win32api.GetCursorPos", (50, 60)),
               ("win32api.MonitorFromPoint", 2), ("win32api.MonitorFromWindow", 2),
               ("win32api.GetMonitorInfo", {"Work": (0, 0, 1920, 1040)}),
               ("window_geometry", "selected-window-geometry"),
               ("same_process_window", same_process), ("flower_hud_window", hud_foreground)):
                stack.enter_context(patch(base + name, return_value=value))
            stack.enter_context(patch("win32process.GetWindowThreadProcessId", return_value=(1, pid)))
            stack.enter_context(patch("flower_control.drivers.indicator_operator.resolve_operator",
                                      return_value={"label": "GPT"}))
            return ForegroundIndicator(identity, "test", lambda: None,
                                       prepare=prepare)._target_layout()

    def test_owned_visible_modal_retains_selected_window_frame(self):
        self.assertEqual(self.layout(), ("selected-window-geometry", (0, 0, 1920, 1040)))

    def test_same_application_window_retains_the_task_frame(self):
        # Dialogs and tool panels are frequently created without GW_OWNER while
        # they still belong to the running task; the recorded frame dropped out
        # in exactly those cases.
        self.assertEqual(self.layout(owner=0, same_process=True),
                         ("selected-window-geometry", (0, 0, 1920, 1040)))

    def test_another_flower_hud_never_counts_as_the_task_context(self):
        self.assertEqual(self.layout(owner=0, same_process=True, hud_foreground=True),
                         (None, (0, 0, 1920, 1040)))

    def test_unrelated_window_of_the_same_process_hides_the_frame(self):
        self.assertEqual(self.layout(owner=0), (None, (0, 0, 1920, 1040)))

    def test_other_process_with_an_owner_relation_is_not_accepted(self):
        self.assertEqual(self.layout(pid=789), (None, (0, 0, 1920, 1040)))

    def test_hidden_modal_does_not_retain_frame(self):
        self.assertEqual(self.layout(visible=False), (None, (0, 0, 1920, 1040)))

    def test_minimized_selected_window_keeps_preparation_panel_only(self):
        self.assertEqual(self.layout(minimized=True), (None, (0, 0, 1920, 1040)))

    def test_execute_stage_keeps_the_frame_for_any_foreground(self):
        self.assertEqual(self.layout(owner=0, prepare=False),
                         ("selected-window-geometry", (0, 0, 1920, 1040)))


if __name__ == "__main__":
    unittest.main()
