"""Target-local input metadata; never retrieves or stores composition text."""
import ctypes
import time
from ctypes import wintypes
from dataclasses import dataclass, field

import win32con
import win32gui
import win32process

from .computer_native import (NativeInputError, assert_window, plan_batch, send_batch,
                              virtual_key, virtual_desktop)


class GUIThreadInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                ("hwndActive", wintypes.HWND), ("hwndFocus", wintypes.HWND),
                ("hwndCapture", wintypes.HWND), ("hwndMenuOwner", wintypes.HWND),
                ("hwndMoveSize", wintypes.HWND), ("hwndCaret", wintypes.HWND), ("rcCaret", wintypes.RECT)]


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_imm32 = ctypes.WinDLL("imm32", use_last_error=True)
_user32.GetGUIThreadInfo.argtypes = [wintypes.DWORD, ctypes.POINTER(GUIThreadInfo)]
_user32.GetGUIThreadInfo.restype = wintypes.BOOL
_user32.GetKeyboardLayout.argtypes = [wintypes.DWORD]
_user32.GetKeyboardLayout.restype = wintypes.HANDLE
_user32.GetKeyState.argtypes = [ctypes.c_int]
_user32.GetKeyState.restype = wintypes.SHORT
_user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT,
    ctypes.c_size_t, ctypes.c_ssize_t, wintypes.UINT, wintypes.UINT,
    ctypes.POINTER(ctypes.c_size_t)]
_user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
_imm32.ImmGetDefaultIMEWnd.argtypes = [wintypes.HWND]
_imm32.ImmGetDefaultIMEWnd.restype = wintypes.HWND
_imm32.ImmGetContext.argtypes = [wintypes.HWND]
_imm32.ImmGetContext.restype = wintypes.HANDLE
_imm32.ImmReleaseContext.argtypes = [wintypes.HWND, wintypes.HANDLE]
_imm32.ImmReleaseContext.restype = wintypes.BOOL
_imm32.ImmGetCompositionStringW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
_imm32.ImmGetCompositionStringW.restype = wintypes.LONG


@dataclass(frozen=True)
class InputContext:
    focus: int | None = None
    layout: int | None = None
    composition: str = "unknown"
    composition_source: str = field(default="unknown", compare=False)
    composition_bytes: int | None = field(default=None, compare=False)

    def changed(self, current):
        return (self.focus is not None and current.focus != self.focus or
                self.layout is not None and current.layout != self.layout or
                self.composition != "unknown" and current.composition != self.composition)

    def public(self):
        return {"focus_known": self.focus is not None, "layout_known": self.layout is not None,
                "ime_composition": self.composition,
                "ime_composition_source": self.composition_source,
                "imm_composition_bytes": self.composition_bytes,
                "composition_text_read": False}


def check_mouse_receiver(steps, identity, geometry):
    """Inspect only the selected GUI thread's capture and planned hit points."""
    if geometry is None or geometry.identity != identity:
        raise NativeInputError("mouse_geometry_required")
    thread, pid = win32process.GetWindowThreadProcessId(identity.hwnd)
    info = GUIThreadInfo()
    info.cbSize = ctypes.sizeof(info)
    if pid != identity.pid or not _user32.GetGUIThreadInfo(thread, ctypes.byref(info)):
        raise NativeInputError("mouse_receiver_unavailable")
    capture = int(info.hwndCapture or 0)
    if capture:
        if win32gui.GetAncestor(capture, win32con.GA_ROOT) != identity.hwnd:
            raise NativeInputError("mouse_receiver_changed")
        return
    desktop = None
    points = []
    for step in steps:
        mouse = step.raw.data.mi
        if step.raw.type == 0 and mouse.dwFlags & 0x8000:
            desktop = desktop or virtual_desktop()
            points.append((desktop.left + round(mouse.dx * max(1, desktop.width - 1) / 65535),
                           desktop.top + round(mouse.dy * max(1, desktop.height - 1) / 65535)))
    if not points:
        points = [win32gui.GetCursorPos()]
    for point in points:
        receiver = win32gui.WindowFromPoint(point)
        if not receiver or win32gui.GetAncestor(receiver, win32con.GA_ROOT) != identity.hwnd:
            raise NativeInputError("mouse_receiver_changed")


def activation_probe(identity):
    """Fixed target-only GUI flags; no foreign focus/title or input contents."""
    thread, pid = win32process.GetWindowThreadProcessId(identity.hwnd)
    info = GUIThreadInfo()
    info.cbSize = ctypes.sizeof(info)
    known = bool(pid == identity.pid and _user32.GetGUIThreadInfo(thread, ctypes.byref(info)))
    focus = int(info.hwndFocus or 0)
    return {"target_thread_id": thread, "target_enabled": bool(win32gui.IsWindowEnabled(identity.hwnd)),
            "gui_probe_known": known, "active_is_target": bool(known and info.hwndActive == identity.hwnd),
            "focus_root_is_target": bool(known and focus and win32gui.GetAncestor(focus, win32con.GA_ROOT) == identity.hwnd),
            "target_menu_active": bool(known and info.flags & 0x1c)}


def _read_local_candidates(identity, thread, focus) -> dict:
    """Only the locally proven Sogou classes on the selected GUI thread.

    A foreground focus bound to this root is required; missing classes are
    unknown, not proof that no candidate exists. No titles or text are read.
    """
    report = {"source": "sogou_target_thread_windows", "state": "unknown",
              "candidate_visible": None, "composition_window_visible": None,
              "reason": "candidate_binding_unavailable"}
    try:
        assert_window(identity)
        if (not focus or win32gui.GetForegroundWindow() != identity.hwnd or
                win32gui.GetAncestor(focus, win32con.GA_ROOT) != identity.hwnd or
                tuple(win32process.GetWindowThreadProcessId(focus)) != (thread, identity.pid)):
            return report
        ime = int(_imm32.ImmGetDefaultIMEWnd(focus) or 0)
        if (not ime or tuple(win32process.GetWindowThreadProcessId(ime)) != (thread, identity.pid) or
                win32gui.GetClassName(ime).casefold() != "ime" or
                win32gui.GetAncestor(win32gui.GetWindow(ime, win32con.GW_OWNER), win32con.GA_ROOT) != identity.hwnd):
            return report
        layout = int(_user32.GetKeyboardLayout(thread) or 0)
        found = {}
        count = 0
        truncated = False
        failed = False

        def collect(hwnd, _parameter):
            nonlocal count, truncated, failed
            if count >= 64:
                truncated = True
                return False
            count += 1
            try:
                if tuple(win32process.GetWindowThreadProcessId(hwnd)) != (thread, identity.pid):
                    failed = True
                    return False
                name = win32gui.GetClassName(hwnd)
                if name in {"SoPY_Cand", "SoPY_Comp2"}:
                    found.setdefault(name, []).append(hwnd)
                return True
            except (win32gui.error, OSError):
                failed = True
                return False

        win32gui.EnumThreadWindows(thread, collect, None)
        if truncated or failed:
            report["reason"] = "candidate_enumeration_unavailable"
            return report
        assert_window(identity)
        info = GUIThreadInfo()
        info.cbSize = ctypes.sizeof(info)
        if (tuple(win32process.GetWindowThreadProcessId(identity.hwnd)) != (thread, identity.pid) or
                not _user32.GetGUIThreadInfo(thread, ctypes.byref(info)) or
                int(info.hwndFocus or 0) != focus or not layout or
                int(_user32.GetKeyboardLayout(thread) or 0) != layout or
                win32gui.GetForegroundWindow() != identity.hwnd):
            report["reason"] = "candidate_binding_changed"
            return report
        if set(found) == {"SoPY_Cand", "SoPY_Comp2"}:
            visible = {name: any(win32gui.IsWindowVisible(hwnd) for hwnd in windows)
                       for name, windows in found.items()}
            report.update(state="known", reason=None,
                          candidate_visible=visible["SoPY_Cand"],
                          composition_window_visible=visible["SoPY_Comp2"])
        else:
            report["reason"] = "candidate_classes_unavailable"
    except (NativeInputError, win32gui.error, OSError):
        pass
    return report


def read_input_context(identity) -> InputContext:
    """Call under target preflight; unknown IMM is not proof of inactive IME."""
    try:
        thread, pid = win32process.GetWindowThreadProcessId(identity.hwnd)
    except win32gui.error:
        return InputContext()
    if not thread or pid != identity.pid:
        return InputContext()
    info = GUIThreadInfo()
    info.cbSize = ctypes.sizeof(info)
    if not _user32.GetGUIThreadInfo(thread, ctypes.byref(info)):
        return InputContext()
    focus = int(info.hwndFocus or 0)
    if not focus or win32gui.GetAncestor(focus, win32con.GA_ROOT) != identity.hwnd:
        return InputContext()
    layout = int(_user32.GetKeyboardLayout(thread) or 0) or None
    context = _imm32.ImmGetContext(focus)
    count = None
    source = "unknown"
    if not context:
        composition = "unknown"
    else:
        try:
            # NULL buffer / zero length asks only for the byte count.
            count = _imm32.ImmGetCompositionStringW(context, 0x0008, None, 0)
        finally:
            released = _imm32.ImmReleaseContext(focus, context)
        composition = "unknown" if count < 0 or not released else "active" if count > 0 else "inactive"
        if composition != "unknown":
            source = "windows_imm_count"
    if composition != "active":
        candidates = _read_local_candidates(identity, thread, focus)
        if candidates["state"] == "known":
            composition = ("active" if candidates["candidate_visible"] or
                           candidates["composition_window_visible"] else "inactive")
            source = candidates["source"]
    return InputContext(focus, layout, composition, source, count)


def is_target_candidate_window(identity, hwnd) -> bool:
    """Exclude only confirmed local IME windows from business-dialog discovery."""
    try:
        thread, pid = win32process.GetWindowThreadProcessId(identity.hwnd)
        if (pid != identity.pid or tuple(win32process.GetWindowThreadProcessId(hwnd)) != (thread, pid) or
                win32gui.GetClassName(hwnd) not in {"SoPY_Cand", "SoPY_Comp2"}):
            return False
        context = read_input_context(identity)
        probe = _read_local_candidates(identity, thread, context.focus)
        return probe["state"] == "known"
    except (NativeInputError, win32gui.error, OSError):
        return False


def _input_mode_binding(identity):
    """Read only the exact target, its focus and its thread's IME stub."""
    assert_window(identity)
    thread, pid = win32process.GetWindowThreadProcessId(identity.hwnd)
    if not thread or pid != identity.pid:
        raise NativeInputError("input_mode_target_changed")
    info = GUIThreadInfo()
    info.cbSize = ctypes.sizeof(info)
    if not _user32.GetGUIThreadInfo(thread, ctypes.byref(info)):
        raise NativeInputError("input_mode_focus_unavailable")
    focus = int(info.hwndFocus or 0)
    if focus and (win32gui.GetAncestor(focus, win32con.GA_ROOT) != identity.hwnd or
                  tuple(win32process.GetWindowThreadProcessId(focus)) != (thread, pid)):
        raise NativeInputError("input_mode_focus_changed")
    layout = int(_user32.GetKeyboardLayout(thread) or 0)
    if not layout:
        raise NativeInputError("input_mode_layout_unavailable")
    ime = int(_imm32.ImmGetDefaultIMEWnd(focus or identity.hwnd) or 0)
    if not ime:
        raise NativeInputError("input_mode_ime_unavailable")
    if (tuple(win32process.GetWindowThreadProcessId(ime)) != (thread, pid) or
            win32gui.GetClassName(ime).casefold() != "ime"):
        raise NativeInputError("input_mode_ime_changed")
    return (thread, focus, layout, ime,
            win32gui.GetForegroundWindow() == identity.hwnd,
            bool(_user32.GetKeyState(win32con.VK_CAPITAL) & 1))


def read_input_mode(identity) -> dict:
    """Bounded Windows GET metadata, advisory for the confirmed local IME.

    The current user confirmed English and CapsLock are direct input. This
    does not claim to discover private modes in arbitrary future IMEs. Unknown
    Candidate visibility is read separately from the IME's open/native mode.
    """
    report = {"source": "windows_imm_default_ime", "state": "unknown",
              "reason": None, "query_succeeded": False, "queries": {},
              "ime_open": None, "conversion_mode": None, "sentence_mode": None,
              "native_mode": None, "alphanumeric_mode": None,
              "keyboard_layout": None, "layout_known": False,
              "target_is_foreground": None, "focus_known": False,
              "caps_lock": None, "ime_composition": "unknown",
              "ime_composition_source": "unknown", "imm_composition_bytes": None,
              "candidate_visible": None, "composition_window_visible": None,
              "candidate_visibility_source": "sogou_target_thread_windows",
              "candidate_visibility_reason": "candidate_binding_unavailable",
              "composition_text_read": False, "text_read": False,
              "key_dispatch_proves_text_submission": False, "ime_may_consume_keys": True,
              "mode": "unknown", "mode_basis": None,
              "local_ime_assumption": "user_confirmed_english_and_caps_lock_direct",
              "direct_typing_ready": False, "suggested_action": "observe_again"}
    try:
        before = _input_mode_binding(identity)
        values = {}
        for name, command in (("open", 5), ("conversion", 1), ("sentence", 3)):
            if _input_mode_binding(identity) != before:
                raise NativeInputError("input_mode_binding_changed")
            value = ctypes.c_size_t()
            ctypes.set_last_error(0)
            # WM_IME_CONTROL, GET only; BLOCK | ABORTIFHUNG | ERRORONEXIT.
            success = bool(_user32.SendMessageTimeoutW(
                before[3], 0x0283, command, 0, 0x23, 120, ctypes.byref(value)))
            error = ctypes.get_last_error() if not success else 0
            report["queries"][name] = {"succeeded": success,
                "value": value.value if success else None, "error": error}
            if not success:
                raise NativeInputError("input_mode_query_failed")
            values[name] = value.value
        composition = read_input_context(identity)
        candidates = _read_local_candidates(identity, before[0], before[1])
        if (_input_mode_binding(identity) != before or
                composition.focus is not None and composition.focus != before[1] or
                composition.layout is not None and composition.layout != before[2]):
            raise NativeInputError("input_mode_binding_changed")
        if values["open"] not in (0, 1):
            raise NativeInputError("input_mode_open_status_invalid")
        _, focus, layout, _, foreground, caps = before
        opened, native = bool(values["open"]), bool(values["conversion"] & 1)
        direct = not opened or not native or caps
        basis = ("ime_closed" if not opened else "caps_lock_local_ime" if caps else
                 "alphanumeric_local_ime" if not native else "native_local_ime")
        composing = (composition.composition == "active" or
                     candidates["candidate_visible"] is True or
                     candidates["composition_window_visible"] is True)
        ready = bool(direct and foreground and focus and not composing)
        suggestion = ("activate_then_recheck" if not foreground or not focus else
                      "observe_again" if composing else
                      "text" if direct else "switch_mode_then_recheck")
        report.update(state="known", query_succeeded=True, ime_open=opened,
            conversion_mode=values["conversion"], sentence_mode=values["sentence"],
            native_mode=native, alphanumeric_mode=not native,
            keyboard_layout=hex(layout), layout_known=True,
            target_is_foreground=foreground, focus_known=bool(focus), caps_lock=caps,
            ime_composition=composition.composition,
            ime_composition_source=composition.composition_source,
            imm_composition_bytes=composition.composition_bytes,
            candidate_visible=candidates["candidate_visible"],
            composition_window_visible=candidates["composition_window_visible"],
            candidate_visibility_reason=candidates["reason"],
            mode="direct" if direct else "candidate", mode_basis=basis,
            direct_typing_ready=ready, suggested_action=suggestion)
        report["ime_may_consume_keys"] = bool(not ready)
    except (NativeInputError, win32gui.error, OSError) as error:
        report["reason"] = (error.code if isinstance(error, NativeInputError)
                            else "input_mode_query_unavailable")
    return report


def prepare_ime(identity, geometry, ledger, *, preflight, stopped, accepted):
    """One balanced Escape only while the target's same focus is composing.

    It is a real task-priority input effect, counted independently of business
    text. No layout/open-status changes, message injection or user-key ups.
    """
    before = read_input_context(identity)
    report = {**before.public(), "escape_sent_events": 0, "state": "not_needed"}
    if before.composition != "active":
        return before, report
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    current = read_input_context(identity)
    if (current.focus == before.focus and current.layout == before.layout and
            current.composition == "inactive"):
        report.update(**current.public(), state="composition_already_closed")
        return current, report
    if before.changed(current):
        raise NativeInputError("input_context_changed")
    batch = plan_batch((virtual_key(0x1B, down=True), virtual_key(0x1B, down=False)))
    closed = None
    def exact_preflight():
        nonlocal closed
        if not preflight():
            return False
        fresh = read_input_context(identity)
        if (fresh.focus == before.focus and fresh.layout == before.layout and fresh.composition == "inactive"):
            closed = fresh
            raise NativeInputError("ime_composition_already_closed")
        if before.changed(fresh):
            raise NativeInputError("input_context_changed")
        return True
    try:
        sent = send_batch(batch, ledger, expected=identity, geometry=geometry,
                          preflight=exact_preflight, stopped=stopped, final_preflight=exact_preflight)
    except NativeInputError as error:
        if error.code != "ime_composition_already_closed" or closed is None:
            raise
        report.update(**closed.public(), state="composition_already_closed")
        return closed, report
    accepted(sent)
    report["escape_sent_events"] = sent
    deadline = time.monotonic() + .150
    while True:
        if stopped() or not preflight():
            raise NativeInputError("input_stopped")
        after = read_input_context(identity)
        if (before.focus != after.focus or before.layout != after.layout):
            raise NativeInputError("input_context_changed")
        if after.composition == "inactive":
            report.update(state="composition_interrupted", ime_composition="inactive")
            return after, report
        if after.composition == "unknown" or time.monotonic() >= deadline:
            raise NativeInputError("input_context_changed")
        time.sleep(.010)
