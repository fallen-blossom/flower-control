"""Short-lived, no-activate Computer task indicator for one exact window.

The caller owns permission, ledger pause and held-input release. The Stop
button only signals `on_stop`; the indicator never sends input to the target.
Four thin border windows are click-through, while the small Stop panel consumes
its own clicks. Every window carries FlowerControlTaskIndicator so target
selection and follow-up enumeration can exclude it.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import gc
import hashlib
from pathlib import Path
import threading
import time
from typing import Callable, Iterable

import win32api
import win32con
import win32gui

from flower_control.drivers.computer_native import (
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE, MOUSEEVENTF_VIRTUALDESK,
    InputBatch, VirtualDesktop, WindowIdentity, assert_window, virtual_desktop,
    window_geometry, is_owned_popup, same_process_window,
)
from . import indicator_native_draw as drawing
from .indicator_operator import OperatorCache
from .indicator_language import hud_text, hud_stop_text, snapshot_language
from .indicator_visual import (
    frame_strips, px, render_neon_strip, render_status_image, render_action_image,
    preferred_status_width, TITLE_CONTROL_TEMPLATE, hud_status_rows,
    folded_panel_height,
)


_MARKER = "FlowerControlTaskIndicator"
_HUD_RANK = "FlowerControlHudDisplayRank"
_HUD_GROUP = "FlowerControlHudDisplayGroup"
_HUD_TARGET = "FlowerControlHudTarget."
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_TRANSPARENT = 0x00000020
_WS_EX_LAYERED = 0x00080000
_WS_EX_NOACTIVATE = 0x08000000
_WS_EX_TOPMOST = 0x00000008
_GWL_EXSTYLE = -20
_SWP_NOACTIVATE = 0x0010
_SWP_SHOWWINDOW = 0x0040
_SWP_NOSIZE = 0x0001
_SWP_NOMOVE = 0x0002
_HWND_TOPMOST = -1
_SW_HIDE = 0
_SW_SHOWNA = 8
# Bounded, read-only z-order probe intervals and history for diagnostics.
_Z_ORDER_INTERVAL = 0.5
_MAX_Z_ORDER_WALK = 64
_LAYOUT_NOTE_LIMIT = 32
_MAX_FRAME_PIXELS = 8_000_000
ScreenRect = tuple[int, int, int, int]

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.SetThreadDpiAwarenessContext.argtypes = (ctypes.c_void_p,)
_user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
_user32.GetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int)
_user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
_user32.SetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t)
_user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
_user32.SetWindowPos.argtypes = (wintypes.HWND, wintypes.HWND, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT)
_user32.SetWindowPos.restype = wintypes.BOOL
_user32.SetPropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.HANDLE)
_user32.SetPropW.restype = wintypes.BOOL
_user32.RemovePropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
_user32.RemovePropW.restype = wintypes.HANDLE
_user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
_user32.ShowWindow.restype = wintypes.BOOL
_user32.GetPropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
_user32.GetPropW.restype = wintypes.HANDLE
_user32.SetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
_user32.SetWindowTextW.restype = wintypes.BOOL
_user32.GetWindowDisplayAffinity.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
_user32.GetWindowDisplayAffinity.restype = wintypes.BOOL


class IndicatorError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _valid_rect(rect: ScreenRect) -> bool:
    return (type(rect) is tuple and len(rect) == 4 and
            all(type(value) is int for value in rect) and
            rect[0] < rect[2] and rect[1] < rect[3])


def _intersects(first: ScreenRect, second: ScreenRect) -> bool:
    return (first[0] < second[2] and second[0] < first[2] and
            first[1] < second[3] and second[1] < first[3])


def _contained(inner: ScreenRect, outer: ScreenRect) -> bool:
    return (outer[0] <= inner[0] and outer[1] <= inner[1] and
            inner[2] <= outer[2] and inner[3] <= outer[3])


def _rects(rects: Iterable[ScreenRect]) -> tuple[ScreenRect, ...]:
    try:
        result = tuple(rects)
    except TypeError as error:
        raise ValueError("invalid_screen_rects") from error
    if len(result) > 4096 or any(not _valid_rect(rect) for rect in result):
        raise ValueError("invalid_screen_rects")
    return result


def flower_hud_window(hwnd: int) -> bool:
    """True for any Flower task indicator window, including another chat's HUD."""
    try:
        return bool(hwnd and win32gui.IsWindow(hwnd) and _user32.GetPropW(hwnd, _MARKER))
    except win32gui.error:
        return False


def covering_window(hwnd: int, rect: ScreenRect,
                    own: Iterable[int] = ()) -> int | None:
    """Read-only z-order probe: the first visible window above hwnd that overlaps.

    IsWindowVisible alone cannot prove that a topmost border is still on screen;
    this walks the real z-order so a covered border can be reported and re-raised.
    """
    own_handles = frozenset(own)
    try:
        current = hwnd
        for _ in range(_MAX_Z_ORDER_WALK):
            current = win32gui.GetWindow(current, win32con.GW_HWNDPREV)
            if not current:
                return None
            if current in own_handles or flower_hud_window(current):
                continue
            if not win32gui.IsWindowVisible(current) or win32gui.IsIconic(current):
                continue
            if _intersects(rect, tuple(win32gui.GetWindowRect(current))):
                return int(current)
        return None
    except win32gui.error:
        return None


def describe_window(hwnd: int) -> dict:
    """Read-only window facts for the HUD inspector; never activates anything."""
    try:
        if not hwnd or not win32gui.IsWindow(hwnd):
            return {"hwnd": int(hwnd or 0), "alive": False}
        style = int(_user32.GetWindowLongPtrW(hwnd, _GWL_EXSTYLE))
        affinity_value = wintypes.DWORD()
        affinity_ok = bool(_user32.GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity_value)))
        rect = tuple(int(value) for value in win32gui.GetWindowRect(hwnd))
        return {"hwnd": int(hwnd), "alive": True,
                "visible": bool(win32gui.IsWindowVisible(hwnd)),
                "minimized": bool(win32gui.IsIconic(hwnd)), "rect": list(rect),
                "class_name": win32gui.GetClassName(hwnd),
                "text": win32gui.GetWindowText(hwnd)[:160],
                "click_through": bool(style & _WS_EX_TRANSPARENT),
                "no_activate": bool(style & _WS_EX_NOACTIVATE),
                "topmost": bool(style & _WS_EX_TOPMOST),
                "layered": bool(style & _WS_EX_LAYERED),
                "display_affinity": int(affinity_value.value) if affinity_ok else 0}
    except win32gui.error:
        return {"hwnd": int(hwnd or 0), "alive": False, "error": "window_query_failed"}


def choose_panel_rect(window_rect: ScreenRect, client_rect: ScreenRect,
                      work_rect: ScreenRect,
                      avoid_screen_rects: Iterable[ScreenRect] = (), *,
                      panel_size: tuple[int, int] = (330, 42), margin: int = 8,
                      content=None, previous=None, preferred_corner="auto", allow_busy=False) -> ScreenRect | None:
    """Use only the target's non-client space or known quiet target pixels.

    Other applications outside this window are unknown, never empty space.
    With no content map the caller may choose a readable compact fallback.
    """
    if (any(not _valid_rect(rect) for rect in
            (window_rect, client_rect, work_rect)) or
            type(panel_size) is not tuple or len(panel_size) != 2 or
            any(type(value) is not int or value <= 0 for value in panel_size) or
            type(margin) is not int or not 1 <= margin <= 128 or
            preferred_corner not in {"auto", "top_left", "top_right", "bottom_left", "bottom_right"}):
        raise ValueError("invalid_panel_geometry")
    avoid = _rects(avoid_screen_rects)
    if content is not None:
        avoid += _rects(content.protected)
    width, height = panel_size
    # Preserve the top-left anchor through stage/title size changes. This is
    # geometry only: it is rechecked against the current bounds and paths.
    if previous is not None:
        previous = (previous[0], previous[1], previous[0] + width, previous[1] + height)
    half_margin = max(1, margin // 2)
    wl, wt, wr, wb = window_rect
    cl, ct, cr, cb = client_rect
    al, at, ar, ab = work_rect
    if width > ar - al or height > ab - at:
        return None

    non_client = ((cl + margin, ct - height - half_margin), (cr - width - margin, ct - height - half_margin),
                  (cr + half_margin, ct + margin), (cl - width - half_margin, ct + margin),
                  (cl + margin, cb + half_margin), (cr - width - margin, cb + half_margin))
    inside_client = ((cl + margin, ct + margin), (cr - width - margin, ct + margin),
                     (cl + margin, cb - height - margin), (cr - width - margin, cb - height - margin))
    if preferred_corner != "auto":
        index = ("top_left", "top_right", "bottom_left", "bottom_right").index(preferred_corner)
        inside_client = (inside_client[index],) + tuple(p for i, p in enumerate(inside_client) if i != index)
        non_client = ()
    for position in non_client:
        x, y = position
        candidate = (x, y, x + width, y + height)
        if (_contained(candidate, work_rect) and _contained(candidate, window_rect) and
                not _intersects(candidate, client_rect) and
                not any(_intersects(candidate, rect) for rect in avoid)):
            return candidate
    candidates = []
    if content is not None:
        # These use only the last already-authorized target capture. Skip
        # unknown pixels and known controls; keep a usable position stable.
        inside_client += tuple((cl + margin + (cr-cl-width-2*margin)*x//12,
                                ct + margin + (cb-ct-height-2*margin)*y//8)
                               for y in range(9) for x in range(13))
    for x, y in inside_client:
        candidate = (x, y, x + width, y + height)
        if (_contained(candidate, client_rect) and
                _contained(candidate, work_rect) and
                not any(_intersects(candidate, rect) for rect in avoid)):
            candidates.append(candidate)
    if content is None:
        # A stale capture must not send an otherwise safe panel back to the
        # first corner on every layout tick.  Do not reuse stale pixels; keep
        # only the last geometry, after the same target and path checks.
        if (previous is not None
                and (preferred_corner == "auto" or candidates and previous == candidates[0])
                and _contained(previous, client_rect) and _contained(previous, work_rect)
                and not any(_intersects(previous, rect) for rect in avoid)):
            return previous
        return candidates[0] if candidates else None
    if preferred_corner != "auto" and candidates and content.score(candidates[0]) < .12:
        return candidates[0]
    ranked = sorted(candidates, key=content.score)
    if (previous is not None and _contained(previous, client_rect)
            and _contained(previous, work_rect)
            and not any(_intersects(previous, rect) for rect in avoid)
            and (preferred_corner == "auto" or candidates and previous == candidates[0])
            and ranked):
        old_score, best_score = content.score(previous), content.score(ranked[0])
        # Move for a meaningful reduction in visible clutter, not small
        # measurement noise; preserve hard protection/path constraints above.
        if (old_score < .12 or allow_busy and old_score < float('inf')) and old_score <= best_score + .01:
            return previous
    return ranked[0] if ranked and (content.score(ranked[0]) < 0.12 or allow_busy and content.score(ranked[0]) < float('inf')) else None


def mouse_path_rects(batches: Iterable[InputBatch], *,
                     desktop: VirtualDesktop | None = None,
                     cursor: tuple[int, int] | None = None,
                     padding: int = 4) -> tuple[ScreenRect, ...]:
    """Decode planned absolute moves into padded screen-space path envelopes."""
    if type(padding) is not int or not 0 <= padding <= 32:
        raise ValueError("invalid_mouse_path_padding")
    try:
        planned = tuple(batches)
    except TypeError as error:
        raise ValueError("invalid_input_batches") from error
    if any(not isinstance(batch, InputBatch) for batch in planned):
        raise ValueError("invalid_input_batches")
    moves = [step.raw.data.mi for batch in planned for step in batch.steps
             if step.raw.type == 0 and
             step.raw.data.mi.dwFlags & MOUSEEVENTF_MOVE]
    if not moves:
        return ()
    if any(move.dwFlags != (MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                            MOUSEEVENTF_VIRTUALDESK) for move in moves):
        raise ValueError("unsupported_mouse_path")
    desktop = desktop if desktop is not None else virtual_desktop()
    cursor = cursor if cursor is not None else win32gui.GetCursorPos()
    if (not isinstance(desktop, VirtualDesktop) or type(cursor) is not tuple or
            len(cursor) != 2 or any(type(value) is not int for value in cursor)):
        raise ValueError("invalid_mouse_path_geometry")
    previous = cursor
    paths: list[ScreenRect] = []
    for move in moves:
        point = (desktop.left + move.dx * desktop.width // 65536,
                 desktop.top + move.dy * desktop.height // 65536)
        paths.append((min(previous[0], point[0]) - padding,
                      min(previous[1], point[1]) - padding,
                      max(previous[0], point[0]) + padding + 1,
                      max(previous[1], point[1]) + padding + 1))
        previous = point
    return tuple(paths)


class ForegroundIndicator:
    """A bounded HUD whose lifetime is tied to one selected window instance."""

    TITLE_CONTROL_TEMPLATE = TITLE_CONTROL_TEMPLATE
    STOP_CLOSE_SECONDS = 1.0

    def __init__(self, identity: WindowIdentity, task_hint: str,
                 on_stop: Callable[[], None], *, lifetime_s: float = 90, persistent: bool = False,
                 avoid_screen_rects: Iterable[ScreenRect] = (), prepare: bool = False,
                 capture_excluded: bool = True, stop_probe: Callable[[], bool] | None = None,
                 channel: str = "computer", previous_status_bounds: ScreenRect | None = None) -> None:
        if (not isinstance(identity, WindowIdentity) or
                type(task_hint) is not str or not task_hint.strip() or
                len(task_hint) > 80 or not callable(on_stop) or
                type(lifetime_s) not in (int, float) or
                not 1 <= lifetime_s <= 300 or type(prepare) is not bool or
                type(capture_excluded) is not bool or channel not in {"computer", "app"}):
            raise ValueError("invalid_indicator_request")
        self.identity = identity
        self.channel = channel
        self.task_hint = task_hint
        self.on_stop = on_stop
        # Presentation is fixed for this lifetime. No file read is added to
        # paint, mouse/keyboard, Stop or release paths.
        self._language = snapshot_language()
        self.lifetime_s = float(lifetime_s)
        if type(persistent) is not bool:
            raise ValueError("invalid_indicator_lifetime")
        self.persistent = persistent
        self.prepare = prepare
        # False is for an explicitly owned source preview; production defaults
        # to exclusion and treats failure as an indicator error.
        self.capture_excluded = capture_excluded
        self._avoid_screen_rects = _rects(avoid_screen_rects)
        self.stop_requested = threading.Event()
        # One immutable binding is captured at the user gesture. Signals are
        # thread Events only; durable state/IPC remains with the exact owner.
        self._stop_binding = (on_stop, ())
        self._stop_pending = False
        self._stop_notifying = False
        self._close_requested = threading.Event()
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None
        self.error_detail: str | None = None
        self._window_handles: list[int] = []
        self._painted_stage = None
        self._painted_windows = None
        self._layout_condition = threading.Condition()
        self._layout_revision = 0
        self._layout_applied_revision = -1
        self._panel_bounds: ScreenRect | None = None
        self._status_bounds: ScreenRect | None = None
        self._previous_status_bounds = (_rects((previous_status_bounds,))[0]
                                        if previous_status_bounds is not None else None)
        self._display_allowed = True
        self._presentation_suspended = False
        self._panel_mode = "full"
        self._user_compact = False
        self._hud_position = "auto"
        # Native window properties coordinate display only, never input or
        # grants. Full instance identity avoids HWND-reuse collisions.
        instance = repr((identity.hwnd, identity.pid, identity.process_created, identity.window_nonce))
        self._display_property = _HUD_TARGET + hashlib.sha256(instance.encode()).hexdigest()
        application = repr((identity.pid, identity.process_created))
        self._application_property = "FlowerControlHudApplication." + hashlib.sha256(application.encode()).hexdigest()
        self._stage_changed = time.monotonic_ns()
        self._content_map = None
        self._operation_started = time.monotonic()
        self._expires = float("inf") if persistent else self._operation_started + self.lifetime_s
        self._stop_probe = stop_probe
        self._operator = OperatorCache()
        self._stage = "prepare" if prepare else "execute"
        self._checkpoint = "动作结束后核对结果"
        self._estimated_seconds = None
        # Host-authored HUD text, layout reasons, paint counters and the last
        # rendered frames; all of them are diagnostics, never authority.
        self._next_step: str | None = None
        self._layout_reason = "target_window"
        self._layout_notes: list[dict] = []
        self._covered_by: dict[int, int | None] = {}
        self._paints = {"borders": 0, "panel": 0, "stop": 0}
        self._topmost_raises = 0
        self._frames: dict | None = None
        self._stop_close_deadline: float | None = None
        self._stop_close_thread: threading.Thread | None = None

    _STAGES = {"execute": "执行阶段", "prepare": "准备目标", "queued": "等待执行", "input": "输入阶段",
               "verify": "核对结果", "observe": "读取窗口", "idle": "等待下一步",
               "wait": "等待目标变化", "stopping": "已阻止后续输入",
               "stopped": "已停止，释放已确认", "release_unconfirmed": "释放未确认",
               "takeover": "等待首次接管"}

    def set_stage(self, stage: str, *, checkpoint: str,
                  estimated_seconds: float | None = None, input_release: str | None = None):
        """Trusted callers report actual stages; estimates are never inferred from TTL.

        A Stop callback alone does not prove release. Callers may report stopped
        only after the input owner has independently confirmed its release.
        """
        if (type(stage) is not str or stage not in self._STAGES or type(checkpoint) is not str or
                not 1 <= len(checkpoint) <= 64 or any(ord(c) < 32 for c in checkpoint) or
                estimated_seconds is not None and (type(estimated_seconds) not in (int, float) or
                    not 0 <= estimated_seconds <= 300) or
                stage == "stopped" and input_release != "released"):
            raise ValueError("invalid_indicator_stage")
        with self._layout_condition:
            if self.stop_requested.is_set() and stage not in {"stopping", "stopped", "release_unconfirmed"}:
                return
            if (self._stage, self._checkpoint, self._estimated_seconds) == (stage, checkpoint, estimated_seconds):
                return
            self._painted_stage = None
            self._stage = stage
            self._checkpoint = checkpoint
            self._estimated_seconds = estimated_seconds
            self._stage_changed = time.monotonic_ns()
            self._layout_revision += 1
            self._layout_condition.notify_all()

    def title_text(self) -> str:
        with self._layout_condition:
            stage = self._stage
        name = "Flower App" if self.channel == "app" else "Flower Computer Use"
        if stage == "stopped":
            template = "{name} · {operator} 已停止"
        elif stage == "stopping":
            template = "{name} · {operator} 已中止控制"
        elif stage == "release_unconfirmed":
            template = "{name} · {operator} 等待确认释放"
        elif stage == "idle":
            template = "{name} · {operator} 待命"
        elif stage == "takeover":
            template = "{name} 等待 {operator} 接管"
        elif stage in {"prepare", "queued"}:
            template = "{name} 准备由 {operator} 操作"
        elif stage in {"wait", "verify", "observe"}:
            template = "{name} 正在由 {operator} 观察"
        else:
            template = "{name} 正在由 {operator} 操作"
        return hud_text(template, self._language).format(name=name, operator=self._display_operator())

    def _display_operator(self):
        operator = self._operator.label()
        return hud_text("未知", self._language) if operator == "未知" else operator

    def keep_alive(self, task_hint: str | None = None):
        with self._layout_condition:
            self._expires = float("inf") if self.persistent else time.monotonic() + self.lifetime_s
            if task_hint and task_hint[:80] != self.task_hint:
                self.task_hint = task_hint[:80]
                self._layout_revision += 1
                self._layout_condition.notify_all()

    def set_task_started(self, started: float):
        """Inherit one task's monotonic display clock after an exact rebind.

        This changes presentation only. Input release, Stop and permission
        remain owned by the runtime and never follow this timestamp.
        """
        if type(started) not in (int, float) or not 0 <= started <= time.monotonic():
            raise ValueError("invalid_indicator_task_clock")
        with self._layout_condition:
            self._operation_started = min(self._operation_started, started)

    def linger(self, seconds: float = 3):
        with self._layout_condition:
            self._expires = min(self._expires, time.monotonic() + seconds)

    def retain_release_warning(self):
        with self._layout_condition:
            self._expires = float("inf")

    def _begin_stop_close(self) -> None:
        """Stop presentation locally, without waiting for owner cleanup.

        The Stop hit area is the user's direct cancellation control. Once it
        is pressed, keeping a daemon-owned topmost window alive is not useful
        evidence of release work. Hide immediately, latch the close request,
        and force any matching stale Flower HUD windows (same exact target and
        application properties) closed as well.
        """
        now = time.monotonic()
        with self._layout_condition:
            if self._stop_close_deadline is None:
                self._stop_close_deadline = now + self.STOP_CLOSE_SECONDS
        self._close_requested.set()
        self._hide_and_request_close(self._window_handles)
        # The exact target/application properties also catch HUD windows left
        # by an older persistent daemon for this same target.
        self._hide_matching_hud_windows()
        if self._thread is not None and not self._closed.is_set():
            with self._layout_condition:
                if self._stop_close_thread is None:
                    self._stop_close_thread = threading.Thread(
                        target=self._reap_stop_windows,
                        name="flower-indicator-stop-close", daemon=True)
                    self._stop_close_thread.start()
        if self._thread is None:
            self._closed.set()

    @staticmethod
    def _hide_and_request_close(handles) -> None:
        for hwnd in tuple(handles):
            try:
                if win32gui.IsWindow(hwnd):
                    _user32.ShowWindow(hwnd, _SW_HIDE)
                    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            except win32gui.error:
                pass

    def _hide_matching_hud_windows(self) -> None:
        matches = []
        def collect(hwnd, _context):
            try:
                if (flower_hud_window(hwnd) and
                        _user32.GetPropW(hwnd, self._display_property) and
                        _user32.GetPropW(hwnd, self._application_property)):
                    matches.append(hwnd)
            except win32gui.error:
                pass
            return True
        try:
            win32gui.EnumWindows(collect, None)
        except win32gui.error:
            pass
        self._hide_and_request_close(matches)

    def _reap_stop_windows(self) -> None:
        """Repeat the exact Stop cleanup until the deadline, then leave hidden.

        Hiding is deliberately repeated because a daemon's paint loop may race
        the first message. It cannot dispatch input or extend presentation.
        """
        while not self._closed.is_set():
            deadline = self._stop_close_deadline or time.monotonic()
            if time.monotonic() >= deadline:
                self._hide_and_request_close(self._window_handles)
                self._hide_matching_hud_windows()
                return
            self._closed.wait(.05)

    def set_presented(self, presented: bool):
        if type(presented) is not bool:
            raise ValueError("invalid_indicator_presentation")
        with self._layout_condition:
            self._presentation_suspended = not presented
            if not presented:
                self._painted_stage = None
            self._layout_revision += 1
            self._layout_condition.notify_all()

    def stage_visible(self, stage: str, checkpoint: str) -> bool:
        """A startup acknowledgement is not a painted, elected HUD frame."""
        if self.error is not None or self._closed.is_set():
            raise IndicatorError("indicator_display_unavailable")
        with self._layout_condition:
            windows = self._painted_windows
            return (not self.stop_requested.is_set() and not self._presentation_suspended
                    and self._painted_stage == (stage, checkpoint)
                    and (self._stage, self._checkpoint) == (stage, checkpoint)
                    and self._panel_bounds is not None and windows is not None
                    and all(win32gui.IsWindowVisible(hwnd) for hwnd in windows))

    def _record_painted_stage(self, stage, checkpoint, *, panel_hwnd, button_hwnd,
                              bounds, stop_only, panel_image, stop_image):
        with self._layout_condition:
            # The Stop-only panel is transparent and cannot show a countdown.
            painted = (bounds is not None and not stop_only and panel_image is not None
                       and stop_image is not None and not self.stop_requested.is_set()
                       and (self._stage, self._checkpoint) == (stage, checkpoint))
            self._painted_stage = (stage, checkpoint) if painted else None
            self._painted_windows = (panel_hwnd, button_hwnd) if painted else None

    def set_task_hint(self, task_hint: str | None):
        """Update observation text without extending a stopped HUD's lifetime."""
        if task_hint:
            with self._layout_condition:
                value = task_hint[:80]
                if value != self.task_hint:
                    self.task_hint = value
                    self._layout_revision += 1
                    self._layout_condition.notify_all()

    def set_next_step(self, next_step: str | None):
        """Show the host's short next step on its own panel line.

        This is display text from the calling model: it never grants authority,
        never changes stage semantics and never replaces a real receipt.
        """
        if next_step is not None and (type(next_step) is not str or
                not 1 <= len(next_step.strip()) <= 48 or
                any(ord(c) < 32 for c in next_step)):
            raise ValueError("invalid_indicator_next_step")
        with self._layout_condition:
            value = None if next_step is None else next_step.strip()
            if value != self._next_step:
                self._next_step = value
                self._layout_revision += 1
                self._layout_condition.notify_all()

    def next_step(self) -> str | None:
        with self._layout_condition:
            return self._next_step

    def bind_stop(self, callback, *signals, owner_token=None):
        """Replace only the display's exact current action/run binding."""
        if not callable(callback) or any(not isinstance(signal, threading.Event) for signal in signals):
            raise ValueError("invalid_indicator_stop_binding")
        with self._layout_condition:
            if self.stop_requested.is_set():
                return False
            self._stop_binding = (callback, tuple(signals))
            self._stop_owner_binding = owner_token
            return True

    def request_stop(self) -> bool:
        """Latch cancellation on mouse-down, before scheduling owner cleanup."""
        with self._layout_condition:
            if self.stop_requested.is_set():
                return False
            callback, signals = self._stop_binding
            self._stop_pending = True
            self.stop_requested.set()
        for signal in signals:
            signal.set()
        self._begin_stop_close()
        released = getattr(self, "_input_released", False)
        self.set_stage("stopped" if released else "stopping",
                       checkpoint=hud_text("本次控制已结束" if released else "确认原执行器的按键释放", self._language),
                       input_release="released" if released else None)

        self.retry_pending_stop()
        return True

    def retry_pending_stop(self, timeout=0):
        """Retry only the frozen owner's metadata cleanup, never input."""
        with self._layout_condition:
            if not self._stop_pending:
                return True
            if not self._stop_notifying:
                callback = self._stop_binding[0]
                self._stop_notifying = True
                def notify_owner():
                    try:
                        if callback() is not False:
                            with self._layout_condition:
                                self._stop_pending = False
                    except BaseException as error:
                        self._record_error(error)
                    finally:
                        with self._layout_condition:
                            self._stop_notifying = False
                self._stop_thread = threading.Thread(target=notify_owner, name="flower-indicator-stop", daemon=True)
                self._stop_thread.start()
            worker = self._stop_thread
        if timeout:
            worker.join(timeout)
        return not self._stop_pending

    def latch_external_stop(self):
        """Reflect an executor Stop without invoking a durable pause callback."""
        with self._layout_condition:
            self.stop_requested.set()
            signals = self._stop_binding[1]
        for signal in signals:
            signal.set()
        self._begin_stop_close()
        released = getattr(self, "_input_released", False)
        self.set_stage("stopped" if released else "stopping", checkpoint=hud_text("本次控制已结束" if released else "确认原执行器的按键释放", self._language),
                       input_release="released" if released else None)

    def stop_button_text(self, compact=False) -> str:
        with self._layout_condition:
            stage = self._stage
        if stage == "stopped":
            label = "已停止"
        elif stage == "release_unconfirmed":
            label = "释放待确认"
        elif stage == "stopping":
            label = "控制已中止"
        else:
            label = "立即停止" if compact else "停止本次控制"
        return hud_stop_text(label, self._language, compact)

    def panel_text(self, target_label: str | None = None) -> str:
        """One-line HUD text, also mirrored into the panel window title."""
        with self._layout_condition:
            stage, checkpoint = self._stage, self._checkpoint
            note = self._next_step or (self.task_hint if self.persistent else None)
            purpose = self.task_hint
        rows = hud_status_rows(self._STAGES[stage], checkpoint, purpose, note, language=self._language)
        return f"{self.title_text()} | " + " | ".join(prefix + body for _kind, prefix, body in rows)

    def status_text(self, target_label: str | None = None) -> str:
        with self._layout_condition:
            elapsed = max(0, time.monotonic() - self._operation_started)
            note = self._next_step or (self.task_hint if self.persistent else None)
            purpose = self.task_hint
            elapsed_label = "接管等待" if self._stage == "takeover" else "控制累计"
            timing = hud_text("{label} {seconds:.1f} 秒", self._language).format(
                label=hud_text(elapsed_label, self._language), seconds=elapsed)
            if self._estimated_seconds is not None:
                timing += hud_text(" · 预计 {seconds:.1f} 秒", self._language).format(seconds=self._estimated_seconds)
            stage, checkpoint = self._stage, self._checkpoint
        rows = hud_status_rows(self._STAGES[stage], checkpoint, purpose, note, language=self._language)
        return '\n'.join([self.title_text(), *(prefix + body for _kind, prefix, body in rows), timing])

    def set_content_map(self, content):
        with self._layout_condition:
            self._content_map = content
            self._layout_revision += 1
            self._layout_condition.notify_all()

    def reserve_mouse_paths(self, rects: Iterable[ScreenRect]) -> bool:
        """Keep the panel clear of these paths before dispatch; return visibility."""
        avoid = _rects(rects)
        with self._layout_condition:
            if self._thread is None or self._closed.is_set() or self.error is not None:
                raise IndicatorError("indicator_unavailable")
            if (avoid == self._avoid_screen_rects and
                    self._layout_applied_revision >= self._layout_revision):
                bounds = self._panel_bounds
                if bounds is None or not any(_intersects(bounds, rect) for rect in avoid):
                    return bounds is not None
            self._avoid_screen_rects = avoid
            self._layout_revision += 1
            revision = self._layout_revision
            self._layout_condition.notify_all()
            ready = self._layout_condition.wait_for(
                lambda: (self._layout_applied_revision >= revision or
                         self._closed.is_set()), timeout=0.65)
            if not ready or self._closed.is_set() or self.error is not None:
                raise IndicatorError("indicator_layout_unconfirmed")
            bounds = self._panel_bounds
            if bounds is not None and any(_intersects(bounds, rect) for rect in avoid):
                raise IndicatorError("indicator_mouse_path_blocked")
            return bounds is not None

    def _record_error(self, error: BaseException) -> None:
        # Do not retain a UI-thread traceback through the shared indicator.
        code = error.code if isinstance(error, IndicatorError) else "indicator_ui_failed"
        self.error_detail = f"{type(error).__name__}: {error}"[:500]
        if error.__cause__ is not None:
            self.error_detail = (self.error_detail + f"; {error.__cause__}")[:500]
        self.error = IndicatorError(code)

    def _note_layout(self, code: str, **facts) -> None:
        """Bounded in-memory layout history for the HUD inspector."""
        entry = {"code": code, "at": round(time.monotonic(), 3), **facts}
        self._layout_notes.append(entry)
        del self._layout_notes[:-_LAYOUT_NOTE_LIMIT]

    @staticmethod
    def _style(hwnd: int, *, click_through: bool, capture_excluded: bool = True) -> None:
        ctypes.set_last_error(0)
        old = _user32.GetWindowLongPtrW(hwnd, _GWL_EXSTYLE)
        if not old and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        flags = _WS_EX_NOACTIVATE | _WS_EX_TOOLWINDOW | _WS_EX_LAYERED
        if click_through:
            flags |= _WS_EX_TRANSPARENT | _WS_EX_LAYERED
        ctypes.set_last_error(0)
        changed = _user32.SetWindowLongPtrW(hwnd, _GWL_EXSTYLE, old | flags)
        if not changed and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        if not _user32.SetPropW(hwnd, _MARKER, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if capture_excluded:
            try:
                drawing.exclude_capture(hwnd)
            except OSError as error:
                raise IndicatorError("indicator_capture_exclusion_failed") from error

    @staticmethod
    def _place(hwnd: int, left: int, top: int, width: int, height: int,
               *, show: bool = True) -> None:
        if not _user32.SetWindowPos(hwnd, _HWND_TOPMOST, left, top, width, height,
                                   _SWP_NOACTIVATE | (_SWP_SHOWWINDOW if show else 0)):
            raise ctypes.WinError(ctypes.get_last_error())

    def _raise_topmost(self, hwnd: int, keep_above: Iterable[int] = ()) -> None:
        """One no-activate z-order re-assert without moving or resizing."""
        flags = _SWP_NOMOVE | _SWP_NOSIZE | _SWP_NOACTIVATE
        if not _user32.SetWindowPos(hwnd, _HWND_TOPMOST, 0, 0, 0, 0, flags):
            raise ctypes.WinError(ctypes.get_last_error())
        for other in keep_above:
            if other and other != hwnd and win32gui.IsWindow(other):
                _user32.SetWindowPos(other, _HWND_TOPMOST, 0, 0, 0, 0, flags)
        self._topmost_raises += 1

    def _target_layout(self):
        assert_window(self.identity)
        minimized = win32gui.IsIconic(self.identity.hwnd)
        reason = "target_minimized" if minimized else "target_window"
        if not minimized:
            foreground = win32gui.GetForegroundWindow()
            if foreground:
                try:
                    foreground = win32gui.GetAncestor(foreground, win32con.GA_ROOT)
                except win32gui.error:
                    # Foreground can briefly be empty or disappear during a
                    # normal switch. Hide for this sample, keep the session.
                    foreground = 0
            reason = self._task_context(foreground) or "foreground_other_app"
        self._layout_reason = reason
        with self._layout_condition:
            # Construction-time prepare must not keep an idle HUD on a
            # different app after the activation has already completed.
            attention = self._stage in {"prepare", "takeover", "stopping", "release_unconfirmed"}
            takeover = self._stage == "takeover"
        self._display_allowed = attention or (not self._presentation_suspended and
            not (minimized or reason == "foreground_other_app"))
        if minimized or reason == "foreground_other_app" and not takeover:
            if minimized and not self.persistent and not attention:
                return None, None
            monitor = win32api.MonitorFromPoint(win32gui.GetCursorPos(), win32con.MONITOR_DEFAULTTONEAREST)
            return None, tuple(win32api.GetMonitorInfo(monitor)["Work"])
        geometry = window_geometry(self.identity)
        monitor = win32api.MonitorFromWindow(self.identity.hwnd, win32con.MONITOR_DEFAULTTONEAREST)
        return geometry, tuple(win32api.GetMonitorInfo(monitor)["Work"])

    def _display_rank(self) -> int:
        with self._layout_condition:
            stage, changed = self._stage, self._stage_changed
        priority = (5 if stage in {"stopping", "release_unconfirmed"} else
                    4 if stage == "input" else
                    3 if stage in {"execute", "prepare", "queued", "takeover"} else
                    2 if stage in {"verify", "observe"} else 1)
        relation = 2 if stage in {"stopping", "release_unconfirmed", "takeover"} else int(
            self._layout_reason in {"target_window", "owned_modal"})
        priority += 8 * relation
        return (priority << 56) | ((changed // 1000) & ((1 << 56) - 1))

    def _display_winner(self, panel_hwnd: int) -> bool:
        """Elect one HUD for this target, including hidden but live candidates."""
        rank = self._display_rank() if self._display_allowed else 0
        if not _user32.SetPropW(panel_hwnd, _HUD_RANK, rank):
            raise IndicatorError("indicator_display_registration_failed")
        candidates = [(rank, int(panel_hwnd))]
        peer_windows = []
        def collect(hwnd, _context):
            if (hwnd != panel_hwnd and flower_hud_window(hwnd) and
                    (_user32.GetPropW(hwnd, self._display_property) or
                     _user32.GetPropW(hwnd, self._application_property))):
                peer_rank = int(_user32.GetPropW(hwnd, _HUD_RANK) or 0)
                if peer_rank:
                    candidates.append((peer_rank, int(hwnd)))
                group = int(_user32.GetPropW(hwnd, _HUD_GROUP) or 0)
                if group and group != panel_hwnd:
                    peer_windows.append((int(hwnd), group))
        win32gui.EnumWindows(collect, None)
        winner = max(candidates) == (rank, int(panel_hwnd))
        if winner and self._display_allowed:
            # Hide only Flower's marked layers for this exact instance before
            # showing the new winner. No target window or input is touched.
            losing_groups = {hwnd for _rank, hwnd in candidates if hwnd != panel_hwnd}
            for hwnd, group in peer_windows:
                if group in losing_groups:
                    _user32.ShowWindow(hwnd, _SW_HIDE)
        return winner

    def _task_context(self, foreground: int) -> str | None:
        """Classify the current foreground for the HUD frame; None means unrelated.

        An owned modal was already accepted. A same-application visible
        top-level window is accepted as well, because dialogs, wizards and tool
        panels are frequently created without GW_OWNER while they still belong
        to the running task; users reported the flowing frame dropping out in
        exactly those cases. Flower HUD windows of any chat are never accepted,
        and this relation authorizes nothing: input still requires its own exact
        foreground, target, Stop and receipt checks.
        """
        if foreground == self.identity.hwnd:
            return "target_window"
        if is_owned_popup(self.identity, foreground):
            return "owned_modal"
        if (foreground and foreground not in self._window_handles
                and same_process_window(self.identity, foreground)
                and not flower_hud_window(foreground)):
            return "same_app_window"
        return None

    def _run_ui(self) -> None:
        """The shared Medium/High HUD; only its independent Stop hit area clicks."""
        hinstance = win32api.GetModuleHandle(None)
        class_names = []
        button_hwnd = panel_hwnd = 0
        class_prefix = f"FlowerControlIndicator_{id(self):x}_{threading.get_ident():x}"

        def window_proc(hwnd, message, wparam, lparam):
            try:
                if message == win32con.WM_MOUSEACTIVATE:
                    return win32con.MA_NOACTIVATE
                if message == win32con.WM_NCHITTEST and hwnd != button_hwnd:
                    return -1  # The status letters and frame always pass through.
                if message == win32con.WM_LBUTTONDOWN and hwnd == button_hwnd:
                    # Stop is not a cancellable drag-out button. Do not steal
                    # the target's drag capture while waiting for mouse-up.
                    self.request_stop()
                    return 0
                if message == win32con.WM_LBUTTONUP and hwnd == button_hwnd:
                    return 0
                if message == win32con.WM_PAINT:
                    dc, paint = win32gui.BeginPaint(hwnd)
                    win32gui.EndPaint(hwnd, paint)
                    return 0
                if message == win32con.WM_CLOSE:
                    self._close_requested.set()
                    return 0
                return win32gui.DefWindowProc(hwnd, message, wparam, lparam)
            except BaseException as error:
                self._record_error(error)
                self._close_requested.set()
                return 0

        def create(suffix, click_through, owner=0):
            name = class_prefix + suffix
            klass = win32gui.WNDCLASS()
            klass.hInstance, klass.lpszClassName, klass.lpfnWndProc = hinstance, name, window_proc
            win32gui.RegisterClass(klass)
            class_names.append(name)
            # Match the original native indicator: TOPMOST at creation, with
            # independent status/first frame and status-owned side/action popups.
            exstyle = _WS_EX_NOACTIVATE | _WS_EX_TOOLWINDOW | _WS_EX_TOPMOST | _WS_EX_LAYERED
            if click_through:
                exstyle |= _WS_EX_TRANSPARENT
            hwnd = win32gui.CreateWindowEx(exstyle,
                name, hud_text("停止本次操作", self._language) if suffix == "_stop" else "", win32con.WS_POPUP,
                0, 0, 1, 1, owner, 0, hinstance, None)
            self._window_handles.append(hwnd)
            self._style(hwnd, click_through=click_through, capture_excluded=self.capture_excluded)
            return hwnd

        try:
            assert_window(self.identity)
            first_border = create("_border_0", True)
            panel_hwnd = create("_status", True)
            if not _user32.SetPropW(panel_hwnd, self._display_property, 1):
                raise IndicatorError("indicator_display_registration_failed")
            button_hwnd = create("_stop", False, panel_hwnd)
            borders = [first_border] + [create(f"_border_{index}", True, panel_hwnd)
                                        for index in range(1, 4)]
            # Preserve the current controller's externally observed handle order.
            self._window_handles[:] = [*borders, panel_hwnd, button_hwnd]
            for hwnd in self._window_handles:
                if not (_user32.SetPropW(hwnd, self._display_property, 1) and
                        _user32.SetPropW(hwnd, self._application_property, 1) and
                        _user32.SetPropW(hwnd, _HUD_GROUP, panel_hwnd)):
                    raise IndicatorError("indicator_display_registration_failed")
            next_geometry = 0.0
            next_preferences = 0.0
            next_occlusion = 0.0
            strips = ()
            old_strips = None
            bounds = button_bounds = None
            last_text_signature = None
            last_stop_signature = None
            width_signature = None
            preferred_width = 0
            dpi = 96
            geometry = None
            panel_image = None
            stop_image = None
            frame_images = []
            compact = False
            stop_only = False
            previous_winner = None
            last_status_bounds = self._previous_status_bounds
            while not self._close_requested.is_set() and time.monotonic() < self._expires:
                if win32gui.PumpWaitingMessages():
                    break
                now = time.monotonic()
                if self._stop_probe is not None and self._stop_probe():
                    with self._layout_condition:
                        stage = self._stage
                    if stage not in {"stopping", "stopped", "release_unconfirmed"}:
                        self.set_stage("stopping", checkpoint=hud_text("全局停止，关闭本次显示", self._language))
                    self._begin_stop_close()
                    break
                title = self.title_text()
                if now >= next_preferences:
                    from flower_control.permissions import active_policy, PermissionError
                    try:
                        policy = active_policy.read()
                        compact_setting, position_setting = policy["HudCompact"], policy["HudPosition"]
                    except PermissionError:
                        # A policy read failure blocks control elsewhere; it
                        # must not silently opt the user into a reduced HUD.
                        compact_setting, position_setting = self._user_compact, self._hud_position
                    if (compact_setting, position_setting) != (self._user_compact, self._hud_position):
                        with self._layout_condition:
                            self._user_compact, self._hud_position = compact_setting, position_setting
                            self._layout_revision += 1
                    next_preferences = now + .5
                with self._layout_condition:
                    revision, avoid = self._layout_revision, self._avoid_screen_rects
                if now >= next_geometry or revision != self._layout_applied_revision:
                    geometry, work = self._target_layout()
                # Recheck display ownership before every frame. A previous
                # winner cannot keep repainting until its slower layout tick.
                winner = self._display_winner(panel_hwnd)
                if (now >= next_geometry or revision != self._layout_applied_revision or
                        not winner or previous_winner != winner):
                    previous_winner = winner
                    geometry, work = self._target_layout()
                    if work is None:
                        break
                    if not self._display_allowed or not winner:
                        for hwnd in self._window_handles:
                            _user32.ShowWindow(hwnd, _SW_HIDE)
                        bounds = button_bounds = None
                        strips = old_strips = ()
                        last_text_signature = last_stop_signature = None
                        with self._layout_condition:
                            self._painted_stage = None
                            self._painted_windows = None
                            self._panel_bounds = self._status_bounds = None
                            self._layout_applied_revision = revision
                            self._frames = {"dpi": dpi, "title": title, "visible": None,
                                            "strips": (), "panel": None}
                            self._layout_condition.notify_all()
                        self._ready.set()
                        next_geometry = now + .18
                        self._close_requested.wait(.067)
                        continue
                    dpi = drawing.get_dpi(self.identity.hwnd) or 96
                    if geometry is None:
                        visible = client = work
                        strips = ()
                    else:
                        full = (geometry.window.left, geometry.window.top,
                                geometry.window.right, geometry.window.bottom)
                        visible = drawing.visible_bounds(self.identity.hwnd, full)
                        client = (geometry.client_origin[0], geometry.client_origin[1],
                                  geometry.client_origin[0] + geometry.client_size[0],
                                  geometry.client_origin[1] + geometry.client_size[1])
                        strips = frame_strips(visible, dpi)
                    if width_signature != (title, dpi):
                        preferred_width = preferred_status_width(title, dpi)
                        width_signature = (title, dpi)
                    with self._layout_condition:
                        note = self._next_step or (self.task_hint if self.persistent else None)
                        stage = self._stage
                        checkpoint = self._checkpoint
                    self._note_layout(self._layout_reason, borders=bool(strips),
                                      foreground_kept=geometry is not None, next_step=bool(note))
                    panel_width = min(preferred_width, work[2] - work[0] - px(16, dpi),
                                      client[2] - client[0] - px(16, dpi))
                    panel_height = px(84 if note or self.task_hint else 56, dpi)
                    with self._layout_condition:
                        content = self._content_map
                        previous = self._status_bounds or last_status_bounds
                    if (content is not None and
                            (not content.fresh() or geometry is not None and
                             getattr(content, "window_bounds", content.bounds) != full)):
                        with self._layout_condition:
                            if self._content_map is content:
                                self._content_map = None
                        content = None
                    if geometry is None:
                        content = None
                    compact = False
                    stop_only = False
                    bounds = choose_panel_rect(visible, client, work, avoid,
                                               panel_size=(max(1, panel_width), panel_height), margin=px(8, dpi),
                                               content=content, previous=previous, preferred_corner=self._hud_position) if not self._user_compact and panel_width >= px(420, dpi) else None
                    if bounds is None:
                        # Quiet space may be unknown or busy. Keep a small
                        # transparent panel without inspecting other apps.
                        compact = True
                        compact_width = min(px(260 if self._user_compact else 240, dpi), client[2] - client[0] - px(16, dpi))
                        bounds = choose_panel_rect(visible, client, work, avoid,
                            panel_size=(max(1, compact_width), px(folded_panel_height(
                                self._STAGES[stage], checkpoint, self.task_hint,
                                next_step=note) if self._user_compact else 84, dpi)), margin=px(8, dpi),
                            content=content, previous=previous, preferred_corner=self._hud_position, allow_busy=True) if compact_width >= px(160, dpi) else None
                    if bounds is None:
                        # Small dialogs still get a readable Stop endpoint.
                        # It remains inside the target and obeys planned paths.
                        stop_only = True
                        bounds = choose_panel_rect(visible, client, work, avoid,
                            panel_size=(px(72, dpi), px(32, dpi)), margin=px(4, dpi), content=content, preferred_corner=self._hud_position, allow_busy=True)
                    self._panel_mode = "stop_only" if stop_only else "compact" if compact else "full"
                    if bounds is not None:
                        last_status_bounds = bounds
                    if bounds is None:
                        last_text_signature = last_stop_signature = None
                        if geometry is None:
                            raise IndicatorError("indicator_prepare_no_safe_panel")
                        for hwnd in (panel_hwnd, button_hwnd):
                            _user32.ShowWindow(hwnd, _SW_HIDE)
                        button_bounds = None
                    else:
                        l, t, r, b = bounds
                        button_width = px(72 if compact else 112, dpi)
                        button_height = px(28 if compact else 32, dpi)
                        button_bounds = (r - button_width - px(8, dpi), b - px(8, dpi) - button_height,
                                         r - px(8, dpi), b - px(8, dpi))
                        if stop_only:
                            button_bounds = bounds
                        # No show/position churn when geometry and DPI are unchanged.
                        if (win32gui.GetWindowRect(panel_hwnd) != bounds or
                                not win32gui.IsWindowVisible(panel_hwnd)):
                            self._place(panel_hwnd, l, t, r - l, b - t)
                        if win32gui.GetWindowRect(button_hwnd) != button_bounds:
                            self._place(button_hwnd, button_bounds[0], button_bounds[1],
                                button_bounds[2] - button_bounds[0], button_bounds[3] - button_bounds[1], show=False)
                    with self._layout_condition:
                        # Only the alpha-1 Stop rectangle can intercept planned input.
                        self._panel_bounds = button_bounds
                        self._status_bounds = bounds
                        self._layout_applied_revision = revision
                        self._layout_condition.notify_all()
                    next_geometry = now + .18
                frame_images = []
                if strips:
                    perimeter = max(1, 2 * ((visible[2] - visible[0]) + (visible[3] - visible[1])) - 4)
                    for hwnd, (x, y, w, h, vertical, reverse, offset) in zip(borders, strips):
                        reposition = strips != old_strips or not win32gui.IsWindowVisible(hwnd)
                        if reposition:
                            self._place(hwnd, x, y, w, h, show=False)
                        edge = 'end' if reverse != vertical else 'start'
                        image = render_neon_strip(h if vertical else w, w if vertical else h,
                                                  now * .12 % 1, offset, perimeter, vertical,
                                                  reverse, edge, not vertical)
                        drawing.paint_image(hwnd, image)
                        self._paints["borders"] += 1
                        frame_images.append((x, y, image))
                        if reposition:
                            _user32.ShowWindow(hwnd, _SW_SHOWNA)
                    if now >= next_occlusion:
                        # A topmost border can still be buried by a later topmost
                        # window; IsWindowVisible cannot see that. Probe the real
                        # z-order at a bounded interval and re-raise only then.
                        next_occlusion = now + _Z_ORDER_INTERVAL
                        for hwnd, (x, y, w, h, *_rest) in zip(borders, strips):
                            covered = covering_window(hwnd, (x, y, x + w, y + h),
                                                      self._window_handles)
                            self._covered_by[hwnd] = covered
                            if covered is not None:
                                try:
                                    self._raise_topmost(hwnd, keep_above=(panel_hwnd, button_hwnd))
                                except OSError as exc:
                                    # A failed z-order re-assert must not tear
                                    # down an otherwise usable HUD.
                                    self._note_layout("border_reassert_failed", hwnd=int(hwnd),
                                                      error=type(exc).__name__)
                                else:
                                    self._note_layout("border_covered_reasserted", hwnd=int(hwnd),
                                                      covered_by=int(covered))
                else:
                    for hwnd in borders:
                        _user32.ShowWindow(hwnd, _SW_HIDE)
                        self._covered_by.pop(hwnd, None)
                old_strips = strips
                if bounds is not None:
                    l, t, r, b = bounds
                    width, height = r - l, b - t
                    with self._layout_condition:
                        stage, checkpoint, estimate = self._stage, self._checkpoint, self._estimated_seconds
                        note = self._next_step or (self.task_hint if self.persistent else None)
                        elapsed = int(max(0, now - self._operation_started))
                    signature = (bounds, dpi, title, stage, checkpoint, estimate, elapsed, note, self.task_hint, compact, stop_only, self._user_compact)
                    if signature != last_text_signature:
                        next_hint = checkpoint
                        panel_image = render_status_image((width, height), dpi, title,
                                                          self._STAGES[stage], next_hint, elapsed,
                                                          estimate, note, purpose=self.task_hint,
                                                          compact=compact, operator=self._display_operator(), stop_only=stop_only,
                                                          folded=self._user_compact,
                                                          elapsed_label="接管等待" if stage == "takeover" else "控制累计",
                                                          language=self._language)
                        drawing.paint_image(panel_hwnd, panel_image)
                        self._paints["panel"] += 1
                        # The drawn text is pixels; mirror one line into the panel
                        # title so a read-only inspector can still read it.
                        _user32.SetWindowTextW(panel_hwnd, self.panel_text())
                        last_text_signature = signature
                    button_label = self.stop_button_text(compact)
                    stop_signature = (button_bounds, dpi, button_label, stop_only)
                    if stop_signature != last_stop_signature:
                        bw, bh = button_bounds[2] - button_bounds[0], button_bounds[3] - button_bounds[1]
                        image = render_action_image(button_label,
                                                    (bw, bh), dpi, destructive=True, backed=stop_only)
                        stop_image = image
                        drawing.paint_image(button_hwnd, image)
                        self._paints["stop"] += 1
                        _user32.ShowWindow(button_hwnd, _SW_SHOWNA)
                        last_stop_signature = stop_signature
                self._record_painted_stage(stage, checkpoint, panel_hwnd=panel_hwnd,
                    button_hwnd=button_hwnd, bounds=bounds, stop_only=stop_only,
                    panel_image=panel_image, stop_image=stop_image)
                with self._layout_condition:
                    self._frames = {
                        "dpi": dpi, "title": title,
                        "visible": tuple(visible) if geometry is not None else None,
                        "strips": tuple(frame_images),
                        "panel": (tuple(bounds), panel_image)
                        if bounds is not None and panel_image is not None else None,
                        "stop": (tuple(button_bounds), stop_image)
                        if button_bounds is not None and stop_image is not None else None}
                self._ready.set()
                self._close_requested.wait(max(0, .067 - (time.monotonic() - now)))
        except BaseException as error:
            self._record_error(error)
        finally:
            self._ready.set()
            if button_hwnd and win32gui.GetCapture() == button_hwnd:
                win32gui.ReleaseCapture()
            with self._layout_condition:
                self._panel_bounds = None
                self._status_bounds = None
                self._layout_condition.notify_all()
            for hwnd in reversed(self._window_handles):
                if win32gui.IsWindow(hwnd):
                    _user32.RemovePropW(hwnd, _MARKER)
                    _user32.RemovePropW(hwnd, _HUD_RANK)
                    _user32.RemovePropW(hwnd, _HUD_GROUP)
                    _user32.RemovePropW(hwnd, self._display_property)
                    _user32.RemovePropW(hwnd, self._application_property)
                    try:
                        win32gui.DestroyWindow(hwnd)
                    except win32gui.error as error:
                        if self.error is None:
                            self._record_error(error)
            self._window_handles.clear()
            win32gui.PumpWaitingMessages()
            for name in reversed(class_names):
                try:
                    win32gui.UnregisterClass(name, hinstance)
                except win32gui.error as error:
                    if self.error is None:
                        self._record_error(error)

    def _thread_main(self) -> None:
        previous_dpi = None
        try:
            previous_dpi = _user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
            if not previous_dpi:
                raise IndicatorError("per_monitor_dpi_awareness_required")
            self._run_ui()
        except BaseException as error:
            self._record_error(error)
            self._ready.set()
        finally:
            if previous_dpi:
                _user32.SetThreadDpiAwarenessContext(previous_dpi)
            # Release Win32 callback cycles on the thread that owns the windows.
            gc.collect()
            self._closed.set()

    def start(self) -> "ForegroundIndicator":
        if self._thread is not None:
            raise IndicatorError("indicator_already_started")
        self._thread = threading.Thread(target=self._thread_main,
                                        name="flower-foreground-indicator", daemon=True)
        self._thread.start()
        if not self._ready.wait(4):
            self._close_requested.set()
            raise IndicatorError("indicator_start_timeout")
        if self.error is not None or self._closed.is_set():
            raise IndicatorError("indicator_start_failed") from self.error
        return self

    def close(self) -> bool:
        self._close_requested.set()
        if self._thread is None:
            self._closed.set()
        elif threading.current_thread() is not self._thread:
            return self._closed.wait(2)
        return self._closed.is_set()

    def __enter__(self) -> "ForegroundIndicator":
        return self.start()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def state(self) -> dict:
        """Read-only HUD diagnostics for the inspector; it never sends input."""
        with self._layout_condition:
            stage, checkpoint, note = self._stage, self._checkpoint, self._next_step
            panel = self._panel_bounds
            status = self._status_bounds
            notes = list(self._layout_notes)
            applied, revision = self._layout_applied_revision, self._layout_revision
            estimated = self._estimated_seconds
        handles = list(self._window_handles)
        return {
            "title": self.title_text(),
            "stage": stage, "stage_label": hud_text(self._STAGES[stage], self._language),
            "checkpoint": checkpoint, "next_step": note, "task_hint": self.task_hint,
            "text": self.panel_text(),
            "elapsed_seconds": round(max(0.0, time.monotonic() - self._operation_started), 3),
            "estimated_seconds": estimated,
            "thread_alive": bool(self._thread is not None and self._thread.is_alive()),
            "closed": self._closed.is_set(),
            "error": getattr(self.error, "code", None), "error_detail": self.error_detail,
            "capture_excluded": bool(self.capture_excluded),
            "persistent": bool(self.persistent), "prepare": bool(self.prepare),
            "target": {"hwnd": int(self.identity.hwnd), "pid": int(self.identity.pid)},
            "layout_reason": self._layout_reason,
            "layout_applied": applied >= revision,
            "panel_bounds": list(panel) if panel else None,
            "status_bounds": list(status) if status else None,
            "stop_bounds": list(panel) if panel else None,
            "panel_mode": self._panel_mode,
            "borders": [describe_window(hwnd) for hwnd in handles[:4]],
            "border_covered_by": {str(hwnd): self._covered_by.get(hwnd)
                                  for hwnd in handles[:4]},
            "panel_windows": [describe_window(hwnd) for hwnd in handles[4:]],
            "paints": dict(self._paints), "topmost_raises": self._topmost_raises,
            "layout_notes": notes,
        }

    def dump_frames(self, directory) -> dict:
        """Export this HUD's own rendered layers; screen capture cannot see them.

        The indicator windows use WDA_EXCLUDEFROMCAPTURE, so desktop screenshots
        omit them. These PNGs come from the exact layered images the indicator
        uploads, which makes them the faithful record of frame and text.
        """
        from PIL import Image
        with self._layout_condition:
            frames = self._frames
        if not frames:
            raise IndicatorError("indicator_frames_unavailable")
        strips = list(frames.get("strips") or ())
        panel = frames.get("panel")
        stop = frames.get("stop")
        pieces = [(int(x), int(y), image) for x, y, image in strips]
        if panel is not None:
            pieces.append((int(panel[0][0]), int(panel[0][1]), panel[1]))
        if stop is not None:
            pieces.append((int(stop[0][0]), int(stop[0][1]), stop[1]))
        if not pieces:
            raise IndicatorError("indicator_frames_unavailable")
        root = Path(directory)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise IndicatorError("indicator_dump_directory_unavailable") from exc
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        written = []
        frame_skipped = None
        if panel is not None:
            panel_path = root / f"hud-{stamp}-panel.png"
            panel[1].save(panel_path)
            written.append(str(panel_path))
        if stop is not None:
            stop_path = root / f"hud-{stamp}-stop.png"
            stop[1].save(stop_path)
            written.append(str(stop_path))
        left = min(x for x, _, _ in pieces)
        top = min(y for _, y, _ in pieces)
        right = max(x + image.size[0] for x, _, image in pieces)
        bottom = max(y + image.size[1] for _, y, image in pieces)
        if (right - left) * (bottom - top) <= _MAX_FRAME_PIXELS:
            canvas = Image.new("RGBA", (right - left, bottom - top), (0, 0, 0, 0))
            for x, y, image in pieces:
                canvas.alpha_composite(image.convert("RGBA"), (x - left, y - top))
            frame_path = root / f"hud-{stamp}-frame.png"
            canvas.save(frame_path)
            written.append(str(frame_path))
        else:
            # A silent omission once looked exactly like "the border was never
            # drawn", so the skipped composite is reported explicitly.
            frame_skipped = "pixel_limit"
        result = {"directory": str(root), "files": written,
                  "origin": [left, top, right, bottom],
                  "borders": [[x, y, image.size[0], image.size[1]]
                              for x, y, image in pieces[:len(strips)]],
                  "panel_bounds": list(panel[0]) if panel is not None else None,
                  "text": self.panel_text()}
        if frame_skipped is not None:
            result["frame_skipped"] = frame_skipped
        return result
