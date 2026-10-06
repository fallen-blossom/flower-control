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
import threading
import time
from typing import Callable, Iterable

import win32api
import win32con
import win32gui

from flower_control.drivers.computer_native import (
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE, MOUSEEVENTF_VIRTUALDESK,
    InputBatch, VirtualDesktop, WindowIdentity, assert_window, virtual_desktop,
    window_geometry, is_owned_popup,
)
from . import indicator_native_draw as drawing
from .indicator_operator import OperatorCache
from .indicator_visual import (
    frame_strips, px, render_neon_strip, render_status_image, render_action_image,
    preferred_status_width, TITLE_CONTROL_TEMPLATE,
)


_MARKER = "FlowerControlTaskIndicator"
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_TRANSPARENT = 0x00000020
_WS_EX_LAYERED = 0x00080000
_WS_EX_NOACTIVATE = 0x08000000
_WS_EX_TOPMOST = 0x00000008
_GWL_EXSTYLE = -20
_SWP_NOACTIVATE = 0x0010
_SWP_SHOWWINDOW = 0x0040
_HWND_TOPMOST = -1
_SW_HIDE = 0
_SW_SHOWNA = 8
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


def choose_panel_rect(window_rect: ScreenRect, client_rect: ScreenRect,
                      work_rect: ScreenRect,
                      avoid_screen_rects: Iterable[ScreenRect] = (), *,
                      panel_size: tuple[int, int] = (330, 42), margin: int = 8) -> ScreenRect | None:
    """Place the clickable panel outside the client first, then in a clear corner."""
    if (any(not _valid_rect(rect) for rect in
            (window_rect, client_rect, work_rect)) or
            type(panel_size) is not tuple or len(panel_size) != 2 or
            any(type(value) is not int or value <= 0 for value in panel_size) or
            type(margin) is not int or not 1 <= margin <= 128):
        raise ValueError("invalid_panel_geometry")
    avoid = _rects(avoid_screen_rects)
    width, height = panel_size
    half_margin = max(1, margin // 2)
    wl, wt, wr, wb = window_rect
    cl, ct, cr, cb = client_rect
    al, at, ar, ab = work_rect
    if width > ar - al or height > ab - at:
        return None

    # The first group does not cover any of the target window. The next group
    # can use titlebar or non-client space. Work-area corners help when a target
    # sits at one edge of the monitor. Client corners are the last resort.
    outside_window = (((wl + wr - width) // 2, wt - height - margin),
                      (wl + margin, wt - height - half_margin), (wr - width - margin, wt - height - half_margin),
                      (wr + half_margin, wt + margin), (wl - width - half_margin, wt + margin),
                      (wl + margin, wb + half_margin), (wr - width - margin, wb + half_margin))
    work_corners = ((al + margin, at + margin), (ar - width - margin, at + margin),
                    (al + margin, ab - height - margin), (ar - width - margin, ab - height - margin))
    non_client = ((cl + margin, ct - height - half_margin), (cr - width - margin, ct - height - half_margin),
                  (cr + half_margin, ct + margin), (cl - width - half_margin, ct + margin),
                  (cl + margin, cb + half_margin), (cr - width - margin, cb + half_margin))
    inside_client = ((cl + margin, ct + margin), (cr - width - margin, ct + margin),
                     (cl + margin, cb - height - margin), (cr - width - margin, cb - height - margin))
    for position in (*outside_window, *work_corners, *non_client):
        x, y = position
        candidate = (x, y, x + width, y + height)
        if (_contained(candidate, work_rect) and
                not _intersects(candidate, client_rect) and
                not any(_intersects(candidate, rect) for rect in avoid)):
            return candidate
    for x, y in inside_client:
        candidate = (x, y, x + width, y + height)
        if (_contained(candidate, client_rect) and
                _contained(candidate, work_rect) and
                not any(_intersects(candidate, rect) for rect in avoid)):
            return candidate
    return None


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
        point = (desktop.left + round(move.dx * max(1, desktop.width - 1) / 65535),
                 desktop.top + round(move.dy * max(1, desktop.height - 1) / 65535))
        paths.append((min(previous[0], point[0]) - padding,
                      min(previous[1], point[1]) - padding,
                      max(previous[0], point[0]) + padding + 1,
                      max(previous[1], point[1]) + padding + 1))
        previous = point
    return tuple(paths)


class ForegroundIndicator:
    """A bounded HUD whose lifetime is tied to one selected window instance."""

    TITLE_CONTROL_TEMPLATE = TITLE_CONTROL_TEMPLATE

    def __init__(self, identity: WindowIdentity, task_hint: str,
                 on_stop: Callable[[], None], *, lifetime_s: float = 90, persistent: bool = False,
                 avoid_screen_rects: Iterable[ScreenRect] = (), prepare: bool = False,
                 capture_excluded: bool = True, stop_probe: Callable[[], bool] | None = None) -> None:
        if (not isinstance(identity, WindowIdentity) or
                type(task_hint) is not str or not task_hint.strip() or
                len(task_hint) > 80 or not callable(on_stop) or
                type(lifetime_s) not in (int, float) or
                not 1 <= lifetime_s <= 300 or type(prepare) is not bool or
                type(capture_excluded) is not bool):
            raise ValueError("invalid_indicator_request")
        self.identity = identity
        self.task_hint = task_hint
        self.on_stop = on_stop
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
        self._close_requested = threading.Event()
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None
        self.error_detail: str | None = None
        self._window_handles: list[int] = []
        self._layout_condition = threading.Condition()
        self._layout_revision = 0
        self._layout_applied_revision = -1
        self._panel_bounds: ScreenRect | None = None
        self._operation_started = time.monotonic()
        self._expires = float("inf") if persistent else self._operation_started + self.lifetime_s
        self._stop_probe = stop_probe
        self._operator = OperatorCache()
        self._stage = "prepare" if prepare else "execute"
        self._checkpoint = "动作结束后核对结果"
        self._estimated_seconds = None

    _STAGES = {"execute": "执行阶段", "prepare": "准备目标", "queued": "等待执行", "input": "输入阶段",
               "verify": "核对结果", "wait": "等待变化", "stopping": "停止请求已收到",
               "stopped": "已停止，释放已确认", "release_unconfirmed": "释放未确认"}

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
            self._stage = stage
            self._checkpoint = checkpoint
            self._estimated_seconds = estimated_seconds

    def title_text(self) -> str:
        return self.TITLE_CONTROL_TEMPLATE.format(operator=self._operator.label())

    def keep_alive(self, task_hint: str | None = None):
        with self._layout_condition:
            self._expires = float("inf") if self.persistent else time.monotonic() + self.lifetime_s
            if task_hint:
                self.task_hint = task_hint[:80]

    def linger(self, seconds: float = 3):
        with self._layout_condition:
            self._expires = min(self._expires, time.monotonic() + seconds)

    def status_text(self, target_label: str | None = None) -> str:
        with self._layout_condition:
            elapsed = max(0, time.monotonic() - self._operation_started)
            estimate = ("未知" if self._estimated_seconds is None else f"{self._estimated_seconds:.1f} 秒")
            return (self.title_text() + '\n' +
                    f"接下来：{self._STAGES[self._stage]} · {(target_label or self.task_hint)[:20]} · {self._checkpoint[:20]}\n"
                    f"已耗时 {elapsed:.1f} 秒 · 预计耗时：{estimate}")

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

    def _target_layout(self):
        assert_window(self.identity)
        minimized = win32gui.IsIconic(self.identity.hwnd)
        foreground_matches = True
        if self.prepare and not minimized:
            foreground = win32gui.GetAncestor(win32gui.GetForegroundWindow(), win32con.GA_ROOT)
            # An owned modal belongs to this visible task context. This only
            # preserves the HUD; input still requires its exact foreground grant.
            foreground_matches = (foreground == self.identity.hwnd or
                                  is_owned_popup(self.identity, foreground))
        if self.prepare and (minimized or not foreground_matches):
            monitor = win32api.MonitorFromPoint(win32gui.GetCursorPos(), win32con.MONITOR_DEFAULTTONEAREST)
            return None, tuple(win32api.GetMonitorInfo(monitor)["Work"])
        if minimized:
            return None, None
        geometry = window_geometry(self.identity)
        monitor = win32api.MonitorFromWindow(self.identity.hwnd, win32con.MONITOR_DEFAULTTONEAREST)
        return geometry, tuple(win32api.GetMonitorInfo(monitor)["Work"])

    def _run_ui(self) -> None:
        """The shared Medium/High HUD; only its independent Stop hit area clicks."""
        hinstance = win32api.GetModuleHandle(None)
        class_names = []
        button_hwnd = panel_hwnd = 0
        pressed = False
        stopping = False
        class_prefix = f"FlowerControlIndicator_{id(self):x}_{threading.get_ident():x}"

        def call_owner():
            try:
                self.on_stop()
            except BaseException as error:
                self._record_error(error)
            # The owner reports actual release later. A returned callback is
            # neither release proof nor an instruction to hide the Stop result.

        def window_proc(hwnd, message, wparam, lparam):
            nonlocal pressed, stopping
            try:
                if message == win32con.WM_MOUSEACTIVATE:
                    return win32con.MA_NOACTIVATE
                if message == win32con.WM_NCHITTEST and hwnd != button_hwnd:
                    return -1  # The status letters and frame always pass through.
                if message == win32con.WM_LBUTTONDOWN and hwnd == button_hwnd:
                    if not stopping:
                        pressed = True
                        win32gui.SetCapture(hwnd)
                    return 0
                if message == win32con.WM_CAPTURECHANGED:
                    pressed = False
                if message == win32con.WM_LBUTTONUP and hwnd == button_hwnd:
                    had_press, pressed = pressed, False
                    if win32gui.GetCapture() == hwnd:
                        win32gui.ReleaseCapture()
                    x, y = ctypes.c_short(lparam & 0xffff).value, ctypes.c_short(lparam >> 16).value
                    rect = win32gui.GetClientRect(hwnd)
                    if had_press and not stopping and 0 <= x < rect[2] and 0 <= y < rect[3]:
                        stopping = True
                        self.stop_requested.set()
                        self.set_stage("stopping", checkpoint="等待执行者确认释放")
                        threading.Thread(target=call_owner, name="flower-indicator-stop", daemon=True).start()
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
                name, "停止本次操作" if suffix == "_stop" else "", win32con.WS_POPUP,
                0, 0, 1, 1, owner, 0, hinstance, None)
            self._window_handles.append(hwnd)
            self._style(hwnd, click_through=click_through, capture_excluded=self.capture_excluded)
            return hwnd

        try:
            assert_window(self.identity)
            first_border = create("_border_0", True)
            panel_hwnd = create("_status", True)
            button_hwnd = create("_stop", False, panel_hwnd)
            borders = [first_border] + [create(f"_border_{index}", True, panel_hwnd)
                                        for index in range(1, 4)]
            # Preserve the current controller's externally observed handle order.
            self._window_handles[:] = [*borders, panel_hwnd, button_hwnd]
            next_geometry = 0.0
            strips = ()
            old_strips = None
            bounds = button_bounds = None
            last_text_signature = None
            last_stop_signature = None
            width_signature = None
            preferred_width = 0
            dpi = 96
            geometry = None
            while not self._close_requested.is_set() and time.monotonic() < self._expires:
                if win32gui.PumpWaitingMessages():
                    break
                now = time.monotonic()
                if self._stop_probe is not None and self._stop_probe():
                    with self._layout_condition:
                        stage = self._stage
                    if stage not in {"stopping", "stopped", "release_unconfirmed"}:
                        if stage == "wait":
                            self.set_stage("stopped", checkpoint="全局写入已停止", input_release="released")
                            self.linger()
                        else:
                            self.set_stage("stopping", checkpoint="全局停止，等待输入释放")
                title = self.title_text()
                with self._layout_condition:
                    revision, avoid = self._layout_revision, self._avoid_screen_rects
                if now >= next_geometry or revision != self._layout_applied_revision:
                    geometry, work = self._target_layout()
                    if work is None:
                        break
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
                    panel_width = min(preferred_width, work[2] - work[0] - px(16, dpi))
                    panel_height = px(56, dpi)
                    bounds = choose_panel_rect(visible, client, work, avoid,
                                               panel_size=(max(1, panel_width), panel_height), margin=px(8, dpi))
                    if bounds is None:
                        last_text_signature = last_stop_signature = None
                        if geometry is None:
                            raise IndicatorError("indicator_prepare_no_safe_panel")
                        for hwnd in (panel_hwnd, button_hwnd):
                            _user32.ShowWindow(hwnd, _SW_HIDE)
                        button_bounds = None
                    else:
                        l, t, r, b = bounds
                        button_width = min(px(112, dpi), max(1, (r - l) // 3))
                        button_height = min(px(44, dpi), max(1, b - t - 2 * px(8, dpi)))
                        button_bounds = (r - button_width - px(8, dpi), b - px(8, dpi) - button_height,
                                         r - px(8, dpi), b - px(8, dpi))
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
                        self._layout_applied_revision = revision
                        self._layout_condition.notify_all()
                    next_geometry = now + .18
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
                        if reposition:
                            _user32.ShowWindow(hwnd, _SW_SHOWNA)
                else:
                    for hwnd in borders:
                        _user32.ShowWindow(hwnd, _SW_HIDE)
                old_strips = strips
                if bounds is not None:
                    l, t, r, b = bounds
                    width, height = r - l, b - t
                    with self._layout_condition:
                        stage, checkpoint, estimate = self._stage, self._checkpoint, self._estimated_seconds
                        elapsed = int(max(0, now - self._operation_started))
                    signature = (bounds, dpi, title, stage, checkpoint, estimate, elapsed)
                    if signature != last_text_signature:
                        next_hint = self.task_hint if checkpoint == "动作结束后核对结果" else checkpoint
                        image = render_status_image((width, height), dpi, title,
                                                    self._STAGES[stage], next_hint, elapsed, estimate)
                        drawing.paint_image(panel_hwnd, image)
                        last_text_signature = signature
                    stop_signature = (button_bounds, dpi, stopping)
                    if stop_signature != last_stop_signature:
                        bw, bh = button_bounds[2] - button_bounds[0], button_bounds[3] - button_bounds[1]
                        image = render_action_image("正在停止" if stopping else "停止本次操作",
                                                    (bw, bh), dpi, destructive=True)
                        drawing.paint_image(button_hwnd, image)
                        _user32.ShowWindow(button_hwnd, _SW_SHOWNA)
                        last_stop_signature = stop_signature
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
                self._layout_condition.notify_all()
            for hwnd in reversed(self._window_handles):
                if win32gui.IsWindow(hwnd):
                    _user32.RemovePropW(hwnd, _MARKER)
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

    def close(self) -> None:
        self._close_requested.set()
        if self._thread is not None and threading.current_thread() is not self._thread:
            self._closed.wait(2)

    def __enter__(self) -> "ForegroundIndicator":
        return self.start()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()
