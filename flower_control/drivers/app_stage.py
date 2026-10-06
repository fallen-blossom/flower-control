"""Thin App consumer of Core stages and the existing Computer indicator."""
from contextlib import contextmanager
import threading
import win32gui
from contextvars import ContextVar

from flower_control.control.foreground_stage import begin_foreground_stage, foreground_stage_context
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE, process_creation_filetime
from flower_control.control.state import ControlError
from flower_control.drivers.computer_native import bind_window, NativeInputError
from flower_control.drivers.foreground_indicator import ForegroundIndicator, IndicatorError
from flower_control.drivers.foreground_watch import ForegroundWatch
from flower_control.control.takeover import TakeoverBarrier
from flower_control.drivers.computer_native import is_owned_popup


_current_stage = ContextVar("app_dispatch_stage", default=None)


def check_app_stage():
    stage = _current_stage.get()
    if stage is not None:
        stage.check()


class AppTakeoverBarrier(TakeoverBarrier):
    """App policy for the existing WinEvent watcher; background UIA stays valid."""
    def __init__(self, identity, operation, signal_stop):
        super().__init__(identity.hwnd, lambda: None)
        self.identity = identity
        self.require_foreground = operation == "invoke"
        self.expected_close = operation == "flower_app_invoke"
        self.signal_stop = signal_stop

    def _stop(self, reason, *, persistent=False):
        super()._stop(reason, persistent=persistent)
        self.signal_stop()

    def foreground_changed(self, hwnd):
        if not self.require_foreground or hwnd == self.target_hwnd:
            return
        # Invoking an owned popup is an application follow-up, not user takeover.
        if hwnd and is_owned_popup(self.identity, hwnd):
            return
        super().foreground_changed(hwnd)

    def minimized(self, hwnd):
        if self.require_foreground:
            super().minimized(hwnd)

    def target_destroyed(self, hwnd, current_foreground=None):
        if hwnd == self.target_hwnd and not self.expected_close:
            self._stop("target_destroyed")


class AppStage:
    def __init__(self, stage, watch, barrier):
        self.stage, self.watch, self.barrier = stage, watch, barrier

    def check(self):
        try:
            self.watch.check()
        except ControlError:
            reason = {"foreground_left_target": "foreground_changed", "target_minimized": "target_minimized",
                      "target_destroyed": "target_closed"}.get(self.barrier.reason, "provider_changed")
            self.stage.interrupt(reason)
            raise
        self.stage.check()

    def snapshot(self):
        return self.stage.snapshot()


_HINTS = {"set_value": "设置控件文本", "set_toggle": "设置开关状态", "select_item": "选择项目",
          "expand_collapse": "展开或折叠项目", "scroll": "滚动控件", "realize_item": "显现虚拟项目",
          "invoke": "调用控件", "flower_app_invoke": "正常关闭窗口", "close_window": "正常关闭窗口"}


def app_task_hint(operation):
    return _HINTS.get(operation, "执行当前 App 操作")


@contextmanager
def app_external_stage(store, owner, action, *, task, resource, resources,
                       identity, operation, cost, lease, signal_stop):
    """Prepare Stop/HUD only; the High executor watches after its activation."""
    if FOREGROUND_INPUT_RESOURCE not in resources:
        yield None
        return
    stage = begin_foreground_stage(store, owner, action, target_resource=resource,
                                   channel="app", operation=operation)
    stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
    indicator = None
    diagnostic_stage = "app_high_indicator_create"

    def request_stop():
        store.pause_task(task)
        signal_stop()

    try:
        # High restores/activates after go. The existing preparation HUD keeps
        # Stop reachable while the target is minimized or in the background.
        indicator = ForegroundIndicator(identity, app_task_hint(operation), request_stop, prepare=True)
        indicator.set_stage("prepare", checkpoint="准备目标后执行，再重新观察结果",
            estimated_seconds=cost.estimated_ms / 1000 if cost.estimated_ms is not None else None)
        diagnostic_stage = "app_high_indicator_start"
        indicator.start()
        with foreground_stage_context(stage):
            token = _current_stage.set(stage)
            try:
                stage.check()
                yield stage
            finally:
                _current_stage.reset(token)
    except (NativeInputError, IndicatorError, OSError, ValueError) as error:
        failure = ControlError("app_foreground_indicator_unavailable")
        failure.diagnostic = {"state": "rejected", "dispatched": False,
            "reason": getattr(error, "code", "app_foreground_indicator_unavailable"),
            "stage": diagnostic_stage, "exception_type": type(error).__name__}
        raise failure from error
    finally:
        if indicator is not None:
            indicator.close()


@contextmanager
def app_foreground_stage(store, owner, action, *, task, resource, resources, target,
                         operation, cost, signal_stop, before_watch=None):
    # Read-only and isolated test-resource lanes do not own the real desktop
    # mutex; they cannot create a Core foreground stage or a real HUD.
    if FOREGROUND_INPUT_RESOURCE not in resources:
        yield None
        return
    stage = begin_foreground_stage(store, owner, action, target_resource=resource,
                                   channel="app", operation=operation)
    stop = threading.Event()
    indicator = None
    watch = None
    entered = False
    callback_started = False
    diagnostic_stage = "app_bind_target"
    def request_stop():
        stop.set()
        store.pause_task(task)
        signal_stop()
    try:
        try:
            identity = bind_window(target["hwnd"])
            if (identity.pid != target["pid"] or process_creation_filetime(identity.pid,
                    expected_iso=identity.process_created) != target["process_start_filetime"]):
                raise ControlError("target_changed")
        except (NativeInputError, IndicatorError, OSError, ValueError) as error:
            reason = getattr(error, "code", "app_foreground_indicator_unavailable")
            # The shared HUD wraps UI-thread failures. Recover only this fixed
            # native code, never arbitrary error_detail/message text.
            if (indicator is not None and getattr(indicator, "error_detail", None)
                    == "NativeInputError: per_monitor_dpi_awareness_required"):
                reason = "per_monitor_dpi_awareness_required"
            failure = ControlError("app_foreground_indicator_unavailable")
            failure.diagnostic = {"state": "rejected", "dispatched": False,
                "reason": reason, "stage": diagnostic_stage, "exception_type": type(error).__name__}
            if type(getattr(error, "winerror", None)) is int:
                failure.diagnostic["winerror"] = error.winerror
            raise failure from error
        with foreground_stage_context(stage):
            if before_watch is not None:
                callback_started = True
                before_watch(identity, stage, stop.is_set)
            # Invoke restores/activates before the HUD binds visible geometry.
            # Background UIA can work on a minimized target: its receipt and
            # existing cancel endpoint remain available without a visible HUD.
            try:
                if not win32gui.IsIconic(identity.hwnd):
                    diagnostic_stage = "app_indicator_create"
                    indicator = ForegroundIndicator(identity, app_task_hint(operation), request_stop)
                    indicator.set_stage("input", checkpoint="本次操作结束后重新观察结果",
                        estimated_seconds=cost.estimated_ms / 1000 if cost.estimated_ms is not None else None)
                    diagnostic_stage = "app_indicator_start"
                    indicator.start()
                elif operation == "invoke":
                    raise ControlError("target_minimized")
            except (NativeInputError, IndicatorError, OSError, ValueError) as error:
                reason = getattr(error, "code", "app_foreground_indicator_unavailable")
                if (indicator is not None and getattr(indicator, "error_detail", None)
                        == "NativeInputError: per_monitor_dpi_awareness_required"):
                    reason = "per_monitor_dpi_awareness_required"
                failure = ControlError("app_foreground_indicator_unavailable")
                failure.diagnostic = {"state": "rejected", "dispatched": False,
                    "reason": reason, "stage": diagnostic_stage, "exception_type": type(error).__name__}
                if type(getattr(error, "winerror", None)) is int:
                    failure.diagnostic["winerror"] = error.winerror
                raise failure from error
            barrier = AppTakeoverBarrier(identity, operation, signal_stop)
            watch = ForegroundWatch(barrier)
            checked_stage = AppStage(stage, watch, barrier)
            try:
                watch.start()
            except ControlError:
                # Preserve the actual ordinary/lifecycle event as Core metadata.
                checked_stage.check()
                raise
            checked_stage.check()
            entered = True
            token = _current_stage.set(checked_stage)
            try:
                yield checked_stage
            finally:
                _current_stage.reset(token)
    finally:
        if not entered:
            # No UIA provider call was reachable. Preserve any activation
            # helper prefix that already occurred during stage preparation.
            store.record_action_effects(owner, action, activation_dispatched=None if callback_started else False,
                                        business_dispatched=False)
        if stop.is_set():
            # Callback threads signal only; Core interruption runs on the
            # original dispatcher with its actual mutex still held.
            try:
                stage.interrupt("explicit_stop")
            except ControlError:
                pass  # a terminal action still retains the persistent pause
        if indicator is not None:
            # UIA success/worker exit is not a held-input ledger release proof.
            # Never display 'stopped/released' based on either receipt.
            if stop.is_set():
                indicator.set_stage("stopping", checkpoint="停止请求已收到，核对实际动作状态")
            indicator.close()
        if watch is not None:
            watch.close()
