"""Thin App consumer of Core stages and the existing Computer indicator."""
from contextlib import contextmanager
import threading
import time
import win32gui
import win32con
from contextvars import ContextVar

from flower_control.control.foreground_stage import begin_foreground_stage, foreground_stage_context
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE, process_creation_filetime
from flower_control.control.state import ControlError
from flower_control.drivers.computer_native import bind_window, NativeInputError
from flower_control.drivers.foreground_indicator import ForegroundIndicator, IndicatorError
from flower_control.drivers.foreground_watch import ForegroundWatch
from flower_control.control.takeover import TakeoverBarrier
from flower_control.drivers.computer_native import is_owned_popup, _read_window_identity


class AppInvokeDrain:
    """Exact pre-call owner identities for finishing one disposed-menu Invoke.

    Window properties and policy checks grant no ancestor content/input scope.
    This is a drain gate; a separate owned-worker completion is still required.
    """
    def __init__(self, identity, anchors, policy_revision):
        self.identity, self.anchors, self.policy_revision = identity, tuple(anchors), policy_revision
        self.process_start_filetime = process_creation_filetime(identity.pid, expected_iso=identity.process_created)
        self.armed = False
        self._destroy_notified = False
        self._ancestor_transition_started = None

    @classmethod
    def capture(cls, identity, policy_revision):
        from flower_control.permissions import revision, require_window, PermissionError
        try:
            anchors, seen, current = [], {identity.hwnd}, identity.hwnd
            for _ in range(16):
                owner = win32gui.GetWindow(current, win32con.GW_OWNER)
                if not owner:
                    if not anchors:
                        return None
                    drain = cls(identity, anchors, policy_revision)
                    drain.check_bound_chain()
                    return drain
                if owner in seen:
                    return None
                seen.add(owner)
                require_window(owner)
                anchor = bind_window(owner)
                if (anchor.pid != identity.pid or anchor.process_created != identity.process_created
                        or revision() != policy_revision):
                    return None
                anchors.append(anchor)
                current = owner
        except (NativeInputError, PermissionError, OSError, ValueError, AttributeError, win32gui.error):
            pass
        return None

    def check_bound_chain(self):
        from flower_control.permissions import revision, require_window
        if (revision() != self.policy_revision or _read_window_identity(self.identity.hwnd) != self.identity
                or process_creation_filetime(self.identity.pid, expected_iso=self.identity.process_created) != self.process_start_filetime):
            raise NativeInputError('window_changed')
        current = self.identity.hwnd
        for anchor in self.anchors:
            if (win32gui.GetWindow(current, win32con.GW_OWNER) != anchor.hwnd
                    or _read_window_identity(anchor.hwnd) != anchor):
                raise NativeInputError('window_changed')
            require_window(anchor.hwnd)
            current = anchor.hwnd
        if win32gui.GetWindow(current, win32con.GW_OWNER) or revision() != self.policy_revision:
            raise NativeInputError('window_changed')

    def arm(self):
        self.check_bound_chain()
        self.armed = True

    def continuation(self):
        if not self.armed or win32gui.IsWindow(self.identity.hwnd):
            return None
        return self._live_anchor()

    def _live_anchor(self):
        from flower_control.permissions import revision, require_window, PermissionError
        if not self.armed:
            return None
        try:
            if revision() != self.policy_revision:
                return None
            first = None
            for anchor in self.anchors:
                if not win32gui.IsWindow(anchor.hwnd):
                    continue
                if _read_window_identity(anchor.hwnd) != anchor or win32gui.IsIconic(anchor.hwnd):
                    return None
                if process_creation_filetime(anchor.pid, expected_iso=anchor.process_created) != self.process_start_filetime:
                    return None
                require_window(anchor.hwnd)
                first = first or anchor
            return first if revision() == self.policy_revision else None
        except (NativeInputError, PermissionError, OSError, ValueError, win32gui.error):
            return None
        return None

    def notify_destroy(self, hwnd, foreground):
        # WinEvent DESTROY is delivered while IsWindow can still be true and
        # the child's nonce/owner properties are already being dismantled.
        # Admit only drain of this armed Invoke; completion still requires the
        # HWND gone and both original executors confirmed ended.
        if hwnd != self.identity.hwnd or not self.armed:
            return False
        self._destroy_notified = True
        return self.allows(foreground)

    def allows(self, hwnd):
        anchor = self.continuation()
        if anchor is None:
            # WPF/native dialogs can focus their original owner immediately
            # before destroying the child. Drain only the already-sent Invoke,
            # with the original admitted owner chain and a bounded transition.
            if not self.armed or not hwnd or not win32gui.IsWindow(self.identity.hwnd):
                return False
            try:
                if not self._destroy_notified:
                    self.check_bound_chain()
                if self._live_anchor() is None:
                    return False
                root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT) or hwnd
                # The original child is also owned by every captured ancestor.
                # Its normal foreground time must not consume the short owner
                # transition allowance. The ordinary barrier admits it itself.
                if root == self.identity.hwnd or is_owned_popup(self.identity, root):
                    return False
                if not any(root == candidate.hwnd or is_owned_popup(candidate, root)
                           for candidate in self.anchors):
                    return False
            except (NativeInputError, OSError, ValueError, win32gui.error):
                # Reconcile a child which disappeared during the identity
                # check. A fresh original-owner check cannot grant new input.
                if win32gui.IsWindow(self.identity.hwnd):
                    return False
                return self.allows(hwnd)
            now = time.monotonic()
            if self._ancestor_transition_started is None:
                self._ancestor_transition_started = now
            return now - self._ancestor_transition_started <= .25
        if not hwnd:  # brief no-foreground gap, only after old HWND is gone
            return True
        root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT) or hwnd
        return any(win32gui.IsWindow(candidate.hwnd) and
            (root == candidate.hwnd or is_owned_popup(candidate, root)) for candidate in self.anchors)


_current_stage = ContextVar("app_dispatch_stage", default=None)
display_next_step = ContextVar("app_display_next_step", default=None)
display_task_purpose = ContextVar("app_display_task_purpose", default=None)
execution_mode = ContextVar("app_execution_mode", default="foreground")
BACKGROUND_PATTERNS = frozenset({"set_value", "set_toggle", "select_item", "expand_collapse"})


def finish_app_indicator(store, owner, action, indicator, *, task, stopped=False, layout_memory=None):
    """Keep short truthful Stop/release warnings; normal completed phases close."""
    if layout_memory is None:
        layout_memory = getattr(indicator, '_layout_memory', None)
    try:
        receipt = store.status(owner, action)
        stopped = stopped or receipt.get("cancel_requested") or bool(
            indicator.stop_requested.is_set()) or store.task_write_stopped(task)
        release = receipt.get("input_release")
        with store.read_transaction() as db:
            binding = db.execute("SELECT confirmed FROM input_release_bindings WHERE action=?", (action,)).fetchone()
        unknown = release in {"unknown", "release_pending"} or binding is not None and binding[0] is None
    except ControlError:
        release, unknown = None, True
    if unknown:
        if layout_memory is not None:
            layout_memory.invalidate()
        indicator.set_stage("release_unconfirmed", checkpoint="输入释放尚未确认", input_release="unknown")
        indicator.retain_release_warning()
    elif stopped:
        if layout_memory is not None:
            layout_memory.invalidate()
        indicator.set_stage("stopped" if release == "released" else "stopping",
            checkpoint="写入已停止" if release == "released" else "停止请求已收到，核对实际动作状态",
            input_release="released" if release == "released" else None)
        indicator.linger()
    else:
        if layout_memory is not None:
            layout_memory.remember(indicator.identity, getattr(indicator, '_status_bounds', None))
        indicator.close()


def check_app_stage():
    stage = _current_stage.get()
    if stage is not None:
        stage.check()


def arm_app_invoke_drain():
    from flower_control.permissions import PermissionError
    stage = _current_stage.get()
    if isinstance(stage, AppStage):
        stage.check()
        if stage.barrier.drain is not None:
            try:
                stage.barrier.drain.arm()
            except (NativeInputError, PermissionError, OSError, ValueError, win32gui.error) as error:
                raise ControlError('observation_unavailable') from error
        # The following request body may reach the provider. Ordinary switching
        # now drains that one result; it cannot cause another Invoke.
        stage.barrier.business_sent = True


class AppTakeoverBarrier(TakeoverBarrier):
    """App policy for the existing WinEvent watcher; background UIA stays valid."""
    def __init__(self, identity, operation, signal_stop, *, drain=None):
        super().__init__(identity.hwnd, lambda: None)
        self.identity = identity
        self.require_foreground = operation == "invoke"
        self.expected_close = operation == "flower_app_invoke"
        self.signal_stop = signal_stop
        self.drain = drain if operation == "invoke" else None
        self.business_sent = False

    def _stop(self, reason, *, persistent=False):
        super()._stop(reason, persistent=persistent)
        if persistent or reason not in {"foreground_left_target", "target_minimized"}:
            self.signal_stop()

    def foreground_changed(self, hwnd):
        if not self.require_foreground:
            return
        if self.drain is not None and self.drain.allows(hwnd):
            return
        if hwnd == self.target_hwnd and win32gui.IsWindow(self.target_hwnd):
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
            if self.drain is not None and self.drain.notify_destroy(hwnd, current_foreground):
                return
            self._stop("target_destroyed")


class AppStage:
    def __init__(self, stage, watch, barrier, recovery=None, stop_signal=None):
        self.stage, self.watch, self.barrier = stage, watch, barrier
        self.recovery = recovery
        self.recovered = False
        self.stop_signal = stop_signal

    def check(self):
        if self.stop_signal is not None and self.stop_signal.is_set():
            raise ControlError("input_stopped")
        try:
            self.watch.check()
        except ControlError as error:
            if self.recover_interruption(error):
                return
            reason = {"foreground_left_target": "foreground_changed", "target_minimized": "target_minimized",
                      "target_destroyed": "target_closed"}.get(self.barrier.reason, "provider_changed")
            self.stage.interrupt(reason)
            raise
        self.stage.check()

    def recover_interruption(self, error):
        ordinary = (error.code == "foreground_phase_interrupted" and self.barrier.reason in
            {"foreground_left_target", "target_minimized"} and not self.barrier.persistent_stop_requested)
        if ordinary and self.barrier.business_sent:
            self.stage.check()
            return True
        if ordinary and self.recovery is not None and not self.recovered:
            self.recovered = True
            self.stage.check()
            self.watch.close()
            self.recovery()
            self.barrier.restart_transient()
            self.watch = ForegroundWatch(self.barrier)
            self.watch.start()
            self.watch.check()
            self.stage.check()
            return True
        return False

    def snapshot(self):
        return self.stage.snapshot()


_HINTS = {"set_value": "设置控件文本", "set_toggle": "设置开关状态", "select_item": "选择项目",
          "expand_collapse": "展开或折叠项目", "scroll": "滚动控件", "realize_item": "显现虚拟项目",
          "invoke": "调用控件", "flower_app_invoke": "正常关闭窗口", "close_window": "正常关闭窗口"}


def app_task_hint(operation):
    return _HINTS.get(operation, "执行当前 App 操作")


@contextmanager
def app_external_stage(store, owner, action, *, task, resource, resources,
                       identity, operation, cost, lease, signal_stop, stop_signal=None,
                       content_for_identity=None, layout_memory=None):
    """Prepare Stop/HUD only; the High executor watches after its activation."""
    if FOREGROUND_INPUT_RESOURCE not in resources:
        yield None
        return
    stage = begin_foreground_stage(store, owner, action, target_resource=resource,
                                   channel="app", operation=operation)
    stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
    indicator = None
    diagnostic_stage = "app_high_indicator_create"
    stop_signal = threading.Event() if stop_signal is None else stop_signal

    def request_stop():
        stop_signal.set()
        signal_stop()
        store.pause_task(task)
        with store.transaction() as db:
            store._mark_stage_stop(db,action)

    try:
        # High restores/activates after go. The existing preparation HUD keeps
        # Stop reachable while the target is minimized or in the background.
        indicator = ForegroundIndicator(identity, display_task_purpose.get() or app_task_hint(operation),
            request_stop, prepare=True, channel="app",
            previous_status_bounds=layout_memory.position(identity) if layout_memory is not None else None)
        indicator._layout_memory = layout_memory
        if content_for_identity is not None:
            content = content_for_identity(identity)
            if content is not None:
                indicator.set_content_map(content)
        indicator.bind_stop(request_stop, stop_signal)
        indicator.set_next_step(display_next_step.get())
        indicator.set_stage("prepare", checkpoint="准备目标后执行，再重新观察结果",
            estimated_seconds=cost.estimated_ms / 1000 if cost.estimated_ms is not None else None)
        diagnostic_stage = "app_high_indicator_start"
        indicator.start()
        with foreground_stage_context(stage):
            token = _current_stage.set(stage)
            try:
                if stop_signal.is_set():
                    raise ControlError("input_stopped")
                stage.check()
                indicator.set_stage("execute", checkpoint=app_task_hint(operation))
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
            finish_app_indicator(store, owner, action, indicator, task=task, layout_memory=layout_memory)


@contextmanager
def app_foreground_stage(store, owner, action, *, task, resource, resources, target,
                         operation, cost, signal_stop, before_watch=None,
                         invoke_policy_revision=None, defer_finish=None, content_for_identity=None,
                         layout_memory=None):
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
    checked_stage = None
    entered = False
    callback_started = False
    diagnostic_stage = "app_bind_target"
    def request_stop():
        stop.set()
        signal_stop()
        store.pause_task(task)
        with store.transaction() as db:
            store._mark_stage_stop(db,action)
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
                    indicator = ForegroundIndicator(identity, display_task_purpose.get() or app_task_hint(operation),
                        request_stop, channel="app",
                        previous_status_bounds=layout_memory.position(identity) if layout_memory is not None else None)
                    indicator._layout_memory = layout_memory
                    if content_for_identity is not None:
                        content = content_for_identity(identity)
                        if content is not None:
                            indicator.set_content_map(content)
                    indicator.bind_stop(request_stop, stop)
                    indicator.set_next_step(display_next_step.get())
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
            drain = (AppInvokeDrain.capture(identity, invoke_policy_revision)
                     if operation == "invoke" and invoke_policy_revision is not None else None)
            barrier = AppTakeoverBarrier(identity, operation, signal_stop, drain=drain)
            watch = ForegroundWatch(barrier)
            checked_stage = AppStage(stage, watch, barrier,
                recovery=(lambda: before_watch(identity, stage, stop.is_set)) if before_watch is not None else None,
                stop_signal=stop)
            try:
                watch.start()
            except ControlError as error:
                # Preserve the actual ordinary/lifecycle event as Core metadata.
                if not checked_stage.recover_interruption(error):
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
        try:
            if checked_stage is not None:
                checked_stage.watch.close()
            elif watch is not None:
                watch.close()
        finally:
            if indicator is not None:
                if defer_finish is not None:
                    defer_finish(indicator, stop.is_set())
                else:
                    finish_app_indicator(store, owner, action, indicator, task=task, stopped=stop.is_set())
