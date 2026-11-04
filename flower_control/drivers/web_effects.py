"""Request-local browser effect boundary; missing evidence stays unknown."""
from contextvars import ContextVar
from dataclasses import dataclass
from flower_control.control.state import ControlError


class WebClosePending(ControlError):
    """Normal close yielded a confirmation; the live session must be retained."""
    def __init__(self, result: dict):
        super().__init__("web_browser_close_pending")
        self.result = result


CLOSE_STOP_CODES = frozenset({"user_paused_or_cancelled", "task_revoked_or_missing",
                            "task_authorization_required", "owner_expired_or_missing",
                            "resource_paused_or_quarantined", "dispatcher_dead"})


@dataclass
class WebEffects:
    dispatched: bool = False
    stage: str = "preflight"


@dataclass
class WebDispatchWitness:
    """One in-process operation's admitted write boundary, not authority."""
    started: bool = False


current_effects: ContextVar[WebEffects | None] = ContextVar("web_effects", default=None)
current_write_admission: ContextVar[object] = ContextVar("web_write_admission", default=None)
current_dispatch_witness: ContextVar[WebDispatchWitness | None] = ContextVar("web_dispatch_witness", default=None)
KNOWN_STAGES = frozenset({"preflight", "transport_preflight", "runtime_preflight", "runtime_policy_preflight",
                         "control_policy_preflight", "control_queue_preflight", "close_preflight", "fill", "type", "click", "press",
                         "select_option", "set_checked", "drag", "upload", "editor_replace",
                         "terminal_focus", "close_browser", "new_page", "close_page", "hover",
                         "navigate", "history", "element_scroll", "scroll", "download_click",
                         "dialog_action", "chooser_upload", "prepare_hide_page", "hide_page", "show_page",
                         "reconcile_window_visibility", "recover_pending_page"})


def require_write_admission() -> None:
    """Check a write before dispatch, without claiming that it was attempted."""
    admission = current_write_admission.get()
    if admission is not None:
        with admission():
            pass  # Gate is released before any browser/IPC await.


def record_write_attempt(stage: str) -> None:
    """Retain an already possible effect; a late Stop cannot erase this fact.

    This function grants nothing. Only use after dispatch may have occurred;
    pre-dispatch code must use mark_write or require_write_admission first.
    """
    effects = current_effects.get()
    if effects is not None:
        effects.dispatched = True
        effects.stage = stage
    witness = current_dispatch_witness.get()
    if witness is not None:
        witness.started = True


def mark_write(stage: str) -> None:
    require_write_admission()
    record_write_attempt(stage)


def error_with_effect(error: Exception, *, dispatched: bool | None,
                      stage: str) -> Exception:
    error.web_dispatched = dispatched
    error.web_stage = stage
    return error
