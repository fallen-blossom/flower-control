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


current_effects: ContextVar[WebEffects | None] = ContextVar("web_effects", default=None)
current_write_admission: ContextVar[object] = ContextVar("web_write_admission", default=None)
KNOWN_STAGES = frozenset({"preflight", "transport_preflight", "fill", "type", "click", "press",
                         "select_option", "set_checked", "drag", "upload", "editor_replace",
                         "terminal_focus", "close_browser", "new_page", "close_page", "hover",
                         "navigate", "history", "element_scroll", "scroll", "download_click",
                         "dialog_action", "chooser_upload"})


def mark_write(stage: str) -> None:
    admission = current_write_admission.get()
    if admission is not None:
        with admission():
            pass  # Gate is released before any browser/IPC await.
    effects = current_effects.get()
    if effects is not None:
        effects.dispatched = True
        effects.stage = stage


def error_with_effect(error: Exception, *, dispatched: bool | None,
                      stage: str) -> Exception:
    error.web_dispatched = dispatched
    error.web_stage = stage
    return error
