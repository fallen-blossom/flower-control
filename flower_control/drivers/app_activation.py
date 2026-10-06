"""App consumer of existing bounded activation and exact ledger evidence.

The caller owns a real Core stage/mutex and supplies the shared ledger phase.
This module creates no authority, dispatch, input ledger or focus retry loop.
"""
from dataclasses import dataclass, field
import re

from flower_control.control.state import ControlError
from flower_control.drivers.computer_native import activate_window, NativeInputError


_CODE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_FIELDS = frozenset({"state", "reason", "foreground", "activation_method", "restored_from_minimized",
                     "activation_input_events", "activation_input_release", "activation_input_complete"})


@dataclass
class AppActivationAttempt:
    phase: object
    progress: dict = field(default_factory=lambda: {"activation_request_sent": False,
        "activation_input_events": 0, "activation_input_release": "not_used"})
    result: dict = field(default_factory=dict)
    ready: bool = False
    attempted: bool = False

    @property
    def dispatched(self):
        return bool(self.progress.get("activation_request_sent") or self.progress.get("activation_input_events", 0))

    def run(self, identity, *, stage, preflight, stopped):
        if self.attempted:
            raise ControlError("app_activation_attempt_already_used")
        self.attempted = True
        native_prefix = None
        def check():
            stage.check()
            return bool(preflight())
        try:
            native = activate_window(identity, preflight=check, stopped=stopped,
                restore_minimized=True, progress=self.progress, on_input_ledger=self.phase.track)
            self.result = {key: value for key, value in native.items() if key in _FIELDS}
            native_prefix = dict(self.result)
            if not check():  # activation is not evidence that the old observation survived
                raise ControlError("activation_not_authorized")
            self.ready = native.get("foreground") is True
        except (NativeInputError, ControlError) as error:
            reason = error.code if type(error.code) is str and _CODE.fullmatch(error.code) else "activation_failed"
            self.result = {"state": "rejected", "foreground": False, "reason": reason}
        except Exception:
            # Retain actual progress, but never expose arbitrary native messages.
            self.result = {"state": "outcome_uncertain", "foreground": False, "reason": "activation_outcome_uncertain"}
        release = self.phase.release_state
        if release in {"unknown", "release_pending"}:
            self.ready = False
            self.result.update(state="outcome_uncertain", reason="input_release_unconfirmed")
        self.result.update({key: value for key, value in self.progress.items()
                           if key in _FIELDS or key == "activation_request_sent"})
        self.result["activation_dispatched"] = self.dispatched
        self.result["input_release"] = release
        self.result["uia_dispatched"] = False
        if native_prefix is not None:
            self.result["native_result"] = native_prefix
        if not self.ready:
            self.result["continuation"] = {"state": "recovery_required" if release in
                {"unknown", "release_pending"} else "needs_fresh_observation", "repeat_old_action": False,
                                           "persistent_pause_requested": False}
        return self.ready

    def record_effects(self, store, owner, action, *, uia_aborted=False):
        store.record_action_effects(owner, action, activation_dispatched=self.dispatched,
            business_dispatched=False if uia_aborted else None,
            input_release=None if self.phase.release_state == "not_used" else self.phase.release_state)
