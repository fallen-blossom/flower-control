"""App consumer of the fixed global broker; no installation or elevation here."""
from contextlib import contextmanager
from dataclasses import dataclass
import threading
import uuid

from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.native import physical_window_resource
from flower_control.control.state import ControlError
from flower_control.control.worker_call import command_hash
from flower_control.drivers.high_helper import HighHelperClient, HighHelperError, HighTarget
from flower_control.drivers.high_broker_types import AppRequest, InputBinding


@dataclass(frozen=True)
class AppHighRoute:
    session: object
    target: HighTarget


class AppHighBridge:
    def __init__(self, store, task, *, client=None, inspect=None):
        self.store, self.task = store, task
        self.client = client or HighHelperClient(channel="flower-app")
        self.inspect = inspect or HighTarget.inspect
        self._lock = threading.RLock()
        self._session = None
        self._bound = {}

    def close(self):
        # Only this connection closes. The shared broker remains alive.
        if self._session is not None:
            self._session.close()
            self._session = None

    def adopt_identity(self, hwnd, pid, created, nonce):
        """Cache only the in-process resolver's already admitted window nonce."""
        with self._lock:
            self._bound[(hwnd, pid, created)] = nonce

    @contextmanager
    def route(self, target, command):
        with self._lock:
            physical = self.inspect(target["hwnd"], target["pid"])
            if physical.facts["Created"] != target["process_start_filetime"]:
                raise HighHelperError("target_identity_changed")
            high_target = physical.facts["Integrity"] > 8192
            if not high_target and command in {"observe", "read_text"}:
                yield None
                return
            from flower_control._executor_metadata import executor_metadata
            actor = executor_metadata()
            if (not actor["metadata_available"] or physical.facts["Session"] != actor["session_id"]
                    or physical.facts["Integrity"] not in {8192, 12288}):
                raise HighHelperError("target_integrity_or_session_rejected")
            try:
                if self._session is None:
                    self._session = self.client.open_session(self.task)
                try:
                    status = self._session.status()
                except HighHelperError as error:
                    if error.code != "helper_session_closed":
                        raise
                    # A fresh call may reconnect after a previous uncertain
                    # request. This retries status only, never the old action.
                    self.close()
                    self._session = self.client.open_session(self.task)
                    status = self._session.status()
            except HighHelperError as error:
                self.close()
                # A pre-dispatch unavailable broker is the only fallback boundary.
                if (error.code in {"broker_unavailable", "broker_not_installed"}
                        and actor["integrity_rid"] >= physical.facts["Integrity"]):
                    yield None
                    return
                raise
            nonce = self._bound.get((target["hwnd"], target["pid"], physical.facts["Created"]), 0)
            fresh = self.inspect(target["hwnd"], target["pid"], nonce=nonce,
                                 broker_revision=status.desktop_revision)
            if fresh.facts != physical.facts:
                raise HighHelperError("target_identity_changed")
            yield AppHighRoute(self._session, fresh)

    def bind(self, route, owner, *, scope=None, shared_resource=None,
             current=lambda: True, authorized_until=None):
        """Bind one actual window through its own read-only ledger action."""
        target = route.target
        if not current():
            raise ControlError("target_changed")
        if target.nonce:
            from flower_control.drivers.computer_native import WindowIdentity
            if not current():
                raise ControlError("target_changed")
            return route, WindowIdentity(target.hwnd, target.facts["Pid"], target.process_created, target.nonce)
        resource = physical_window_resource(target.facts["Pid"], target.facts["Created"], target.hwnd)
        resources = (resource,) + ((shared_resource,) if shared_resource else ())
        key = self.task + ":app:high-bind-" + uuid.uuid4().hex
        self.store.register_resource(resource, required_scope=scope)
        self.store.bind_owned_resource(owner, resource)
        if shared_resource:
            self.store.register_resource(shared_resource, required_scope=scope)
        self.store.enqueue(owner, action_id=key, fingerprint=command_hash("high_bind", target.wire()),
                           resources=resources, read_only=True,
                           context={"channel": "app", "operation": "bind"})
        try:
            decision = wait_for_turn_sync(self.store, owner, key, resources, timeout=2)
        except BaseException:
            if self.store.status(owner, key)["state"] == "queued":
                self.store.cancel(owner, key)
            raise
        if decision.action_id != key:
            self.store.cancel(owner, key)
            raise ControlError("window_binding_queued")

        @contextmanager
        def before_go(lease):
            with self.store.dispatch_external(owner, key, decision.decision_id, lease):
                if not current() or (authorized_until is not None and self.store.clock() >= authorized_until):
                    raise ControlError("target_changed")
                yield
                if not current() or (authorized_until is not None and self.store.clock() >= authorized_until):
                    raise ControlError("target_changed")
                self.store.check_dispatch(owner, key)
                result = lease.result
                self.store.finish(owner, key, "verified" if result and result["State"] == "bound"
                                  else "not_verified", result_code="app_high_bind")

        try:
            outcome = route.session.execute(self.task, target, {"Kind": "bind"}, resources=resources,
                before_go=before_go, stopped=lambda: not current() or
                    self.store.external_dispatch_stopped(owner, key))
        except BaseException:
            if self.store.status(owner, key)["state"] == "queued":
                self.store.cancel(owner, key)
            raise
        if outcome["receipt"]["State"] != "bound" or not current():
            raise HighHelperError("window_binding_not_verified")
        identity = outcome["target"]
        rebound = self.inspect(target.hwnd, target.facts["Pid"], nonce=identity.window_nonce,
                               broker_revision=route.session.status().desktop_revision)
        if rebound.facts != target.facts:
            raise HighHelperError("target_identity_changed")
        if not current():
            raise HighHelperError("window_binding_not_verified")
        self._bound[(target.hwnd, target.facts["Pid"], target.facts["Created"])] = identity.window_nonce
        return AppHighRoute(route.session, rebound), identity

    @staticmethod
    def request(task, key, command, args, observation, generation):
        return AppRequest.create(command, args, InputBinding(task, key, observation, generation))
