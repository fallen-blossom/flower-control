"""Narrow helper contract tests; OS peers and locks are isolated native fakes."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import MagicMock, patch

from flower_control.control.foreground_stage import begin_foreground_stage, yielded_foreground_wait
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from flower_control.control.state import ControlError, StateStore
from flower_control.control.write_gate import SharedWriteGate
from flower_control.drivers import high_helper as helper


class HighHelperTests(unittest.TestCase):
    def test_frozen_dotnet_runtimepack_is_immutable_but_core_unknown_and_legacy_stay_checked(self):
        import json
        with tempfile.TemporaryDirectory(prefix="flower-dotnet-immutable-") as temporary:
            root = Path(temporary) / "Program"
            version = "a" * 32
            directory = root / "versions" / version
            directory.mkdir(parents=True)
            package = "runtimepack.Microsoft.NETCore.App.Runtime.win-x64/10.0.10"
            deps = {"runtimeTarget": {"name": "test"}, "libraries": {package: {"type": "runtimepack"}},
                "targets": {"test": {package: {"runtime": {"System.Private.CoreLib.dll": {}, "Flower.HighHelper.dll": {}},
                    "native": {"coreclr.dll": {}}}}}}
            for name in (*helper._BUNDLE_NAMES, "coreclr.dll", "System.Private.CoreLib.dll", "unknown-plugin.dll"):
                (directory / name).write_bytes(b"owned immutable fixture")
            (directory / "Flower.HighHelper.deps.json").write_text(json.dumps(deps))
            nested = {"runtime/python.exe": "1" * 64}
            manifest = {"schema": 1, "files": nested, "dependency_inventory_sha256": "2" * 64,
                "downloads": False, "data_migrated": False}
            (directory / "runtime-inventory.json").write_text(json.dumps(manifest))
            hashes = {name: helper._digest(directory / name) for name in
                (*helper._BUNDLE_NAMES, "coreclr.dll", "System.Private.CoreLib.dll", "unknown-plugin.dll", "runtime-inventory.json")}
            active = dict(schema=1, version=version, hashes=hashes, runtime_hashes=nested)
            def write(value):
                (root / "active.json").write_text(json.dumps(value))
                (directory / "installation.json").write_text(json.dumps(value))
            with patch.object(helper, "program_root", return_value=root), patch.object(helper, "require_protected_path"):
                write(active)
                with patch.object(helper, "_digest", wraps=helper._digest) as digest:
                    helper._installed_bundle()
                checked = {Path(call.args[0]).name for call in digest.call_args_list}
                self.assertNotIn("coreclr.dll", checked)
                self.assertNotIn("System.Private.CoreLib.dll", checked)
                self.assertIn("Flower.HighHelper.dll", checked)
                self.assertIn("unknown-plugin.dll", checked)
                (directory / "unknown-plugin.dll").write_bytes(b"changed")
                with self.assertRaisesRegex(helper.HighHelperError, "installation_changed"):
                    helper._installed_bundle()
                (directory / "unknown-plugin.dll").write_bytes(b"owned immutable fixture")
                (directory / "Flower.HighHelper.exe").write_bytes(b"changed")
                with self.assertRaisesRegex(helper.HighHelperError, "bundle_changed"):
                    helper._installed_bundle()
                (directory / "Flower.HighHelper.exe").write_bytes(b"owned immutable fixture")
                write({**active, "hashes": {**hashes, "../outside.dll": "3" * 64}})
                with self.assertRaisesRegex(helper.HighHelperError, "installation_rejected"):
                    helper._installed_bundle()
                legacy = {key: value for key, value in active.items() if key != "runtime_hashes"}
                write(legacy)
                (directory / "coreclr.dll").write_bytes(b"changed")
                with self.assertRaisesRegex(helper.HighHelperError, "installation_changed"):
                    helper._installed_bundle()

    def test_frozen_runtime_manifest_is_pinned_without_rehashing_nested_runtime(self):
        import json
        import os
        with tempfile.TemporaryDirectory(prefix='flower-runtime-pin-') as directory:
            root = Path(directory) / 'FlowerControl/HighHelper'
            version = root / 'versions' / ('a' * 32)
            version.mkdir(parents=True)
            for name in helper._BUNDLE_NAMES:
                (version / name).write_bytes(b'local helper fixture')
            files = {'runtime/python.exe': '1' * 64, 'python-source/flower_control/app.py': '2' * 64}
            manifest = {'schema': 1, 'files': files, 'dependency_inventory_sha256': '3' * 64,
                        'downloads': False, 'data_migrated': False}
            manifest_path = version / 'runtime-inventory.json'
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            hashes = {name: helper._digest(version / name) for name in (*helper._BUNDLE_NAMES, 'runtime-inventory.json')}
            active = {'schema': 1, 'version': 'a' * 32, 'hashes': hashes, 'runtime_hashes': files}
            def write(value):
                (root / 'active.json').write_text(json.dumps(value), encoding='utf-8')
            with patch.object(helper, "program_root", return_value=root), patch.object(helper, "require_protected_path"):
                write(active)
                bundle, actual = helper._installed_bundle()
                self.assertEqual(actual, 'a' * 32)
                self.assertEqual(bundle.directory, version)
                write({**active, 'unexpected': True})
                with self.assertRaisesRegex(helper.HighHelperError, 'installation_rejected'):
                    helper._installed_bundle()
                for bad in ('runtime/../private.py', 'C:/runtime/python.exe', 'runtime/python.exe:stream',
                            'runtime\\python.exe', 'python-source//app.py', 'runtime/trailing. '):
                    write({**active, 'runtime_hashes': {bad: '1' * 64}})
                    with self.assertRaisesRegex(helper.HighHelperError, 'installation_rejected'):
                        helper._installed_bundle()
                write(active)
                manifest_path.write_text(json.dumps({**manifest, 'files': {'runtime/other.exe': '1' * 64}}), encoding='utf-8')
                with self.assertRaisesRegex(helper.HighHelperError, 'installation_changed'):
                    helper._installed_bundle()

    def test_background_write_plan_uses_target_only_and_rejects_activation(self):
        from flower_control.drivers.high_broker_types import AppRequest, InputBinding
        arguments = {"target": {"pid": 55, "hwnd": 7, "process_start_filetime": 101, "root_runtime_id": [2]},
            "reference": {"runtime_id": [1], "automation_id": "Field"},
            "observation": {"root_runtime_id": [2], "reference_runtime_id": [1], "observed_at_ms": 1},
            "privacy": "content_allowed", "privacy_scope": "content", "value": "test", "execution_mode": "must_background"}
        operation = AppRequest.create("set_value", arguments,
            InputBinding("task", "task:app:write", "observation", "generation")).operation()
        resources = self.target.resources_for(operation)
        self.assertEqual(resources, (self.target.resources[1],))
        helper._validate_plan(self.target, operation, resources)
        with self.assertRaisesRegex(helper.HighHelperError, "app_request_rejected"):
            helper._validate_plan(self.target, {**operation, "Activate": True}, resources)

    def setUp(self):
        self.write_gate = SharedWriteGate(namespace=uuid.uuid4().hex)
        self.addCleanup(self.write_gate.close)
        self.peer = {"Pid": 55, "Created": 101, "Session": 1, "User": "fixture-user", "ImageDigest": "a" * 64, "Integrity": 12288}
        self.target = helper.HighTarget(self.peer, "fixture-created", 7, (0, 0, 100, 100), 11, 1)

    def metadata_session(self):
        session = helper.HighHelperSession(SimpleNamespace(), "privacy-fixture")
        session._connection_id = "fixture-connection"
        session._pipe = MagicMock()
        session._pipe.read.return_value = {
            "Phase": "password_metadata", "TaskId": session.chat_id,
            "ConnectionId": session._connection_id, "DesktopRevision": 1,
            "Target": {"Hwnd": 7, "Pid": 55, "Created": 101, "WindowNonce": 11},
            "Metadata": {"Rectangles": [[10, 20, 40, 50]], "FocusRectangle": None, "FocusPassword": None},
            "Dispatched": False}
        self.enterContext(patch.object(session, "_start"))
        self.enterContext(patch.object(session, "_verify_peer"))
        return session

    def test_password_metadata_is_bound_read_only_and_has_no_write_lease(self):
        session = self.metadata_session()
        result = session.password_metadata(self.target, preflight=lambda: None, stopped=lambda: False)
        self.assertIs(result["dispatched"], False)
        self.assertEqual(result["rectangles"], [[10, 20, 40, 50]])
        request = session._pipe.write.call_args.args[0]
        self.assertEqual(request["Phase"], "password_metadata")
        self.assertNotIn("Operation", request)

    def test_password_metadata_rejects_replaced_target_and_preexisting_stop(self):
        session = self.metadata_session()
        pipe = session._pipe
        pipe.read.return_value["Target"]["WindowNonce"] = 12
        with self.assertRaisesRegex(helper.HighHelperError, "privacy_password_scan_incomplete"):
            session.password_metadata(self.target, preflight=lambda: None, stopped=lambda: False)
        session = self.metadata_session()
        with self.assertRaisesRegex(helper.HighHelperError, "privacy_scan_cancelled"):
            session.password_metadata(self.target, preflight=lambda: None, stopped=lambda: True)
        # Save the fake pipe because rejection closes this connection.
        self.assertEqual(pipe.write.call_count, 1)

    def result(self, lease, **changes):
        result = dict(Phase="done", LedgerIdentity=lease.ledger_identity, State="bound", Reason=None, Winerror=None,
            TaskId=getattr(lease, "chat_id", ""), ConnectionId=getattr(lease, "connection_id", ""),
            DesktopRevision=getattr(lease, "desktop_revision", 0), RequiresNewObservation=False,
            BusinessAttempted=False, NativeCountKnown=True, ImeEvents=0, ImePreparation=None, InputResult=None,
            RequestBinding=None, SemanticExecutor=None, SemanticExecutorExited=None, SemanticBusinessDispatched=False, AppResult=None,
            Target=lease.target, SentEvents=0, ActivationEvents=0, BusinessEvents=0, RequestedEvents=0,
            ReleaseEvents=0, InputRelease="released", ActivationRequested=False, ActivationDiagnostics=[], Foreground=False,
            MutexReleased=True, HighVerified=True, BusinessVerified=False, TimingsMs={})
        result.update(changes)
        return result

    @contextmanager
    def ready(self, operation=None):
        bundle = MagicMock(spec=helper.HelperBundle)
        bundle.directory = Path("C:/fixed-local-fixture")
        pipe = SimpleNamespace(handle=object())
        native = "flower_control.drivers.high_helper."
        with (patch(native + "_process", return_value=(self.peer, "fixture-created")),
              patch(native + "win32pipe.GetNamedPipeServerProcessId", return_value=55),
              patch(native + "win32event.CreateMutex"),
              patch(native + "win32event.ReleaseMutex"),
              patch(native + "process_is_alive", return_value=True),
              patch(native + "win32event.WaitForSingleObject", return_value=helper.win32event.WAIT_TIMEOUT),
              patch("flower_control.control.foreground_stage.process_is_alive", return_value=True)):
            yield helper.ExternalDispatchLease(helper._SEAL, pipe=pipe, helper=self.peer, bundle=bundle,
                target={"Hwnd": 7, "Pid": 55, "Created": 101, "WindowNonce": 11}, resources=self.target.resources,
                deadline=time.monotonic() + 5, ledger_identity="b" * 64, chat_id=getattr(self, "chat", "unit-no-dispatch"), operation=operation)

    def test_native_privacy_timings_do_not_discard_terminal_release(self):
        with self.ready() as lease:
            result = self.result(lease, State="interrupted", Reason="deadline_expired",
                TimingsMs={"privacy_worker_validation": 8.5, "privacy_scan": 4000.25, "privacy_query_wait": 31.5, "total": 4955})
            helper._validate_result(result, lease.target)
            self.assertEqual(result["InputRelease"], "released")
            self.assertEqual(result["Reason"], "deadline_expired")
            helper._validate_result(self.result(lease, TimingsMs={"privacy_query_wait": 0}), lease.target)
            for key, value in (("privacy_scan", -1), ("privacy_worker_validation", float("nan")),
                               ("privacy_scan", True), ("privacy_query_wait", -1),
                               ("privacy_query_wait", float("nan")), ("privacy_query_wait", float("inf")),
                               ("privacy_query_wait", True), ("unexpected_timing", 1)):
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(helper.HighHelperError, "result_rejected"):
                        helper._validate_result(self.result(lease, TimingsMs={key: value}), lease.target)

    def test_pointer_approach_timing_keeps_native_terminal_evidence(self):
        with self.ready() as lease:
            result = self.result(lease, State="interrupted", Reason="pointer_motion_incomplete",
                TimingsMs={"pointer_approach": 60.5, "dispatch": 3.25, "total": 70})
            helper._validate_result(result, lease.target)
            self.assertEqual(result["InputRelease"], "released")
            self.assertEqual(result["TimingsMs"]["pointer_approach"], 60.5)
            for value in (-1, float("inf"), True):
                with self.subTest(value=value), self.assertRaisesRegex(helper.HighHelperError, "result_rejected"):
                    helper._validate_result(self.result(lease, TimingsMs={"pointer_approach": value}), lease.target)

    def test_pointer_budget_diagnostic_is_bounded_and_does_not_discard_release(self):
        with self.ready() as lease:
            diagnostic = {"Start": [100, 200], "End": [900, 400], "Stage": "geometry", "Work": 128, "ElapsedMs": 105.25}
            result = self.result(lease, State="rejected", Reason="pointer_planning_budget_exceeded",
                RequiresNewObservation=True, PointerPlanningFailure=diagnostic, TimingsMs={"pointer_planning": 106})
            helper._validate_result(result, lease.target)
            self.assertEqual(result["InputRelease"], "released")
            for key, value in (("Stage", []), ("Stage", "other"), ("Work", True), ("Work", -1),
                               ("ElapsedMs", float("nan")), ("Start", [0]), ("End", [2**32, 0])):
                with self.subTest(key=key), self.assertRaisesRegex(helper.HighHelperError, "result_rejected"):
                    helper._validate_result({**result, "PointerPlanningFailure": {**diagnostic, key: value}}, lease.target)
            # Cancellation/cleanup can supersede the original planning error.
            # Optional diagnostics must not discard a valid terminal release.
            for reason in ("input_stopped", "release_partial", "foreground_changed"):
                helper._validate_result({**result, "Reason": reason}, lease.target)

    def test_partial_native_receipt_with_privacy_timings_reaches_durable_release(self):
        store, owner, decision = self.store(operation="drag")
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                    channel="computer", operation="drag")
                stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                lease.go_sent = True
                progress = dict(Binding=None, BusinessStarted=True, BusinessComplete=False, AcceptedEvents=10,
                    CompletedPlans=0, CompletedSegments=9,
                    PartialSegment={"plan": 0, "segment": 9, "accepted_count": 0, "requested_count": 1},
                    CleanupEvents=1, NativeCountKnown=True)
                terminal = self.result(lease, State="interrupted", Reason="input_stopped", BusinessAttempted=True,
                    SentEvents=10, BusinessEvents=10, RequestedEvents=11, ReleaseEvents=1, InputResult=progress,
                    TimingsMs={"privacy_worker_validation": 8.5, "privacy_scan": 900.0, "total": 1100.0})
                lease._accept(terminal)
                self.assertEqual(lease.terminal_for_interruption(), terminal)
                store.finish(owner, "a", "not_verified", result_code="input_stopped")
            self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "released")
            self.assertEqual(store.status(owner, "a")["input_release"], "released")
            self.assertEqual(store.status(owner, "a")["state"], "not_verified")
            with store.transaction() as db:
                self.assertIsNotNone(db.execute("SELECT confirmed FROM input_release_bindings WHERE action='a'").fetchone()[0])

    def test_native_segment_count_supports_full_valid_batch_budget(self):
        # Receipt structural capacity follows plans + timed segments. Work
        # admission is independently checked before dispatch, not by this DTO.
        with self.ready() as lease:
            progress = dict(Binding=None, BusinessStarted=True, BusinessComplete=True, AcceptedEvents=3300,
                CompletedPlans=100, CompletedSegments=3100, PartialSegment=None, CleanupEvents=0, NativeCountKnown=True)
            terminal = self.result(lease, State="dispatched_unverified", BusinessAttempted=True,
                SentEvents=3300, BusinessEvents=3300, RequestedEvents=3300, InputResult=progress)
            helper._validate_result(terminal, lease.target)
            helper._validate_result({**terminal, "InputResult": {**progress, "CompletedSegments": 8192+3000}}, lease.target)
            for invalid in (8192+3001, True, -1):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(helper.HighHelperError, "input_result_rejected"):
                    helper._validate_result({**terminal, "InputResult": {**progress, "CompletedSegments": invalid}}, lease.target)

    def test_motion_progress_accepts_native_pair_and_legacy_but_rejects_malformed_counters(self):
        with self.ready() as lease:
            progress=dict(Binding=None,BusinessStarted=True,BusinessComplete=True,AcceptedEvents=12,
                CompletedPlans=1,CompletedSegments=5,PartialSegment=None,CleanupEvents=0,NativeCountKnown=True)
            terminal=self.result(lease,State="dispatched_unverified",BusinessAttempted=True,
                SentEvents=12,BusinessEvents=12,RequestedEvents=12,InputResult=progress)
            helper._validate_result(terminal,lease.target)
            extended={**progress,"SkippedMotionSegments":2,"MotionClockRebases":1}
            helper._validate_result({**terminal,"InputResult":extended},lease.target)
            for field in ("SkippedMotionSegments","MotionClockRebases"):
                helper._validate_result({**terminal,"InputResult":{**extended,field:8192+3000}},lease.target)
                for bad in (True,-1,1.5,8192+3001):
                    with self.subTest(field=field,bad=bad),self.assertRaisesRegex(helper.HighHelperError,"input_result_rejected"):
                        helper._validate_result({**terminal,"InputResult":{**extended,field:bad}},lease.target)
                missing=dict(extended);missing.pop(field)
                with self.assertRaisesRegex(helper.HighHelperError,"input_result_rejected"):
                    helper._validate_result({**terminal,"InputResult":missing},lease.target)
            with self.assertRaisesRegex(helper.HighHelperError,"input_result_rejected"):
                helper._validate_result({**terminal,"InputResult":{**extended,"Unknown":0}},lease.target)

    def store(self, operation="bind"):
        temp = tempfile.TemporaryDirectory(prefix="flower-high-ledger-")
        self.addCleanup(temp.cleanup)
        store = StateStore(Path(temp.name), boot="high-unit-test", write_gate=self.write_gate)
        self.chat = store.create_task()
        owner = store.register_owner(self.chat)
        store.enqueue(owner, action_id="a", fingerprint="a", resources=self.target.resources,
                      context={"channel": "computer", "operation": operation})
        decision = store.prepare_decision(self.target.resources)
        self.assertTrue(store.adopt_decision(decision["id"], "a"))
        return store, owner, decision["id"]

    def test_no_arbitrary_command_or_unbound_input_can_reach_the_launcher(self):
        for operation in ({"Kind": "command", "Text": "fixture"}, {"Kind": "bind", "Script": "fixture"},
                          {"Kind": "text", "Text": "x" * 65}, {"Kind": "text", "Text": "\ud800"}):
            with self.subTest(operation=operation):
                with self.assertRaises(helper.HighHelperError):
                    helper._validate_plan(self.target, operation, self.target.resources)
        unbound = helper.HighTarget(self.peer, "fixture-created", 7, (0, 0, 100, 100))
        with self.assertRaisesRegex(helper.HighHelperError, "operation_rejected"):
            helper._validate_plan(unbound, {"Kind": "click", "X": 1, "Y": 1}, unbound.resources)
        helper._validate_plan(unbound, {"Kind": "bind"}, unbound.resources)

    def test_wrong_physical_resource_and_raw_lease_are_rejected(self):
        with self.assertRaisesRegex(helper.HighHelperError, "resources_rejected"):
            helper._validate_plan(self.target, {"Kind": "bind"}, (FOREGROUND_INPUT_RESOURCE, "physical-window-v1:55:102:7"))
        store, owner, decision = self.store()
        with self.assertRaisesRegex(ControlError, "external_executor_unverified"):
            with store.dispatch_external(owner, "a", decision, {"MutexOwned": True}):
                self.fail("raw receipt granted external dispatch")
        self.assertEqual(store.status(owner, "a")["state"], "queued")

    def test_other_chat_cannot_claim_this_helpers_native_lock_receipt(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            lease.chat_id = "a-different-chat"
            with self.assertRaisesRegex(ControlError, "external_executor_chat_mismatch"):
                with store.dispatch_external(owner, "a", decision, lease):
                    self.fail("another task used the bound helper")
        self.assertEqual(store.status(owner, "a")["state"], "queued")

    def test_external_stage_and_exact_ledger_release_do_not_fake_parent_handles(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                self.assertNotIn("a", store._dispatch_locks)
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1], channel="computer", operation="bind")
                binding = stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                self.assertEqual(binding.executor_process, lease.executor_process)
                self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "held")
                with self.assertRaisesRegex(ControlError, "foreground_wait_requires_yield"):
                    with yielded_foreground_wait(store, owner, reason="model"):
                        self.fail("model wait kept helper input lock")
                lease.go_sent = True
                lease._accept(self.result(lease))
                store.finish(owner, "a", "verified")
            self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "released")
            with store.transaction() as db:
                self.assertIsNotNone(db.execute("SELECT confirmed FROM input_release_bindings WHERE action='a'").fetchone()[0])
            with self.assertRaisesRegex(helper.HighHelperError, "external_lease_reused"):
                lease.claim("b", lease.resources, None)

    def test_go_without_terminal_receipt_stays_unknown_and_quarantines(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with self.assertRaisesRegex(helper.HighHelperError, "pipe_deadline"):
                with store.dispatch_external(owner, "a", decision, lease):
                    lease.go_sent = True
                    raise helper.HighHelperError("pipe_deadline")
        receipt = store.status(owner, "a")
        self.assertEqual(receipt["state"], "outcome_uncertain")
        self.assertEqual(receipt["input_release"], "unknown")
        with store.transaction() as db:
            quarantine = dict(db.execute("SELECT id,quarantined FROM resources WHERE id IN (?,?)", self.target.resources).fetchall())
        self.assertEqual(quarantine, {resource: 1 for resource in self.target.resources})

    def test_no_go_confirms_no_input_but_does_not_invent_mutex_release(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with self.assertRaisesRegex(helper.HighHelperError, "fixture_authorization_failed"):
                with store.dispatch_external(owner, "a", decision, lease):
                    stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                                                   channel="computer", operation="bind")
                    stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                    raise helper.HighHelperError("fixture_authorization_failed")
            self.assertEqual(stage.snapshot()["input_release"], "released")
            self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "unconfirmed")
        with store.transaction() as db:
            self.assertIsNone(db.execute("SELECT confirmed FROM input_release_bindings WHERE action='a'").fetchone()[0])

    def test_unconfirmed_mutex_release_quarantines_without_a_recovery_claim(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                                               channel="computer", operation="bind")
                stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                lease.go_sent = True
                lease._accept(self.result(lease, MutexReleased=False, Reason="mutex_release_unconfirmed"))
                self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "unconfirmed")
                store.finish(owner, "a", "verified")
            self.assertEqual(stage.snapshot()["state"], "outcome_uncertain")
            with self.assertRaisesRegex(ControlError, "foreground_wait_requires_yield"):
                with yielded_foreground_wait(store, owner, reason="model"):
                    self.fail("a live executor with unconfirmed mutex release overlapped a model wait")
            with patch.object(helper, "process_is_alive", return_value=False):
                with yielded_foreground_wait(store, owner, reason="model"):
                    pass
            self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "unconfirmed")
        with store.transaction() as db:
            self.assertIsNone(db.execute("SELECT confirmed FROM input_release_bindings WHERE action='a'").fetchone()[0])
            self.assertEqual([row[0] for row in db.execute("SELECT quarantined FROM resources WHERE id IN (?,?)",
                                                        self.target.resources)], [1, 1])

    def test_existing_stop_is_observed_by_the_external_watcher(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                self.assertFalse(store.external_dispatch_stopped(owner, "a"))
                with store.transaction() as db:
                    task = db.execute("SELECT task FROM owners WHERE id=?", (owner,)).fetchone()[0]
                store.revoke_task(task)
                self.assertTrue(store.external_dispatch_stopped(owner, "a"))
                lease._accept(self.result(lease, Reason="input_stopped", State="rejected"))

    def test_cross_chat_and_closed_sessions_reject_before_launch(self):
        client = helper.HighHelperClient(MagicMock(spec=helper.HelperBundle), medium_fixture=True)
        with client.open_session("chat-a") as session:
            with patch.object(session, "_start") as start:
                with self.assertRaisesRegex(helper.HighHelperError, "chat_binding_mismatch"):
                    session.execute("chat-b", self.target, {"Kind": "bind"}, before_go=lambda lease: None,
                                    stopped=lambda: False)
                start.assert_not_called()
        with self.assertRaisesRegex(helper.HighHelperError, "helper_session_closed"):
            medium = helper.HighTarget({**self.peer, "Integrity": 8192}, "fixture-created", 7, (0, 0, 100, 100), 11, 1)
            session.execute("chat-a", medium, {"Kind": "bind"}, before_go=lambda lease: None, stopped=lambda: False)

    def test_global_connection_reuses_one_peer_and_close_does_not_shutdown_broker(self):
        store, owner, decision = self.store()
        test = self
        with store.transaction() as db:
            owner_process = db.execute("SELECT process FROM owners WHERE id=?", (owner,)).fetchone()[0]
        bundle = MagicMock(spec=helper.HelperBundle)
        bundle.directory = Path("C:/fixed-local-fixture")
        bundle.hashes = tuple((name, "d" * 64 if name.endswith(".dll") else "a" * 64) for name in helper._BUNDLE_NAMES)
        parent = {**self.peer, "Pid": 77, "Created": 202, "Integrity": 8192}
        evidence = dict(Pid=77, Created=202, Session=1, Source="codex-flower", Channel="flower-computer",
                        ProductionAdmitted=True, LauncherPid=88, LauncherCreated=180, CodexPid=99)
        connection = "f" * 32
        class Pipe:
            handle = object()
            def __init__(self, name):
                self.messages, self.number = [], 0
                self.queue = [{"Phase": "hello", "Helper": test.peer, "AssemblyDigest": "d" * 64,
                    "Version": "e" * 16, "ConnectionId": connection, "PeerEvidence": evidence, "Status": {"desktop_revision": 1}}]
            def connect(self): pass
            def close(self): self.handle = None
            def write(self, message):
                self.messages.append(message)
                if message["Phase"] == "prepare":
                    self.number += 1
                    self.ledger = str(self.number) * 64
                    self.bound = {"Hwnd": 7, "Pid": 55, "Created": 101, "WindowNonce": 11}
                    self.queue.append({"Phase": "ready", "Helper": test.peer, "AssemblyDigest": "d" * 64,
                        "Target": self.bound, "Resources": message["Resources"], "MutexOwned": True,
                        "LedgerIdentity": self.ledger, "TaskId": test.chat, "ConnectionId": connection, "DesktopRevision": 1})
                elif message["Phase"] == "go":
                    self.queue.append(test.result(SimpleNamespace(ledger_identity=self.ledger, target=self.bound,
                        chat_id=test.chat, connection_id=connection, desktop_revision=1)))
            def read(self, timeout): return self.queue.pop(0)
        pipe = Pipe("fixture")
        native = "flower_control.drivers.high_helper."
        def process(pid, **options): return (parent if pid == 77 else self.peer), "fixture-created"
        with (patch(native + "_Pipe", return_value=pipe), patch(native + "_process", side_effect=process),
              patch("flower_control.control.state.process_identity", return_value=owner_process),
              patch(native + "_installed_bundle", return_value=(bundle, "e" * 16)),
              patch(native + "win32api.GetCurrentProcessId", return_value=77),
              patch(native + "win32pipe.GetNamedPipeServerProcessId", return_value=55),
              patch(native + "win32event.CreateMutex"),
              patch(native + "win32event.WaitForSingleObject", return_value=helper.win32event.WAIT_TIMEOUT)):
            with helper.HighHelperClient().open_session(self.chat) as session:
                results = []
                for index in range(2):
                    action = "a" if index == 0 else "b"
                    if index:
                        store.enqueue(owner, action_id=action, fingerprint=action, resources=self.target.resources)
                        chosen = store.prepare_decision(self.target.resources)
                        self.assertTrue(store.adopt_decision(chosen["id"], action))
                        decision = chosen["id"]
                    @contextmanager
                    def before_go(lease):
                        with store.dispatch_external(owner, action, decision, lease):
                            yield
                            store.finish(owner, action, "verified")
                    results.append(session.execute(self.chat, self.target, {"Kind": "bind"},
                        before_go=before_go, stopped=lambda: store.external_dispatch_stopped(owner, action), resources=self.target.resources))
            self.assertTrue(session.lifecycle["connection_closed"])
            self.assertIsNone(session.lifecycle["helper_exited"])
        self.assertEqual([r["new_connection"] for r in results], [True, False])
        self.assertEqual(results[0]["executor_process"], results[1]["executor_process"])
        self.assertNotEqual(results[0]["receipt"]["LedgerIdentity"], results[1]["receipt"]["LedgerIdentity"])
        self.assertEqual([m["Phase"] for m in pipe.messages], ["hello", "prepare", "go", "ack", "prepare", "go", "ack"])

    def test_close_can_cancel_an_in_flight_connection_without_waiting_on_its_dispatch_lock(self):
        session = helper.HighHelperClient(medium_fixture=True).open_session("chat-a")
        pipe = MagicMock()
        session._pipe = pipe
        session._lock.acquire()
        try:
            session.close()
            pipe.close.assert_called_once()
            self.assertIsNone(session.lifecycle["helper_exited"])
        finally:
            session._lock.release()

    def test_wrong_ledger_and_high_claim_are_not_accepted_as_release(self):
        with self.ready() as lease:
            with self.assertRaisesRegex(helper.HighHelperError, "result_ledger_mismatch"):
                lease._accept(self.result(lease, LedgerIdentity="c" * 64))
            with self.assertRaisesRegex(helper.HighHelperError, "result_integrity_mismatch"):
                lease._accept(self.result(lease, HighVerified=False))
            self.assertIsNone(lease.result)

    def test_bundle_bytes_are_pinned_and_import_never_launches(self):
        temp = tempfile.TemporaryDirectory(prefix="flower-high-bundle-")
        self.addCleanup(temp.cleanup)
        for name in helper._BUNDLE_NAMES:
            (Path(temp.name) / name).write_bytes(b"local fixture")
        bundle = helper.HelperBundle.snapshot(temp.name)
        (Path(temp.name) / helper._BUNDLE_NAMES[1]).write_bytes(b"changed local fixture")
        with self.assertRaisesRegex(helper.HighHelperError, "bundle_changed"):
            bundle.verify()
        with self.assertRaisesRegex(helper.HighHelperError, "production_bundle_override_rejected"):
            helper.HighHelperClient(bundle)
        session = helper.HighHelperClient().open_session("unit-no-dispatch")
        with patch.object(helper, "_installed_bundle", side_effect=helper.HighHelperError("broker_not_installed")):
            with self.assertRaisesRegex(helper.HighHelperError, "broker_not_installed"):
                session.status()
        self.assertTrue(session.lifecycle["connection_closed"])

    def test_buffered_frames_share_reads_and_keep_the_per_message_limit(self):
        pipe = helper._Pipe("isolated-buffered-frames")
        pipe.handle, pipe._read_buffer = object(), bytearray()
        first = b'{"Phase":"hello"}\n{"Phase":"ready"}\n'
        with (patch.object(helper.win32file, "ReadFile", return_value=(0, first)) as read,
              patch.object(helper.win32event, "CreateEvent"),
              patch.object(pipe, "_finish", return_value=len(first))):
            self.assertEqual(pipe.read(1), {"Phase": "hello"})
            self.assertEqual(pipe.read(1), {"Phase": "ready"})
            self.assertEqual(read.call_count, 1)
        pipe._read_buffer = bytearray(b"a" * helper._LIMIT)
        with self.assertRaisesRegex(helper.HighHelperError, "message_too_large"):
            pipe.read(1)

    def test_missing_native_mutex_and_wrong_peer_cannot_confirm_readiness(self):
        with self.ready() as lease:
            with patch.object(helper.win32event, "WaitForSingleObject", return_value=helper.win32event.WAIT_OBJECT_0):
                with self.assertRaisesRegex(helper.HighHelperError, "helper_mutex_not_owned"):
                    lease.verify()
            with patch.object(helper.win32pipe, "GetNamedPipeServerProcessId", return_value=56):
                with self.assertRaisesRegex(helper.HighHelperError, "helper_identity_changed"):
                    lease.verify()

    def test_medium_target_high_foreground_hint_is_conditional_and_never_launches(self):
        facts = {**self.peer, "Integrity": 8192}
        target = helper.HighTarget(facts, "fixture-created", 7, (0, 0, 100, 100), 11)
        actor = {"metadata_available": True, "session_id": 1, "integrity_rid": 8192, "ui_access": False}
        with patch("flower_control._executor_metadata.executor_metadata", return_value=actor):
            normal = helper.assess_high_route(target, foreground_integrity=12288)
            self.assertEqual(normal["route"], "ordinary")
            failed = helper.assess_high_route(target, failure_code="user_activation_required", foreground_integrity=12288)
            self.assertEqual(failed["route"], "high_helper_available")
            self.assertFalse(failed["activation_failure_cause_verified"])

    def test_full_action_binding_is_checked_before_any_go(self):
        from flower_control.drivers.high_broker_types import InputBinding
        store, owner, decision = self.store()
        with self.ready() as lease:
            lease.binding = InputBinding(self.chat, "a-different-full-action", "observation", "geometry")
            with self.assertRaisesRegex(ControlError, "external_executor_unverified"):
                with store.dispatch_external(owner, "a", decision, lease):
                    self.fail("wrong action claimed a live executor")
            self.assertFalse(lease.go_sent)
        self.assertEqual(store.status(owner, "a")["state"], "queued")

    def test_accepted_released_native_terminal_can_record_stage_interruption(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                                               channel="computer", operation="bind")
                lease.go_sent = True
                lease._accept(self.result(lease, State="interrupted", Reason="geometry_changed", RequiresNewObservation=True))
                self.assertFalse(lease.holds_resource(FOREGROUND_INPUT_RESOURCE))
                with self.assertRaisesRegex(ControlError, "stage_requires_foreground_dispatch"):
                    stage.interrupt("geometry_changed")
                snapshot = stage.interrupt_after_external(lease, "geometry_changed")["foreground_stage"]
                self.assertEqual(snapshot["interruption"], "geometry_changed")
                self.assertEqual(snapshot["input_release"], "released")
                self.assertTrue(snapshot["requires_new_observation"])
                store.finish(owner, "a", "not_verified")

    def test_terminal_interruption_preserves_unknown_release_and_prior_stop(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                                               channel="computer", operation="bind")
                stage.interrupt("explicit_stop")
                lease.go_sent = True
                lease._accept(self.result(lease, State="interrupted", InputRelease="unknown", NativeCountKnown=False,
                                          Reason="input_stopped", RequiresNewObservation=True))
                snapshot = stage.interrupt_after_external(lease, "geometry_changed")["foreground_stage"]
                self.assertEqual(snapshot["interruption"], "explicit_stop")
                self.assertEqual(snapshot["input_release"], "unknown")
                self.assertIsNone(snapshot["release_completed"])
                self.assertFalse(snapshot["automatic_reentry"])
                store.finish(owner, "a", "not_verified")

    def test_stage_terminal_interruption_rejects_forged_or_changed_ledger(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                stage = begin_foreground_stage(store, owner, "a", target_resource=self.target.resources[1],
                                               channel="computer", operation="bind")
                with self.assertRaisesRegex(ControlError, "external_terminal_unverified"):
                    stage.interrupt_after_external({"MutexReleased": True}, "geometry_changed")
                lease.go_sent = True
                lease._accept(self.result(lease))
                with store.transaction() as db:
                    db.execute("UPDATE input_release_bindings SET ledger_identity=? WHERE action='a'", ("c" * 64,))
                with self.assertRaisesRegex(ControlError, "external_terminal_binding_mismatch"):
                    stage.interrupt_after_external(lease, "geometry_changed")
                store.finish(owner, "a", "not_verified")

    def test_unknown_ime_prefix_does_not_invent_a_business_dispatch(self):
        store, owner, decision = self.store()
        with self.ready() as lease:
            with store.dispatch_external(owner, "a", decision, lease):
                lease.go_sent = True
                lease._accept(self.result(lease, State="interrupted", Reason="ime_count_unknown",
                    NativeCountKnown=False, ImeEvents=2, SentEvents=2, RequestedEvents=4,
                    BusinessAttempted=False, InputRelease="unknown"))
                store.finish(owner, "a", "outcome_uncertain", result_code="ime_count_unknown")
        status = store.status(owner, "a")
        self.assertFalse(status["business_dispatched"])
        self.assertEqual(status["input_release"], "unknown")
        self.assertEqual(status["state"], "outcome_uncertain")

    def test_background_uia_observe_uses_only_target_resource_and_sealed_zero_input(self):
        from flower_control.drivers.high_broker_types import AppRequest, InputBinding
        args = {"target": {"pid": 55, "hwnd": 7, "process_start_filetime": 101, "root_runtime_id": []},
                "limits": {"max_nodes": 16, "max_depth": 2}, "privacy": "structure_only", "privacy_scope": ""}
        operation = AppRequest.create("observe", args, InputBinding("task", "task:app:action", "observation", "geometry")).operation()
        required = self.target.resources_for(operation)
        self.assertEqual(required, (self.target.resources[1],))
        helper._validate_plan(self.target, operation, required)
        helper._validate_plan(self.target, {"Kind": "bind"}, required)
        with self.assertRaisesRegex(helper.HighHelperError, "resources_rejected"):
            helper._validate_plan(self.target, {"Kind": "activate"}, required)
        with self.ready(operation) as lease:
            temp = tempfile.TemporaryDirectory(prefix="flower-read-lease-")
            self.addCleanup(temp.cleanup)
            store = StateStore(Path(temp.name), boot="read-only-fixture", write_gate=self.write_gate)
            task = store.create_task(); owner = store.register_owner(task)
            lease.chat_id = task; lease.resources = required
            store.enqueue(owner, action_id="read", fingerprint="read", resources=required, read_only=True)
            decision = store.prepare_decision(required); store.adopt_decision(decision["id"], "read")
            with store.dispatch_external(owner, "read", decision["id"], lease):
                status = store.status(owner, "read")
                self.assertEqual(status["input_release"], "released")
                self.assertFalse(status["business_dispatched"])

    def test_external_sequence_keeps_one_action_and_rebinds_only_after_real_cleanup(self):
        from flower_control.drivers.high_broker_types import InputBinding
        store, owner, decision = self.store()
        resource = self.target.resources[1]
        first_obs = store.observe(owner, resource, "geometry")
        # The first real observer is normally established before enqueue.
        with store.transaction() as db:
            db.execute("UPDATE actions SET observation=?,generation=? WHERE id='a'", (first_obs, "geometry"))
        chosen = store.prepare_decision(self.target.resources); store.adopt_decision(chosen["id"], "a")
        with self.ready() as first, self.ready() as second:
            first.binding = InputBinding(self.chat, "a", first_obs, "geometry", 0)
            second.ledger_identity = "c" * 64
            with store.external_sequence(owner, "a", chosen["id"], total_steps=2) as chain:
                with chain.before_go(first):
                    stage = begin_foreground_stage(store, owner, "a", target_resource=resource, channel="computer", operation="bind")
                    stage.bind_input_release(first.ledger_identity, executor_process=first.executor_process)
                    store.start_computer_sequence(owner, "a", 2)
                    store.begin_computer_sequence_step(owner, "a", 0)
                    first.go_sent = True
                    progress = dict(Binding=first.binding.result_wire(), BusinessStarted=True, BusinessComplete=True,
                                    AcceptedEvents=2, CompletedPlans=1, CompletedSegments=1, PartialSegment=None,
                                    CleanupEvents=0, NativeCountKnown=True)
                    first._accept(self.result(first, RequestBinding=first.binding.result_wire(), InputResult=progress,
                        State="dispatched_unverified", BusinessAttempted=True, BusinessEvents=2, SentEvents=2, RequestedEvents=2))
                self.assertEqual(store.status(owner, "a")["state"], "running")
                stage.check()  # Capture/expect phase checks remain valid between released requests.
                store.finish_computer_sequence_step(owner, "a", 0, complete=True, input_release="released")
                fresh = store.observe(owner, resource, "geometry")
                second.binding = InputBinding(self.chat, "a", fresh, "geometry", 1)
                with chain.before_go(second):
                    with store.transaction() as db:
                        pending = db.execute("SELECT ledger_identity,confirmed FROM input_release_bindings WHERE action='a'").fetchone()
                        self.assertEqual(pending[0], second.ledger_identity)
                        self.assertIsNone(pending[1])
                    stage.bind_input_release(second.ledger_identity, executor_process=second.executor_process)
                    store.begin_computer_sequence_step(owner, "a", 1)
                    self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "held")
                    second.go_sent = True
                    # A failed second step must retain the already sent first step.
                    second._accept(self.result(second, RequestBinding=second.binding.result_wire(), State="rejected"))
                store.finish_computer_sequence_step(owner, "a", 1, complete=False, input_release="released")
                self.assertTrue(store.status(owner, "a")["business_dispatched"])
                store.finish(owner, "a", "outcome_uncertain", sequence_final_state="sequence_stopped")
            self.assertEqual(stage.snapshot()["foreground_stage"]["lease_state"], "released")
            with store.transaction() as db:
                row = db.execute("SELECT * FROM input_release_bindings WHERE action='a'").fetchone()
                self.assertEqual(row["ledger_identity"], "c" * 64)
                self.assertIsNotNone(row["confirmed"])

    def test_external_continuation_refuses_missing_done_and_old_observation(self):
        from flower_control.drivers.high_broker_types import InputBinding
        store, owner, decision = self.store()
        with self.ready() as previous, self.ready() as following:
            previous.binding = InputBinding(self.chat, "a", "old", "geometry", 0)
            following.binding = InputBinding(self.chat, "a", "old", "geometry", 1)
            following.ledger_identity = "c" * 64
            with self.assertRaisesRegex(ControlError, "external_continuation_release_required"):
                store._continue_external(owner, "a", previous, following, 1)
            previous.go_sent = True
            progress = dict(Binding=previous.binding.result_wire(), BusinessStarted=True, BusinessComplete=True,
                            AcceptedEvents=2, CompletedPlans=1, CompletedSegments=1, PartialSegment=None,
                            CleanupEvents=0, NativeCountKnown=True)
            previous._accept(self.result(previous, RequestBinding=previous.binding.result_wire(), InputResult=progress,
                State="dispatched_unverified", BusinessAttempted=True, BusinessEvents=2, SentEvents=2, RequestedEvents=2))
            with self.assertRaisesRegex(ControlError, "external_continuation_fresh_observation_required"):
                store._continue_external(owner, "a", previous, following, 1)

    def test_fresh_owner_recovers_exact_native_release_without_old_memory_token(self):
        store, old_owner, decision = self.store()
        with self.ready() as lease:
            with self.assertRaisesRegex(RuntimeError, "fixture_mcp_died"):
                with store.dispatch_external(old_owner, "a", decision, lease):
                    stage = begin_foreground_stage(store, old_owner, "a", target_resource=self.target.resources[1], channel="computer", operation="bind")
                    stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                    lease.go_sent = True
                    raise RuntimeError("fixture_mcp_died")
            with store.transaction() as db:
                db.execute("UPDATE owners SET process='99:dead-fixture' WHERE id=?", (old_owner,))
            fresh = StateStore(store.path.parent, boot="high-unit-test", write_gate=self.write_gate)
            new_owner = fresh.register_owner(self.chat)
            native = "flower_control.drivers.high_helper."
            session = SimpleNamespace(_closed=False, _pipe=lease._pipe,
                _helper=self.peer, _evidence={"ProductionAdmitted": True},
                client=SimpleNamespace(bundle=lease._bundle, medium_fixture=False))
            expected = (self.chat, "a", lease.executor_process, lease.ledger_identity)
            terminal = dict(Phase="release_recovery", TaskId=self.chat, ActionId="a", ExecutorProcess=lease.executor_process,
                LedgerIdentity=lease.ledger_identity, State="finished", InputRelease="released", MutexReleased=True,
                SemanticExecutorExited=True, NativeCountKnown=True)
            with patch("flower_control.control.state.process_is_alive", side_effect=lambda identity: identity != "99:dead-fixture"):
                with self.assertRaisesRegex(ControlError, "external_release_unverified"):
                    fresh.confirm_external_release(new_owner, "a", terminal)
                for changed in (dict(MutexReleased=False), dict(InputRelease="unknown"), dict(NativeCountKnown=False),
                                dict(SemanticExecutorExited=False), dict(LedgerIdentity="c" * 64)):
                    with self.assertRaises(helper.HighHelperError):
                        helper.ReleaseRecovery(helper._SEAL, session, expected, {**terminal, **changed})
                proof = helper.ReleaseRecovery(helper._SEAL, session, expected, terminal)
                # ready() simulates the High peer's probing mutex as busy.
                # Recovery uses a different, locally quiescent execution lock;
                # keep its real Python non-reentrancy guard active.
                with patch("flower_control.control.native.win32event.WaitForSingleObject",
                           return_value=helper.win32event.WAIT_OBJECT_0):
                    recovered = fresh.confirm_external_release(new_owner, "a", proof)
            self.assertEqual(recovered["input_release"], "released")
            self.assertFalse(recovered["replay_old_action"])
            receipt = fresh.status(new_owner, "a")
            self.assertEqual(receipt["state"], "outcome_uncertain")
            self.assertEqual(receipt["input_release"], "released")
            with fresh.transaction() as db:
                self.assertTrue(db.execute("SELECT quarantined FROM resources WHERE id=?", (self.target.resources[0],)).fetchone()[0])
                self.assertIsNotNone(db.execute("SELECT confirmed FROM input_release_bindings WHERE action='a'").fetchone()[0])
