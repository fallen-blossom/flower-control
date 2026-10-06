"""Private App worker. The MCP status server does not import or expose this module.

The dispatcher must hold StateStore.dispatch's native lock while calling this
process and bind an exact command_hash permit to this process identity. UIA is
performed by a disposable .NET child in a kill-on-close Windows Job.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import win32api
import win32con
import win32job

from flower_control.control.state import ControlError
from flower_control.control.native import process_identity
from flower_control.control.worker_call import WorkerCallGuard
from flower_control.drivers.worker_lifetime import WorkerLifetime
from flower_control.drivers.app_scope import validate_local_scope
from flower_control.drivers.app_timing import timed_phase, safe_timings, NATIVE_EXECUTION_FIELDS


MAX_MESSAGE = 98_304
NATIVE_EXE = Path(__file__).with_name("app_native") / "bin" / "Release" / "net10.0-windows10.0.19041.0" / "win-x64" / "Flower.AppWorker.exe"
COMMANDS = frozenset({"observe", "set_value", "invoke", "focus", "guarded_input", "set_toggle", "select_item",
                      "expand_collapse", "scroll", "realize_item", "read_text"})


def validate_request(command: str, arguments: dict) -> None:
    """Reject malformed work before consuming a permit or starting UIA."""
    if command not in COMMANDS or type(arguments) is not dict:
        raise ValueError("invalid_app_command")
    expected = {"target", "limits", "privacy", "privacy_scope"} if command == "observe" else {"target", "reference", "observation", "privacy", "privacy_scope"}
    if command == "set_value":
        expected.add("value")
    if command == "guarded_input":
        expected.add("text")
        if "replace" in arguments:
            expected.add("replace")
    if command == "set_toggle":
        expected.add("desired")
    if command == "select_item" and "desired" in arguments:
        expected.add("desired")
    if command == "expand_collapse":
        expected.add("desired")
    if command == "scroll":
        expected.update(("direction", "amount"))
    if command == "realize_item":
        expected.add("item_name")
    if command == "read_text":
        expected.add("text")
    if "local" in arguments:
        expected.add("local")
        validate_local_scope(arguments["local"])
    if "tree" in arguments:
        if command != "observe":
            raise ValueError("invalid_app_tree_cursor")
        expected.add("tree")
        validate_tree_cursor(arguments["tree"])
    if set(arguments) != expected:
        raise ValueError("invalid_app_arguments")
    target = arguments["target"]
    if (type(target) is not dict or set(target) != {"pid", "hwnd", "process_start_filetime", "root_runtime_id"}
            or type(target["pid"]) is not int or not 0 < target["pid"] <= 0xFFFFFFFF
            or type(target["hwnd"]) is not int or not 0 < target["hwnd"] <= 0x7FFFFFFFFFFFFFFF
            or type(target["process_start_filetime"]) is not int or target["process_start_filetime"] <= 0
            or not _runtime_id(target["root_runtime_id"], allow_empty=command == "observe")):
        raise ValueError("invalid_app_target")
    if arguments["privacy"] not in ("structure_only", "content_allowed") or type(arguments["privacy"]) is not str:
        raise ValueError("invalid_app_privacy")
    if "local" in arguments and (arguments["privacy"] != "content_allowed" or not target["root_runtime_id"]):
        raise ValueError("invalid_app_local_scope")
    scope = arguments["privacy_scope"]
    if (type(scope) is not str or len(scope) > 256
            or (arguments["privacy"] == "content_allowed") != bool(scope)):
        raise ValueError("invalid_app_privacy_scope")
    if command == "observe":
        if "tree" in arguments and not target["root_runtime_id"]:
            raise ValueError("invalid_app_tree_cursor")
        limits = arguments["limits"]
        if (type(limits) is not dict or set(limits) != {"max_nodes", "max_depth"}
                or type(limits["max_nodes"]) is not int or not 1 <= limits["max_nodes"] <= 192
                or type(limits["max_depth"]) is not int or not 0 <= limits["max_depth"] <= 8):
            raise ValueError("invalid_app_limits")
        return
    ref = arguments["reference"]
    if (type(ref) is not dict or set(ref) != {"runtime_id", "automation_id"}
            or not _runtime_id(ref["runtime_id"])
            or type(ref["automation_id"]) is not str or len(ref["automation_id"]) > 256):
        raise ValueError("invalid_app_reference")
    observation = arguments["observation"]
    if (type(observation) is not dict or set(observation) != {"root_runtime_id", "reference_runtime_id", "observed_at_ms"}
            or not _runtime_id(observation["root_runtime_id"])
            or observation["reference_runtime_id"] != ref["runtime_id"]
            or type(observation["observed_at_ms"]) is not int or observation["observed_at_ms"] <= 0):
        raise ValueError("invalid_app_observation")
    if arguments["privacy"] != "content_allowed":
        raise ValueError("app_write_requires_content_scope")
    if command == "read_text":
        options = arguments["text"]
        if (type(options) is not dict or set(options) != {"offset", "max_chars", "version"}
                or type(options["offset"]) is not int or not 0 <= options["offset"] <= 1_048_576
                or type(options["max_chars"]) is not int or not 1 <= options["max_chars"] <= 4096
                or options["version"] is not None and (type(options["version"]) is not str
                    or len(options["version"]) != 64 or any(c not in "0123456789abcdef" for c in options["version"]))):
            raise ValueError("invalid_app_text_options")
    if command == "set_value" and (type(arguments["value"]) is not str or len(arguments["value"]) > 8192):
        raise ValueError("invalid_app_value")
    if command == "guarded_input" and (type(arguments["text"]) is not str or not 1 <= len(arguments["text"]) <= 8192):
        raise ValueError("invalid_app_value")
    if command == "guarded_input" and type(arguments.get("replace", False)) is not bool:
        raise ValueError("invalid_app_replace")
    if command == "set_toggle" and type(arguments["desired"]) is not bool:
        raise ValueError("invalid_app_toggle")
    if command == "select_item" and type(arguments.get("desired", True)) is not bool:
        raise ValueError("invalid_app_selection")
    if command == "expand_collapse" and arguments["desired"] not in ("Expanded", "Collapsed"):
        raise ValueError("invalid_app_expand_collapse_state")
    if command == "scroll" and (arguments["direction"] not in ("up", "down", "left", "right")
                                or arguments["amount"] not in ("small", "large")):
        raise ValueError("invalid_app_scroll")
    if command == "realize_item" and (type(arguments["item_name"]) is not str
                                      or not 1 <= len(arguments["item_name"]) <= 256
                                      or not arguments["item_name"].strip()):
        raise ValueError("invalid_app_item_name")


def _runtime_id(value: object, *, allow_empty: bool = False) -> bool:
    return (type(value) is list and (allow_empty and not value or 1 <= len(value) <= 32)
            and all(type(item) is int and -(2**31) <= item < 2**31 for item in value))


def validate_tree_cursor(value):
    def path_valid(path):
        return (type(path) is list and 1 <= len(path) <= 17
                and all(_runtime_id(item) for item in path))
    if (type(value) is not dict or set(value) != {"scope", "pending", "observed_at_ms"}
            or not path_valid(value["scope"]) or type(value["pending"]) is not list
            or not 1 <= len(value["pending"]) <= 256
            or type(value["observed_at_ms"]) is not int or value["observed_at_ms"] <= 0
            or any(not path_valid(path) or path[:len(value["scope"])] != value["scope"]
                   for path in value["pending"])):
        raise ValueError("invalid_app_tree_cursor")


def _child_job(process: subprocess.Popen) -> object:
    """The child is inert until assigned to this kill-on-close job and fed stdin."""
    job = win32job.CreateJobObject(None, "")
    limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
    try:
        handle = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, process.pid)
        try:
            win32job.AssignProcessToJobObject(job, handle)
        finally:
            handle.Close()
    except BaseException:
        job.Close()
        process.kill()
        process.wait(timeout=3)
        raise
    return job


def _native_environment() -> dict[str, str]:
    """Keep host credentials/provider overrides out of the disposable .NET child."""
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not system_root or not Path(system_root).is_absolute():
        raise ControlError("windows_system_root_missing")
    environment = {"SystemRoot": system_root, "WINDIR": system_root,
                   "DOTNET_CLI_TELEMETRY_OPTOUT": "1"}
    for name in ("TEMP", "TMP"):
        value = os.environ.get(name)
        if value and Path(value).is_absolute():
            environment[name] = value
    return environment


def _check_content_scope(guard: WorkerCallGuard, arguments: dict) -> None:
    if arguments["privacy"] != "content_allowed":
        return
    with guard.store.transaction() as db:
        action = db.execute("SELECT scope FROM actions WHERE id=?", (guard.action,)).fetchone()
        if not action or action["scope"] != arguments["privacy_scope"]:
            raise ControlError("app_content_scope_mismatch")


def normalize_app_result(command: str, result: dict) -> dict:
    """Read-only work cannot have an uncertain UIA write outcome."""
    if command in {"observe", "read_text"}:
        return {**result, "dispatched": False,
                "state": "not_verified" if result.get("state") == "outcome_uncertain" else result.get("state")}
    if result.get("dispatched") is False and result.get("state") == "outcome_uncertain":
        return {**result, "state": "not_verified"}
    return result


async def run_native(command: str, arguments: dict, guard: WorkerCallGuard, *,
                     native_exe: Path = NATIVE_EXE, deadline_s: float = 5.0,
                     native_command: tuple[str, ...] | None = None) -> dict:
    timings = {}
    result = await _run_native(command, arguments, guard, native_exe=native_exe,
                               deadline_s=deadline_s, native_command=native_command, timings=timings)
    native_timings = {key: value for key, value in safe_timings(result.get("timing_ms")).items()
                      if key in NATIVE_EXECUTION_FIELDS}
    return {**normalize_app_result(command, result), "timing_ms": {**native_timings, **timings}}


def record_app_phase(store, action: str, command: str, stage: str, dispatched) -> None:
    # Fail fast under contention: diagnostic writes cannot inherit the control
    # ledger's five-second wait while a foreground/native lock is held.
    try:
        path = (store.directory / "control.sqlite3").absolute()
        db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0.025)
        try:
            cursor = db.execute("INSERT INTO control_events(wall_time,monotonic,event,action,details) "
                "VALUES (?,?,?,?,?)", (time.time(), time.monotonic(), "app_diagnostic", action,
                json.dumps({"command": command, "stage": stage, "dispatched": dispatched})))
            if cursor.lastrowid % 128 == 0:
                db.execute("DELETE FROM control_events WHERE seq<=?", (cursor.lastrowid - 20000,))
            db.commit()
        finally:
            db.close()
    except sqlite3.Error:
        print("Flower App phase diagnostic write failed", file=sys.stderr)


def _record_native_phase(guard, command: str, stage: str, dispatched) -> None:
    # Fixed local metadata only. A 'go' handshake grants permission; it is not
    # proof that the UIA provider performed the requested business effect.
    store = getattr(guard, "store", None)
    if store is None:
        return
    record_app_phase(store, guard.action, command, stage, dispatched)


@contextmanager
def native_write_admission(guard, command):
    store = getattr(guard, "store", None)
    if command in {"observe", "read_text"} or store is None:
        yield
        return
    if store.write_stopped():
        raise ControlError("global_write_stopped")
    with store.worker_write_admission(guard.action, guard.token, guard.fingerprint):
        yield


async def check_live_guard(guard, command):
    store = getattr(guard, "store", None)
    if command not in {"observe", "read_text"} and store is not None and store.write_stopped():
        raise ControlError("global_write_stopped")
    await guard.check()


async def _run_native(command: str, arguments: dict, guard: WorkerCallGuard, *,
                     native_exe: Path = NATIVE_EXE, deadline_s: float = 5.0,
                     native_command: tuple[str, ...] | None = None, timings=None) -> dict:
    timings = {} if timings is None else timings
    validate_request(command, arguments)
    await check_live_guard(guard, command)
    if command == "guarded_input":
        raise ControlError("app_guarded_input_requires_high_executor")
    if native_command is None and not native_exe.is_file():
        return {"state": "rejected", "dispatched": False,
                "reason": "app_native_worker_missing"}
    body = json.dumps({"command": command, "arguments": arguments}, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    if len(body) > MAX_MESSAGE:
        raise ValueError("app_request_too_large")
    spawn_started = time.perf_counter()
    process = subprocess.Popen(native_command or (str(native_exe),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
                               env=_native_environment())
    job = _child_job(process)
    timings["native_spawn"] = max(0, round((time.perf_counter() - spawn_started) * 1000))
    start = time.monotonic()
    result_started = None
    reply_received = False
    try:
        _record_native_phase(guard, command, "native_preflight_wait", False)
        process.stdin.write(body)
        process.stdin.flush()
        try:
            with timed_phase(timings, "native_preflight"):
                first = await _wait_native_line(process, guard, start, deadline_s, command=command)
        except ControlError:
            return {"state": "rejected", "dispatched": False,
                    "reason": "permit_revoked_before_native_call"}
        if first is None:
            return {"state": "outcome_uncertain", "dispatched": False,
                    "reason": "native_preflight_timeout" if process.poll() is None else "native_preflight_failed"}
        try:
            first_result = json.loads(first)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"state": "outcome_uncertain", "dispatched": False,
                    "reason": "native_response_invalid"}
        if first_result == {"phase": "ready"}:
            try:
                await check_live_guard(guard, command)
            except ControlError:
                return {"state": "rejected", "dispatched": False,
                        "reason": "permit_revoked_before_native_call"}
            with native_write_admission(guard, command):
                process.stdin.write(b"go\n")
                process.stdin.flush()
            _record_native_phase(guard, command, "native_result_wait", None)
            result_started = time.perf_counter()
        else:
            await check_live_guard(guard, command)
            if type(first_result) is dict and first_result.get("state") == "rejected" and first_result.get("dispatched") is False:
                return first_result
            return {"state": "outcome_uncertain", "dispatched": False,
                    "reason": "native_protocol_invalid"}
        while True:
            try:
                output = await _wait_native_line(process, guard, start, deadline_s, command=command)
            except ControlError:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "reason": "permit_revoked_during_native_call"}
            if output is None:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "reason": "native_call_timeout" if process.poll() is None else "native_worker_failed"}
            timings["native_reply_wait"] = max(0, round((time.perf_counter() - result_started) * 1000))
            reply_received = True
            break
        try:
            with timed_phase(timings, "native_exit_wait"):
                exited = await _wait_native_exit(process, guard, start, deadline_s, command=command)
        except ControlError:
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "permit_revoked_during_native_call"}
        if not exited:
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "native_exit_timeout"}
        timings["native_result"] = max(0, round((time.perf_counter() - result_started) * 1000))
        await check_live_guard(guard, command)  # no content leaves a paused/revoked task
        if process.returncode != 0 or len(output) > MAX_MESSAGE:
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "native_worker_failed"}
        try:
            result = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "native_response_invalid"}
        if type(result) is not dict or result.get("state") not in ("verified", "not_verified", "outcome_uncertain", "observed", "rejected"):
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "native_response_invalid"}
        return result
    finally:
        cleanup_started = time.perf_counter()
        if result_started is not None and "native_result" not in timings:
            timings["native_result"] = max(0, round((cleanup_started - result_started) * 1000))
        if result_started is not None and not reply_received:
            timings["native_reply_wait"] = max(0, round((cleanup_started - result_started) * 1000))
        # Closing the job kills a provider call even if COM ignores cancellation.
        job.Close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdin.close()
        process.stdout.close()
        timings["native_cleanup"] = max(0, round((time.perf_counter() - cleanup_started) * 1000))


async def _wait_native_line(process: subprocess.Popen, guard: WorkerCallGuard,
                            start: float, deadline_s: float, *, command="observe") -> bytes | None:
    reader = asyncio.create_task(asyncio.to_thread(process.stdout.readline, MAX_MESSAGE + 1))
    try:
        while True:
            await check_live_guard(guard, command)
            remaining = deadline_s - (time.monotonic() - start)
            if remaining <= 0:
                return None
            done, _ = await asyncio.wait({reader}, timeout=min(0.05, remaining))
            if done:
                line = reader.result()
                return line if line and len(line) <= MAX_MESSAGE and line.endswith(b"\n") else None
    finally:
        if not reader.done():
            reader.cancel()


async def _wait_native_exit(process: subprocess.Popen, guard: WorkerCallGuard,
                            start: float, deadline_s: float, *, command="observe") -> bool:
    while True:
        await check_live_guard(guard, command)
        if process.poll() is not None:
            return True
        remaining = deadline_s - (time.monotonic() - start)
        if remaining <= 0:
            return False
        await asyncio.sleep(min(0.05, remaining))


def _write_response(response: dict) -> None:
    encoded = (json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        encoded = b'{"id":null,"ok":false,"error":"app_response_too_large"}\n'
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


async def serve() -> None:
    # A Windows venv launcher can start a second interpreter process. Bind the
    # permit to the interpreter that actually checks it, not Popen.pid.
    _write_response({"id": 0, "ok": True,
                     "result": {"worker_identity": process_identity(), "ready": True}})
    while True:
        stage = "worker_request_read"
        line = await asyncio.to_thread(sys.stdin.buffer.readline, MAX_MESSAGE + 1)
        if not line:
            return
        if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
            return
        request_id = None
        try:
            stage = "worker_request_validation"
            request = json.loads(line)
            if type(request) is not dict or set(request) != {"id", "command", "arguments", "execution"}:
                raise ValueError("invalid_app_request")
            request_id = request["id"]
            if type(request_id) is not int or request_id < 1:
                raise ValueError("invalid_app_request")
            command, arguments = request["command"], request["arguments"]
            validate_request(command, arguments)
            stage = "worker_permit_check"
            guard = WorkerCallGuard(request["execution"], command, arguments)
            _check_content_scope(guard, arguments)
            stage = "native_call"
            result = await run_native(command, arguments, guard)
            _write_response({"id": request_id, "ok": True, "result": result})
        except ControlError as error:
            _write_worker_error(request_id, "control:" + error.code,
                                error.code, stage, error,
                                False if stage != "native_call" else None)
        except (ValueError, TypeError) as error:
            _write_worker_error(request_id, "invalid_app_request",
                                "invalid_app_request", stage, error,
                                False if stage != "native_call" else None)
        except Exception as error:
            _write_worker_error(request_id, "app_worker_failed",
                                "app_worker_failed", stage, error,
                                False if stage != "native_call" else None)


def _write_worker_error(request_id: int | None, public_code: str, reason: str,
                        stage: str, error: BaseException,
                        dispatched: bool | None) -> None:
    """Emit only bounded protocol metadata; exception text is never serialized."""
    from flower_control.control.errors import safe_app_diagnostic

    diagnostic = safe_app_diagnostic({
        "reason": reason, "stage": stage,
        "exception_type": type(error).__name__, "dispatched": dispatched,
    })
    _write_response({"id": request_id, "ok": False, "error": public_code,
                     "diagnostic": diagnostic})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", required=True)
    parser.add_argument("--stop-event", required=True)
    args = parser.parse_args()
    lifetime = WorkerLifetime(args.owner, args.stop_event)
    code = 0
    try:
        asyncio.run(serve())
    except Exception:
        code = 1
    lifetime.exit(code)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
