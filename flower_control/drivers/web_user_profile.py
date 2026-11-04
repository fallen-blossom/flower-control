"""Explicit local user opening; no Codex task, grant, page read or input."""
from pathlib import Path

from flower_control.data_paths import resolve_data_root, physical_path
from flower_control.profile_registry import profile_paths
from flower_control.control.state import ControlError
from flower_control.control.native import process_is_alive
from .web_session import TemporaryWebSession


def user_profile_plan(kind, *, data_root=None, window_mode="visible", browser=None):
    if kind not in {"ai", "luohua"} or window_mode not in {"visible", "hidden", "minimized"}:
        raise ControlError("invalid_user_profile_request")
    root = physical_path(Path(data_root)) if data_root is not None else resolve_data_root()
    from flower_control.browser_preferences import browser_profiles, selected_browser, canonical_browser
    from flower_control.browsers import resolve_browser_executable
    if browser is None:
        family, executable = selected_browser(root)
    else:
        family = canonical_browser(browser)
        executable = resolve_browser_executable(family)
    selected = browser_profiles(root, family)[kind]
    return {"profile": kind, "profile_path": str(selected), "data_root": str(root),
            "window_mode": window_mode, "browser": family, "browser_executable": str(executable),
            "authorization_issued": False}


async def open_user_profile(kind, *, data_root=None, window_mode="visible", brave_executable=None, profile_path=None,
                            auto_started=False, browser=None):
    from flower_control.browsers import browser_family
    if browser is None and brave_executable is not None:
        browser = browser_family(brave_executable)
    plan = user_profile_plan(kind, data_root=data_root, window_mode=window_mode, browser=browser)
    brave_executable = brave_executable if brave_executable is not None else Path(plan["browser_executable"])
    if browser_family(brave_executable) != plan["browser"]:
        raise ControlError("browser_profile_browser_mismatch")
    if profile_path is not None:
        from flower_control.profile_registry import direct_path
        plan["profile_path"] = str(direct_path(profile_path))
    session = TemporaryWebSession(persistent_profile=Path(plan["profile_path"]), profile_kind=kind,
        headless=window_mode == "hidden", guarded=True, user_open=True,
        **({"brave_executable": brave_executable} if brave_executable is not None else {}),
        **({"start_minimized": True} if window_mode == "minimized" else {}))
    session.profile_path = session.persistent_profile
    mode_conflict = None
    if (session.profile_path / "flower-session.json").exists():
        session._acquire_profile_lock()
        try:
            marker = session._read_marker(ignore_mode=True, allow_closed_browser_update=True)
            if marker["state"] == "running":
                identity = f"{marker['browser_pid']}:{marker['browser_created']}"
                if process_is_alive(identity):
                    if marker.get("login_only"):
                        return {**plan, "state": "login_in_progress", "opened": False}
                    current_mode = ("hidden" if marker["headless"] else
                                    "minimized" if marker.get("start_minimized", False) else "visible")
                    if current_mode != window_mode:
                        mode_conflict = {**plan, "state": "window_mode_conflict", "opened": False,
                                         "current_window_mode": current_mode}
                    else:
                        exact = session._open_verified_process(marker)
                        try:
                            session.process_id, session.process_created = exact.pid, exact.created
                            session._verified_endpoint(marker)
                            return {**plan, "state": "reused", "opened": True,
                                    "session_id": marker["session_id"], "window_visible": session.window_visible}
                        finally:
                            exact.close()
                else:
                    if any(process_is_alive(value) for value in
                           (marker.get("owner_process"), marker.get("worker_process")) if value):
                        return {**plan, "state": "previous_instance_recovery_required", "opened": False}
                    # Every recorded identity has exited. Seal only this exact
                    # crashed instance, under the same short profile lock.
                    marker.update(state="closed", owner_process=None, worker_process=None)
                    session._write_marker(marker)
        finally:
            await session._release_profile_lock()
    if mode_conflict:
        # Only the explicit local visible opener may retire an idle browser
        # originally started headless by automation. Never retire a manual or
        # visible/minimized instance to satisfy an automation mode preference.
        if auto_started or window_mode != "visible" or mode_conflict["current_window_mode"] != "hidden":
            return mode_conflict
        from .web_shared_profile import retire_shared_idle
        retired = await retire_shared_idle(kind, profile_path=Path(plan["profile_path"]),
            brave_executable=brave_executable, ledger_directory=Path(plan["data_root"]) / "state-v1")
        if not retired["retired"]:
            return {**mode_conflict, "reason": retired.get("reason") or retired["state"]}
    session.profile_path = None
    await session.start()
    try:
        if auto_started:
            # start() still owns the profile lock. Mark only the exact new
            # instance; a reused/manual browser is never relabelled automatic.
            marker = session._read_marker()
            if marker["session_id"] != session.session_id or marker.get("owner_kind") != "user":
                raise ControlError("shared_browser_identity_changed")
            marker["auto_started"] = True
            session._write_marker(marker)
        return {**plan, "state": "opened", "opened": True, "session_id": session.session_id,
                "window_visible": session.window_visible, "owner_kind": "user"}
    finally:
        await session.disconnect()
