"""Non-content borrower records for one exact user-owned browser instance.

Startup uses the short profile lock. Each worker subsequently writes only its
own borrower file. Records never issue a task grant or adopt unknown tabs.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from flower_control.control.state import ControlError
from flower_control.profile_registry import direct_path
from .web_page_registry import page_registry, decode_shared_registry
from flower_control.control.worker_call import WorkerCallGuard


def task_key(task):
    if type(task) is not str or not task or len(task) > 4096:
        raise ControlError("invalid_shared_browser_task")
    return hashlib.sha256(task.encode()).hexdigest()


def borrower_resource(profile, task):
    """Stable conflict/unknown fence, distinct from actual browser/page IDs."""
    physical = str(direct_path(Path(profile)).resolve()).casefold()
    return "web-borrower:" + hashlib.sha256(physical.encode()).hexdigest() + ":" + task_key(task)


async def retire_shared_idle(kind, *, profile_path, brave_executable=None, ledger_directory=None):
    """Explicit local mode-change preparation for an idle auto-started browser.

    A user-started instance, retained/unsaved tab, live borrower, or unresolved
    ledger makes this a zero-close busy result. No task/grant is created and no
    result/Stop/quarantine is changed. The normal opener performs any relaunch.
    """
    import asyncio
    import sqlite3
    from contextlib import closing
    from urllib.parse import quote
    from playwright.async_api import async_playwright, Error as PlaywrightError
    from flower_control.control.native import process_is_alive
    from flower_control.browsers import profile_resource_id
    from .web_session import TemporaryWebSession
    busy = lambda reason: {"retired": False, "state": "shared_browser_busy", "reason": reason}
    if kind not in {"ai", "luohua"} or ledger_directory is None:
        return busy("shared_browser_ledger_unverified")
    probe = TemporaryWebSession(persistent_profile=profile_path, profile_kind=kind, guarded=True, user_open=True,
        **({"brave_executable": brave_executable} if brave_executable is not None else {}))
    probe.profile_path = probe.persistent_profile
    try:
        probe._acquire_profile_lock()
    except ControlError:
        return busy("shared_browser_transition_in_progress")
    exact = None
    try:
        marker = probe._read_marker(ignore_mode=True)
        if (marker.get("state") != "running" or marker.get("owner_kind") != "user"
                or marker.get("owner_task") is not None or marker.get("auto_started") is not True
                or marker.get("headless") is not True
                or marker.get("owner_process") is not None or marker.get("worker_process") is not None
                or marker.get("login_only")):
            return busy("shared_browser_user_instance_retained")
        browser_id = marker["session_id"]
        identity = f"{marker['browser_pid']}:{marker['browser_created']}"
        instance = direct_path(probe.profile_path / "flower-shared" / browser_id)
        records = list(instance.glob("*.json")) if instance.is_dir() else []
        if len(records) > 256:
            return busy("shared_browser_borrower_limit")
        for path in records:
            direct_path(path)
            if path.stat().st_size > 200000:
                return busy("shared_browser_borrower_unverified")
            row = json.loads(path.read_bytes())
            if (type(row) is not dict or row.get("schema") != 1 or row.get("browser_id") != browser_id
                    or row.get("browser_process") != identity or row.get("task_key") != path.stem
                    or not re.fullmatch(r"[0-9a-f]{64}", path.stem)
                    or type(row.get("pages")) is not dict or page_registry(row["pages"]) != row["pages"]
                    or any(row.get(key) is not None and type(row.get(key)) is not str
                           for key in ("owner_process", "worker_process"))):
                return busy("shared_browser_borrower_unverified")
            if any(value and process_is_alive(value) for value in (row.get("owner_process"), row.get("worker_process"))):
                return busy("shared_browser_borrower_active")
            if row["pages"]:
                return busy("shared_browser_retained_pages")
        ledger = direct_path(Path(ledger_directory) / "control.sqlite3")
        if not ledger.is_file():
            return busy("shared_browser_ledger_unverified")
        prefix = borrower_resource(probe.profile_path, "idle-probe").rsplit(":", 1)[0] + ":%"
        legacy = profile_resource_id(kind, probe.brave_executable)
        def ledger_ready():
            with closing(sqlite3.connect("file:" + quote(ledger.as_posix(), safe="/:") + "?mode=ro", uri=True, timeout=.1)) as db:
                if db.execute("SELECT 1 FROM resources WHERE (id=? OR id LIKE ?) AND (paused OR quarantined) LIMIT 1",
                              (legacy, prefix)).fetchone():
                    return False
                return db.execute("SELECT 1 FROM actions a,json_each(a.resources) r "
                    "WHERE a.state IN ('queued','running','outcome_uncertain') AND (r.value=? OR r.value LIKE ?) LIMIT 1",
                    (legacy, prefix)).fetchone() is None
        if not ledger_ready():
            return busy("shared_browser_action_recovery_required")
        exact = probe._open_verified_process(marker)
        endpoint = probe._verified_endpoint(marker)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.connect_over_cdp(endpoint, no_defaults=True, timeout=3000)
            try:
                pages = [page for context in browser.contexts for page in context.pages]
                if len(pages) != 1 or pages[0].url != "about:blank":
                    return busy("shared_browser_unowned_pages_retained")
                session = await browser.new_browser_cdp_session()
                initial = (await session.send("Target.getTargets"))["targetInfos"]
                original_targets = {value["targetId"] for value in initial if value.get("type") == "page"}
                if len(original_targets) != 1:
                    return busy("shared_browser_idle_state_changed")
                changed = [False]
                def target_changed(event):
                    value = event.get("targetInfo", {})
                    if value.get("type") == "page" and (value.get("targetId") not in original_targets
                            or value.get("url") != "about:blank"):
                        changed[0] = True
                session.on("Target.targetCreated", target_changed)
                session.on("Target.targetInfoChanged", target_changed)
                await session.send("Target.setDiscoverTargets", {"discover": True})
                empty = await asyncio.wait_for(pages[0].evaluate("""() => location.href==='about:blank'
                    && document.body?.childElementCount===0 && document.body?.textContent===''
                    && typeof window.onbeforeunload!=='function'"""), timeout=1)
                if empty is not True or not ledger_ready() or probe._read_marker(ignore_mode=True) != marker:
                    return busy("shared_browser_idle_state_changed")
                targets = (await session.send("Target.getTargets"))["targetInfos"]
                page_targets = [value for value in targets if value.get("type") == "page"]
                if (changed[0] or len(page_targets) != 1 or page_targets[0].get("url") != "about:blank"
                        or page_targets[0].get("targetId") not in original_targets or not ledger_ready()):
                    return busy("shared_browser_idle_state_changed")
                await session.send("Browser.close")  # Normal quit; never kill a live process.
            finally:
                await browser.close()  # Disconnect this CDP client.
        try:
            await asyncio.to_thread(exact.wait, 5)
        except TimeoutError:
            return {"retired": False, "state": "shared_browser_close_pending", "browser_session_id": browser_id}
        marker.update(state="closed", owner_process=None, worker_process=None)
        probe._write_marker(marker)
        return {"retired": True, "state": "shared_idle_browser_exited", "browser_session_id": browser_id,
                "browser_process": identity, "normal_close": True, "profile_data": "retained"}
    except (OSError, ValueError, TypeError, KeyError, ControlError, sqlite3.Error, PlaywrightError, asyncio.TimeoutError):
        return busy("shared_browser_idle_state_unverified")
    finally:
        if exact is not None:
            exact.close()
        await probe._release_profile_lock()


def shared_paths(profile, browser_id, task):
    if type(browser_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", browser_id):
        raise ControlError("shared_browser_identity_unverified")
    profile = direct_path(Path(profile))
    root = direct_path(profile / "flower-shared")
    root.mkdir(exist_ok=True)
    instance = direct_path(root / browser_id)
    instance.mkdir(exist_ok=True)
    spool = direct_path(instance / "downloads")
    spool.mkdir(exist_ok=True)
    return direct_path(instance / (task_key(task) + ".json")), spool


def read_borrower(path, *, browser_process, browser_id, task):
    path = direct_path(path)
    if not path.exists():
        return None
    try:
        if path.stat().st_size > 200000:
            raise ValueError()
        value = json.loads(path.read_bytes())
        if (type(value) is not dict or value.get("schema") != 1
                or value.get("browser_id") != browser_id or value.get("browser_process") != browser_process
                or value.get("task_key") != task_key(task)
                or not re.fullmatch(r"[0-9a-f]{32}", value.get("session_id", ""))
                or any(value.get(key) is not None and type(value.get(key)) is not str
                       for key in ("owner_process", "worker_process"))
                or type(value.get("pages")) is not dict
                or page_registry(value["pages"]) != value["pages"]):
            raise ValueError()
        decode_shared_registry(value["pages"], value.get("user_pages", []))
        return value
    except (OSError, ValueError, TypeError):
        raise ControlError("shared_browser_borrower_recovery_required") from None


def shared_borrowers(profile, task):
    """Find only this authenticated task's records, bounded across instances."""
    root = direct_path(Path(profile) / "flower-shared")
    if not root.exists():
        return []
    instances = list(root.iterdir())
    if len(instances) > 256:
        raise ControlError("shared_browser_borrower_recovery_required")
    output = []
    for instance in instances:
        direct_path(instance)
        if not instance.is_dir() or not re.fullmatch(r"[0-9a-f]{32}", instance.name):
            raise ControlError("shared_browser_borrower_recovery_required")
        path = direct_path(instance / (task_key(task) + ".json"))
        if not path.exists():
            continue
        if path.stat().st_size > 200000:
            raise ControlError("shared_browser_borrower_recovery_required")
        try:
            raw = json.loads(path.read_bytes())
            process = raw["browser_process"]
        except (ValueError, TypeError, KeyError):
            raise ControlError("shared_browser_borrower_recovery_required") from None
        value = read_borrower(path, browser_process=process, browser_id=instance.name, task=task)
        output.append((path, value))
    return output


def exact_process_identity(value):
    from datetime import datetime
    if type(value) is not str:
        return False
    pid, separator, created = value.partition(":")
    try:
        return bool(separator and pid.isdecimal() and int(pid) > 0 and datetime.fromisoformat(created).tzinfo is not None)
    except ValueError:
        return False


def write_borrower(path, value):
    path = direct_path(path)
    temporary = direct_path(path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp"))
    try:
        with temporary.open("xb") as output:
            output.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()  # Exact newly-created unpublished metadata only.


def require_profile_gate(store, resource):
    """Keep original whole-profile Stop/quarantine and legacy pending fences.

    New borrower actions use their own resources; the profile gate is read-only,
    so unrelated tabs do not become one serialized profile action.
    """
    with store.transaction() as db:
        row = db.execute("SELECT paused,quarantined FROM resources WHERE id=?", (resource,)).fetchone()
        if row and (row["paused"] or row["quarantined"]):
            raise ControlError("shared_profile_action_recovery_required")
        rows = db.execute("SELECT resources FROM actions WHERE state IN ('queued','running')").fetchall()
        if any(resource in json.loads(row["resources"]) for row in rows):
            raise ControlError("shared_profile_legacy_action_in_flight")


class SharedWorkerCallGuard(WorkerCallGuard):
    """The original exact permit, plus the existing profile-wide fence."""
    def __init__(self, envelope, command, arguments, resource):
        super().__init__(envelope, command, arguments)
        self.profile_resource = resource

    async def check(self):
        await super().check()
        require_profile_gate(self.store, self.profile_resource)

    def admission(self):
        return self.store.worker_write_admission(self.action, self.token, self.fingerprint,
                                                guard_resource=self.profile_resource)
