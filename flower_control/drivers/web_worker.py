"""Private JSONL Playwright worker for one owned temporary Brave process.

Only the parent session invokes this module. It uses the public Playwright API;
the parent owns authorization, exact Brave Job and operation receipts.
"""

from __future__ import annotations

import asyncio
import argparse
import base64
import binascii
import io
import hashlib
import json
import re
import mimetypes
import os
import sys
import shutil
import sqlite3
import tempfile
import threading
import uuid
import zipfile
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlunsplit
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError, async_playwright

from flower_control.control.state import ControlError
from flower_control.authorization.luohua_policy import allowed_url, site_matches_url
from flower_control.control.native import process_identity
from flower_control.control.worker_call import WorkerCallGuard
from flower_control.drivers.web_page import (PageDriver, validate_observation_projection,
    validate_observation_root, validate_observation_max_chars, observation_node_limit)
from .web_diagnostics import safe_failure_facts, exception_facts
from .web_uploads import decode_files
from .web_page_registry import page_registry, native_window_binding
from .web_effects import (CLOSE_STOP_CODES, WebEffects, WebDispatchWitness, current_effects,
                          current_write_admission, current_dispatch_witness, mark_write)
from .web_discovery import source_origin
from flower_control.drivers.web_artifacts import artifact_path, persist_bytes, persist_file, persist_web_download, checked_publication
from flower_control.drivers.worker_lifetime import WorkerLifetime


from flower_control.drivers.web_session import WEB_WORKER_PHASES, WEB_EXCEPTION_TYPES


MAX_MESSAGE = 16_000_000
POPUP_GRACE_SECONDS = 5.0
_diagnostic_lock = threading.Lock()


def _write_lifecycle(phase: str, exit_code=None, *, error=None) -> None:
    if phase not in WEB_WORKER_PHASES:
        return
    exception_type = type(error).__name__ if error is not None else None
    if exception_type is not None and exception_type not in WEB_EXCEPTION_TYPES:
        exception_type = "Exception"
    try:
        record = {"kind": "flower_web_lifecycle", "phase": phase,
                  "process": process_identity(),
                  "exit_code": exit_code if type(exit_code) is int else None,
                  "exception_type": exception_type}
        with _diagnostic_lock:
            sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
            sys.stderr.flush()
    except Exception:
        pass  # Neither raw errors nor a logging failure may enter protocol stdout.


COMMANDS = frozenset({"ping", "close_browser", "close_status", "new_page", "list_pending_pages", "recover_pending_page", "native_window", "window_visibility", "reconcile_window_visibility", "prepare_hide_page", "hide_page", "show_page", "local_upload_pending", "list_pages", "mark_page", "clear_page_mark", "mark_tab", "observe", "read_text", "page_state",
                      "page_diagnostics", "screenshot", "record", "media_state", "play_media", "pause_media", "navigate_paused",
                      "fill", "type", "click", "hover", "press", "select_option", "set_checked", "navigate",
                      "back", "forward", "reload", "close_page", "scroll", "dispose_page", "editor_inspect",
                      "editor_read", "editor_replace", "terminal_input", "drag", "upload",
                      "download", "trace", "dialog_state", "dialog_action", "wait_condition", "assert_condition", "transition", "wait_page",
                      "wait_navigation", "chooser_state", "chooser_upload", "chooser_cancel",
                      "workflow_bind", "workflow_check", "result_probe", "message_baseline",
                      "local_upload_begin", "local_upload_status", "local_upload_commit", "local_upload_release"})


async def _noop_check() -> None:
    return None


def _field(arguments: dict, key: str, kind: type, *, maximum: int | None = None) -> Any:
    value = arguments.get(key)
    if type(value) is not kind or (maximum is not None and isinstance(value, str) and len(value) > maximum):
        raise ValueError("invalid_worker_argument")
    return value


def _safe_download_source(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return parsed.scheme + ":[content_omitted]"
    host = parsed.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    authority = host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))


class _FocusDefaults:
    """Retain background focus emulation without overriding native media."""

    def __init__(self, browser, *, shared=False) -> None:
        self.contexts = tuple(browser.contexts)
        self.tasks: dict[Any, asyncio.Task] = {}
        self.sessions: dict[Any, Any] = {}
        self.shared = shared
        for context in (() if shared else self.contexts):
            context.on("page", self.track)

    def track(self, page) -> None:
        if page.is_closed() or page in self.tasks:
            return
        task = asyncio.create_task(self._restore(page))
        self.tasks[page] = task

        def completed(done):
            if not done.cancelled():
                done.exception()  # ready(page) reports failures; consume background errors.
            if page.is_closed():
                self.tasks.pop(page, None)
                self.sessions.pop(page, None)

        task.add_done_callback(completed)
        def closed(*_):
            self.sessions.pop(page, None)
            if task.done():
                self.tasks.pop(page, None)

        page.once("close", closed)

    async def _restore(self, page) -> None:
        session = None
        try:
            async with asyncio.timeout(3):
                session = await page.context.new_cdp_session(page)
                self.sessions[page] = session
                await session.send("Emulation.setFocusEmulationEnabled", {"enabled": True})
        except BaseException as error:
            self.sessions.pop(page, None)
            if session is not None:
                try:
                    await asyncio.wait_for(session.detach(), timeout=1)
                except (PlaywrightError, asyncio.TimeoutError):
                    pass
            if not isinstance(error, (PlaywrightError, asyncio.TimeoutError)):
                raise
            if not page.is_closed():
                raise

    async def ready(self, page) -> None:
        self.track(page)
        task = self.tasks.get(page)
        if task is not None:
            try:
                await task
            finally:
                if task.done() and (task.cancelled() or task.exception() is not None):
                    self.tasks.pop(page, None)  # A later request may retry this idempotent setup.

    async def close(self) -> None:
        for context in (() if self.shared else self.contexts):
            context.remove_listener("page", self.track)
        tasks = tuple(self.tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.tasks.clear()
        for session in tuple(self.sessions.values()):
            try:
                await asyncio.wait_for(session.detach(), timeout=1)
            except (PlaywrightError, asyncio.TimeoutError):
                pass
        self.sessions.clear()


class _CdpDownloadCapture:
    """One action's download, scoped to its page frames and direct popup."""

    def __init__(self, session, directory: str, page) -> None:
        self.session, self.directory, self.page = session, Path(directory), page
        self.started = asyncio.get_running_loop().create_future()
        self.completed = asyncio.get_running_loop().create_future()
        self.frame_ids: set[str] = set()
        self.target_id = None
        self.guid = None
        self.url = ""
        self.suggested_filename = ""
        self.armed = False
        self.page_session = None

    async def __aenter__(self):
        page_session = await self.page.context.new_cdp_session(self.page)
        self.page_session = page_session
        page_session.on("Page.frameAttached", self._frame)
        try:
            await page_session.send("Page.enable")
            tree = await page_session.send("Page.getFrameTree")

            def frames(node):
                self.frame_ids.add(node["frame"]["id"])
                for child in node.get("childFrames", []):
                    frames(child)

            frames(tree["frameTree"])
            target = await page_session.send("Target.getTargetInfo")
            self.target_id = target["targetInfo"]["targetId"]
        except BaseException:
            await page_session.detach()
            raise
        self.session.on("Target.targetCreated", self._popup)
        self.session.on("Browser.downloadWillBegin", self._begin)
        self.session.on("Browser.downloadProgress", self._progress)
        return self

    def _popup(self, event):
        target = event.get("targetInfo", {})
        if self.armed and target.get("openerId") == self.target_id:
            self.frame_ids.add(target["targetId"])

    def _frame(self, event):
        if event.get("parentFrameId") in self.frame_ids:
            self.frame_ids.add(event["frameId"])

    def _begin(self, event):
        if not self.armed or self.started.done() or event.get("frameId") not in self.frame_ids:
            return
        guid = event.get("guid")
        try:
            if str(uuid.UUID(guid)) != guid:
                return
        except (ValueError, TypeError, AttributeError):
            return
        self.guid = guid
        self.url = event.get("url", "")
        self.suggested_filename = event.get("suggestedFilename", "download")
        self.started.set_result(self)

    def _progress(self, event):
        if self.guid is not None and event.get("guid") == self.guid and not self.completed.done():
            if event.get("state") in {"completed", "canceled"}:
                self.completed.set_result(event["state"])

    async def save_as(self, target) -> None:
        if await asyncio.shield(self.completed) != "completed":
            raise ControlError("download_cancelled")
        await asyncio.to_thread(shutil.copyfile, self.directory / self.guid, target)

    async def __aexit__(self, *_):
        if self.guid is not None and not self.completed.done():
            try:
                await asyncio.wait_for(self.session.send("Browser.cancelDownload", {"guid": self.guid}), timeout=1)
                await asyncio.wait((self.completed,), timeout=1)
            except (PlaywrightError, asyncio.TimeoutError):
                pass
        self.session.remove_listener("Target.targetCreated", self._popup)
        self.session.remove_listener("Browser.downloadWillBegin", self._begin)
        self.session.remove_listener("Browser.downloadProgress", self._progress)
        if self.page_session is not None:
            self.page_session.remove_listener("Page.frameAttached", self._frame)
            try:
                await self.page_session.detach()
            except PlaywrightError:
                pass
        if self.guid is not None and self.completed.done() and not self.completed.cancelled():
            # This exact GUID was witnessed for our frame/opener, never a user
            # supplied filename. Other workers' spool entries remain untouched.
            try:
                from flower_control.profile_registry import direct_path
                source = direct_path(self.directory / self.guid)
                if source.is_file():
                    source.unlink()
            except (OSError, ControlError):
                pass  # Publication fact is independent of spool cleanup.


class _Runtime:
    def __init__(self, browser, *, profile_kind: str = "temporary", shared_browser=False, shared_headless=True) -> None:
        if type(shared_headless) is not bool:
            raise ValueError("invalid_shared_browser_mode")
        self.browser = browser
        self.profile_kind = profile_kind
        self.shared_browser = shared_browser
        self.shared_headless = shared_headless
        self.profile_resource = None
        self.pages: dict[str, PageDriver] = {}
        self.owned_pages: set[str] = set()
        self.user_pages: set[str] = set()
        self.page_close_targets: dict[str, object] = {}
        self.instance_close_requested = False
        self.close_wait_reason = None
        self.page_close_requested: set[str] = set()
        self.window_close_requested: set[int] = set()
        self.page_targets: dict[str, str] = {}
        self.page_windows: dict[str, dict] = {}
        self.hidden_pages: set[str] = set()
        self.hidden_unbound: set[str] = set()
        self.restored_pages = {}
        self.page_marks: dict[str, str] = {}
        self.popup_provenance: dict[str, dict] = {}
        self.popup_watches: dict[str, dict] = {}
        self.pending_popup_claims: dict[str, dict] = {}
        self.pending_popup_pages: dict[str, object] = {}
        self.trace_page_id: str | None = None
        self.trace_context = None
        self.trace_violation = False
        self.trace_listener = None
        from .web_diagnostic_recording import DiagnosticRecordings
        self.diagnostic_recordings = DiagnosticRecordings()
        self.diagnostic_page_listeners = {}
        self.focus_defaults: _FocusDefaults | None = None
        self.download_session = None
        self.download_directory = None
        self.browser_policy_identity = None
        self.browser_process_identity = None
        self.file_selections = {}
        self.file_selection_origins = {}

    async def start_browser_defaults(self, artifacts_dir: str) -> None:
        self.download_directory = artifacts_dir
        self.download_session = await self.browser.new_browser_cdp_session()
        from flower_control.permissions import process_facts
        info = await self.download_session.send("SystemInfo.getProcessInfo")
        browsers = [row for row in info.get("processInfo", ()) if row.get("type") == "browser"]
        if len(browsers) != 1 or type(browsers[0].get("id")) is not int:
            raise ControlError("browser_policy_identity_unavailable")
        pid = browsers[0]["id"]
        image, _ = process_facts(pid)
        self.browser_policy_identity = (pid, image)
        self.browser_process_identity = process_identity(pid)
        if self.shared_browser:
            from flower_control.browsers import profile_resource_id
            self.profile_resource = profile_resource_id(self.profile_kind, image)
        from flower_control.permissions import require_browser, PermissionError
        try:
            require_browser(pid, image)
        except PermissionError as error:
            raise ControlError(error.code) from None
        await self.download_session.send("Browser.setDownloadBehavior", {
            "behavior": "allowAndName", "downloadPath": artifacts_dir, "eventsEnabled": True})
        await self.download_session.send("Target.setDiscoverTargets", {"discover": True})
        self.focus_defaults = _FocusDefaults(self.browser, shared=self.shared_browser)
        for context in (() if self.shared_browser else self.browser.contexts):
            for page in context.pages:
                self.focus_defaults.track(page)
        await self._admit_initial_temporary_pages()

    async def _admit_initial_temporary_pages(self) -> None:
        # The newly launched temporary browser is exclusive to this session.
        # Admit only its startup pages here, before any business dispatch;
        # later discovered popups still require their exact dispatch witness.
        if self.profile_kind != "temporary" or self.shared_browser:
            return
        for context in self.browser.contexts:
            for page in context.pages:
                if page.is_closed() or any(driver.page is page for driver in self.pages.values()):
                    continue
                page_id = uuid.uuid4().hex
                self.pages[page_id] = self._driver(page)
                self.owned_pages.add(page_id)
                await self._remember_page(page_id, page)

    def _page(self, page_id: str) -> PageDriver:
        if self.shared_browser and page_id not in self.owned_pages:
            raise ControlError("page_not_owned_by_chat")
        driver = self.pages.get(page_id)
        if driver is None or driver.page.is_closed():
            raise ControlError("target_closed")
        return driver

    def _driver(self, page) -> PageDriver:
        if self.shared_browser and self.focus_defaults is not None:
            self.focus_defaults.track(page)
        return PageDriver(page, event_filter=allowed_url if self.profile_kind == "luohua" else None,
            diagnostic_sink=lambda event:self._diagnostic_event(page,event))

    def _diagnostic_event(self,page,event):
        if not self.diagnostic_recordings.active:return
        if self.profile_kind=='luohua' and not allowed_url(page.url):return
        identifier=next((key for key,driver in self.pages.items() if driver.page is page),None)
        if self.shared_browser and identifier not in self.owned_pages:return
        if identifier is not None:self.diagnostic_recordings.event(identifier,event)
        self._stop_diagnostic_listeners()

    def _track_diagnostic_page(self,page):
        if self.shared_browser:return  # No context-wide listeners or foreign drivers.
        if page.is_closed() or any(driver.page is page for driver in self.pages.values()):return
        if len(self.pages)>=256:
            for run in self.diagnostic_recordings.active.values():run['truncated']=True
            return
        self.pages[uuid.uuid4().hex]=self._driver(page)

    def _stop_diagnostic_listeners(self):
        if self.diagnostic_recordings.active:return
        for context,listener in list(self.diagnostic_page_listeners.items()):
            context.remove_listener('page',listener)
        self.diagnostic_page_listeners.clear()

    async def _remember_page(self, page_id, page):
        if page_id in self.page_targets or len(self.page_targets) >= 256:
            return page_id
        try:
            session = await page.context.new_cdp_session(page)
            try:
                target = (await asyncio.wait_for(session.send("Target.getTargetInfo"), timeout=1))["targetInfo"]["targetId"]
            finally:
                await session.detach()
        except (PlaywrightError, AttributeError, KeyError, TimeoutError):
            return page_id
        restored = self.restored_pages.get(target)
        if restored is not None and restored["page_id"] not in self.pages:
            previous = page_id
            page_id = restored["page_id"]
            self.pages[page_id] = self.pages.pop(previous)
            if previous in self.page_windows:
                self.page_windows[page_id] = self.page_windows.pop(previous)
            if previous in self.hidden_pages:
                self.hidden_pages.discard(previous)
                self.hidden_pages.add(page_id)
            if previous in self.hidden_unbound:
                self.hidden_unbound.discard(previous)
                self.hidden_unbound.add(page_id)
            if previous in self.user_pages:
                self.user_pages.discard(previous)
                self.user_pages.add(page_id)
            if restored["owned"]:
                self.owned_pages.add(page_id)
            if restored.get("user_page") is True:
                self.user_pages.add(page_id)
            binding = native_window_binding(restored.get("native_window"))
            if binding is not None:
                self.page_windows[page_id] = binding
            if restored.get("hidden") is True:
                self.hidden_pages.add(page_id)
            if restored.get("hidden_unbound") is True:
                self.hidden_unbound.add(page_id)
        self.page_targets[page_id] = target
        return page_id

    def registry_snapshot(self):
        return page_registry({target: {"page_id": key, "owned": key in self.owned_pages,
            **({"user_page": True} if key in self.user_pages else {}),
            **({"native_window": self.page_windows[key]} if key in self.page_windows else {}),
            **({"hidden": True} if key in self.hidden_pages else {}),
            **({"hidden_unbound": True} if key in self.hidden_unbound else {})}
            for key, target in self.page_targets.items() if key in self.pages})

    async def _list_pages(self, site: str | None = None) -> list[str]:
        if site is not None:
            site = site.lower()
            if self.profile_kind != "luohua" or not site_matches_url("https://" + site, site):
                raise ControlError("invalid_private_site")
        for page_id, driver in list(self.pages.items()):
            if driver.page.is_closed():
                await driver.dispose()
                self.pages.pop(page_id)
                self.owned_pages.discard(page_id)
                self.user_pages.discard(page_id)
                self.page_targets.pop(page_id, None)
                self.page_windows.pop(page_id, None)
                self.hidden_pages.discard(page_id)
                self.hidden_unbound.discard(page_id)
                self.page_marks.pop(page_id, None)
                self.popup_provenance.pop(page_id, None)
                self.pending_popup_claims.pop(page_id, None)
        for context in (() if self.shared_browser else self.browser.contexts):
            for page in context.pages:
                if page.is_closed() or any(driver.page is page for driver in self.pages.values()):
                    continue
                self.pages[uuid.uuid4().hex] = self._driver(page)
        for page_id, driver in tuple(self.pages.items()):
            await self._remember_page(page_id, driver.page)
        admitted = self.owned_pages if self.shared_browser else self.pages
        if self.profile_kind == "luohua":
            return [page_id for page_id, driver in self.pages.items()
                    if page_id in admitted and allowed_url(driver.page.url, blank=True)
                    and (site is None or site_matches_url(driver.page.url, site))]
        return [key for key in self.pages if key in admitted]

    async def _discover_user_pages(self, guard, *, check):
        """Expose only manual tabs of this profile, not another chat's tabs."""
        if not self.shared_browser or guard is None or not self.browser_process_identity:
            return True
        from .web_user_tabs import other_borrower_targets
        with guard.store.read_transaction() as db:
            action = db.execute("SELECT task,resources FROM actions WHERE id=?", (guard.action,)).fetchone()
            if not action:
                raise ControlError("action_not_found")
            task = action["task"]
            borrower = next((r for r in json.loads(action["resources"]) if r.startswith("web-borrower:")), None)
            if not borrower:
                raise ControlError("shared_browser_identity_unverified")
            prefix = borrower.rsplit(":", 1)[0] + ":"
            watermark = db.execute("SELECT COALESCE(MAX(seq),0) FROM control_events").fetchone()[0]
            foreign_running = any(row["task"] != task and any(r.startswith(prefix) for r in json.loads(row["resources"]))
                for row in db.execute("SELECT task,resources FROM actions WHERE state='running'"))
        # An unfinished foreign action can still be creating or claiming a
        # popup. Keep showing this task's existing pages and retry discovery
        # on the next list instead of guessing that popup is a manual tab.
        if foreign_running:
            return False
        try:
            foreign = other_borrower_targets(self.download_directory, self.browser_process_identity, task)
        except ControlError:
            return False  # Existing owned pages remain usable; unknown ownership is not guessed.
        known = set(self.page_targets.values())
        candidates = []
        capacity = max(0, 256 - len(self.pages))
        for context in self.browser.contexts:
            for page in context.pages:
                if len(candidates) >= capacity:
                    break
                if page.is_closed() or any(driver.page is page for driver in self.pages.values()):
                    continue
                if not page.url.startswith(("https://", "http://")):
                    continue
                if self.profile_kind == "luohua" and not allowed_url(page.url, blank=True):
                    continue
                await check()
                session = await context.new_cdp_session(page)
                try:
                    target = (await session.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
                finally:
                    await session.detach()
                if target not in known and target not in foreign:
                    candidates.append((target, page))
        await check()
        try:
            foreign.update(other_borrower_targets(self.download_directory, self.browser_process_identity, task))
        except ControlError:
            return False
        # Each target is claimed atomically across new workers. Existing
        # foreign registry and pending creation targets remain excluded.
        with guard.store.transaction() as db:
            foreign_running = any(row["task"] != task and any(r.startswith(prefix) for r in json.loads(row["resources"]))
                for row in db.execute("SELECT task,resources FROM actions WHERE state='running'"))
            if foreign_running:
                return False
            if any(row["task"] != task and any(r.startswith(prefix) for r in json.loads(row["resources"]))
                   for row in db.execute("SELECT a.task,a.resources FROM control_events e JOIN actions a ON a.id=e.action "
                                         "WHERE e.seq>? AND e.event='action_dispatched'", (watermark,))):
                return False
            claimed = []
            new_claims = []
            for target, page in candidates:
                if target in foreign:
                    continue
                foreign_creation = db.execute("SELECT 1 FROM web_created_targets WHERE browser_process=? AND target=? AND state!='closed'",
                                              (self.browser_process_identity, target)).fetchone()
                if foreign_creation:
                    continue
                page_id = uuid.uuid4().hex
                inserted = db.execute("INSERT OR IGNORE INTO web_user_tab_claims VALUES (?,?,?,?)",
                                      (self.browser_process_identity, target, task, page_id)).rowcount
                if inserted:
                    new_claims.append((target, page_id))
                row = db.execute("SELECT task,page_id FROM web_user_tab_claims WHERE browser_process=? AND target=?",
                                 (self.browser_process_identity, target)).fetchone()
                if row and row["task"] == task:
                    claimed.append((target, page, row["page_id"]))
        try:
            await check()
        except BaseException:
            # Nothing has been exposed yet; undo only claims made by this call.
            with guard.store.transaction() as db:
                for target, page_id in new_claims:
                    db.execute("DELETE FROM web_user_tab_claims WHERE browser_process=? AND target=? AND task=? AND page_id=?",
                               (self.browser_process_identity, target, task, page_id))
            raise
        for target, page, page_id in claimed:
            if page.is_closed() or page_id in self.pages or target in self.page_targets.values():
                continue
            # Discovery attaches no focus emulation and performs no input.
            self.pages[page_id] = PageDriver(page, event_filter=allowed_url if self.profile_kind == "luohua" else None,
                                            diagnostic_sink=lambda event, page=page: self._diagnostic_event(page, event))
            self.owned_pages.add(page_id)
            self.user_pages.add(page_id)
            self.page_targets[page_id] = target
        return True

    def _user_page_claim_valid(self, guard, page_id):
        if guard is None:
            return False
        with guard.store.read_transaction() as db:
            row = db.execute("SELECT a.task,c.task AS claim_task,c.page_id FROM actions a "
                             "LEFT JOIN web_user_tab_claims c ON c.browser_process=? AND c.target=? "
                             "WHERE a.id=?", (self.browser_process_identity, self.page_targets.get(page_id), guard.action)).fetchone()
            return bool(row and row["task"] == row["claim_task"] and row["page_id"] == page_id)

    async def _drop_stale_user_pages(self, guard):
        for page_id in tuple(self.user_pages):
            if self._user_page_claim_valid(guard, page_id):
                continue
            driver = self.pages.pop(page_id, None)
            if driver is not None:
                await driver.dispose()
            self.owned_pages.discard(page_id)
            self.user_pages.discard(page_id)
            self.page_targets.pop(page_id, None)

    async def _page_metadata(self, arguments: dict, site: str | None, *, check) -> dict:
        offset, limit = arguments.get("offset", 0), arguments.get("limit", 25)
        expected = arguments.get("expected_digest")
        if (type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50
                or (expected is not None and (type(expected) is not str or len(expected) != 64
                                             or any(c not in "0123456789abcdef" for c in expected)))):
            raise ControlError("invalid_page_metadata_bounds")

        async def snapshot():
            ids = await self._list_pages(site=site)
            return [(key, self.pages[key].generation, self.pages[key].page.url) for key in ids]

        before = await snapshot()
        digest = hashlib.sha256(json.dumps(before, ensure_ascii=False).encode("utf-8")).hexdigest()
        if expected is not None and expected != digest:
            raise ControlError("pages_changed")

        async def entry(key, generation, url):
            driver = self._page(key)
            value = {"page_id": key, "generation": generation,
                     "navigation_version": driver.navigation_version,
                     "source_origin": source_origin(url), "owned_by_chat": key in self.owned_pages}
            if key in self.user_pages:
                value["user_opened"] = True
            value["marker"] = self.page_marks.get(key)
            if driver.pending_dialog is not None:
                return {**value, "title": None, "title_unavailable": "dialog_pending"}
            try:
                title = await asyncio.wait_for(driver.page.title(), timeout=2)
                return {**value, "title": title[:256], "title_truncated": len(title) > 256}
            except Exception:
                return {**value, "title": None, "title_unavailable": "page_title_unavailable"}

        entries = await asyncio.gather(*(entry(*item) for item in before[offset:offset + limit]))
        await check()
        if await snapshot() != before:
            raise ControlError("pages_changed")
        await check()
        return {"pages": entries, "total_at_start": len(before), "offset": offset, "digest": digest,
                "next_offset": offset + limit if offset + limit < len(before) else None,
                "complete": offset == 0 and len(before) <= limit,
                "source_scope": "origins_only", "discovery_grants_ownership": False}

    @staticmethod
    def _remove_popup_listener(page, handler):
        try:
            page.remove_listener("popup", handler)
        except Exception:
            pass

    def _drop_popup_watch(self, dispatch_id):
        watch = self.popup_watches.pop(dispatch_id, None)
        if watch is None:
            return
        task = watch.get("task")
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if task is not None and task is not current and not task.done():
            task.cancel()
        self._remove_popup_listener(watch["page"], watch["handler"])
        for page_id, claim in list(self.pending_popup_claims.items()):
            if claim["dispatch_id"] == dispatch_id:
                self.pending_popup_claims.pop(page_id, None)
                self.popup_provenance.pop(page_id, None)
                self.pending_popup_pages.pop(page_id, None)

    def release_popup_watches(self):
        for dispatch_id in list(self.popup_watches):
            self._drop_popup_watch(dispatch_id)
        self.pending_popup_claims.clear()
        self.pending_popup_pages.clear()

    async def _expire_popup_watch(self, dispatch_id):
        try:
            await asyncio.sleep(POPUP_GRACE_SECONDS)
        except asyncio.CancelledError:
            return
        self._drop_popup_watch(dispatch_id)

    async def _popup_window_baseline(self, check):
        if not self.shared_browser or self.shared_headless:
            return None
        import pywintypes
        from . import web_native_window as native
        await check()
        try:
            pid = await native._browser_pid(self.download_session)
            identity = native.process_identity(pid)
            windows = native._windows(pid)
            # Window nonces distinguish HWND reuse. The cache contains only
            # metadata; it grants no page ownership or native input authority.
            native_identities = frozenset(native.bind_window(hwnd) for hwnd in windows)
            if any(row.pid != pid or f'{pid}:{row.process_created}' != identity for row in native_identities):
                return None
            targets = (await self.download_session.send("Target.getTargets")).get("targetInfos", [])
            if len(targets) > 1024:
                return None
            page_ids = frozenset(row['targetId'] for row in targets if row.get('type') == 'page')
        except (ControlError, native.NativeInputError, PlaywrightError, AttributeError, KeyError,
                OSError, ValueError, pywintypes.error):
            return None
        await check()
        signature = (self.download_session, pid, identity, native_identities, page_ids)
        cached = getattr(self, '_popup_window_cache', None)
        if cached is not None and cached[0] == signature:
            return cached[1]
        window_ids = set()
        for target in page_ids:
            await check()
            try:
                window_ids.add((await native._target_window(self.download_session, target))['windowId'])
            except (ControlError, native.NativeInputError, PlaywrightError, KeyError,
                    OSError, ValueError, pywintypes.error):
                return None
        await check()
        # Cache only a coherent snapshot, never a map spanning a window race.
        try:
            if (native._windows(pid) != windows or native.process_identity(pid) != identity
                    or frozenset(native.bind_window(hwnd) for hwnd in windows) != native_identities):
                return None
        except (ControlError, native.NativeInputError, OSError, ValueError, pywintypes.error):
            return None
        baseline = (pid, identity, windows, window_ids)
        self._popup_window_cache = signature, baseline
        return baseline

    async def _bind_popup_window(self, page_id, baseline, check):
        if baseline is None or page_id not in self.owned_pages or page_id not in self.page_targets:
            return
        from dataclasses import asdict
        import pywintypes
        from . import web_native_window as native
        try:
            pid, identity, before, previous_windows = baseline
            target = self.page_targets[page_id]
            info = await native._target_window(self.download_session, target)
            delta = native._windows(pid) - before
            if (len(delta) != 1 or info["windowId"] in previous_windows
                    or native.process_identity(pid) != identity
                    or await native._window_targets(self.download_session, info["windowId"]) != {target}):
                return
            hwnd = next(iter(delta))
            bounds = info["bounds"]
            rect = native._normal_rect(hwnd)
            cdp_rect = (bounds["left"], bounds["top"], bounds["left"] + bounds["width"], bounds["top"] + bounds["height"])
            if any(type(n) is not int for n in cdp_rect) or any(abs(a-b) > 2 for a,b in zip(rect, cdp_rect)):
                return
            window = native.bind_window(hwnd)
            if window.pid != pid or f"{pid}:{window.process_created}" != identity:
                return
            binding = native_window_binding({"identity": asdict(window), "window_id": info["windowId"]})
            if binding is None:
                return
            await native.validate_native_page(self.browser, self.download_session, self.pages[page_id].page,
                                              target, binding)
        except (ControlError, native.NativeInputError, PlaywrightError, KeyError, OSError, ValueError, pywintypes.error):
            return
        await check()
        self.page_windows[page_id] = binding

    async def _input_with_popups(self, source_id, operation, *, check):
        before = set(await self._list_pages())
        window_baseline = await self._popup_window_baseline(check)
        source = self._page(source_id)
        generation = source.generation
        dispatch_id = uuid.uuid4().hex
        captured = []
        witness = WebDispatchWitness()
        late = {"enabled": False}
        kept = False

        def on_popup(page):
            if page.is_closed():
                return
            stable = (source.generation == generation and source_id in self.owned_pages)
            # A shared browser can report a human-created popup while the
            # action is still awaiting its dispatch gate. Merely observing
            # that event must not install a driver or write focus emulation.
            if self.shared_browser and (not witness.started or not stable):
                return
            page_id = next((key for key, driver in self.pages.items() if driver.page is page), None)
            if page_id is None:
                page_id = next((key for key, pending in self.pending_popup_pages.items() if pending is page), None)
            if page_id is None:
                page_id = uuid.uuid4().hex
                if self.shared_browser and late["enabled"]:
                    self.pending_popup_pages[page_id] = page
                else:
                    self.pages[page_id] = self._driver(page)
            if late["enabled"]:
                # A popup after the result can still belong to the original
                # dispatch, but it is only a bounded pending claim. Ownership
                # is promoted only when wait_page presents the exact dispatch
                # id and the source generation/ownership still match.
                now = asyncio.get_running_loop().time()
                stable = (source.generation == generation and
                          source_id in self.owned_pages)
                association = ("popup_event_after_dispatch_pending" if stable else
                    "popup_event_after_dispatch_generation_changed"
                    if source.generation != generation else
                    "popup_event_after_dispatch_unowned_source")
                self.popup_provenance[page_id] = {
                    "source_page_id": source_id, "source_generation": generation,
                    "dispatch_id": dispatch_id, "association": association,
                    "claim_expires": now + POPUP_GRACE_SECONDS}
                if stable:
                    self.pending_popup_claims[page_id] = {
                        "dispatch_id": dispatch_id, "source_page_id": source_id,
                        "source_generation": generation,
                        "expires": now + POPUP_GRACE_SECONDS, "window_baseline": window_baseline}
                return
            captured.append(page_id)
            provenance = {"source_page_id": source_id, "source_generation": generation,
                          "dispatch_id": dispatch_id, "association": "popup_event_during_action"
                          if witness.started else "popup_event_before_dispatch"}
            self.popup_provenance[page_id] = provenance
            if witness.started and source_id in self.owned_pages and source.generation == generation:
                self.owned_pages.add(page_id)

        source.page.on("popup", on_popup)
        token = current_dispatch_witness.set(witness)
        try:
            result = await operation()
            await check()
            current = await self._list_pages()
            for page_id in captured:
                if page_id in self.owned_pages:
                    await self._remember_page(page_id, self.pages[page_id].page)
                    await self._bind_popup_window(page_id, window_baseline, check)
            await check()
            result["opened_pages"] = [page_id for page_id in captured if page_id in current]
            result["observed_new_pages"] = [page_id for page_id in current if page_id not in before]
            result["popup_dispatch_id"] = dispatch_id
            if source_id in self.hidden_pages and captured:
                # A browser can show a popup even when its opener is hidden.
                # Do not guess an HWND or silently continue as if it stayed hidden.
                result["background_attention_required"] = True
                result["background_attention_reason"] = "popup_may_be_visible"
                result["next_action"] = "inspect_exact_popup_before_continuing"
            if not captured and witness.started:
                late["enabled"] = True
                kept = True
                task = asyncio.create_task(self._expire_popup_watch(dispatch_id))
                self.popup_watches[dispatch_id] = {
                    "page": source.page, "handler": on_popup, "task": task}
            return result
        finally:
            if not kept:
                self._remove_popup_listener(source.page, on_popup)
            current_dispatch_witness.reset(token)

    async def _wait_page(self, arguments, *, check):
        previous = arguments.get("after_page_ids")
        timeout_ms = arguments.get("timeout_ms")
        expected_url = arguments.get("expected_url")
        dispatch_id = arguments.get("popup_dispatch_id")
        if (type(previous) is not list or len(previous) > 1000
                or any(type(value) is not str or not 1 <= len(value) <= 64 for value in previous)
                or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000
                or (expected_url is not None and (type(expected_url) is not str or len(expected_url) > 8192))
                or (dispatch_id is not None and (type(dispatch_id) is not str or len(dispatch_id) != 32))):
            raise ControlError("invalid_wait_condition")
        deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
        while True:
            await check()
            current = await self._list_pages()
            now = asyncio.get_running_loop().time()
            for page_id, claim in list(self.pending_popup_claims.items()):
                if claim["expires"] <= now:
                    self.pending_popup_claims.pop(page_id, None)
                    self.popup_provenance.pop(page_id, None)
                    self.pending_popup_pages.pop(page_id, None)
                    continue
                if dispatch_id is None or claim["dispatch_id"] != dispatch_id:
                    continue
                source_driver = self.pages.get(claim["source_page_id"])
                target_driver = self.pages.get(page_id)
                target_page = target_driver.page if target_driver is not None else self.pending_popup_pages.get(page_id)
                if (source_driver is not None and target_page is not None and not target_page.is_closed()
                        and page_id not in previous and source_driver.generation == claim["source_generation"]
                        and claim["source_page_id"] in self.owned_pages
                        and expected_url is not None and target_page.url != expected_url):
                    # Keep the exact admitted popup while it navigates; the
                    # original claim expiry and wait deadline remain bounded.
                    continue
                if (source_driver is not None and target_page is not None and not target_page.is_closed()
                        and page_id not in previous
                        and (expected_url is None or target_page.url == expected_url)
                        and source_driver.generation == claim["source_generation"]
                        and claim["source_page_id"] in self.owned_pages):
                    self.owned_pages.add(page_id)
                    if target_driver is None:
                        self.pages[page_id] = self._driver(target_page)
                    await self._remember_page(page_id, target_page)
                    await self._bind_popup_window(page_id, claim.get("window_baseline"), check)
                    if self.shared_browser and page_id not in current:
                        current.append(page_id)
                    self.popup_provenance[page_id] = {
                        **self.popup_provenance.get(page_id, {}),
                        "association": "popup_event_after_dispatch",
                        "promoted": True}
                self.pending_popup_claims.pop(page_id, None)
                self.pending_popup_pages.pop(page_id, None)
            entries = []
            for page_id in current:
                driver = self.pages[page_id]
                provenance = self.popup_provenance.get(page_id)
                if page_id in self.pending_popup_claims:
                    provenance = None
                if page_id in previous or (expected_url is not None and driver.page.url != expected_url):
                    continue
                if dispatch_id is not None and (not provenance or provenance["dispatch_id"] != dispatch_id):
                    continue
                entries.append({"page_id": page_id, "url": driver.page.url,
                                "owned": page_id in self.owned_pages, "provenance": provenance})
            await check()
            if entries:
                attention = any(isinstance(row.get("provenance"), dict)
                    and row["provenance"].get("source_page_id") in self.hidden_pages for row in entries)
                return {"state": "verified", "observed": True, "pages": entries,
                        "business_result_verified": False, **({"background_attention_required": True,
                            "background_attention_reason": "popup_may_be_visible",
                            "next_action": "inspect_exact_popup_before_continuing"} if attention else {})}
            if asyncio.get_running_loop().time() >= deadline:
                if dispatch_id is not None:
                    self._drop_popup_watch(dispatch_id)
                return {"state": "not_verified", "observed": False, "reason": "condition_timeout",
                        "business_result_verified": False}
            await asyncio.sleep(0.05)

    def verify_private_response(self, command: str, arguments: dict) -> None:
        if command=='trace' and arguments.get('mode')=='stop':
            # The exact session run stamp was consumed before metadata export;
            # no closed page is read or resurrected by this cleanup response.
            return
        if self.profile_kind != "luohua" or command in {"ping", "close_browser", "close_status", "new_page", "list_pending_pages", "recover_pending_page", "native_window", "window_visibility", "reconcile_window_visibility", "prepare_hide_page", "hide_page", "show_page", "local_upload_pending", "list_pages", "wait_page", "close_page", "local_upload_status", "local_upload_release"}:
            return
        driver = self._page(_field(arguments, "page_id", str, maximum=64))
        if not allowed_url(driver.page.url):
            raise ControlError("private_site_out_of_scope")

    async def verify_hidden_window(self, command: str, arguments: dict, *, check):
        page_id = arguments.get("page_id")
        if page_id in self.hidden_unbound and command not in {"close_page", "local_upload_status", "local_upload_release"}:
            raise ControlError("hidden_window_identity_unverified")
        if (page_id not in self.hidden_pages or command in {"native_window", "window_visibility", "reconcile_window_visibility", "prepare_hide_page", "hide_page", "show_page",
                "close_page", "local_upload_status", "local_upload_release"}):
            return
        binding, target = self.page_windows.get(page_id), self.page_targets.get(page_id)
        driver = self._page(page_id)
        if binding is None or target is None:
            raise ControlError("hidden_window_identity_unverified")
        from .web_native_window import validate_native_page
        import win32gui
        identity = await validate_native_page(self.browser, self.download_session, driver.page, target, binding, check=check)
        if win32gui.IsWindowVisible(identity["hwnd"]):
            raise ControlError("hidden_window_visibility_changed")
        for popup_id, provenance in self.popup_provenance.items():
            if provenance.get("source_page_id") != page_id:
                continue
            popup_driver = self.pages.get(popup_id)
            popup = popup_driver.page if popup_driver is not None else self.pending_popup_pages.get(popup_id)
            if popup is not None and not popup.is_closed():
                raise ControlError("hidden_popup_attention_required")
        # Recover the fence after a worker restart using the browser's own
        # target/opener relationship. Never select or hide the popup here.
        rows = (await self.download_session.send("Target.getTargets")).get("targetInfos", [])
        if len(rows) > 1024:
            raise ControlError("shared_window_target_limit")
        if any(row.get("type") == "page" and row.get("openerId") == target for row in rows):
            raise ControlError("hidden_popup_attention_required")

    def verify_private_request(self, driver: PageDriver, command: str,
                               arguments: dict) -> None:
        if self.profile_kind != "luohua":
            return
        if not allowed_url(driver.page.url, blank=command in {"navigate", "navigate_paused"}):
            raise ControlError("private_site_out_of_scope")
        if command in {"navigate", "navigate_paused"} and not allowed_url(arguments.get("url")):
            raise ControlError("private_site_out_of_scope")

    @staticmethod
    def _selection_action(guard):
        if guard is None:
            raise ControlError("file_selection_guard_required")
        with guard.store.read_transaction() as db:
            row = db.execute("SELECT task,owner,scope,resources FROM actions WHERE id=?", (guard.action,)).fetchone()
            if row is None:
                raise ControlError("file_selection_guard_required")
            return dict(row)

    def _pending_page_context(self, guard):
        if guard is None:
            raise ControlError("pending_page_guard_required")
        action = self._selection_action(guard)
        resources = json.loads(action["resources"])
        borrowers = [item for item in resources if isinstance(item, str) and item.startswith("web-borrower:")]
        if not self.shared_browser or len(borrowers) != 1 or not self.browser_process_identity:
            raise ControlError("pending_page_context_unavailable")
        return action, borrowers[0]

    async def _assert_pending_browser(self, *, check):
        from .web_native_window import _browser_pid
        await check()
        pid = await _browser_pid(self.download_session)
        if process_identity(pid) != self.browser_process_identity:
            raise ControlError("pending_page_browser_changed")
        await check()

    def _prepare_pending_page(self, guard, *, hidden_requested=False):
        action, resource = self._pending_page_context(guard)
        identifier = uuid.uuid4().hex
        with guard.store.transaction() as db:
            count = db.execute("SELECT count(*) FROM web_created_targets WHERE task=? AND resource=? AND browser_process=? AND state!='closed'",
                               (action["task"], resource, self.browser_process_identity)).fetchone()[0]
            if count >= 256:
                raise ControlError("pending_page_limit")
            db.execute("INSERT INTO web_created_targets(id,action,task,resource,browser_process,target,page_id,state,created,hidden_requested) VALUES (?,?,?,?,?,NULL,NULL,'prepared',?,?)",
                       (identifier, guard.action, action["task"], resource, self.browser_process_identity, guard.store.clock(), int(hidden_requested)))
        return identifier

    def _record_pending_target(self, guard, identifier, target):
        if type(target) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target):
            raise ControlError("pending_page_target_invalid")
        with guard.store.transaction() as db:
            changed = db.execute("UPDATE web_created_targets SET target=?,state='created' WHERE id=? AND action=? AND state='prepared'",
                                 (target, identifier, guard.action)).rowcount
            if changed != 1:
                raise ControlError("pending_page_record_unavailable")

    def _close_undispatched_pending(self, guard, identifier):
        effects = current_effects.get()
        if effects is None or effects.dispatched:
            return
        with guard.store.transaction() as db:
            db.execute("UPDATE web_created_targets SET state='closed' WHERE id=? AND action=? AND target IS NULL AND state='prepared'",
                       (identifier, guard.action))

    def _pending_page_rows(self, guard, *, close_cleanup=False):
        action, resource = self._pending_page_context(guard)
        with guard.store.read_transaction() as db:
            rows = db.execute("SELECT p.* FROM web_created_targets p JOIN actions a ON a.id=p.action "
                "WHERE p.task=? AND p.resource=? AND p.browser_process=? AND p.state!='closed' "
                + ("" if close_cleanup else "AND a.scope IS ? ") + "ORDER BY p.created LIMIT 256",
                (action["task"], resource, self.browser_process_identity) + (() if close_cleanup else (action["scope"],))).fetchall()
            return [dict(row) for row in rows]

    async def _reconcile_absent_pending_pages(self, guard, *, check):
        await self._assert_pending_browser(check=check)
        rows = self._pending_page_rows(guard)
        if not any(row["target"] for row in rows):
            return
        await check()
        targets = (await self.download_session.send("Target.getTargets")).get("targetInfos", [])
        await check()
        if len(targets) > 1024:
            raise ControlError("shared_window_target_limit")
        live = {row.get("targetId") for row in targets}
        with guard.store.transaction() as db:
            for row in rows:
                if row["target"] and row["target"] not in live:
                    # This records only current absence, never a past action's
                    # business outcome and never authorizes a replay.
                    db.execute("UPDATE web_created_targets SET state='closed' WHERE id=? AND target=?",
                               (row["id"], row["target"]))

    async def _recover_pending_page(self, guard, identifier, *, check, close_cleanup=False):
        await self._assert_pending_browser(check=check)
        rows = [row for row in self._pending_page_rows(guard, close_cleanup=close_cleanup) if row["id"] == identifier]
        if len(rows) != 1:
            raise ControlError("pending_page_unavailable")
        row = rows[0]
        if row["target"] is None:
            return {"pending_id": identifier, "state": "outcome_unknown", "replayed": False,
                    "reason": "created_target_identity_not_recorded",
                    "next_action": "preserve_pending_without_replaying_creation",
                    "page_recovery_available": False, "pending_auto_clear_available": False,
                    "manual_observation": "only_if_visible_for_context_does_not_resolve_pending"}
        for context in self.browser.contexts:
            for page in context.pages:
                await check()
                if page.is_closed():
                    continue
                probe = await context.new_cdp_session(page)
                try:
                    target = (await probe.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
                except PlaywrightError:
                    if page.is_closed():
                        continue
                    raise
                finally:
                    await probe.detach()
                if target != row["target"]:
                    continue
                await self._assert_pending_browser(check=check)
                page_id = next((key for key, value in self.page_targets.items() if value == target), None)
                if page_id is not None and page_id not in self.owned_pages:
                    raise ControlError("pending_page_unavailable")
                already_registered = page_id is not None
                if page_id is None:
                    page_id = row["page_id"] or uuid.uuid4().hex
                    self.pages[page_id] = self._driver(page)
                    self.owned_pages.add(page_id)
                    self.page_targets[page_id] = target
                if row["hidden_requested"] and not already_registered:
                    if page_id in self.page_windows:
                        self.hidden_pages.add(page_id)
                    else:
                        self.hidden_unbound.add(page_id)
                with guard.store.transaction() as db:
                    db.execute("UPDATE web_created_targets SET page_id=?,state='located' WHERE id=? AND target=? AND state!='closed'",
                               (page_id, identifier, target))
                return {"pending_id": identifier, "state": "page_recovered", "page_id": page_id,
                        "replayed": False, "native_window_verified": page_id in self.page_windows,
                        "next_action": ("close_exact_page_or_resolve_window_manually" if page_id in self.hidden_unbound
                                        else "inspect_window_visibility_then_hide" if page_id in self.hidden_pages
                                        else "observe_exact_page_before_continuing")}
        await check()
        targets = (await self.download_session.send("Target.getTargets")).get("targetInfos", [])
        await check()
        if len(targets) > 1024:
            raise ControlError("shared_window_target_limit")
        if not any(entry.get("targetId") == row["target"] for entry in targets):
            with guard.store.transaction() as db:
                db.execute("UPDATE web_created_targets SET state='closed' WHERE id=? AND target=?", (identifier, row["target"]))
            return {"pending_id": identifier, "state": "target_not_live", "replayed": False,
                    "original_action_outcome": "unchanged"}
        return {"pending_id": identifier, "state": "waiting_for_exact_page", "replayed": False}

    def _selection_owner_allowed(self, identifier, item, action, guard, *, cleanup_only, allow_transition=False):
        if item[1] != action["task"]:
            return False
        if item[4] == action["owner"]:
            return True
        if not cleanup_only or (not allow_transition and item[0].state not in {"cancelled", "expired", "invalidated", "cleanup_pending", "released"}):
            return False
        origin = self.file_selection_origins.get(identifier)
        if origin is None or guard is None:
            return False
        with guard.store.read_transaction() as db:
            original = db.execute("SELECT task,owner,scope,resources FROM actions WHERE id=?", (origin,)).fetchone()
            old = db.execute("SELECT task,process,retired FROM owners WHERE id=?", (item[4],)).fetchone()
            new = db.execute("SELECT task,process,retired,live_until FROM owners WHERE id=?", (action["owner"],)).fetchone()
            if (not original or not old or not new or original["task"] != action["task"]
                    or original["owner"] != item[4] or original["scope"] != action["scope"]
                    or original["resources"] != action["resources"]
                    or old["task"] != action["task"] or new["task"] != action["task"]
                    or not old["retired"] or new["retired"] or new["live_until"] <= guard.store.clock()
                    or old["process"] != new["process"]):
                return False
            current = item[4]
            for _ in range(128):
                link = db.execute("SELECT replacement FROM owner_replacements WHERE prior=? AND task=?", (current, action["task"])).fetchone()
                if not link:
                    return False
                current = link[0]
                if current == action["owner"]:
                    return True
            return False

    async def _local_upload(self, command, arguments, driver, *, check, guard):
        from flower_control.permissions import revision
        from .web_file_session import FileSelectionSession
        action = self._selection_action(guard)
        page_id = arguments.get("page_id")
        if command == "local_upload_begin":
            for key, item in list(self.file_selections.items()):
                if (item[0].state in {"cancelled", "expired", "invalidated"}
                        and self._selection_owner_allowed(key, item, action, guard, cleanup_only=True)):
                    await item[0].close()
                    await self._dispose_selection_handle(item[2], item[3])
                    self.file_selections.pop(key, None)
                    self.file_selection_origins.pop(key, None)
            if set(arguments) != {"page_id", "reference"} or self.file_selections:
                raise ControlError("file_selection_busy_or_invalid")
            ref = await driver._fresh(_field(arguments, "reference", str, maximum=100))
            if ref.descriptor["tag"] != "INPUT" or ref.descriptor["type"] != "file":
                raise ControlError("file_input_required")
            page = driver.page
            frame = await ref.handle.owner_frame()
            origin = source_origin(page.url)
            if frame is None or source_origin(frame.url) != origin:
                raise ControlError("file_selection_frame_origin_mismatch")
            page_url, frame_url = page.url, frame.url
            store, task, owner, scope = guard.store, action["task"], action["owner"], action["scope"]
            resources = json.loads(action["resources"])
            if type(resources) is not list or not resources or any(type(item) is not str for item in resources):
                raise ControlError("file_selection_resource_invalid")
            epoch = store.write_gate.snapshot().epoch
            policy_revision = revision()
            with store.read_transaction() as db:
                lifecycle = db.execute("SELECT sequence FROM task_lifecycle WHERE task=?", (task,)).fetchone()
                lifecycle = lifecycle[0] if lifecycle else 0
            def valid():
                if (self.pages.get(page_id) is not driver or driver.page is not page or page.is_closed()
                        or page.url != page_url or frame.url != frame_url or revision() != policy_revision
                        or store.task_write_stopped(task) or store.write_gate.snapshot().epoch != epoch):
                    return False
                with store.read_transaction() as db:
                    row = db.execute("SELECT paused,revoked FROM tasks WHERE id=?", (task,)).fetchone()
                    current = db.execute("SELECT sequence FROM task_lifecycle WHERE task=?", (task,)).fetchone()
                    own = db.execute("SELECT retired,live_until,process FROM owners WHERE id=? AND task=?", (owner, task)).fetchone()
                    from flower_control.control.native import process_is_alive
                    if (not row or row[0] or row[1] or not own or own[0] or own[1] <= store.clock()
                            or not process_is_alive(own[2])
                            or (current[0] if current else 0) != lifecycle):
                        return False
                    if scope:
                        store._require_scope(db, task, scope)
                    for resource in resources:
                        target = db.execute("SELECT paused,quarantined,required_scope FROM resources WHERE id=?", (resource,)).fetchone()
                        if not target or target[0] or store._effective_quarantine(db, resource, target):
                            return False
                        if target[2]:
                            store._require_scope(db, task, target[2])
                if self.shared_browser:
                    from .web_shared_profile import require_profile_gate
                    require_profile_gate(store, self.profile_resource)
                return True
            await check()
            original = await ref.handle.evaluate_handle("e => e")
            original = original.as_element()
            if original is None:
                raise ControlError("file_selection_target_changed")
            selection = FileSelectionSession(origin=origin, valid=valid, task_key=task)
            try:
                await selection.start()
            except BaseException:
                await original.dispose()
                raise
            self.file_selections[selection.identifier] = (selection, task, driver, original, owner, page_id)
            self.file_selection_origins[selection.identifier] = guard.action
            return {"state": "verified", "selection_state": "pending", "selection_id": selection.identifier,
                    "site_origin": origin, "upload_dispatched": False}
        identifier = _field(arguments, "selection_id", str, maximum=32)
        item = self.file_selections.get(identifier)
        if (item is None or item[2] is not driver or item[5] != page_id
                or not self._selection_owner_allowed(identifier, item, action, guard,
                    cleanup_only=command in {"local_upload_status", "local_upload_release"})):
            raise ControlError("file_selection_unavailable")
        selection, _, _, original, _, _ = item
        if command == "local_upload_status":
            if set(arguments) != {"page_id", "selection_id"}:
                raise ControlError("invalid_worker_argument")
            return {"state": "verified", "selection_state": selection.state,
                    "selection_consumed": selection.consumed,
                    "snapshot_available": selection.state in {"ready", "consumed"} and selection.snapshot is not None,
                    "reselect_required": selection.consumed and selection.state in {"expired", "invalidated", "released", "cleanup_pending"},
                    "business_result_verified": False}
        if command == "local_upload_release":
            if set(arguments) != {"page_id", "selection_id"}:
                raise ControlError("invalid_worker_argument")
            await selection.close()
            await self._dispose_selection_handle(driver, original)
            self.file_selections.pop(identifier, None)
            self.file_selection_origins.pop(identifier, None)
            return {"state": "verified", "selection_state": "released",
                    "reselect_required": selection.consumed,
                    "page_file_may_be_unreadable": selection.consumed,
                    "business_result_verified": False}
        if command != "local_upload_commit" or set(arguments) != {"page_id", "selection_id", "reference"}:
            raise ControlError("invalid_worker_argument")
        ref = await driver._fresh(_field(arguments, "reference", str, maximum=100))
        if not await ref.handle.evaluate("(e, original) => e === original && e.isConnected && e.type === 'file'", original):
            raise ControlError("file_selection_target_changed")
        await check()
        snapshot = selection.take()
        snapshot.verify(check=selection._thread_check)
        selection._check()
        await check()
        mark_write("upload")
        await ref.handle.set_input_files(str(snapshot.path), timeout=30000)
        selected = await ref.handle.evaluate("e => Array.from(e.files || [], f => ({name:f.name,size:f.size}))")
        await check()
        matched = len(selected) == 1 and selected[0] == {"name": snapshot.path.name, "size": snapshot.size}
        return {"state": "verified" if matched else "not_verified", "selection_state": "consumed",
                "verification": "file_input_selection", "business_result_verified": False,
                "site_submission_verified": False,
                "release_after": "site_submission_and_result_verified",
                "bytes": snapshot.size, "sha256": snapshot.sha256}

    @staticmethod
    async def _dispose_selection_handle(driver, handle):
        try:
            await handle.dispose()
        except PlaywrightError:
            if not driver.page.is_closed():
                raise

    async def execute(self, command: str, arguments: dict, *, check=_noop_check, lease_guard=None) -> object:
        from flower_control.permissions import active_policy, revision, require_browser, PermissionError
        original_check = check
        recording_checker=None
        if command=='trace' and arguments.get('mode')=='start':
            from .web_diagnostic_recording import finite_recording_checker
            guard=getattr(original_check,'__self__',None)
            recording_checker=finite_recording_checker(guard)
            if self.shared_browser:
                from .web_shared_profile import require_profile_gate
                finite=recording_checker
                def recording_checker():
                    require_profile_gate(guard.store,self.profile_resource)
                    return finite()
        try:
            policy_revision = revision()
        except PermissionError as error:
            raise ControlError(error.code) from None
        async def check():
            await original_check()
            selected = arguments.get("page_id")
            if type(selected) is str and selected in self.user_pages and not self._user_page_claim_valid(lease_guard, selected):
                raise ControlError("page_not_owned_by_chat")
            try:
                policy = active_policy.read()
                if policy["Revision"] != policy_revision:
                    raise ControlError("user_policy_requires_new_observation")
                if self.browser_policy_identity is not None:
                    require_browser(*self.browser_policy_identity)
                    from flower_control.privacy import application_masks
                    if application_masks(self.browser_policy_identity[1], policy):
                        raise ControlError("privacy_web_window_mapping_unavailable")
                elif policy["DeniedApplications"] or not policy["AdminWindows"] or policy["AdminScope"] != "all":
                    raise ControlError("browser_policy_identity_unavailable")
            except PermissionError as error:
                raise ControlError(error.code) from None
        # Normal close/retirement must remain possible after permission revoke.
        privacy_check = check
        if command in {"close_browser", "dispose_page", "chooser_cancel"}:
            # chooser_cancel only releases our intercepted listener; it does
            # not select files, clear FileList or touch the native dialog.
            check = original_check
        result_driver = (self.pages.get(arguments.get("page_id"))
            if command in {"observe", "message_baseline"} and type(arguments.get("page_id")) is str else None)
        result = await self._execute(command, arguments, check=check,recording_checker=recording_checker, lease_guard=lease_guard)
        # Cached reads and less common branches must pass the same final gate.
        try:
            await check()
            if command in {"observe", "message_baseline"}:
                self.verify_private_response(command, arguments)
                if command == "observe":
                    result_driver.verify_observation(result)
                else:
                    result_driver.verify_message_baseline(result)
        except BaseException:
            await _discard_failed_upload_begin(self, command, result)
            if command=='trace' and arguments.get('mode')=='start' and type(result) is dict:
                kind=arguments.get('kind','trace')
                run=self.diagnostic_recordings.active.get(kind)
                if run is not None and run['run_id']==result.get('run_id'):
                    self.diagnostic_recordings.active.pop(kind);self._stop_diagnostic_listeners()
            if result_driver is not None:
                if command == "observe":
                    await result_driver.discard_observation(result)
                else:
                    result_driver.discard_message_baseline(result)
            raise
        if command == "close_browser":
            try:
                await privacy_check()
            except ControlError as error:
                # Closing owned resources remains available after revocation,
                # but this exemption must not return a private dialog message.
                # Never accept a save/discard prompt on the user's behalf.
                pending = []
                for row in result.get("pending_pages", []):
                    item = {key: row[key] for key in ("page_id", "closed", "state") if key in row}
                    dialog = row.get("dialog")
                    item["dialog"] = ({key: dialog[key] for key in ("dialog_id", "type", "generation") if key in dialog}
                                      if type(dialog) is dict else None)
                    pending.append(item)
                return {"requested": result.get("requested", False),
                        "state": result.get("state", "closed" if result.get("requested") else "close_pending"),
                        "closed_pages": result.get("closed_pages", []), "pending_pages": pending,
                        "content_redacted": True, "reason": error.code,
                        "requires_user_takeover": bool(pending),
                        "ask_user_via_host_popup": bool(pending)}
        return result

    async def _execute(self, command: str, arguments: dict, *, check,recording_checker=None, lease_guard=None) -> object:
        await check()
        if command == "ping":
            if arguments:
                if set(arguments) != {"page_registry"}:
                    raise ControlError("invalid_worker_ping")
                self.restored_pages = page_registry(arguments["page_registry"])
                if self.shared_browser and self.restored_pages:
                    # Reconnect only exact targets in this borrower's record.
                    # Other pages get no PageDriver, event listener or content read.
                    for context in self.browser.contexts:
                        for page in context.pages:
                            session = await context.new_cdp_session(page)
                            try:
                                target = (await session.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
                            finally:
                                await session.detach()
                            restored = self.restored_pages.get(target)
                            if restored and restored["owned"]:
                                key = restored["page_id"]
                                self.pages[key] = (PageDriver(page, event_filter=allowed_url if self.profile_kind == "luohua" else None,
                                    diagnostic_sink=lambda event, page=page: self._diagnostic_event(page, event))
                                    if restored.get("user_page") is True else self._driver(page))
                                self.owned_pages.add(key)
                                if restored.get("user_page") is True:
                                    self.user_pages.add(key)
                                self.page_targets[key] = target
                                binding = native_window_binding(restored.get("native_window"))
                                if binding is not None:
                                    self.page_windows[key] = binding
                                if restored.get("hidden") is True:
                                    self.hidden_pages.add(key)
                                if restored.get("hidden_unbound") is True:
                                    self.hidden_unbound.add(key)
            if not self.browser.contexts:
                raise RuntimeError("browser_context_missing")
            return {"ready": True, "process": process_identity(), "pid": os.getpid(), "parent_pid": os.getppid()}
        if command == "close_browser":
            if (self.profile_kind not in ("temporary", "ai", "luohua")
                    or not arguments.keys() <= {"preserve_tabs"}
                    or ("preserve_tabs" in arguments and type(arguments["preserve_tabs"]) is not bool)):
                raise ControlError("browser_close_unavailable")
            return await self._close_browser(check=check, preserve_tabs=arguments.get("preserve_tabs", False), lease_guard=lease_guard)
        if command == "close_status":
            requested = arguments.get("page_ids", [])
            if (set(arguments) - {"page_ids"} or type(requested) is not list or len(requested) > 64
                    or any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value) for value in requested)
                    or len(set(requested)) != len(requested)):
                raise ControlError("invalid_close_status_arguments")
            await self._list_pages()
            await check()
            pending = [{"page_id": key, "page_close_requested": key in self.page_close_requested,
                        "dialog_id": driver.pending_dialog_id,
                        "dialog_type": driver.pending_dialog.type if driver.pending_dialog else None}
                       for key, driver in self.pages.items() if driver.pending_dialog is not None
                       or key in self.page_close_requested]
            facts = []
            for page_id in requested:
                original = self.page_close_targets.get(page_id)
                closed = original.is_closed() if original is not None else None
                facts.append({"page_id": page_id, "original_close_known": original is not None,
                              "closed": closed if type(closed) is bool else None})
            return {"state": "waiting_for_user" if any(row["dialog_id"] for row in pending) or self.close_wait_reason
                    else "waiting_for_browser_exit" if self.instance_close_requested else "not_requested",
                    "instance_close_requested": self.instance_close_requested,
                    "page_close_requested": sorted(self.page_close_requested), "pending_pages": pending,
                    "page_facts": facts,
                    "wait_reason": self.close_wait_reason,
                    "dispatched": False}
        if command == "new_page":
            if self.trace_page_id is not None:
                raise ControlError("trace_target_exclusive")
            if not self.browser.contexts:
                raise RuntimeError("browser_context_missing")
            binding = None
            prepare_hidden = arguments.get("window_mode") == "hidden"
            if "window_mode" in arguments and not prepare_hidden:
                raise ControlError("invalid_page_window_mode")
            if prepare_hidden and (not self.shared_browser or self.shared_headless):
                raise ControlError("hidden_page_requires_shared_headed_browser")
            before = None
            pending_id = None
            if self.shared_browser and not self.shared_headless:
                from .web_native_window import create_native_page, _browser_pid, _windows
                if prepare_hidden:
                    await check()
                    before = _windows(await _browser_pid(self.download_session))
                if lease_guard is not None:
                    await check()
                    await self._reconcile_absent_pending_pages(lease_guard, check=check)
                    pending_id = self._prepare_pending_page(lease_guard, hidden_requested=prepare_hidden)
                    async def on_target(target):
                        self._record_pending_target(lease_guard, pending_id, target)
                    try:
                        page, binding = await create_native_page(self.browser, self.download_session, check=check, on_target=on_target)
                    except BaseException:
                        self._close_undispatched_pending(lease_guard, pending_id)
                        raise
                else:
                    page, binding = await create_native_page(self.browser, self.download_session, check=check)
                checked_binding = native_window_binding(binding)
                if binding is not None and checked_binding is None:
                    raise ControlError("native_window_identity_unverified")
                binding = checked_binding
            elif self.shared_headless:
                from .web_native_window import create_headless_page
                if self.shared_browser and lease_guard is not None:
                    await check()
                    await self._reconcile_absent_pending_pages(lease_guard, check=check)
                    pending_id = self._prepare_pending_page(lease_guard)
                    async def on_target(target):
                        self._record_pending_target(lease_guard, pending_id, target)
                    try:
                        page = await create_headless_page(self.browser.contexts[0], self.download_session, check=check, on_target=on_target)
                    except BaseException:
                        self._close_undispatched_pending(lease_guard, pending_id)
                        raise
                else:
                    page = await create_headless_page(self.browser.contexts[0], self.download_session, check=check)
            else:
                mark_write("new_page")
                page = await self.browser.contexts[0].new_page()
            if self.focus_defaults is not None:
                self.focus_defaults.track(page)
            page_id = next((key for key,driver in self.pages.items() if driver.page is page),None)
            if page_id is None:
                page_id = uuid.uuid4().hex
                self.pages[page_id] = self._driver(page)
            self.owned_pages.add(page_id)
            if prepare_hidden:
                # Fence the newly owned page before any later await can fail.
                # Only a verified native binding can replace this fence.
                self.hidden_unbound.add(page_id)
            page_id = await self._remember_page(page_id, page)
            if pending_id is not None:
                target = self.page_targets.get(page_id)
                with lease_guard.store.transaction() as db:
                    changed = db.execute("UPDATE web_created_targets SET page_id=?,state='located' WHERE id=? AND action=? AND target=? AND state='created'",
                                         (page_id, pending_id, lease_guard.action, target)).rowcount
                    if changed != 1:
                        raise ControlError("pending_page_record_unavailable")
            if prepare_hidden:
                from .web_hidden_window import bind_new_page
                target, binding = await bind_new_page(self.browser, self.download_session, page, before=before, check=check)
                if self.page_targets.get(page_id) != target:
                    raise ControlError("hidden_window_page_changed")
            if binding is not None:
                self.page_windows[page_id] = binding
            if prepare_hidden:
                # Persist desired state together with the exact binding in the
                # completed new_page response before any hide is dispatched.
                self.hidden_unbound.discard(page_id)
                self.hidden_pages.add(page_id)
            await check()
            return {"page_id": page_id, **({"pending_id": pending_id} if pending_id else {}),
                    **({"hidden_prepared": True, "next_action": "hide_page"} if prepare_hidden else {})}
        if command == "wait_page":
            return await self._wait_page(arguments, check=check)
        if command == "list_pages":
            site = (_field(arguments, "site", str, maximum=253)
                    if self.profile_kind == "luohua" and "site" in arguments else None)
            include_metadata = arguments.get("include_metadata", False)
            if type(include_metadata) is not bool:
                raise ControlError("invalid_page_metadata_request")
            await self._drop_stale_user_pages(lease_guard)
            discovery_complete = await self._discover_user_pages(lease_guard, check=check)
            if include_metadata:
                result = await self._page_metadata(arguments, site, check=check)
                if self.shared_browser:
                    result["manual_page_discovery"] = "complete" if discovery_complete else "temporarily_deferred"
                return result
            result = await self._list_pages(site=site)
            await check()
            return result
        if command=='trace' and arguments.get('mode')=='stop':
            return await self._trace(None,None,arguments,check=check)
        if command == "list_pending_pages":
            if arguments:
                raise ControlError("invalid_pending_page_request")
            await check()
            await self._reconcile_absent_pending_pages(lease_guard, check=check)
            return {"pages": [{"pending_id": row["id"], "state": row["state"],
                "page_id": row["page_id"], "exact_target_recorded": row["target"] is not None,
                "next_action": ("recover_pending_page" if row["target"] is not None
                                else "preserve_pending_without_replaying_creation"),
                **({"page_recovery_available": False, "pending_auto_clear_available": False,
                    "manual_observation": "only_if_visible_for_context_does_not_resolve_pending"}
                   if row["target"] is None else {})}
                for row in self._pending_page_rows(lease_guard)]}
        if command == "recover_pending_page":
            if set(arguments) != {"pending_id"}:
                raise ControlError("invalid_pending_page_request")
            identifier = _field(arguments, "pending_id", str, maximum=32)
            await check()
            return await self._recover_pending_page(lease_guard, identifier, check=check)
        if command == "local_upload_pending":
            if arguments:
                raise ControlError("invalid_file_selection_request")
            action = self._selection_action(lease_guard)
            await check()
            selections = [{"selection_id": key, "page_id": item[5], "state": item[0].state}
                for key, item in self.file_selections.items()
                if self._selection_owner_allowed(key, item, action, lease_guard, cleanup_only=True)]
            stopping = any(item[4] != action["owner"] and item[0].state in {"starting", "pending", "ready", "consumed"}
                and self._selection_owner_allowed(key, item, action, lease_guard, cleanup_only=True, allow_transition=True)
                for key, item in self.file_selections.items())
            return {"selections": selections, **({"previous_owner_stopping": True} if stopping else {})}
        page_id = _field(arguments, "page_id", str, maximum=64)
        if command in {"local_upload_status", "local_upload_release"}:
            identifier = _field(arguments, "selection_id", str, maximum=32)
            item = self.file_selections.get(identifier)
            if item is None or item[5] != page_id:
                raise ControlError("file_selection_unavailable")
            return await self._local_upload(command, arguments, item[2], check=check, guard=lease_guard)
        driver = self._page(page_id)
        if self.shared_browser and lease_guard is not None:
            target = self.page_targets.get(page_id)
            if not target or not self.browser_process_identity:
                raise ControlError("shared_browser_identity_unverified")
            await check()
            with lease_guard.store.transaction() as db:
                db.execute("INSERT OR IGNORE INTO web_action_page_targets VALUES (?,?,?)",
                           (lease_guard.action, self.browser_process_identity, target))
                bound = db.execute("SELECT browser_process,target FROM web_action_page_targets WHERE action=?",
                                   (lease_guard.action,)).fetchone()
                if not bound or bound["browser_process"] != self.browser_process_identity or bound["target"] != target:
                    raise ControlError("page_changed")
            await check()
        await self.verify_hidden_window(command, arguments, check=check)
        if command in {"native_window", "window_visibility", "reconcile_window_visibility", "prepare_hide_page", "hide_page", "show_page"}:
            if set(arguments) != {"page_id"} or not self.shared_browser or self.shared_headless:
                raise ControlError("native_window_unavailable")
            binding = native_window_binding(self.page_windows.get(page_id))
            target = self.page_targets.get(page_id)
            if binding is None or target is None:
                raise ControlError("native_window_identity_unverified")
            from .web_native_window import validate_native_page
            identity = await validate_native_page(self.browser, self.download_session, driver.page, target, binding, check=check)
            await check()
            if self._page(page_id) is not driver or self.page_windows.get(page_id) != binding:
                raise ControlError("page_changed")
            import win32con, win32gui
            hwnd = identity["hwnd"]
            if command == "native_window":
                if page_id in self.hidden_pages or not win32gui.IsWindowVisible(hwnd):
                    raise ControlError("native_window_hidden")
                return identity
            if command == "window_visibility":
                return {"page_id": page_id, "visible": bool(win32gui.IsWindowVisible(hwnd)),
                        "minimized": bool(win32gui.IsIconic(hwnd)), "expected_hidden": page_id in self.hidden_pages}
            if command == "prepare_hide_page":
                await check()
                mark_write(command)
                self.hidden_pages.add(page_id)
                return {"page_id": page_id, "next_action": "hide_page", "visible": bool(win32gui.IsWindowVisible(hwnd))}
            if command == "reconcile_window_visibility":
                await check()
                mark_write(command)
                visible = bool(win32gui.IsWindowVisible(hwnd))
                if visible:
                    self.hidden_pages.discard(page_id)
                else:
                    self.hidden_pages.add(page_id)
                return {"page_id": page_id, "visible": visible, "replayed_window_action": False}
            if command == "hide_page" and page_id not in self.hidden_pages:
                raise ControlError("hidden_window_not_prepared")
            from .web_hidden_window import hide_bound_page
            await check()
            mark_write(command)
            if command == "hide_page":
                await hide_bound_page(self.browser, self.download_session, driver.page, target, binding, check=check)
                self.hidden_pages.add(page_id)
            else:
                win32gui.ShowWindow(hwnd, win32con.SW_SHOWNOACTIVATE)
                await validate_native_page(self.browser, self.download_session, driver.page, target, binding, check=check)
                if not win32gui.IsWindowVisible(hwnd):
                    raise ControlError("window_show_unconfirmed")
                self.hidden_pages.discard(page_id)
            return {"page_id": page_id, "visible": command == "show_page", "business_result_verified": False}
        self.verify_private_request(driver, command, arguments)
        if command == "mark_tab":
            if driver.pending_dialog is not None:
                raise ControlError("dialog_pending")
            if driver.pending_chooser is not None:
                raise ControlError("file_chooser_pending")
            return await driver.mark_tab(arguments.get("value", "[Flower]"), check=check)
        if command in {"mark_page", "clear_page_mark"}:
            await check()
            if command == "mark_page":
                from flower_control.control.targets import target_description
                label = _field(arguments, "label", str, maximum=64)
                if not label.strip():
                    raise ControlError("invalid_page_marker")
                self.page_marks[page_id] = target_description(label, 64)
            else:
                self.page_marks.pop(page_id, None)
            await check()
            return {"page_id": page_id, "marker": self.page_marks.get(page_id),
                    "scope": "local_session_metadata", "ownership_granted": False,
                    "page_content_changed": False}
        if (self.trace_page_id is not None and command not in {"trace", "local_upload_status", "local_upload_release"}
                and page_id != self.trace_page_id):
            raise ControlError("trace_target_exclusive")
        if self.focus_defaults is not None and command in {
                "fill", "type", "click", "hover", "press", "select_option", "set_checked", "drag",
                "upload", "download", "editor_replace", "terminal_input", "chooser_upload", "local_upload_commit"}:
            await self.focus_defaults.ready(driver.page)
            await check()
        if command in {"local_upload_begin", "local_upload_status", "local_upload_commit", "local_upload_release"}:
            if (command not in {"local_upload_status", "local_upload_release"}
                    and (driver.pending_dialog is not None or driver.pending_chooser is not None)):
                raise ControlError("dialog_pending")
            return await self._local_upload(command, arguments, driver, check=check, guard=lease_guard)
        if command == "result_probe":
            return {"state": "verified", "page_id": page_id, **await driver.result_probe(arguments, check=check)}
        if command == "dialog_state":
            return await driver.dialog_state(check=check)
        if command == "workflow_bind":
            return await driver.workflow.bind(arguments, check=check)
        if command == "workflow_check":
            return await driver.workflow.check(
                _field(arguments, "binding_id", str, maximum=100),
                _field(arguments, "phase", str, maximum=20),
                editor_reference=arguments.get("editor_reference"), check=check)
        if command == "chooser_state":
            return await driver.chooser_state(check=check)
        if command == "chooser_cancel":
            return await driver.chooser_cancel(_field(arguments, "chooser_id", str, maximum=100), check=check)
        if command == "chooser_upload":
            return await driver.chooser_upload(
                _field(arguments, "chooser_id", str, maximum=100),
                files=decode_files(arguments), check=check)
        if command == "wait_condition":
            return await driver.wait_condition(_field(arguments, "condition", dict), check=check)
        if command == "message_baseline":
            if not {"page_id","container_reference","selector"}<=arguments.keys() or not arguments.keys()<={"page_id","container_reference","selector","ttl"}:
                raise ControlError("invalid_message_baseline")
            return await driver.message_baseline(_field(arguments,"container_reference",str,maximum=100),
                _field(arguments,"selector",str,maximum=2000),ttl=arguments.get("ttl",15),check=check)
        if command == "assert_condition":
            return await driver.assert_condition(_field(arguments, "condition", dict), check=check)
        if command == "wait_navigation":
            return await driver.wait_navigation(
                _field(arguments, "after_navigation_version", int),
                _field(arguments, "timeout_ms", int), expected_url=arguments.get("expected_url"), check=check)
        if command == "dialog_action":
            cancelled_close = (driver.pending_dialog is not None and driver.pending_dialog.type == "beforeunload"
                               and arguments.get("accept") is False)
            result = await driver.dialog_action(
                _field(arguments, "dialog_id", str, maximum=100),
                _field(arguments, "accept", bool), prompt_text=arguments.get("prompt_text"), check=check)
            if cancelled_close:
                self.instance_close_requested = False
                self.window_close_requested.clear()
                self.close_wait_reason = None
            return result
        if driver.pending_dialog is not None and command not in {
                "page_diagnostics", "dispose_page"}:
            raise ControlError("dialog_pending")
        if command == "transition":
            if driver.pending_chooser is not None:
                raise ControlError("chooser_pending")
            return await self._input_with_popups(page_id, lambda: driver.transition(arguments, check=check), check=check)
        if getattr(driver, "pending_chooser", None) is not None and command in {
                "fill", "type", "click", "press", "hover", "select_option", "set_checked", "drag", "upload",
                "download", "editor_replace", "terminal_input", "navigate", "navigate_paused",
                "play_media", "pause_media", "back", "forward", "reload", "scroll"}:
            raise ControlError("chooser_pending")
        if command == "dispose_page":
            await driver.dispose()
            self.pages.pop(page_id)
            self.owned_pages.discard(page_id)
            self.page_targets.pop(page_id, None)
            self.page_windows.pop(page_id, None)
            self.hidden_pages.discard(page_id)
            self.hidden_unbound.discard(page_id)
            self.page_marks.pop(page_id, None)
            self.popup_provenance.pop(page_id, None)
            self.pending_popup_claims.pop(page_id, None)
            return {"disposed": True}
        if command == "close_page":
            if page_id not in self.owned_pages:
                raise ControlError("page_not_owned_by_chat")
            target = self.page_targets.get(page_id)
            outcome = await self._normal_close_page(page_id, driver, check=check)
            if outcome.get("closed") and target is not None and lease_guard is not None and self.shared_browser:
                action, resource = self._pending_page_context(lease_guard)
                with lease_guard.store.transaction() as db:
                    db.execute("UPDATE web_created_targets SET state='closed' WHERE task=? AND resource=? AND browser_process=? AND target=?",
                               (action["task"], resource, self.browser_process_identity, target))
            return outcome
        if command == "observe":
            selector = _field(arguments, "selector", str, maximum=2000)
            ttl = arguments.get("ttl")
            if type(ttl) not in (int, float) or not 0 < ttl <= 30:
                raise ValueError("invalid_worker_argument")
            options = {}
            if 'projection' in arguments:
                validate_observation_projection(arguments['projection'])
                options['projection'] = arguments['projection']
            if 'root_ref' in arguments:
                validate_observation_root(arguments['root_ref'])
                options['root_ref'] = arguments['root_ref']
            if 'max_chars' in arguments:
                validate_observation_max_chars(arguments['max_chars'])
                options['max_chars'] = arguments['max_chars']
            if 'max_nodes' in arguments:
                observation_node_limit(_field(arguments,'limit',int),arguments['max_nodes'])
                options['max_nodes'] = arguments['max_nodes']
            if 'max_depth' in arguments:
                from .web_tree import validate_tree_depth
                validate_tree_depth(arguments['max_depth'])
                options['max_depth'] = arguments['max_depth']
            result = await driver.observe(check=check,
                                        frame_index=_field(arguments, "frame_index", int),
                                        selector=selector, offset=_field(arguments, "offset", int),
                                        limit=_field(arguments, "limit", int),
                                        ttl=ttl, **options)
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
                await driver.discard_observation(result)
                raise ControlError("private_site_out_of_scope")
            return result
        if command == "read_text":
            return await driver.read_text(_field(arguments, "reference", str, maximum=100),
                                          check=check,
                                          offset=_field(arguments, "offset", int),
                                          limit=_field(arguments, "limit", int))
        if command == "page_state":
            offset = arguments.get("offset", 0)
            if type(offset) is not int:
                raise ValueError("invalid_worker_argument")
            result = await driver.page_state(check=check,
                                             offset=offset,
                                             limit=_field(arguments, "limit", int),
                                             expected_digest=(
                                                 _field(arguments, "expected_digest", str, maximum=64)
                                                 if "expected_digest" in arguments else None))
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
                raise ControlError("private_site_out_of_scope")
            return result
        if command == "page_diagnostics":
            return await driver.page_diagnostics(
                check=check, after_seq=_field(arguments, "after_seq", int),
                limit=_field(arguments, "limit", int))
        if command == "record":
            from .web_recording import record_page
            return await record_page(self, driver, page_id, arguments, check=check)
        if command == "screenshot":
            await check()
            animations = arguments.get("animations", "disabled")
            caret = arguments.get("caret", "hide")
            if (type(animations) is not str or animations not in {"disabled", "allow"}
                    or type(caret) is not str or caret not in {"hide", "initial"}):
                raise ControlError("invalid_screenshot_bounds")
            from .web_privacy import password_rectangles, redact_pixels, same_css_mapping, full_page_size
            from flower_control.permissions import revision
            privacy_rects, privacy_dimensions = await password_rectangles(driver.page)
            full_page = arguments.get("full_page", False)
            capture_size = None
            if type(full_page) is not bool:
                raise ControlError("invalid_screenshot_bounds")
            if full_page:
                dimensions = await full_page_size(driver.page)
                await check()
                width, height = dimensions.get("width"), dimensions.get("height")
                if (type(width) is not int or type(height) is not int
                        or not 1 <= width <= 3840 or not 1 <= height <= 20000
                        or width * height > 16_000_000):
                    raise ControlError("screenshot_too_large")
                capture_size = (width, height)
            try:
                if full_page:
                    # Capture the bound document directly: Playwright's viewport
                    # preparation can alter scroll bars and CDP display scale.
                    session = None
                    try:
                        session = await asyncio.wait_for(driver.page.context.new_cdp_session(driver.page), timeout=3)
                        image = await asyncio.wait_for(session.send("Page.captureScreenshot", {
                            "format": "jpeg", "quality": 85, "captureBeyondViewport": True,
                            "fromSurface": True, "clip": {"x": 0, "y": 0, "width": width, "height": height, "scale": 1}}), timeout=7)
                        pixels = base64.b64decode(image["data"], validate=True)
                    except Exception as error:
                        raise ControlError("screenshot_timeout") from error
                    finally:
                        if session is not None:
                            try: await asyncio.wait_for(session.detach(), timeout=2)
                            except Exception: pass
                else:
                    pixels = await driver.page.screenshot(type="jpeg", quality=85,
                                                          full_page=False, timeout=10_000,
                                                          animations=animations, caret=caret)
            except PlaywrightTimeoutError as exc:
                if full_page:
                    raise ControlError("screenshot_timeout") from exc
                # Playwright's screenshot preparation can time out on a live
                # page even while its Chromium target still paints normally.
                # Capture the same target's visible viewport through CDP.
                await check()
                session = None
                try:
                    session = await asyncio.wait_for(
                        driver.page.context.new_cdp_session(driver.page), timeout=3)
                    capture = await asyncio.wait_for(session.send(
                        "Page.captureScreenshot", {"format": "jpeg", "quality": 85,
                                                   "captureBeyondViewport": False}),
                        timeout=7)
                    pixels = base64.b64decode(capture["data"], validate=True)
                except Exception as fallback_exc:
                    raise ControlError("screenshot_timeout") from fallback_exc
                finally:
                    if session is not None:
                        try:
                            await asyncio.wait_for(session.detach(), timeout=2)
                        except Exception:
                            pass
            await check()
            after_rects, after_dimensions = await password_rectangles(driver.page)
            if privacy_rects != after_rects or not same_css_mapping(privacy_dimensions, after_dimensions):
                raise ControlError("privacy_image_mapping_changed")
            # Full-page CDP capture is clipped to the explicitly bound size.
            # Chromium may update scroll-bar width; the password rectangles
            # and visible CSS origin still must match both sides of capture.
            pixels = redact_pixels(pixels, after_rects, after_dimensions, full_page=full_page, capture_size=capture_size)
            if len(pixels) > 4_000_000:
                raise ControlError("screenshot_too_large")
            return {"format": "jpeg", "bytes": len(pixels), "full_page": full_page,
                    "masked_password_fields": len(after_rects), "privacy_revision": revision(),
                    "base64": base64.b64encode(pixels).decode("ascii")}
        if command == "fill":
            return await driver.fill(_field(arguments, "reference", str, maximum=100),
                                     _field(arguments, "text", str, maximum=1_000_000),
                                     check=check)
        if command == "type":
            return await driver.type_text(_field(arguments, "reference", str, maximum=100),
                _field(arguments, "text", str, maximum=1_000_000),
                replace=arguments.get("replace", False),
                input_mode=arguments.get("input_mode", "insert_text"), check=check)
        if command == "editor_inspect":
            return await driver.editor_inspect(_field(arguments, "reference", str, maximum=100),
                                               check=check)
        if command == "editor_read":
            return await driver.editor_read(_field(arguments, "reference", str, maximum=100),
                                            offset=_field(arguments, "offset", int),
                                            limit=_field(arguments, "limit", int), check=check)
        if command == "editor_replace":
            if set(arguments) - {"page_id", "reference", "text", "expected_uri", "expected_version", "old_text"}:
                raise ValueError("invalid_worker_argument")
            return await driver.editor_replace(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "text", str, maximum=1_000_000),
                _field(arguments, "expected_uri", str, maximum=2048),
                _field(arguments, "expected_version", int), check=check,
                **({"old_text": _field(arguments, "old_text", str, maximum=64000)}
                   if "old_text" in arguments else {}))
        if command == "terminal_input":
            return await driver.terminal_input(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "text", str, maximum=64000),
                _field(arguments, "submit", bool), check=check)
        if command == "click":
            return await self._input_with_popups(page_id, lambda: driver.click(
                _field(arguments, "reference", str, maximum=100),
                check=check, wait_for=arguments.get("wait_for"),
                expect_chooser=arguments.get("expect_chooser", False),
                button=arguments.get("button", "left"),
                click_count=arguments.get("click_count", 1),
                modifiers=arguments.get("modifiers"),
                **({"read_page_state": arguments["read_page_state"]} if "read_page_state" in arguments else {})), check=check)
        if command == "hover":
            reference = _field(arguments, "reference", str, maximum=100)
            await driver._fresh(reference)
            await check()
            target = await driver._fresh(reference)
            mark_write("hover")
            await target.handle.hover(timeout=3000)
            await check()
            try:
                state = await driver.page_state(check=check)
            except ControlError:
                raise
            except Exception:
                state = {"state": "unavailable"}
            return {"state": "not_verified", "verification": "postcondition_required",
                    "page_state": state}
        if command == "press":
            return await self._input_with_popups(page_id, lambda: driver.press(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "key", str, maximum=80), check=check,
                wait_for=arguments.get("wait_for"),
                expect_chooser=arguments.get("expect_chooser", False),
                **({"read_page_state": arguments["read_page_state"]} if "read_page_state" in arguments else {})), check=check)
        if command == "select_option":
            return await driver.select_option(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "value", str, maximum=256), check=check)
        if command == "set_checked":
            return await driver.set_checked(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "checked", bool), check=check)
        if command == "drag":
            return await driver.drag(
                _field(arguments, "source_reference", str, maximum=100),
                _field(arguments, "target_reference", str, maximum=100), check=check)
        if command == "upload":
            return await driver.upload(
                _field(arguments, "reference", str, maximum=100),
                files=decode_files(arguments), check=check)
        if command == "download":
            return await self._download(driver, arguments, check=check)
        if command == "trace":
            return await self._trace(driver, page_id, arguments, check=check,recording_checker=recording_checker)
        if command in {"media_state", "play_media", "pause_media"}:
            return await driver.media(_field(arguments, "reference", str, maximum=100), command, check=check)
        if command in {"navigate", "navigate_paused"}:
            url = _field(arguments, "url", str, maximum=8192)
            if urlsplit(url).scheme not in ("http", "https"):
                raise ValueError("unsupported_navigation_scheme")
            await check()
            session = script_id = None
            try:
                if command == "navigate_paused":
                    session = await driver.page.context.new_cdp_session(driver.page)
                    await session.send("Page.enable")
                    script_id = (await session.send("Page.addScriptToEvaluateOnNewDocument", {"source": """
                        (() => {
                          const state = globalThis.__flowerPausedMedia = {allow:new WeakSet()};
                          document.addEventListener('play', event => {
                            if (event.target instanceof HTMLMediaElement && !state.allow.has(event.target))
                              event.target.pause();
                          }, true);
                        })();"""}))["identifier"]
                await check()
                mark_write(command)
                response = await driver.page.goto(url, wait_until="domcontentloaded", timeout=10_000)
                await check()
                if command == "navigate_paused":
                    for frame in list(driver.page.frames):
                        await check()
                        await frame.evaluate("() => { for (const e of document.querySelectorAll('video,audio')) e.pause(); }")
            finally:
                if session is not None:
                    try:
                        if script_id is not None:
                            await session.send("Page.removeScriptToEvaluateOnNewDocument", {"identifier": script_id})
                    finally:
                        await session.detach()
            await check()
            try:
                state = await driver.page_state(check=check)
            except ControlError:
                raise
            except Exception:
                state = {"state": "unavailable"}
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
                raise ControlError("private_site_out_of_scope")
            return {"url": driver.page.url, "http_status": response.status if response else None,
                    "state": "not_verified", "verification": "postcondition_required",
                    "page_state": state,
                    **({"media_paused_at_check": True} if command == "navigate_paused" else {})}
        if command in {"back", "forward", "reload"}:
            generation = driver.generation
            previous_url = driver.page.url
            history_available = None
            if command == "forward":
                # go_forward returns None for both no history and same-document
                # navigation. Read the mature CDP history API to distinguish them.
                cdp = await driver.page.context.new_cdp_session(driver.page)
                try:
                    history = await cdp.send("Page.getNavigationHistory")
                finally:
                    try:
                        await cdp.detach()
                    except Exception:
                        pass
                index, entries = history.get("currentIndex"), history.get("entries")
                if (type(index) is not int or type(entries) is not list or
                        not -1 <= index < len(entries)):
                    raise ControlError("history_state_unavailable")
                history_available = index + 1 < len(entries)
            await check()
            if driver.generation != generation or driver.page.url != previous_url:
                raise ControlError("page_changed")
            if history_available is False:
                state = await driver.page_state(check=check)
                if driver.generation != generation or driver.page.url != previous_url:
                    raise ControlError("page_changed")
                return {"url": driver.page.url, "previous_url": previous_url,
                        "http_status": None, "history_available": False,
                        "state": "not_verified", "verification": "no_forward_history",
                        "reason": "no_forward_history", "page_state": state}
            operation = getattr(driver.page, {"back": "go_back", "forward": "go_forward",
                                             "reload": "reload"}[command])
            mark_write("history")
            response = await operation(wait_until="domcontentloaded", timeout=10_000)
            await check()
            try:
                state = await driver.page_state(check=check)
            except ControlError:
                raise
            except Exception:
                state = {"state": "unavailable"}
            return {"url": driver.page.url, "previous_url": previous_url,
                    "http_status": response.status if response else None,
                    **({"history_available": True} if command == "forward" else {}),
                    "state": "not_verified", "verification": "postcondition_required",
                    "page_state": state}
        if command == "scroll":
            delta_y, delta_x = arguments.get("delta_y", 0), arguments.get("delta_x", 0)
            if (any(type(delta) is not int or not -2000 <= delta <= 2000 for delta in (delta_x, delta_y))
                    or not (delta_x or delta_y)):
                raise ValueError("invalid_scroll_delta")
            if "reference" in arguments:
                reference = _field(arguments, "reference", str, maximum=100)
                await driver._fresh(reference)
                await check()
                target = await driver._fresh(reference)
                mark_write("element_scroll")
                position = await target.handle.evaluate("""(element, delta) => {
                  const before = element.scrollTop;
                  const beforeX = element.scrollLeft;
                  element.scrollBy({top: delta.y, left: delta.x, behavior: 'instant'});
                  // Instant scrolling updates DOM offsets synchronously. A
                  // background/minimized tab may never receive an animation frame.
                  return {before, after: element.scrollTop, beforeX, afterX: element.scrollLeft};
                }""", {"x": delta_x, "y": delta_y})
                await check()
                try:
                    state = await driver.page_state(check=check)
                except ControlError:
                    raise
                except Exception:
                    state = {"state": "unavailable"}
                return {"scroll_y_before": position["before"],
                        "scroll_y_after": position["after"], "scroll_target": "element",
                        "scroll_x_before": position["beforeX"], "scroll_x_after": position["afterX"],
                        "state": "verified" if (position["before"] != position["after"] or
                                                position["beforeX"] != position["afterX"]) else "not_verified",
                        "verification": "observed_element_scroll_position", "page_state": state}
            generation = driver.generation
            url = driver.page.url
            await check()
            if driver.generation != generation or driver.page.url != url:
                raise ControlError("page_changed")
            mark_write("scroll")
            position = await driver.page.evaluate("""delta => {
              const root = document.scrollingElement;
              if (!root) return {before: 0, after: 0, beforeX: 0, afterX: 0};
              const before = root.scrollTop;
              const beforeX = root.scrollLeft;
              window.scrollBy({top: delta.y, left: delta.x, behavior: 'instant'});
              // Read actual offsets without depending on visible-frame delivery.
              return {before, after: root.scrollTop, beforeX, afterX: root.scrollLeft};
            }""", {"x": delta_x, "y": delta_y})
            await check()
            try:
                state = await driver.page_state(check=check)
            except ControlError:
                raise
            except Exception:
                state = {"state": "unavailable"}
            return {"scroll_y_before": position["before"], "scroll_y_after": position["after"],
                    "scroll_x_before": position["beforeX"], "scroll_x_after": position["afterX"],
                    "state": "verified" if (position["before"] != position["after"] or
                                            position["beforeX"] != position["afterX"]) else "not_verified",
                    "verification": "page_scroll_position" if delta_x else "page_vertical_scroll_position",
                    "page_state": state}
        raise ValueError("unknown_worker_command")

    async def _unsaved_close_pages(self):
        """Browser.close skips beforeunload; hidden instances must fail closed."""
        pending = []
        deadline = asyncio.get_running_loop().time() + 4
        for key, driver in self.pages.items():
            if driver.page.is_closed():
                continue
            session = None
            try:
                session = await driver.page.context.new_cdp_session(driver.page)
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise ControlError("close_preflight_unavailable")
                async with asyncio.timeout(min(1, remaining)):
                    contexts = {}
                    def context_created(event):
                        context = event.get("context", {})
                        auxiliary = context.get("auxData", {})
                        if auxiliary.get("isDefault") is True and type(context.get("id")) is int:
                            contexts[auxiliary.get("frameId")] = context["id"]
                    session.on("Runtime.executionContextCreated", context_created)
                    await session.send("Runtime.enable")
                    # OOPIF or a changing document may not be represented on
                    # this exact target's CDP session. Incomplete coverage keeps
                    # the whole instance, rather than assuming other frames clean.
                    if len(contexts) < len(driver.page.frames) or not contexts:
                        raise ControlError("close_preflight_unavailable")
                    for context_id in contexts.values():
                        remote = await session.send("Runtime.evaluate", {"expression": "window", "contextId": context_id,
                            "objectGroup": "flower-close-preflight"})
                        object_id = remote.get("result", {}).get("objectId")
                        if not object_id:
                            raise ControlError("close_preflight_unavailable")
                        listeners = await session.send("DOMDebugger.getEventListeners", {"objectId": object_id})
                        if any(row.get("type") == "beforeunload" for row in listeners.get("listeners", [])):
                            pending.append({"page_id": key, "reason": "unsaved_confirmation_requires_visible_browser"})
                            break
            except (PlaywrightError, AttributeError, KeyError, ControlError, TimeoutError):
                pending.append({"page_id": key, "reason": "close_preflight_unavailable"})
            finally:
                if session is not None:
                    try:
                        await session.send("Runtime.releaseObjectGroup", {"objectGroup": "flower-close-preflight"})
                        await session.detach()
                    except PlaywrightError:
                        pass
            if pending:
                break
        return pending

    async def _normal_window_close(self, *, check):
        if self.browser_policy_identity is None or self.browser_process_identity is None:
            return False
        from .web_session import _taskbar_browser_windows
        import win32gui
        import win32con
        import win32process
        pid, _ = self.browser_policy_identity
        windows = _taskbar_browser_windows(pid)
        if not windows:
            return False
        for hwnd in windows:
            if hwnd in self.window_close_requested:
                continue
            await check()
            if (process_identity(pid) != self.browser_process_identity
                    or win32process.GetWindowThreadProcessId(hwnd)[1] != pid):
                raise ControlError("browser_close_identity_changed")
            mark_write("close_browser")
            self.instance_close_requested = True
            self.window_close_requested.add(hwnd)
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            # Stop the suffix as soon as an exact document needs confirmation.
            for _ in range(10):
                if any(driver.pending_dialog is not None for driver in self.pages.values()):
                    return True
                if not self.browser.is_connected() or not win32gui.IsWindow(hwnd):
                    break
                await asyncio.sleep(.05)
            return True  # A later explicit lifecycle call may close a fresh suffix.
        return bool(self.window_close_requested)

    async def _close_browser(self, *, check, preserve_tabs=False, lease_guard=None):
        if not self.shared_browser and (self.profile_kind in {"ai", "luohua"} or preserve_tabs):
            # Chromium saves the session during instance exit. Removing its
            # historical tabs before Browser.close instead saves an empty one.
            await self._list_pages()
            pending = [{"page_id": key, "dialog": driver.dialog_snapshot()}
                       for key, driver in self.pages.items() if driver.pending_dialog is not None]
            if pending:
                return {"requested": False, "state": "close_pending", "closed_pages": [],
                        "pending_pages": pending, "instance_close_requested": self.instance_close_requested}
            await check()
            if await self._normal_window_close(check=check):
                return {"requested": True, "closed_pages": [], "instance_close_requested": True,
                        "close_method": "normal_window_close"}
            if not self.instance_close_requested and self.browser.is_connected():
                await check()
                blocked = await self._unsaved_close_pages()
                await check()
                if blocked:
                    self.close_wait_reason = blocked[0]["reason"]
                    return {"requested": False, "state": "close_pending", "closed_pages": [],
                            "pending_pages": blocked, "instance_close_requested": False,
                            "requires_user_takeover": True}
                self.close_wait_reason = None
                session = await self.browser.new_browser_cdp_session()
                await check()
                mark_write("close_browser")
                self.instance_close_requested = True
                await session.send("Browser.close")
            return {"requested": self.instance_close_requested, "closed_pages": [],
                    "instance_close_requested": self.instance_close_requested}
        closed_pages = []
        page_id, driver = None, None
        try:
            await self._list_pages()
            unresolved = []
            if self.shared_browser:
                # Close is authorized for this exact borrower, including its
                # private-scope pages after revocation. This does not grant
                # read or recovery access to another scope or borrower.
                await self._assert_pending_browser(check=check)
                rows = self._pending_page_rows(lease_guard, close_cleanup=True)
                for row in rows:
                    recovered = await self._recover_pending_page(lease_guard, row["id"], check=check, close_cleanup=True)
                    if recovered["state"] not in {"page_recovered", "target_not_live"}:
                        unresolved.append({"pending_id": row["id"], "state": recovered["state"]})
            # Instance close has an explicit lifecycle authorization for all
            # tabs. Each page gets normal beforeunload first; no suffix is
            # closed while one exact confirmation is pending.
            for page_id in list(self.pages):
                if self.shared_browser and page_id not in self.owned_pages:
                    continue
                if self.shared_browser and page_id in self.user_pages:
                    # This tab belongs to the person, even while the chat may
                    # use it. Closing the chat never closes that tab.
                    continue
                driver = self.pages.get(page_id)
                await check()
                if driver is None or driver.page.is_closed():
                    continue
                if driver.pending_dialog is not None:
                    return {"requested": False, "state": "close_pending",
                            "closed_pages": closed_pages,
                            "pending_pages": [{"page_id": page_id, "dialog": driver.dialog_snapshot()}]}
                target = self.page_targets.get(page_id) if self.shared_browser else None
                result = await self._normal_close_page(page_id, driver, check=check)
                if not result["closed"]:
                    return {"requested": False, "state": "close_pending",
                            "closed_pages": closed_pages, "pending_pages": [result]}
                closed_pages.append(page_id)
                if self.shared_browser:
                    action, resource = self._pending_page_context(lease_guard)
                    rows = [row for row in self._pending_page_rows(lease_guard, close_cleanup=True)
                            if target and row["target"] == target and row["page_id"] == page_id]
                    if rows:
                        await self._assert_pending_browser(check=check)
                        targets = (await self.download_session.send("Target.getTargets")).get("targetInfos", [])
                        await check()
                        if len(targets) > 1024 or any(item.get("targetId") == target for item in targets):
                            raise ControlError("closed_target_absence_unverified")
                        await self._assert_pending_browser(check=check)
                    with lease_guard.store.transaction() as db:
                        for row in rows:
                            changed = db.execute("UPDATE web_created_targets SET state='closed' WHERE id=? AND task=? AND resource=? AND browser_process=? AND page_id=? AND target=? AND state!='closed'",
                                (row["id"], action["task"], resource, self.browser_process_identity, page_id, target)).rowcount
                            if changed != 1:
                                raise ControlError("pending_page_record_unavailable")
                            db.execute("INSERT INTO web_target_close_receipts(pending,action,resource,browser_process,target,created) VALUES (?,?,?,?,?,?)",
                                (row["id"], lease_guard.action, resource, self.browser_process_identity, target, lease_guard.store.clock()))
            if self.shared_browser:
                if unresolved:
                    return {"requested": False, "state": "close_pending", "reason": "pending_page_unresolved",
                            "closed_pages": closed_pages, "pending_pages": unresolved, "browser_closed": False}
                manual_targets = [self.page_targets.get(key) for key in self.user_pages]
                action, resource = self._pending_page_context(lease_guard)
                with lease_guard.store.transaction() as db:
                    unknown = [row for row in db.execute(
                        "SELECT id,resources FROM actions WHERE task=? AND state='outcome_uncertain'", (action["task"],))
                        if resource in json.loads(row["resources"])]
                    for target in manual_targets:
                        blocked = False
                        for old in unknown:
                            bound = db.execute("SELECT browser_process,target FROM web_action_page_targets WHERE action=?",
                                               (old["id"],)).fetchone()
                            if bound is None:
                                bound = db.execute("SELECT browser_process,target FROM web_creation_recovery_proofs WHERE action=?",
                                                   (old["id"],)).fetchone()
                            if bound is None or (bound["browser_process"] == self.browser_process_identity and bound["target"] == target):
                                blocked = True
                                break
                        if not blocked:
                            db.execute("DELETE FROM web_user_tab_claims WHERE browser_process=? AND target=? AND task=?",
                                       (self.browser_process_identity, target, action["task"]))
                for user_page in tuple(self.user_pages):
                    page = self.pages.pop(user_page, None)
                    if page is not None:
                        await page.dispose()
                    self.owned_pages.discard(user_page)
                    self.user_pages.discard(user_page)
                    self.page_targets.pop(user_page, None)
                return {"requested": True, "closed_pages": closed_pages,
                        "browser_closed": False, "state": "borrower_pages_closed"}
            if self.browser.is_connected():
                await check()
                session = await self.browser.new_browser_cdp_session()
                await check()
                await self._list_pages()
                await check()
                remaining = [key for key, exact in self.pages.items() if not exact.page.is_closed()]
                if remaining:
                    return {"requested": False, "state": "close_pending", "reason": "new_pages_detected",
                            "closed_pages": closed_pages,
                            "pending_pages": [{"page_id": key, "state": "not_verified",
                                               "dialog": (self.pages[key].dialog_snapshot()
                                                          if self.pages[key].pending_dialog is not None else None)}
                                              for key in remaining]}
                mark_write("close_browser")
                self.instance_close_requested = True
                await session.send("Browser.close")
            return {"requested": True, "closed_pages": closed_pages}
        except ControlError as error:
            if error.code not in CLOSE_STOP_CODES:
                raise
            # A check after the close request can fail while the close itself
            # already completed. Preserve that exact observed prefix.
            if page_id is not None and driver is not None and driver.page.is_closed():
                if page_id not in closed_pages:
                    closed_pages.append(page_id)
                await driver.dispose()
                self.pages.pop(page_id, None)
                self.owned_pages.discard(page_id)
                self.page_windows.pop(page_id, None)
                self.hidden_pages.discard(page_id)
                self.hidden_unbound.discard(page_id)
            return {"requested": False, "state": "close_stopped", "reason": error.code,
                    "closed_pages": closed_pages, "pending_pages": []}

    async def _normal_close_page(self, page_id, driver, *, check):
        generation = driver.generation
        url = driver.page.url
        await check()
        if driver.generation != generation or driver.page.url != url:
            raise ControlError("page_changed")
        mark_write("close_page")
        if page_id not in self.page_close_targets and len(self.page_close_targets) >= 128:
            self.page_close_targets.pop(next(iter(self.page_close_targets)))
        self.page_close_targets[page_id] = driver.page
        self.page_close_requested.add(page_id)
        await asyncio.wait_for(driver.page.close(run_before_unload=True), timeout=5)
        deadline = asyncio.get_running_loop().time() + 0.5
        while not driver.page.is_closed() and driver.pending_dialog is None:
            await check()
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(0.02)
        await check()
        closed = driver.page.is_closed()
        if closed:
            await driver.dispose()
            self.pages.pop(page_id, None)
            self.owned_pages.discard(page_id)
            self.page_targets.pop(page_id, None)
            self.page_windows.pop(page_id, None)
            self.hidden_pages.discard(page_id)
            self.hidden_unbound.discard(page_id)
            self.page_marks.pop(page_id, None)
            self.popup_provenance.pop(page_id, None)
        return {"page_id": page_id, "closed": closed, "dialog": driver.dialog_snapshot(),
                "state": "verified" if closed else "not_verified"}

    async def _download(self, driver: PageDriver, arguments: dict, *, check):
        async with AsyncExitStack() as stack:
            capture = None
            if self.download_session is not None:
                capture = await stack.enter_async_context(_CdpDownloadCapture(
                    self.download_session, self.download_directory, driver.page))
            return await self._download_captured(driver, arguments, check=check, capture=capture)

    async def _download_captured(self, driver: PageDriver, arguments: dict, *, check, capture):
        page = driver.page
        async def publish_check():
            await check()
            if (self.pages.get(arguments.get("page_id")) is not driver
                    or driver.page is not page or page.is_closed()):
                raise ControlError("page_changed")
            self.verify_private_request(driver, "download", arguments)
        reference = _field(arguments, "reference", str, maximum=100)
        output_path = arguments.get("output_path")
        if output_path is not None and type(output_path) is not str:
            raise ValueError("invalid_worker_argument")
        artifact_path(output_path, suffix="", suggested="download")
        await driver._fresh(reference)
        await check()
        ref = await driver._fresh(reference)
        try:
            if capture is not None:
                capture.armed = True
                mark_write("download_click")
                await ref.handle.click(timeout=3000)
                download = await asyncio.wait_for(capture.started, timeout=10)
            else:
                async with driver.page.expect_download(timeout=10000) as info:
                    mark_write("download_click")
                    await ref.handle.click(timeout=3000)
                download = await info.value
        except (PlaywrightTimeoutError, asyncio.TimeoutError):
            await check()
            return {"state": "not_verified", "verification": "download_event_timeout",
                    "business_result_verified": False}
        await check()
        from flower_control.data_paths import runtime_temp_root
        with tempfile.TemporaryDirectory(prefix="flower-web-download-", dir=runtime_temp_root()) as directory:
            staged = Path(directory) / "download"
            try:
                await asyncio.wait_for(download.save_as(staged), timeout=30)
            except asyncio.TimeoutError:
                await check()
                return {"state": "not_verified", "verification": "download_incomplete",
                        "business_result_verified": False}
            await check()
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
                raise ControlError("private_site_out_of_scope")
            artifact = await checked_publication(persist_web_download, staged, output_path,
                                    suggested=download.suggested_filename, check=publish_check)
        return {"state": "verified", "verification": "download_artifact_saved",
                "artifact": artifact, "suggested_filename": download.suggested_filename,
                "source_url_without_query": _safe_download_source(download.url),
                "file_type_hint": mimetypes.guess_type(download.suggested_filename)[0],
                "business_result_verified": False}

    async def _trace(self, driver: PageDriver, page_id: str, arguments: dict, *, check,recording_checker=None):
        mode = _field(arguments, "mode", str, maximum=20)
        output_path = arguments.get("output_path")
        if output_path is not None and type(output_path) is not str:
            raise ValueError("invalid_worker_argument")
        if mode == "bundle":
            artifact_path(output_path, suffix=".zip", suggested="page-diagnostic")
            before_url = driver.page.url
            page = driver.page
            async def publish_check():
                await check()
                if (self.pages.get(page_id) is not driver or driver.page is not page
                        or page.is_closed() or page.url != before_url):
                    raise ControlError("page_changed")
                self.verify_private_request(driver, "trace", arguments)
            screenshot = await self.execute("screenshot", {"page_id": page_id}, check=check)
            state = await driver.page_state(check=check, limit=16000)
            latest = driver._next_diagnostic_seq - 1
            diagnostics = await driver.page_diagnostics(
                check=check, after_seq=max(0, latest - 50), limit=50)
            if before_url != driver.page.url:
                raise ControlError("page_changed")
            manifest = {"format": "flower-page-diagnostic-v1", "scope": "target_page_only",
                        "captured_utc": datetime.now(timezone.utc).isoformat(),
                        "page_id": page_id, "page_state": state,
                        "diagnostics": diagnostics, "diagnostics_recent_only": latest > 50,
                        "screenshot": "screenshot.jpg"}
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
                archive.writestr("screenshot.jpg", base64.b64decode(screenshot["base64"]))
            await check()
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
                raise ControlError("private_site_out_of_scope")
            artifact = await checked_publication(persist_bytes, buffer.getvalue(), output_path,
                                     suffix=".zip", suggested="page-diagnostic", check=publish_check)
            return {"state": "verified", "verification": "page_diagnostic_saved",
                    "format": "flower-page-diagnostic-v1", "scope": "target_page_only",
                    "artifact": artifact}
        # Continuous diagnostics consume only the existing redacted cache
        # stream. Raw Playwright DOM/network/pixel archives remain unavailable.
        if mode in {"start", "stop"}:
            from flower_control.permissions import revision
            kind=arguments.get('kind','trace')
            if kind not in {'trace','network','events'} or set(arguments)-{'page_id','mode','kind','run_id','output_path'}:
                raise ControlError('invalid_diagnostic_request')
            await check()
            if mode=='start':
                if arguments.get('run_id') is not None or output_path is not None:raise ControlError('invalid_diagnostic_request')
                if recording_checker is None:raise ControlError('diagnostic_worker_authority_required')
                result=self.diagnostic_recordings.start(kind,revision(),check=recording_checker)
                try:
                    for context in (() if self.shared_browser else self.browser.contexts):
                        if context not in self.diagnostic_page_listeners:
                            listener=self._track_diagnostic_page
                            context.on('page',listener);self.diagnostic_page_listeners[context]=listener
                    await self._list_pages();await check()
                except BaseException:
                    self.diagnostic_recordings.active.pop(kind,None);self._stop_diagnostic_listeners();raise
                return dict(state='verified',verification='diagnostic_started',**result)
            identifier=_field(arguments,'run_id',str,maximum=64)
            try:run=self.diagnostic_recordings.get(kind,identifier,revision())
            except BaseException:self._stop_diagnostic_listeners();raise
            data,suffix=self.diagnostic_recordings.payload(run)
            artifact_path(output_path,suffix=suffix,suggested='redacted-diagnostic')
            await check()
            self.diagnostic_recordings.get(kind,identifier,revision())
            async def export_check():
                await check()
                self.diagnostic_recordings.get(kind,identifier,revision())
            artifact=await checked_publication(persist_bytes,data,output_path,suffix=suffix,
                suggested='redacted-diagnostic',check=export_check)
            self.diagnostic_recordings.active.pop(kind);self._stop_diagnostic_listeners()
            return dict(state='verified',verification='diagnostic_saved',kind=kind,run_id=identifier,
                format='har-1.2-redacted' if kind=='network' else 'flower-redacted-diagnostic-v1',
                scope='session_admitted_pages',entries=len(run['entries']),truncated=run['truncated'],
                content_captured=False,raw_playwright_trace=False,artifact=artifact)
        if self.profile_kind != "temporary":
            raise ControlError("trace_requires_temporary_profile")
        context = driver.page.context
        if mode == "start":
            if self.trace_page_id is not None:
                raise ControlError("trace_already_running")
            if any(page is not driver.page and page.url != "about:blank"
                   for page in context.pages):
                raise ControlError("trace_requires_isolated_page")

            def on_page(page):
                if page is not driver.page:
                    self.trace_violation = True

            context.on("page", on_page)
            try:
                await context.tracing.start(screenshots=True, snapshots=True, sources=False)
            except BaseException:
                context.remove_listener("page", on_page)
                raise
            self.trace_page_id = page_id
            self.trace_context = context
            self.trace_listener = on_page
            self.trace_violation = False
            return {"state": "verified", "verification": "trace_started",
                    "scope": "isolated_temporary_context"}
        if mode == "stop":
            artifact_path(output_path, suffix=".zip", suggested="playwright-trace")
            if self.trace_page_id != page_id or self.trace_context is not context:
                raise ControlError("trace_not_running_for_page")
            context.remove_listener("page", self.trace_listener)
            self.trace_page_id = None
            self.trace_context = None
            self.trace_listener = None
            violated = self.trace_violation or any(
                page is not driver.page and page.url != "about:blank" for page in context.pages)
            self.trace_violation = False
            if violated:
                await context.tracing.stop()
                raise ControlError("trace_scope_changed_discarded")
            from flower_control.data_paths import runtime_temp_root
            with tempfile.TemporaryDirectory(prefix="flower-web-trace-", dir=runtime_temp_root()) as directory:
                staged = Path(directory) / "trace.zip"
                await context.tracing.stop(path=staged)
                await check()
                artifact = await checked_publication(persist_file, staged, output_path, suffix=".zip",
                                        suggested="playwright-trace", check=check)
            return {"state": "verified", "verification": "trace_artifact_saved",
                    "format": "playwright-trace", "scope": "isolated_temporary_context",
                    "artifact": artifact}
        raise ValueError("invalid_trace_mode")

    async def close(self) -> None:
        for selection, _, driver, original, _, _ in list(self.file_selections.values()):
            await selection.close()
            await self._dispose_selection_handle(driver, original)
        self.file_selections.clear()
        self.release_popup_watches()
        self.diagnostic_recordings.active.clear();self._stop_diagnostic_listeners()
        if self.focus_defaults is not None:
            await self.focus_defaults.close()
        if self.download_session is not None:
            try:
                await self.download_session.detach()
            except PlaywrightError:
                pass
        if self.trace_context is not None:
            try:
                await self.trace_context.tracing.stop()
            except Exception:
                pass
        for driver in self.pages.values():
            try:
                await driver.dispose()
            except Exception:
                pass
        self.pages.clear()
        self.page_windows.clear()
        try:
            await self.browser.close()
        except Exception:
            pass


def _read_request() -> bytes:
    return sys.stdin.buffer.readline(MAX_MESSAGE + 1)


def _write_response(response: dict) -> None:
    # JSON can represent DOM lone surrogates; raw UTF-8 cannot. Preserve them
    # as JSON escapes without changing ordinary Unicode bytes or size checks.
    encoded = (json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        'utf-8',errors='backslashreplace')
    if len(encoded) > MAX_MESSAGE:
        encoded = b'{"id":null,"ok":false,"error":"worker_response_too_large"}\n'
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


async def _discard_failed_upload_begin(runtime, command, result):
    if command == "local_upload_begin" and type(result) is dict:
        identifier = result.get("selection_id")
        item = runtime.file_selections.get(identifier)
        if item is not None:
            # Keep the exact item reachable if cleanup fails; popping first
            # would lose the only owner of a still-live picker or snapshot.
            await item[0].close()
            await _Runtime._dispose_selection_handle(item[2], item[3])
            runtime.file_selections.pop(identifier, None)
            getattr(runtime, "file_selection_origins", {}).pop(identifier, None)


async def _verify_response_or_cleanup(runtime, command, arguments, result):
    try:
        runtime.verify_private_response(command, arguments)
    except BaseException:
        await _discard_failed_upload_begin(runtime, command, result)
        raise


async def _serve(endpoint: str, *, guarded: bool = False,
                 profile_kind: str = "temporary", shared_browser=False, download_directory=None, shared_headless=True) -> None:
    from .web_upload_recovery import recover_dead_leases
    await asyncio.to_thread(recover_dead_leases)
    async with async_playwright() as playwright, AsyncExitStack() as stack:
        from flower_control.data_paths import runtime_temp_root
        artifacts_dir = stack.enter_context(tempfile.TemporaryDirectory(prefix="flower-web-worker-artifacts-", dir=runtime_temp_root()))
        browser = await playwright.chromium.connect_over_cdp(
            endpoint, timeout=10_000, no_defaults=True, artifacts_dir=artifacts_dir)
        runtime = _Runtime(browser, profile_kind=profile_kind, shared_browser=shared_browser, shared_headless=shared_headless)
        try:
            if shared_browser:
                from flower_control.profile_registry import direct_path
                fixed = direct_path(Path(download_directory))
                if not fixed.is_absolute() or not fixed.is_dir():
                    raise ControlError("shared_download_directory_unavailable")
                artifacts_dir = str(fixed)
            await runtime.start_browser_defaults(artifacts_dir)
            _write_lifecycle("worker_ready")
            while True:
                line = await asyncio.to_thread(_read_request)
                if not line:
                    _write_lifecycle("stdin_eof")
                    break  # parent EOF; no reconnect or browser relaunch
                if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
                    _write_lifecycle("invalid_frame")
                    break
                request_id = None
                effects = WebEffects()
                effect_token = current_effects.set(effects)
                admission_token = current_write_admission.set(None)
                try:
                    request = json.loads(line)
                    if not isinstance(request, dict):
                        raise ValueError("invalid_worker_request")
                    request_id = request.get("id")
                    command = request.get("command")
                    arguments = request.get("arguments")
                    if type(request_id) is not int or request_id < 1 or command not in COMMANDS or not isinstance(arguments, dict):
                        raise ValueError("invalid_worker_request")
                    envelope = request.get("execution")
                    # Exact owner shutdown has already passed the public MCP
                    # lifecycle gate and may not have an action permit.
                    if guarded and command != "ping" and envelope is None:
                        raise ControlError("worker_permit_required")
                    if shared_browser and envelope is not None:
                        from .web_shared_profile import SharedWorkerCallGuard
                        guard = SharedWorkerCallGuard(envelope, command, arguments, runtime.profile_resource)
                    else:
                        guard = WorkerCallGuard(envelope, command, arguments) if envelope is not None else None
                    if guard is not None:
                        current_write_admission.set(guard.admission if shared_browser else lambda: guard.store.worker_write_admission(
                            guard.action, guard.token, guard.fingerprint))
                    result = await runtime.execute(command, arguments,
                                                   check=guard.check if guard else _noop_check, lease_guard=guard)
                    try:
                        await runtime.verify_hidden_window(command, arguments, check=guard.check if guard else _noop_check)
                    except ControlError as error:
                        if error.code != "hidden_popup_attention_required" or not isinstance(result, dict):
                            await _discard_failed_upload_begin(runtime, command, result)
                            raise
                        # Keep the already-dispatched action and its popup
                        # correlation ID. The next source-page action remains
                        # fenced until the exact popup is handled or closed.
                        result.update(background_attention_required=True,
                            background_attention_reason="popup_may_be_visible",
                            next_action="inspect_exact_popup_before_continuing")
                    except BaseException:
                        await _discard_failed_upload_begin(runtime, command, result)
                        raise
                    await _verify_response_or_cleanup(runtime, command, arguments, result)
                    if guard is not None and effects.dispatched is True:
                        try:
                            guard.store.record_worker_completion(guard.action, guard.token, guard.fingerprint)
                        except (sqlite3.Error, OSError):
                            # An optional recovery fact must not turn a received
                            # successful business reply into an unknown action.
                            # Without this fact a later lost reply stays fenced.
                            pass
                    _write_response({"id": request_id, "ok": True, "result": result,
                                     "dispatched": effects.dispatched, "stage": effects.stage,
                                     "page_registry": runtime.registry_snapshot()})
                except ControlError as exc:
                    _write_response({"id": request_id, "ok": False, "error": f"control:{exc.code}", "dispatched": effects.dispatched, "stage": effects.stage,
                        "diagnostics": safe_failure_facts(getattr(exc, "web_diagnostics", None)),
                        "page_registry": runtime.registry_snapshot()})
                except ValueError as exc:
                    # Values can originate in native/parser messages; never
                    # return arbitrary page content, paths or URLs as errors.
                    code = str(exc)
                    if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code):
                        code = "invalid_worker_argument"
                    _write_response({"id": request_id, "ok": False, "error": code, "dispatched": effects.dispatched, "stage": effects.stage})
                except Exception as exc:
                    _write_response({"id": request_id, "ok": False, "error": "worker_command_failed", "dispatched": effects.dispatched, "stage": effects.stage,
                        "diagnostics": exception_facts(exc, "worker_execute")})
                finally:
                    current_write_admission.reset(admission_token)
                    current_effects.reset(effect_token)
        finally:
            _write_lifecycle("runtime_cleanup_started")
            await runtime.close()
            _write_lifecycle("runtime_cleanup_finished")


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--flower-file-picker":
        from .web_file_picker import choose_file
        lifetime = WorkerLifetime(sys.argv[3], sys.argv[4])
        code = 1
        try:
            locked = choose_file(sys.argv[2])
            if locked is None:
                print(json.dumps({"selected": None, "identity": None}), flush=True)
            else:
                try:
                    print(json.dumps({"selected": locked.path, "identity": locked.identity}, ensure_ascii=True), flush=True)
                    sys.stdin.buffer.read(1)  # Parent holds its own matching lock before releasing this one.
                finally:
                    locked.close()
            code = 0
        except Exception:
            pass
        lifetime.exit(code)
        return code
    if len(sys.argv) < 2:
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--stop-event", required=True)
    parser.add_argument("--guarded", action="store_true")
    parser.add_argument("--profile-kind", choices=("temporary", "ai", "luohua"),
                        default="temporary")
    parser.add_argument("--shared-browser", action="store_true")
    parser.add_argument("--download-directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--shared-headless", dest="shared_headless", action="store_true", default=True)
    mode.add_argument("--shared-headed", dest="shared_headless", action="store_false")
    args = parser.parse_args()
    if not args.endpoint.startswith("ws://127.0.0.1:"):
        return 2
    if args.shared_browser and (not args.guarded or args.profile_kind == "temporary" or not args.download_directory):
        return 2
    lifetime = WorkerLifetime(args.owner, args.stop_event, diagnostic=_write_lifecycle)
    code = 0
    try:
        asyncio.run(_serve(args.endpoint, guarded=args.guarded,
                           profile_kind=args.profile_kind, shared_browser=args.shared_browser,
                           download_directory=args.download_directory, shared_headless=args.shared_headless))
    except Exception as error:
        _write_lifecycle("unhandled_exception", error=error)
        code = 1
    lifetime.exit(code)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
