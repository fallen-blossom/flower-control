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
import mimetypes
import os
import sys
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlunsplit
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import TimeoutError as PlaywrightTimeoutError, async_playwright

from flower_control.control.state import ControlError
from flower_control.authorization.luohua_policy import allowed_url, site_matches_url
from flower_control.control.native import process_identity
from flower_control.control.worker_call import WorkerCallGuard
from flower_control.drivers.web_page import PageDriver
from .web_effects import CLOSE_STOP_CODES, WebEffects, current_effects, current_write_admission, mark_write
from .web_discovery import source_origin
from flower_control.drivers.web_artifacts import artifact_path, persist_bytes, persist_file
from flower_control.drivers.worker_lifetime import WorkerLifetime


from flower_control.drivers.web_session import WEB_WORKER_PHASES, WEB_EXCEPTION_TYPES


MAX_MESSAGE = 16_000_000
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


COMMANDS = frozenset({"ping", "close_browser", "new_page", "list_pages", "observe", "read_text", "page_state",
                      "page_diagnostics", "screenshot",
                      "fill", "type", "click", "hover", "press", "select_option", "set_checked", "navigate",
                      "back", "forward", "reload", "close_page", "scroll", "dispose_page", "editor_inspect",
                      "editor_read", "editor_replace", "terminal_input", "drag", "upload",
                      "download", "trace", "dialog_state", "dialog_action", "wait_condition", "wait_page",
                      "wait_navigation", "chooser_state", "chooser_upload", "chooser_cancel",
                      "workflow_bind", "workflow_check", "result_probe"})


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


class _Runtime:
    def __init__(self, browser, *, profile_kind: str = "temporary") -> None:
        self.browser = browser
        self.profile_kind = profile_kind
        self.pages: dict[str, PageDriver] = {}
        self.owned_pages: set[str] = set()
        self.popup_provenance: dict[str, dict] = {}
        self.trace_page_id: str | None = None
        self.trace_context = None
        self.trace_violation = False
        self.trace_listener = None
    def _page(self, page_id: str) -> PageDriver:
        driver = self.pages.get(page_id)
        if driver is None or driver.page.is_closed():
            raise ControlError("target_closed")
        return driver

    def _driver(self, page) -> PageDriver:
        return PageDriver(page, event_filter=allowed_url if self.profile_kind == "luohua" else None)

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
        for context in self.browser.contexts:
            for page in context.pages:
                if page.is_closed() or any(driver.page is page for driver in self.pages.values()):
                    continue
                self.pages[uuid.uuid4().hex] = self._driver(page)
        if self.profile_kind == "luohua":
            return [page_id for page_id, driver in self.pages.items()
                    if allowed_url(driver.page.url, blank=True)
                    and (site is None or site_matches_url(driver.page.url, site))]
        return list(self.pages)

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

    async def _input_with_popups(self, source_id, operation, *, check):
        before = set(await self._list_pages())
        source = self._page(source_id)
        generation = source.generation
        dispatch_id = uuid.uuid4().hex
        captured = []

        def on_popup(page):
            if page.is_closed():
                return
            page_id = next((key for key, driver in self.pages.items() if driver.page is page), None)
            if page_id is None:
                page_id = uuid.uuid4().hex
                self.pages[page_id] = self._driver(page)
            captured.append(page_id)
            provenance = {"source_page_id": source_id, "source_generation": generation,
                          "dispatch_id": dispatch_id, "association": "popup_event_during_action"}
            self.popup_provenance[page_id] = provenance
            if source_id in self.owned_pages and source.generation == generation:
                self.owned_pages.add(page_id)

        source.page.on("popup", on_popup)
        try:
            result = await operation()
            await check()
            current = await self._list_pages()
            await check()
            result["opened_pages"] = [page_id for page_id in captured if page_id in current]
            result["observed_new_pages"] = [page_id for page_id in current if page_id not in before]
            result["popup_dispatch_id"] = dispatch_id
            return result
        finally:
            source.page.remove_listener("popup", on_popup)

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
            entries = []
            for page_id in current:
                driver = self.pages[page_id]
                provenance = self.popup_provenance.get(page_id)
                if page_id in previous or (expected_url is not None and driver.page.url != expected_url):
                    continue
                if dispatch_id is not None and (not provenance or provenance["dispatch_id"] != dispatch_id):
                    continue
                entries.append({"page_id": page_id, "url": driver.page.url,
                                "owned": page_id in self.owned_pages, "provenance": provenance})
            await check()
            if entries:
                return {"state": "verified", "observed": True, "pages": entries,
                        "business_result_verified": False}
            if asyncio.get_running_loop().time() >= deadline:
                return {"state": "not_verified", "observed": False, "reason": "condition_timeout",
                        "business_result_verified": False}
            await asyncio.sleep(0.05)

    def verify_private_response(self, command: str, arguments: dict) -> None:
        if self.profile_kind != "luohua" or command in {"ping", "close_browser", "new_page", "list_pages", "wait_page", "close_page"}:
            return
        driver = self._page(_field(arguments, "page_id", str, maximum=64))
        if not allowed_url(driver.page.url):
            raise ControlError("private_site_out_of_scope")

    def verify_private_request(self, driver: PageDriver, command: str,
                               arguments: dict) -> None:
        if self.profile_kind != "luohua":
            return
        if not allowed_url(driver.page.url, blank=command == "navigate"):
            raise ControlError("private_site_out_of_scope")
        if command == "navigate" and not allowed_url(arguments.get("url")):
            raise ControlError("private_site_out_of_scope")

    async def execute(self, command: str, arguments: dict, *, check=_noop_check) -> object:
        await check()
        if command == "ping":
            if not self.browser.contexts:
                raise RuntimeError("browser_context_missing")
            return {"ready": True, "process": process_identity(), "pid": os.getpid(), "parent_pid": os.getppid()}
        if command == "close_browser":
            if self.profile_kind not in ("temporary", "ai", "luohua") or arguments:
                raise ControlError("browser_close_unavailable")
            return await self._close_browser(check=check)
        if command == "new_page":
            if self.trace_page_id is not None:
                raise ControlError("trace_target_exclusive")
            if not self.browser.contexts:
                raise RuntimeError("browser_context_missing")
            mark_write("new_page")
            page = await self.browser.contexts[0].new_page()
            page_id = uuid.uuid4().hex
            self.pages[page_id] = self._driver(page)
            self.owned_pages.add(page_id)
            await check()
            return {"page_id": page_id}
        if command == "wait_page":
            return await self._wait_page(arguments, check=check)
        if command == "list_pages":
            site = (_field(arguments, "site", str, maximum=253)
                    if self.profile_kind == "luohua" and "site" in arguments else None)
            include_metadata = arguments.get("include_metadata", False)
            if type(include_metadata) is not bool:
                raise ControlError("invalid_page_metadata_request")
            if include_metadata:
                return await self._page_metadata(arguments, site, check=check)
            result = await self._list_pages(site=site)
            await check()
            return result
        page_id = _field(arguments, "page_id", str, maximum=64)
        driver = self._page(page_id)
        self.verify_private_request(driver, command, arguments)
        if self.trace_page_id is not None and command != "trace" and page_id != self.trace_page_id:
            raise ControlError("trace_target_exclusive")
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
            try:
                content = base64.b64decode(_field(arguments, "content_base64", str, maximum=2_666_672), validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("invalid_upload_payload") from error
            return await driver.chooser_upload(
                _field(arguments, "chooser_id", str, maximum=100),
                name=_field(arguments, "name", str, maximum=255),
                mime_type=_field(arguments, "mime_type", str, maximum=127), content=content, check=check)
        if command == "wait_condition":
            return await driver.wait_condition(_field(arguments, "condition", dict), check=check)
        if command == "wait_navigation":
            return await driver.wait_navigation(
                _field(arguments, "after_navigation_version", int),
                _field(arguments, "timeout_ms", int), expected_url=arguments.get("expected_url"), check=check)
        if command == "dialog_action":
            return await driver.dialog_action(
                _field(arguments, "dialog_id", str, maximum=100),
                _field(arguments, "accept", bool), prompt_text=arguments.get("prompt_text"), check=check)
        if driver.pending_dialog is not None and command not in {
                "page_diagnostics", "dispose_page"}:
            raise ControlError("dialog_pending")
        if getattr(driver, "pending_chooser", None) is not None and command in {
                "fill", "type", "click", "press", "hover", "select_option", "set_checked", "drag", "upload",
                "download", "editor_replace", "terminal_input", "navigate", "back", "forward", "reload", "scroll"}:
            raise ControlError("chooser_pending")
        if command == "dispose_page":
            await driver.dispose()
            self.pages.pop(page_id)
            self.owned_pages.discard(page_id)
            return {"disposed": True}
        if command == "close_page":
            if page_id not in self.owned_pages:
                raise ControlError("page_not_owned_by_chat")
            return await self._normal_close_page(page_id, driver, check=check)
        if command == "observe":
            selector = _field(arguments, "selector", str, maximum=2000)
            ttl = arguments.get("ttl")
            if type(ttl) not in (int, float) or not 0 < ttl <= 30:
                raise ValueError("invalid_worker_argument")
            result = await driver.observe(check=check,
                                        frame_index=_field(arguments, "frame_index", int),
                                        selector=selector, offset=_field(arguments, "offset", int),
                                        limit=_field(arguments, "limit", int),
                                        ttl=ttl)
            if self.profile_kind == "luohua" and not allowed_url(driver.page.url):
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
        if command == "screenshot":
            await check()
            try:
                pixels = await driver.page.screenshot(type="jpeg", quality=85,
                                                      full_page=False, timeout=10_000,
                                                      animations="disabled", caret="hide")
            except PlaywrightTimeoutError as exc:
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
            if len(pixels) > 4_000_000:
                raise ControlError("screenshot_too_large")
            return {"format": "jpeg", "bytes": len(pixels),
                    "base64": base64.b64encode(pixels).decode("ascii")}
        if command == "fill":
            return await driver.fill(_field(arguments, "reference", str, maximum=100),
                                     _field(arguments, "text", str, maximum=1_000_000),
                                     check=check)
        if command == "type":
            return await driver.type_text(_field(arguments, "reference", str, maximum=100),
                _field(arguments, "text", str, maximum=1_000_000),
                replace=arguments.get("replace", False), check=check)
        if command == "editor_inspect":
            return await driver.editor_inspect(_field(arguments, "reference", str, maximum=100),
                                               check=check)
        if command == "editor_read":
            return await driver.editor_read(_field(arguments, "reference", str, maximum=100),
                                            offset=_field(arguments, "offset", int),
                                            limit=_field(arguments, "limit", int), check=check)
        if command == "editor_replace":
            return await driver.editor_replace(
                _field(arguments, "reference", str, maximum=100),
                _field(arguments, "text", str, maximum=1_000_000),
                _field(arguments, "expected_uri", str, maximum=2048),
                _field(arguments, "expected_version", int), check=check)
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
            payload = _field(arguments, "content_base64", str, maximum=2_666_672)
            try:
                content = base64.b64decode(payload, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("invalid_upload_payload") from exc
            return await driver.upload(
                _field(arguments, "reference", str, maximum=100),
                name=_field(arguments, "name", str, maximum=255),
                mime_type=_field(arguments, "mime_type", str, maximum=127),
                content=content, check=check)
        if command == "download":
            return await self._download(driver, arguments, check=check)
        if command == "trace":
            return await self._trace(driver, page_id, arguments, check=check)
        if command == "navigate":
            url = _field(arguments, "url", str, maximum=8192)
            if urlsplit(url).scheme not in ("http", "https"):
                raise ValueError("unsupported_navigation_scheme")
            mark_write("navigate")
            response = await driver.page.goto(url, wait_until="domcontentloaded", timeout=10_000)
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
                    "page_state": state}
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
                position = await target.handle.evaluate("""async (element, delta) => {
                  const before = element.scrollTop;
                  const beforeX = element.scrollLeft;
                  element.scrollBy({top: delta.y, left: delta.x, behavior: 'instant'});
                  await new Promise(resolve => requestAnimationFrame(resolve));
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
            position = await driver.page.evaluate("""async delta => {
              const root = document.scrollingElement;
              if (!root) return {before: 0, after: 0, beforeX: 0, afterX: 0};
              const before = root.scrollTop;
              const beforeX = root.scrollLeft;
              window.scrollBy({top: delta.y, left: delta.x, behavior: 'instant'});
              await new Promise(resolve => requestAnimationFrame(resolve));
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

    async def _close_browser(self, *, check):
        closed_pages = []
        page_id, driver = None, None
        try:
            await self._list_pages()
            # Instance close has an explicit lifecycle authorization for all
            # tabs. Each page gets normal beforeunload first; no suffix is
            # closed while one exact confirmation is pending.
            for page_id in list(self.pages):
                driver = self.pages.get(page_id)
                await check()
                if driver is None or driver.page.is_closed():
                    continue
                if driver.pending_dialog is not None:
                    return {"requested": False, "state": "close_pending",
                            "closed_pages": closed_pages,
                            "pending_pages": [{"page_id": page_id, "dialog": driver.dialog_snapshot()}]}
                result = await self._normal_close_page(page_id, driver, check=check)
                if not result["closed"]:
                    return {"requested": False, "state": "close_pending",
                            "closed_pages": closed_pages, "pending_pages": [result]}
                closed_pages.append(page_id)
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
            return {"requested": False, "state": "close_stopped", "reason": error.code,
                    "closed_pages": closed_pages, "pending_pages": []}

    async def _normal_close_page(self, page_id, driver, *, check):
        generation = driver.generation
        url = driver.page.url
        await check()
        if driver.generation != generation or driver.page.url != url:
            raise ControlError("page_changed")
        mark_write("close_page")
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
        return {"page_id": page_id, "closed": closed, "dialog": driver.dialog_snapshot(),
                "state": "verified" if closed else "not_verified"}

    async def _download(self, driver: PageDriver, arguments: dict, *, check):
        reference = _field(arguments, "reference", str, maximum=100)
        output_path = arguments.get("output_path")
        if output_path is not None and type(output_path) is not str:
            raise ValueError("invalid_worker_argument")
        artifact_path(output_path, suffix="", suggested="download")
        await driver._fresh(reference)
        await check()
        ref = await driver._fresh(reference)
        try:
            async with driver.page.expect_download(timeout=10000) as info:
                mark_write("download_click")
                await ref.handle.click(timeout=3000)
            download = await info.value
        except PlaywrightTimeoutError:
            await check()
            return {"state": "not_verified", "verification": "download_event_timeout",
                    "business_result_verified": False}
        await check()
        with tempfile.TemporaryDirectory(prefix="flower-web-download-") as directory:
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
            artifact = persist_file(staged, output_path, suffix="",
                                    suggested=download.suggested_filename)
        return {"state": "verified", "verification": "download_artifact_saved",
                "artifact": artifact, "suggested_filename": download.suggested_filename,
                "source_url_without_query": _safe_download_source(download.url),
                "file_type_hint": mimetypes.guess_type(download.suggested_filename)[0],
                "business_result_verified": False}

    async def _trace(self, driver: PageDriver, page_id: str, arguments: dict, *, check):
        mode = _field(arguments, "mode", str, maximum=20)
        output_path = arguments.get("output_path")
        if output_path is not None and type(output_path) is not str:
            raise ValueError("invalid_worker_argument")
        if mode == "bundle":
            artifact_path(output_path, suffix=".zip", suggested="page-diagnostic")
            before_url = driver.page.url
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
            artifact = persist_bytes(buffer.getvalue(), output_path,
                                     suffix=".zip", suggested="page-diagnostic")
            return {"state": "verified", "verification": "page_diagnostic_saved",
                    "format": "flower-page-diagnostic-v1", "scope": "target_page_only",
                    "artifact": artifact}
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
            with tempfile.TemporaryDirectory(prefix="flower-web-trace-") as directory:
                staged = Path(directory) / "trace.zip"
                await context.tracing.stop(path=staged)
                await check()
                artifact = persist_file(staged, output_path, suffix=".zip",
                                        suggested="playwright-trace")
            return {"state": "verified", "verification": "trace_artifact_saved",
                    "format": "playwright-trace", "scope": "isolated_temporary_context",
                    "artifact": artifact}
        raise ValueError("invalid_trace_mode")

    async def close(self) -> None:
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
        try:
            await self.browser.close()
        except Exception:
            pass


def _read_request() -> bytes:
    return sys.stdin.buffer.readline(MAX_MESSAGE + 1)


def _write_response(response: dict) -> None:
    encoded = (json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        encoded = b'{"id":null,"ok":false,"error":"worker_response_too_large"}\n'
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


async def _serve(endpoint: str, *, guarded: bool = False,
                 profile_kind: str = "temporary") -> None:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect_over_cdp(endpoint, timeout=10_000)
        runtime = _Runtime(browser, profile_kind=profile_kind)
        _write_lifecycle("worker_ready")
        try:
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
                    guard = WorkerCallGuard(envelope, command, arguments) if envelope is not None else None
                    if guard is not None:
                        current_write_admission.set(lambda: guard.store.worker_write_admission(
                            guard.action, guard.token, guard.fingerprint))
                    result = await runtime.execute(command, arguments,
                                                   check=guard.check if guard else _noop_check)
                    runtime.verify_private_response(command, arguments)
                    _write_response({"id": request_id, "ok": True, "result": result,
                                     "dispatched": effects.dispatched, "stage": effects.stage})
                except ControlError as exc:
                    _write_response({"id": request_id, "ok": False, "error": f"control:{exc.code}", "dispatched": effects.dispatched, "stage": effects.stage})
                except ValueError as exc:
                    _write_response({"id": request_id, "ok": False, "error": str(exc)[:100], "dispatched": effects.dispatched, "stage": effects.stage})
                except Exception:
                    _write_response({"id": request_id, "ok": False, "error": "worker_command_failed", "dispatched": effects.dispatched, "stage": effects.stage})
                finally:
                    current_write_admission.reset(admission_token)
                    current_effects.reset(effect_token)
        finally:
            _write_lifecycle("runtime_cleanup_started")
            await runtime.close()
            _write_lifecycle("runtime_cleanup_finished")


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--stop-event", required=True)
    parser.add_argument("--guarded", action="store_true")
    parser.add_argument("--profile-kind", choices=("temporary", "ai", "luohua"),
                        default="temporary")
    args = parser.parse_args()
    if not args.endpoint.startswith("ws://127.0.0.1:"):
        return 2
    lifetime = WorkerLifetime(args.owner, args.stop_event, diagnostic=_write_lifecycle)
    code = 0
    try:
        asyncio.run(_serve(args.endpoint, guarded=args.guarded,
                           profile_kind=args.profile_kind))
    except Exception as error:
        _write_lifecycle("unhandled_exception", error=error)
        code = 1
    lifetime.exit(code)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
