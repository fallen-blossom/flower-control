"""Exact windows for shared-login pages; no second context or profile.

The caller holds the normal foreground creation turn. DOM/network work keeps
its own borrower resource. Ambiguous native mapping never grants a handoff.
"""
import asyncio
import ctypes
from dataclasses import asdict

import win32con
import win32gui
from playwright.async_api import Error as PlaywrightError
from flower_control.control.state import ControlError
from flower_control.control.native import process_identity
from .computer_native import WindowIdentity, bind_window, assert_window, NativeInputError
from .web_effects import mark_write
from .web_page_registry import native_window_binding


async def _noop():
    pass


async def create_headless_page(context, session, *, check=_noop, on_target=None):
    """Same login context, distinct hidden rendering window; no OS activation.

    Chromium stops compositing inactive sibling tabs in one headless window,
    even with focus emulation. Playwright's two-frame stability check then stalls.
    Keep each new page rendering without weakening click actionability.
    """
    pending = asyncio.Queue(maxsize=128)
    def created(page):
        if not pending.full():
            pending.put_nowait(page)
    context.on("page", created)
    try:
        await check()
        mark_write("new_page")
        target = (await session.send("Target.createTarget", {"url": "about:blank", "newWindow": True}))["targetId"]
        if on_target is not None:
            await on_target(target)
        # Never substitute the first page event: another borrower can create a
        # page concurrently in this same context. Match only our returned ID.
        async with asyncio.timeout(3):
            while True:
                page = await pending.get()
                await check()
                if page.is_closed():
                    continue
                probe = None
                try:
                    probe = await context.new_cdp_session(page)
                    identifier = (await probe.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
                    if identifier == target:
                        return page
                except PlaywrightError:
                    if not page.is_closed():
                        raise
                finally:
                    if probe is not None:
                        try:
                            await asyncio.wait_for(probe.detach(), timeout=1)
                        except (PlaywrightError, asyncio.TimeoutError):
                            pass
    except asyncio.TimeoutError:
        # Creation may already have succeeded. The action stays dispatched;
        # there is no fallback, retry, browser activation or second target.
        raise ControlError("headless_page_creation_pending") from None
    finally:
        context.remove_listener("page", created)


async def _browser_pid(session):
    rows = (await session.send("SystemInfo.getProcessInfo")).get("processInfo", [])
    ids = [row["id"] for row in rows if row.get("type") == "browser" and type(row.get("id")) is int]
    if len(ids) != 1 or ids[0] <= 0:
        raise ControlError("shared_window_process_unverified")
    return ids[0]


def _windows(pid):
    # Import lazily: web_session owns the worker launcher, not this helper.
    from .web_session import _visible_browser_windows
    return set(_visible_browser_windows(pid))


def _normal_rect(hwnd):
    # CDP bounds use DIP. Only these synchronous native geometry calls execute
    # under the temporary unaware context; restore it before any await.
    api = ctypes.windll.user32
    api.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    api.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    previous = api.SetThreadDpiAwarenessContext(ctypes.c_void_p(-1))
    if not previous:
        raise ControlError("shared_window_geometry_unverified")
    try:
        return win32gui.GetWindowPlacement(hwnd)[4]
    finally:
        api.SetThreadDpiAwarenessContext(previous)


async def _target_window(session, target):
    value = await session.send("Browser.getWindowForTarget", {"targetId": target})
    if type(value.get("windowId")) is not int or type(value.get("bounds")) is not dict:
        raise ControlError("shared_window_geometry_unverified")
    return value


async def _window_targets(session, window_id):
    targets = (await session.send("Target.getTargets")).get("targetInfos", [])
    if len(targets) > 1024:
        raise ControlError("shared_window_target_limit")
    found = set()
    for row in targets:
        if row.get("type") != "page":
            continue
        target = row["targetId"]
        window = await _target_window(session, target)
        if window["windowId"] == window_id:
            found.add(target)
    return found


async def create_native_page(browser, session, *, check=_noop, on_target=None):
    pid = await _browser_pid(session)
    exact_process = process_identity(pid)
    before = _windows(pid)
    old_pages = {page for context in browser.contexts for page in context.pages}
    previous_windows = set()
    for row in (await session.send("Target.getTargets")).get("targetInfos", []):
        if row.get("type") == "page":
            previous_windows.add((await _target_window(session, row["targetId"]))["windowId"])
    await check()
    mark_write("new_page")
    created = await session.send("Target.createTarget", {"url": "about:blank", "newWindow": True,
        "background": True, "focus": False, "windowState": "minimized"})
    target = created["targetId"]
    if on_target is not None:
        await on_target(target)
    # No fallback/replay after this point: the original page may exist even if
    # mapping fails. Recover it through the same borrower, not a new creation.
    page = None
    for _ in range(100):
        for context in browser.contexts:
            for candidate in context.pages:
                if candidate in old_pages:
                    continue
                probe = None
                try:
                    probe = await context.new_cdp_session(candidate)
                    candidate_id = (await probe.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
                except PlaywrightError:
                    continue  # A foreign page can close during enumeration.
                finally:
                    if probe is not None:
                        try:
                            await probe.detach()
                        except PlaywrightError:
                            pass
                if candidate_id == target:
                    page = candidate
                    break
            if page is not None:
                break
        if page is not None:
            break
        await asyncio.sleep(.02)
    if page is None:
        raise ControlError("shared_window_page_pending")
    # A mapping problem keeps this exact page and its Web functionality. It
    # simply has no desktop handoff; it never falls back to another HWND.
    try:
        info = await _target_window(session, target)
        delta = _windows(pid) - before
        if (len(delta) != 1 or info["windowId"] in previous_windows
                or process_identity(pid) != exact_process
                or await _window_targets(session, info["windowId"]) != {target}):
            return page, None
        hwnd = next(iter(delta))
        bounds = info["bounds"]
        if not win32gui.IsIconic(hwnd) or bounds.get("windowState") != "minimized":
            return page, None
        rect = _normal_rect(hwnd)
        cdp_rect = (bounds["left"], bounds["top"], bounds["left"] + bounds["width"], bounds["top"] + bounds["height"])
        if any(type(n) is not int for n in cdp_rect) or any(abs(a-b) > 2 for a,b in zip(rect, cdp_rect)):
            return page, None
        identity = bind_window(hwnd)
        if identity.pid != pid or f"{pid}:{identity.process_created}" != exact_process:
            return page, None
        await check()
        binding = {"identity": asdict(identity), "window_id": info["windowId"]}
        await validate_native_page(browser, session, page, target, binding, check=check)
        return page, binding
    except (ControlError, NativeInputError, KeyError, OSError, ValueError, PlaywrightError):
        return page, None


async def validate_native_page(browser, session, page, target_id, binding, *, check=_noop):
    value = native_window_binding(binding)
    if value is None or page.is_closed():
        raise ControlError("shared_window_binding_unavailable")
    identity = WindowIdentity(**value["identity"])
    await check()
    assert_window(identity)
    if await _browser_pid(session) != identity.pid:
        raise ControlError("shared_window_process_unverified")
    info = await _target_window(session, target_id)
    if (info["windowId"] != value["window_id"]
            or await _window_targets(session, value["window_id"]) != {target_id}):
        raise ControlError("shared_window_page_membership_changed")
    await check()
    assert_window(identity)
    return asdict(identity)
