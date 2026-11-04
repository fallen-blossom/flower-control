"""Bind and hide one newly owned browser window in a shared headed profile."""
import asyncio
import uuid
from dataclasses import asdict

import win32con
import win32gui
from playwright.async_api import Error as PlaywrightError
from flower_control.control.native import process_identity
from flower_control.control.state import ControlError
from .computer_native import bind_window
from .web_native_window import (_browser_pid, _normal_rect, _target_window,
                                _window_targets, _windows, validate_native_page)


async def bind_new_page(browser, session, page, *, before, check):
    """Bind a freshly created about:blank page with cross-checked identity.

    The temporary title proves which HWND belongs to the target, supplementing
    PID birth, CDP window membership, geometry and the HWND nonce. The caller
    must already own the exact page and must retain it on any failure.
    """
    await check()
    if page.is_closed() or page.url != "about:blank":
        raise ControlError("hidden_page_not_fresh")
    pid = await _browser_pid(session)
    birth = process_identity(pid)
    probe = await page.context.new_cdp_session(page)
    try:
        target = (await probe.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
    finally:
        await probe.detach()
    marker = "FlowerWindow-" + uuid.uuid4().hex
    await page.evaluate("value => { document.title = value; }", marker)
    try:
        matches = []
        for _ in range(100):
            await check()
            if page.is_closed() or page.url != "about:blank":
                raise ControlError("hidden_page_changed")
            candidates = _windows(pid) - before
            if len(candidates) > 1:
                raise ControlError("hidden_window_identity_unverified")
            matches = [hwnd for hwnd in candidates if win32gui.GetWindowText(hwnd).startswith(marker)]
            if matches:
                break
            await asyncio.sleep(.02)
        if len(matches) != 1 or process_identity(pid) != birth:
            raise ControlError("hidden_window_identity_unverified")
        hwnd = matches[0]
        info = await _target_window(session, target)
        if await _window_targets(session, info["windowId"]) != {target}:
            raise ControlError("hidden_window_membership_changed")
        bounds = info["bounds"]
        if bounds.get("windowState") not in {"normal", "minimized"}:
            raise ControlError("hidden_window_geometry_unverified")
        rect = _normal_rect(hwnd)
        try:
            cdp_rect = (bounds["left"], bounds["top"], bounds["left"] + bounds["width"], bounds["top"] + bounds["height"])
        except (KeyError, TypeError):
            raise ControlError("hidden_window_geometry_unverified") from None
        if any(type(n) is not int for n in cdp_rect) or any(abs(a-b) > 2 for a, b in zip(rect, cdp_rect)):
            raise ControlError("hidden_window_geometry_unverified")
        identity = bind_window(hwnd)
        if identity.pid != pid or f"{pid}:{identity.process_created}" != birth:
            raise ControlError("hidden_window_identity_unverified")
        binding = {"identity": asdict(identity), "window_id": info["windowId"]}
        await validate_native_page(browser, session, page, target, binding, check=check)
        if not win32gui.GetWindowText(hwnd).startswith(marker):
            raise ControlError("hidden_window_identity_unverified")
        return target, binding
    finally:
        if not page.is_closed() and page.url == "about:blank":
            try:
                await page.evaluate("value => { if (document.title === value) document.title = ''; }", marker)
            except PlaywrightError:
                pass  # A disposed page must not hide the original result.


async def hide_bound_page(browser, session, page, target, binding, *, check):
    """Hide an already recorded exact window; never discover a replacement."""
    identity = await validate_native_page(browser, session, page, target, binding, check=check)
    await check()
    win32gui.ShowWindow(identity["hwnd"], win32con.SW_HIDE)
    await validate_native_page(browser, session, page, target, binding, check=check)
    if win32gui.IsWindowVisible(identity["hwnd"]):
        raise ControlError("hidden_window_not_hidden")
