"""Route independent browser profiles and retain exact owned handles."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from flower_control.browsers import (CHROMIUM_BROWSER_PATHS, BROWSER_ALIASES,
                                     browser_family, resolve_browser_executable)
from flower_control.control.state import ControlError
from flower_control.profile_registry import direct_path
from .web_mcp import WebMcpRuntime


class BrowserWebRuntime:
    def __init__(self, store, *, default_executable, use_preferences=False, **options):
        self.store = store
        self.default_executable = default_executable
        self.options = options
        self.use_preferences = use_preferences
        self._base = WebMcpRuntime(store, ai_brave_executable=CHROMIUM_BROWSER_PATHS['brave'], **options)
        self._runtimes = {'brave': self._base}
        self._creation_gate = asyncio.Lock()
        self._finish_gate = asyncio.Lock()
        self._finish_requests = {}

    def __getattr__(self, name):
        # Private-profile APIs keep their established permission and lifecycle.
        return getattr(self._base, name)

    def _selected(self, browser=None):
        if browser is None:
            if self.use_preferences:
                from flower_control.browser_preferences import selected_browser
                _, executable = selected_browser(self.store.directory.parent)
            else:
                executable = self.default_executable
        else:
            if not isinstance(browser, str):
                raise ControlError('unsupported_browser_executable')
            name = BROWSER_ALIASES.get(browser.lower(), browser.lower())
            if name not in CHROMIUM_BROWSER_PATHS:
                raise ControlError('unsupported_browser_executable')
            executable = resolve_browser_executable(name)
        return self._runtime_for_executable(executable)

    def _runtime_for_executable(self, executable):
        family = browser_family(executable)
        if family not in self._runtimes:
            from flower_control.browser_preferences import browser_profiles
            profiles = browser_profiles(self.store.directory.parent, family)
            profile = profiles['ai']
            if profile in {self._base.ai_profile, self._base.luohua_profile}:
                raise ControlError('browser_profile_storage_collision')
            self._runtimes[family] = WebMcpRuntime(self.store, ai_profile=profile, luohua_profile=profiles['luohua'],
                                                  ai_brave_executable=executable, **self.options)
        runtime = self._runtimes[family]
        if Path(runtime.ai_brave_executable) != Path(executable):
            # Aliases/install variants share one physical profile. Switching an
            # executable beneath live records would invalidate their identity.
            if any(not r.closed for r in runtime.sessions.values()) or runtime._logins:
                raise ControlError('browser_executable_change_requires_close')
            if family == 'brave':
                self._base.ai_brave_executable = executable
            else:
                runtime.ai_brave_executable = executable
        return runtime

    def _owned(self, task, handle):
        for runtime in self._runtimes.values():
            if handle in runtime.sessions or handle in runtime._logins:
                return runtime
        # Host restart: match the exact handle, then let the existing runtime
        # recheck chat, PID, creation time, image, worker and Stop boundaries.
        if isinstance(handle, str) and len(handle) == 32:
            for family in ('edge', 'chrome'):
                from flower_control.browser_preferences import browser_profiles
                try:
                    profiles = browser_profiles(self.store.directory.parent, family)
                except ControlError as error:
                    if error.code != 'browser_profile_storage_collision':
                        raise
                    continue  # An unrelated family's collision cannot redirect this handle.
                for profile in profiles.values():
                    marker = direct_path(profile / 'flower-session.json')
                    try:
                        if marker.stat().st_size > 32768:
                            continue
                        data = json.loads(marker.read_bytes())
                    except (OSError, ValueError):
                        continue
                    if not isinstance(data, dict):
                        continue
                    matched = data.get('session_id') == handle and (data.get('owner_task') == task
                        or self.store.same_chat_after_reboot(task, data.get('owner_task')))
                    if not matched and data.get('owner_kind') == 'user':
                        from .web_shared_profile import shared_borrowers
                        matched = any(row.get('session_id') == handle for _, row in shared_borrowers(profile, task))
                    if not matched:
                        continue
                    # Metadata only selects a known family/installation alias;
                    # the runtime still verifies exact process and chat ownership.
                    selected = family
                    executable = data.get('executable')
                    if isinstance(executable, str):
                        if str(self.default_executable).lower() == executable.lower() and browser_family(self.default_executable) == family:
                            return self._runtime_for_executable(self.default_executable)
                        from flower_control.browsers import browser_install_candidates, _trusted_install_candidate
                        for path in browser_install_candidates(family):
                            if str(path).lower() == executable.lower() and _trusted_install_candidate(path):
                                return self._runtime_for_executable(path)
                        for name, path in CHROMIUM_BROWSER_PATHS.items():
                            if browser_family(path) == family and str(path).lower() == executable.lower():
                                selected = name
                                break
                    return self._selected(selected)
        return self._base

    async def start_temp(self, task, *, visible=True, browser=None,start_minimized=False):
        if type(start_minimized) is not bool or start_minimized and visible is not True:
            raise ControlError('invalid_window_mode')
        async with self._creation_gate:
            if sum(not record.closed for runtime in self._runtimes.values()
                   for record in runtime.sessions.values()) >= 32:
                raise ControlError('temporary_session_limit')
            runtime = self._selected(browser)
            result = await runtime.start_temp(task, visible=visible,
                **({'start_minimized':True} if start_minimized else {}))
        return {**result, 'browser': browser_family(runtime.ai_brave_executable)}

    async def open_ai(self, task, *, browser=None, window_mode=None):
        runtime = self._selected(browser)
        result = await runtime.open_ai(task, **({"window_mode": window_mode} if window_mode is not None else {}))
        return {**result, 'browser': browser_family(runtime.ai_brave_executable)}

    def private_runtime(self, browser=None):
        return self._selected(browser)

    async def open_luohua(self, task, *, browser=None, window_mode=None):
        runtime = self._selected(browser)
        result = await runtime.open_luohua(task, **({'window_mode': window_mode} if window_mode is not None else {}))
        return {**result, 'browser': browser_family(runtime.ai_brave_executable)}

    async def begin_luohua_login(self, task, *, browser=None, initial_url='about:blank'):
        runtime = self._selected(browser)
        result = await runtime.begin_luohua_login(task, initial_url=initial_url)
        return {**result, 'browser': browser_family(runtime.ai_brave_executable)}

    async def reconnect_luohua(self, task, session_id):
        return await self._owned(task, session_id).reconnect_luohua(task, session_id)

    async def luohua_login_status(self, task, login_id):
        return await self._owned(task, login_id).luohua_login_status(task, login_id)

    async def finish_luohua_login(self, task, login_id):
        return await self._owned(task, login_id).finish_luohua_login(task, login_id)

    async def cancel_luohua_login(self, task, login_id):
        return await self._owned(task, login_id).cancel_luohua_login(task, login_id)

    async def begin_ai_login(self, task, *, initial_url='about:blank', browser=None):
        runtime = self._selected(browser)
        result = await runtime.begin_ai_login(task, initial_url=initial_url)
        return {**result, 'browser': browser_family(runtime.ai_brave_executable)}

    async def reconnect_ai(self, task, session_id):
        return await self._owned(task, session_id).reconnect_ai(task, session_id)

    async def ai_login_status(self, task, login_id):
        return await self._owned(task, login_id).ai_login_status(task, login_id)

    async def finish_ai_login(self, task, login_id):
        return await self._owned(task, login_id).finish_ai_login(task, login_id)

    async def cancel_ai_login(self, task, login_id):
        return await self._owned(task, login_id).cancel_ai_login(task, login_id)

    async def run(self, task, session_id, command, arguments, action_id):
        return await self._owned(task, session_id).run(task, session_id, command, arguments, action_id)

    def authorize_image_return(self, task, session_id, *, policy_revision=None):
        return self._owned(task, session_id).authorize_image_return(
            task, session_id, policy_revision=policy_revision)

    def action_status(self, task, session_id, action_id):
        return self._owned(task, session_id).action_status(task, session_id, action_id)

    def cancel(self, task, session_id, action_id):
        return self._owned(task, session_id).cancel(task, session_id, action_id)

    async def close_temp(self, task, session_id):
        return await self._owned(task, session_id).close_temp(task, session_id)

    async def close_ai(self, task, session_id):
        return await self._owned(task, session_id).close_ai(task, session_id)

    async def close_luohua(self, task, session_id):
        return await self._owned(task, session_id).close_luohua(task, session_id)

    async def close_status(self, task, session_id):
        return await self._owned(task, session_id).close_status(task, session_id)

    async def set_window_mode(self, task, session_id, window_mode):
        return await self._owned(task, session_id).set_window_mode(task, session_id, window_mode)

    async def finish_run(self, task, **arguments):
        from .web_finish import finish_web_run
        async with self._finish_gate:
            return await finish_web_run(self, task, **arguments)

    async def close_connection(self, tasks):
        for runtime in tuple(self._runtimes.values()):
            await runtime.close_connection(tasks)
