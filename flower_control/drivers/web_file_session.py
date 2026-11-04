"""In-worker, one-use native selection session; no model-supplied paths."""
from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import threading
import time
import uuid
from pathlib import Path
import win32event

from flower_control.control.state import ControlError
from flower_control.control.native import process_identity
from .web_file_picker import picker_origin
from .web_file_snapshot import LockedSnapshot
from .worker_python import worker_command


class FileSelectionSession:
    def __init__(self, *, origin, valid, task_key="synthetic", maximum_seconds=120):
        self.origin = picker_origin(origin)
        self.valid = valid
        self.task_key = task_key
        self.expires = time.monotonic() + maximum_seconds
        self.identifier = secrets.token_hex(16)
        self.stop = threading.Event()
        self.process = None
        self.stop_event = None
        self.task = None
        self.snapshot = None
        self.state = "starting"
        self.consumed = False

    def _check(self):
        if time.monotonic() >= self.expires:
            raise ControlError("file_selection_expired")
        try:
            valid = self.valid()
        except Exception:
            valid = False
        if self.stop.is_set() or not valid:
            raise ControlError("file_selection_cancelled")

    def _thread_check(self):
        if self.stop.is_set() or time.monotonic() >= self.expires:
            raise ControlError("file_selection_cancelled")

    async def start(self):
        self._check()
        stop_name = "Local\\FlowerControl.FilePickerStop." + uuid.uuid4().hex
        self.stop_event = win32event.CreateEvent(None, True, False, stop_name)
        spawning = asyncio.create_task(asyncio.create_subprocess_exec(
            *worker_command("flower_control.drivers.web_worker", "--flower-file-picker", self.origin,
                            process_identity(), stop_name),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW))
        try:
            self.process = await asyncio.shield(spawning)
        except asyncio.CancelledError:
            win32event.SetEvent(self.stop_event)
            process = await spawning
            await process.wait()
            self.stop_event.Close()
            self.stop_event = None
            raise
        except BaseException:
            self.stop_event.Close()
            self.stop_event = None
            raise
        self.state = "pending"
        self.task = asyncio.create_task(self._run())

    async def _wait_checked(self, task, *, must_live=None):
        while not task.done():
            self._check()
            if must_live is not None and must_live.done():
                raise ControlError("file_picker_exited_early")
            await asyncio.wait({task}, timeout=0.2)
        self._check()
        if must_live is not None and must_live.done():
            raise ControlError("file_picker_exited_early")
        return await task

    async def _run(self):
        reading = None
        copying = None
        picker_exit = None
        try:
            reading = asyncio.create_task(self.process.stdout.readline())
            stdout = await self._wait_checked(reading)
            if len(stdout) > 65536 or not stdout.endswith(b"\n"):
                raise ControlError("file_picker_failed")
            response = json.loads(stdout)
            if type(response) is not dict or set(response) != {"selected", "identity"}:
                raise ControlError("file_picker_failed")
            selected = response["selected"]
            if selected is None:
                if response["identity"] is not None:
                    raise ControlError("file_picker_failed")
                self.state = "cancelled"
                return
            identity = response["identity"]
            if (type(selected) is not str or not selected or type(identity) is not list
                    or len(identity) != 5 or any(type(v) is not int or v < 0 for v in identity[:4])
                    or type(identity[4]) is not str):
                raise ControlError("file_picker_failed")
            picker_exit = asyncio.create_task(self.process.wait())
            await asyncio.sleep(0)
            if picker_exit.done():
                raise ControlError("file_picker_exited_early")
            copying = asyncio.create_task(asyncio.to_thread(LockedSnapshot, Path(selected), check=self._thread_check,
                                                     task_key=self.task_key, expected_identity=identity))
            self.snapshot = await self._wait_checked(copying, must_live=picker_exit)
            # Snapshot now owns a matching source handle; only then release the picker.
            self.process.stdin.close()
            await self._wait_checked(picker_exit)
            if self.process.returncode != 0:
                raise ControlError("file_picker_failed")
            self.state = "ready"
            # Retain the live watch after readiness; selection alone never dispatches.
            while True:
                self._check()
                await asyncio.sleep(0.2)
        except ControlError as error:
            if error.code == "file_selection_cleanup_unverified":
                self.state = "cleanup_pending"
            elif self.consumed:
                self.state = "expired" if error.code == "file_selection_expired" else "invalidated"
            else:
                self.state = "cancelled"
        except Exception:
            if self.state != "consumed":
                self.state = "cancelled"
        finally:
            self.stop.set()
            if self.process is not None and self.process.returncode is None:
                win32event.SetEvent(self.stop_event)
            if reading is not None:
                await asyncio.gather(reading, return_exceptions=True)
            if self.process is not None:
                await self.process.wait()
            if self.stop_event is not None:
                self.stop_event.Close()
                self.stop_event = None
            if copying is not None:
                result = await asyncio.gather(copying, return_exceptions=True)
                if self.snapshot is None and result and isinstance(result[0], LockedSnapshot):
                    self.snapshot = result[0]
                elif result and isinstance(result[0], ControlError) and result[0].code == "file_selection_cleanup_unverified":
                    self.state = "cleanup_pending"
            if self.snapshot is not None:
                try:
                    self.snapshot.close()
                    self.snapshot = None
                except Exception:
                    self.state = "cleanup_pending"

    def take(self):
        self._check()
        if self.state != "ready" or self.consumed or self.snapshot is None:
            raise ControlError("file_selection_not_ready")
        self.consumed = True
        self.state = "consumed"
        return self.snapshot

    async def close(self):
        self.stop.set()
        if self.task is not None:
            await self.task
        if self.state == "cleanup_pending":
            if self.snapshot is None:
                raise ControlError("file_selection_cleanup_unverified")
            try:
                self.snapshot.close()
            except Exception:
                raise ControlError("file_selection_cleanup_unverified") from None
            self.snapshot = None
            self.state = "released"
        elif self.state != "cleanup_pending":
            self.state = "released"
