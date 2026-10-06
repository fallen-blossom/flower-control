"""Bounded Windows Hello verification through the local official WinRT helper.

Only the exact child started here can return a result. No PIN, biometric data,
browser content, or profile path enters this process or the ledger.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Callable


class HelloOutcome(Enum):
    VERIFIED = "verified"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    ERROR = "error"


class WindowsHelloVerifier:
    """One-shot system prompt, defaulting to a fixed local Release helper.

    A built helper is an installation prerequisite. Missing SDK/runtime or DLL
    fails closed; no build, download, or dependency restore occurs here.
    """

    DEFAULT_DLL = (Path(__file__).resolve().parent / "hello_verifier" / "bin" /
                   "Release" / "net10.0-windows10.0.26100.0" / "win-x64" /
                   "HelloVerifier.dll")

    def __init__(self, *, helper_dll: Path | None = None):
        self.helper_dll = Path(helper_dll) if helper_dll is not None else self.DEFAULT_DLL

    def verify(self, request_id: str, *, deadline: float,
               cancelled: Callable[[], bool], active: Callable[[], bool]) -> HelloOutcome:
        if (not isinstance(request_id, str) or not request_id
                or len(request_id) > 128 or not isinstance(deadline, (int, float))):
            return HelloOutcome.ERROR
        if sys.platform != "win32" or sys.getwindowsversion().build < 22000:
            return HelloOutcome.UNAVAILABLE
        dll = self.helper_dll
        helper_root = (Path(__file__).resolve().parent / "hello_verifier").resolve()
        # Do not accept a model- or host-controlled ProgramFiles override as
        # the executable path for this privileged local prompt.
        dotnet = Path(r"C:\Program Files\dotnet\dotnet.exe")
        if (dll.name != "HelloVerifier.dll" or not dll.resolve().is_relative_to(helper_root)
                or not dll.is_file() or dll.is_symlink() or not dotnet.is_file()
                or dotnet.is_symlink()):
            return HelloOutcome.UNAVAILABLE
        if cancelled() or not active():
            return HelloOutcome.CANCELLED
        if time.monotonic() >= deadline:
            return HelloOutcome.TIMED_OUT

        challenge = secrets.token_urlsafe(32)
        payload = json.dumps({"Version": 1, "RequestId": request_id,
                              "Challenge": challenge}, separators=(",", ":")) + "\n"
        # Do not inherit .NET startup hooks, profiler injection or alternate
        # dependency search paths from the MCP host environment.
        env = {name: os.environ[name] for name in
               ("SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA")
               if name in os.environ}
        env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        env["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
        env["DOTNET_NOLOGO"] = "1"
        process = None
        try:
            process = subprocess.Popen(
                [str(dotnet), str(dll)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd=str(dll.parent), env=env,
                creationflags=subprocess.CREATE_NO_WINDOW)
            if process.stdin is None:
                return HelloOutcome.ERROR
            process.stdin.write(payload.encode("utf-8"))
            process.stdin.close()
            while process.poll() is None:
                if cancelled() or not active():
                    return HelloOutcome.CANCELLED
                if time.monotonic() >= deadline:
                    return HelloOutcome.TIMED_OUT
                time.sleep(0.1)
            if process.stdout is None:
                return HelloOutcome.ERROR
            response = process.stdout.read(4097)
            if process.returncode != 0 or len(response) > 4096:
                return HelloOutcome.ERROR
            value = json.loads(response.decode("utf-8-sig"))
            if (type(value) is not dict or set(value) !=
                    {"Version", "RequestId", "Challenge", "Result"}
                    or value["Version"] != 1 or value["RequestId"] != request_id
                    or type(value["Challenge"]) is not str
                    or not secrets.compare_digest(value["Challenge"], challenge)
                    or type(value["Result"]) is not str):
                return HelloOutcome.ERROR
            if cancelled() or not active() or time.monotonic() >= deadline:
                return HelloOutcome.CANCELLED
            return (HelloOutcome.VERIFIED if value["Result"] == "Verified"
                    else HelloOutcome.DENIED)
        except (OSError, UnicodeError, ValueError, AssertionError):
            return HelloOutcome.ERROR
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()  # Exact helper child only.
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                if process.stdout is not None:
                    process.stdout.close()
