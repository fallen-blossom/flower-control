"""Job-owned F1 WGC session bridge, fixed identity and no disk frame storage."""
import json
import ctypes
import subprocess
import sys
import threading
import time

import win32job

from .computer_capture_session import read_frame, safe_diagnostic, _DIAGNOSTIC_CODES
from .computer_capture_worker import _WGC_EXE, _native_environment
from .computer_native import WindowIdentity, assert_window, window_geometry
from .worker_lifetime import WorkerLifetime


def main():
    lifetime = None
    began = time.monotonic()
    diagnostic_reader = None
    def diagnostic(stage, code=None):
        print(json.dumps({"origin": "worker", "stage": stage, "code": code,
            "elapsed_ms": (time.monotonic() - began) * 1000}), file=sys.stderr, flush=True)
    try:
        diagnostic("worker_started")
        set_dpi = ctypes.windll.user32.SetProcessDpiAwarenessContext
        set_dpi.argtypes = [ctypes.c_void_p]
        set_dpi.restype = ctypes.c_bool
        if not set_dpi(ctypes.c_void_p(-4)):
            raise RuntimeError("dpi_context_unavailable")
        line = sys.stdin.buffer.readline(4097)
        if len(line) > 4096 or not line.endswith(b"\n"):
            raise ValueError("invalid_session_request")
        request = json.loads(line)
        if type(request) is not dict or set(request) != {"identity", "owner_identity", "stop_event"}:
            raise ValueError("invalid_session_request")
        lifetime = WorkerLifetime(request["owner_identity"], request["stop_event"])
        # Native monitor terminates the entire owned tree even if stdin blocks.
        timer = threading.Timer(9, lambda: win32job.TerminateJobObject(lifetime.job, 1))
        timer.daemon = True
        timer.start()
        identity = WindowIdentity(**request["identity"])
        assert_window(identity)
        geometry = window_geometry(identity)
        if not _WGC_EXE.is_file():
            raise RuntimeError("wgc_binary_missing")
        child = subprocess.Popen([str(_WGC_EXE), "--session"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_native_environment(),
            creationflags=subprocess.CREATE_NO_WINDOW)
        def forward_diagnostics():
            for line in iter(lambda: child.stderr.readline(1025), b""):
                value = safe_diagnostic(line)
                if value is not None:
                    value["elapsed_ms"] = (time.monotonic() - began) * 1000
                    print(json.dumps(value), file=sys.stderr, flush=True)
        diagnostic_reader = threading.Thread(target=forward_diagnostics, daemon=True)
        diagnostic_reader.start()
        diagnostic("child_started")
        child.stdin.write(json.dumps(request["identity"]).encode() + b"\n")
        child.stdin.flush()
        while True:
            line = sys.stdin.buffer.readline(257)
            if not line:
                diagnostic("native_eof")
                child.stdin.close()
                try:
                    code = child.wait(timeout=.75)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("native_shutdown_failed") from None
                if code != 0:
                    raise RuntimeError("native_shutdown_failed")
                diagnostic("native_exited")
                diagnostic_reader.join(timeout=.1)
                timer.cancel()
                diagnostic("session_closed")
                lifetime.exit(0)
            if len(line) > 256 or not line.endswith(b"\n"):
                raise ValueError("invalid_frame_request")
            assert_window(identity)
            if window_geometry(identity) != geometry:
                raise RuntimeError("capture_target_changed")
            child.stdin.write(line)
            child.stdin.flush()
            header, bmp = read_frame(child.stdout)
            assert_window(identity)
            if window_geometry(identity) != geometry:
                raise RuntimeError("capture_target_changed")
            encoded = json.dumps(header, separators=(",", ":")).encode()
            sys.stdout.buffer.write(len(encoded).to_bytes(4, "little") + encoded + bmp)
            sys.stdout.buffer.flush()
    except Exception as error:
        if diagnostic_reader is not None:
            diagnostic_reader.join(timeout=.1)
        code = getattr(error, "code", None)
        if code not in _DIAGNOSTIC_CODES:
            code = str(error) if str(error) in _DIAGNOSTIC_CODES else "worker_error"
        diagnostic("error", code)
        if lifetime is not None:
            lifetime.exit(3)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
