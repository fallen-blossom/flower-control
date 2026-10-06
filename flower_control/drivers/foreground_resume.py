"""One local user click to resume a paused Computer target.

The child only displays the decision. The MCP parent retains the task and
resource identity and changes the ledger after checking the exact target again.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import multiprocessing
import os
from pathlib import Path
import sys
import time

import win32process


_CARD_MARKER = "FlowerControlResumePrompt"


def _ui(pipe, title: str, chat_ref: str) -> None:
    import tkinter as tk

    root = tk.Tk()
    root.title("Flower Control · 恢复前台操作")
    root.geometry("500x215")
    root.resizable(False, False)
    root.attributes("-topmost", True)
    root.columnconfigure(0, weight=1)
    tk.Label(root, text="继续此聊天的 Flower 任务？",
             font=("Microsoft YaHei UI", 12, "bold")).grid(
                 row=0, column=0, columnspan=2, padx=20, pady=(20, 8), sticky="w")
    tk.Label(root, text="暂停来源窗口：" + title[:120], wraplength=460, anchor="w",
             justify="left").grid(row=1, column=0, columnspan=2,
                                   padx=20, sticky="ew")
    tk.Label(root, text="聊天标识：" + chat_ref,
             fg="#555555").grid(row=2, column=0, columnspan=2,
                                  padx=20, pady=(6, 0), sticky="w")
    tk.Label(root, text="继续会解除此窗口的暂停；若聊天也已暂停，会一并解除。",
             fg="#555555").grid(row=3, column=0, columnspan=2,
                                  padx=20, pady=(8, 12), sticky="w")

    def answer(allow: bool) -> None:
        try:
            pipe.send(("decision", allow))
        except (EOFError, OSError):
            pass
        root.destroy()

    def watch_parent() -> None:
        try:
            if pipe.poll():
                pipe.recv()
                root.destroy()
                return
        except (EOFError, OSError):
            root.destroy()
            return
        root.after(100, watch_parent)

    tk.Button(root, text="取消", command=lambda: answer(False)).grid(
        row=4, column=0, padx=(20, 6), sticky="e")
    tk.Button(root, text="继续", command=lambda: answer(True)).grid(
        row=4, column=1, padx=(6, 20), sticky="w")
    root.protocol("WM_DELETE_WINDOW", lambda: answer(False))
    hwnd = 0
    try:
        root.update_idletasks()
        hwnd = int(root.wm_frame(), 0)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.SetPropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.HANDLE)
        user32.SetPropW.restype = wintypes.BOOL
        user32.RemovePropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
        user32.RemovePropW.restype = wintypes.HANDLE
        if not hwnd or not user32.SetPropW(hwnd, _CARD_MARKER, 1):
            raise RuntimeError("resume_card_window_unavailable")
        pipe.send(("ready", os.getpid(), hwnd))
        root.after(100, watch_parent)
        root.mainloop()
    finally:
        if hwnd:
            ctypes.windll.user32.RemovePropW(hwnd, _CARD_MARKER)
        pipe.close()


def show_resume_card(title: str, chat_ref: str, *, timeout: float = 60) -> bool:
    """Return True only for a click in this exact local child window."""
    if (type(title) is not str or type(chat_ref) is not str or
            len(chat_ref) != 8 or not 0 < timeout <= 120):
        raise ValueError("invalid_resume_card_request")
    python = Path(sys.base_prefix) / "python.exe"
    if not python.is_file() or python.is_symlink():
        raise RuntimeError("resume_card_python_unavailable")
    multiprocessing.set_executable(str(python))
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=True)
    process = context.Process(target=_ui, args=(child, title, chat_ref),
                              name="FlowerForegroundResumeCard")
    ready = False
    deadline = time.monotonic() + timeout
    try:
        process.start()
        child.close()
        while time.monotonic() < deadline:
            if not parent.poll(min(0.1, max(0, deadline - time.monotonic()))):
                if not process.is_alive():
                    if not ready:
                        raise RuntimeError("resume_card_unavailable")
                    return False
                continue
            message = parent.recv()
            if not ready:
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                user32.GetPropW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
                user32.GetPropW.restype = wintypes.HANDLE
                if (type(message) is not tuple or len(message) != 3 or
                        message[0] != "ready" or message[1] != process.pid or
                        type(message[2]) is not int or message[2] <= 0 or
                        win32process.GetWindowThreadProcessId(message[2])[1] != process.pid or
                        user32.GetPropW(message[2], _CARD_MARKER) != 1):
                    raise RuntimeError("resume_card_identity_mismatch")
                ready = True
            elif message == ("decision", True):
                return True
            elif message == ("decision", False):
                return False
            else:
                raise RuntimeError("resume_card_response_invalid")
        if not ready:
            raise RuntimeError("resume_card_start_timeout")
        return False
    except (EOFError, OSError):
        return False
    finally:
        try:
            parent.send(("close",))
        except (EOFError, OSError):
            pass
        parent.close()
        child.close()
        if process.pid is not None and process.is_alive():
            process.join(timeout=0.5)
        if process.pid is not None and process.is_alive():
            process.terminate()
        if process.pid is not None:
            process.join(timeout=3)
        if process.pid is not None and process.is_alive():
            process.kill()
            process.join(timeout=3)
