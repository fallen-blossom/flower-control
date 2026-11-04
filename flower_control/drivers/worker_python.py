"""Fixed interpreter and DLL bootstrap for each short-lived private worker."""

from __future__ import annotations

import sys
from pathlib import Path

WORKER_MODULES = frozenset({
    "flower_control.drivers.app_worker",
    "flower_control.drivers.computer_capture_worker",
    "flower_control.drivers.computer_capture_session_worker",
    "flower_control.drivers.web_worker",
})


def worker_python() -> str:
    repository_launcher = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "python.exe"
    if repository_launcher.is_file():
        return str(repository_launcher)
    launcher = Path(sys.prefix) / "Scripts" / "python.exe"
    return str(launcher) if launcher.is_file() else sys.executable


def worker_command(module: str, *arguments: str) -> list[str]:
    """No arbitrary module or script path; initialization precedes pywin32 imports."""
    if module not in WORKER_MODULES or any(type(value) is not str for value in arguments):
        raise ValueError("private_worker_command_rejected")
    return [worker_python(), "-B", "-m", "flower_control.drivers.worker_bootstrap", module, *arguments]
