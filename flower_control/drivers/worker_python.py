"""Use the source repository's venv for short-lived Windows workers.

The installed stdio interpreter has an isolated prefix and initializes
pywin32 DLL directories in its channel bootstrap. Child processes do not
inherit that initialization. The source venv launcher resolves its runtime
and initializes its own dependencies even with our minimal environment.
"""

from __future__ import annotations

import sys
from pathlib import Path


def worker_python() -> str:
    repository_launcher = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "python.exe"
    if repository_launcher.is_file():
        return str(repository_launcher)
    launcher = Path(sys.prefix) / "Scripts" / "python.exe"
    return str(launcher) if launcher.is_file() else sys.executable
