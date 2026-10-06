"""Install a direct CPython executable inside this project's venv.

Windows venv python.exe is a redirector that leaves a second process beside
each idle stdio MCP server. A copy of the matching base executable keeps the
venv's pyvenv.cfg and site-packages while running as one process.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
DESTINATION = VENV / "Scripts" / "flower-python.exe"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    if Path(sys.prefix).resolve() != VENV.resolve():
        raise SystemExit("Run with this project's .venv/Scripts/python.exe")
    source = Path(sys._base_executable).resolve(strict=True)
    if source == DESTINATION.resolve():
        raise SystemExit("Base executable unexpectedly points at destination")
    if DESTINATION.is_file() and digest(source) == digest(DESTINATION):
        print(f"Direct venv Python ready: {DESTINATION}")
        return
    shutil.copyfile(source, DESTINATION)
    if digest(source) != digest(DESTINATION):
        raise SystemExit("Direct Python copy did not match the base executable")
    print(f"Direct venv Python ready: {DESTINATION}")


if __name__ == "__main__":
    main()
