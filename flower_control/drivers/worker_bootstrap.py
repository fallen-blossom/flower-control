"""Initialize fixed local DLLs before importing one of four private workers.

The immutable runtime uses an isolated CPython executable without ``site``.
DLL directory registrations are process-local and must be repeated in children.
This module has no state, target, grant, capture, input or network behavior.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import runpy
import sys

from .worker_python import WORKER_MODULES

_dll_handles: list[object] = []


def initialize_dlls() -> None:
    if os.name != "nt":
        return
    repository = Path(__file__).resolve().parents[2]
    source_site = repository / ".venv" / "Lib" / "site-packages"
    # Frozen packages always use their version-local site. A development
    # candidate may use the already selected interpreter's admitted venv.
    site = source_site if source_site.is_dir() else Path(sys.prefix) / "Lib" / "site-packages"
    directory = site / "pywin32_system32"
    if directory.is_dir():
        _dll_handles.append(os.add_dll_directory(str(directory)))


def main() -> None:
    arguments = sys.argv[1:]
    import_only = bool(arguments and arguments[0] == "--import-only")
    if import_only:
        arguments = arguments[1:]
    if not arguments or arguments[0] not in WORKER_MODULES:
        raise SystemExit("private_worker_module_rejected")
    module, *worker_arguments = arguments
    if import_only and worker_arguments:
        raise SystemExit("private_worker_import_probe_arguments_rejected")
    initialize_dlls()
    if import_only:
        importlib.import_module("win32api")
        importlib.import_module(module)
        print(json.dumps({"module": module, "imported": True,
                          "dispatched": False, "captured": False}))
        return
    sys.argv = [module, *worker_arguments]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
