"""Installed fixed-channel bootstrap; invoked only by the protected launcher."""
import json
import os
from pathlib import Path
import runpy
import sys


def main():
    modules = {"flower-web": "flower_control.web", "flower-app": "flower_control.app",
               "flower-computer": "flower_control.computer"}
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in modules or len(sys.argv) == 3 and sys.argv[2] != "probe":
        raise SystemExit(2)
    root = Path(__file__).resolve().parent
    policy = json.loads((root / "broker.json").read_bytes())
    source = Path(policy["Repository"])
    probe = len(sys.argv) == 3
    if probe:
        # asyncio's local socketpair is allowed. No DNS or external connection,
        # subprocess, browser, provider worker or child can escape this probe.
        def audit(event, args):
            if event == "socket.connect":
                address = args[1]
                if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1", "localhost"):
                    raise OSError("flower_probe_network_blocked")
            elif event == "socket.getaddrinfo" and args[0] not in ("127.0.0.1", "::1", "localhost", None):
                raise OSError("flower_probe_network_blocked")
            elif event in {"socket.sendto", "subprocess.Popen", "os.system", "os.spawn"}:
                raise OSError("flower_probe_external_operation_blocked")
        sys.addaudithook(audit)
    # No user site, PYTHONPATH, sitecustomize or arbitrary .pth execution.
    # Paths are supplied by the protected flower-python._pth installation.
    dll_directory = source / ".venv" / "Lib" / "site-packages" / "pywin32_system32"
    dll_handle = os.add_dll_directory(str(dll_directory))
    sys.dont_write_bytecode = True
    sys.pycache_prefix = str(root / "unused-bytecode")
    os.chdir(source)
    print(json.dumps({"flower_bootstrap": 1, "channel": sys.argv[1], "probe_guard_active": probe,
                      "source_root": str(source), "cwd": os.getcwd(), "pid": os.getpid()}), file=sys.stderr, flush=True)
    sys.argv = [modules[sys.argv[1]]]
    try:
        runpy.run_module(sys.argv[0], run_name="__main__", alter_sys=True)
    finally:
        dll_handle.close()


if __name__ == "__main__":
    main()
