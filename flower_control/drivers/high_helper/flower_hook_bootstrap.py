"""Fixed protected Hook entry with the same source/dependency/data roots as MCP."""
import json
import os
from pathlib import Path
import runpy
import sys


def main():
    if sys.argv[1:] not in ([], ["--host-phase"], ["--dsh-phase"]):
        raise SystemExit(2)
    script = {(): "pre_tool_use.py", ("--host-phase",): "host_phase.py", ("--dsh-phase",): "dsh_phase.py"}[tuple(sys.argv[1:])]
    root = Path(__file__).resolve().parent
    policy = json.loads((root / "broker.json").read_bytes())
    source = Path(policy["Repository"])
    if policy.get("DataRoot"):
        os.environ["FLOWER_DATA_ROOT"] = policy["DataRoot"]
    dll = source / ".venv/Lib/site-packages/pywin32_system32"
    sys.dont_write_bytecode = True
    with os.add_dll_directory(str(dll)):
        sys.argv = [str(source / "hooks" / script)]
        runpy.run_path(sys.argv[0], run_name="__main__")


if __name__ == "__main__":
    main()
