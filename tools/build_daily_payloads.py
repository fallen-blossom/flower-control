"""Build one existing native project and record the exact source/binary bytes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.prepare_high_broker_install import digest, write_json, native_source_hashes, native_binary_hashes


def sources(directory, kind):
    if kind == "native":
        return native_source_hashes(ROOT)
    extensions = {".cs", ".csproj"}
    result = {p.relative_to(ROOT).as_posix(): digest(p) for p in directory.iterdir()
            if p.suffix in extensions or p.name == "packages.lock.json"}
    return result


def build(directory, project, output, kind, compiler_setup=None):
    """Build only; the optional native DLL precedes the normal .NET build."""
    commands, log = [], b""
    identity = kind == "native" and (directory / "program_identity_native.cpp").is_file()
    uac = kind == "native" and (directory / "uac_native.cpp").is_file()
    if kind == "native":
        temporary_root = Path(tempfile.gettempdir()).resolve()
        if not output.is_relative_to(temporary_root) or output == temporary_root:
            raise RuntimeError("native_build_output_must_be_os_temp")
    if identity or uac:
        script = ROOT / ("tools/build_identity_native.ps1" if identity else "tools/build_uac_native.ps1")
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        commands.append([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
                         "-OutputDirectory", str(output)])
        if compiler_setup is not None:
            commands[-1].extend(["-CompilerSetup", str(compiler_setup)])
        completed = subprocess.run(commands[-1], cwd=ROOT, capture_output=True, timeout=180,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        log += completed.stdout + completed.stderr
        if completed.returncode != 0:
            return completed.returncode, commands, log
    commands.append(["dotnet", "build", str(project), "-c", "Release", "--no-restore",
                     "--no-incremental", "-o", str(output)])
    completed = subprocess.run(commands[-1], cwd=ROOT, capture_output=True, timeout=180,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    return completed.returncode, commands, log + completed.stdout + completed.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("native", "app"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--compiler-setup", type=Path,
                        help="Optional absolute vcvarsall.bat path for a nonstandard native C++ toolchain")
    options = parser.parse_args()
    kind = options.kind
    if options.compiler_setup is not None and (kind != "native" or not options.compiler_setup.is_absolute()):
        parser.error("--compiler-setup requires native and an absolute local path")
    directory = ROOT / "flower_control/drivers" / ("high_helper" if kind == "native" else "app_native")
    project = directory / ("Flower.HighHelper.csproj" if kind == "native" else "Flower.AppWorker.csproj")
    output, evidence = options.output.resolve(), options.evidence.resolve()
    if output.exists() or evidence.exists():
        raise RuntimeError("daily_build_destination_exists")
    before = sources(directory, kind)
    exit_code, commands, log = build(directory, project, output, kind, options.compiler_setup)
    after = sources(directory, kind)
    binaries = (native_binary_hashes(ROOT, output) if kind == "native" else
                {p.name: digest(p) for p in output.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}) if exit_code == 0 else {}
    evidence.parent.mkdir(parents=True, exist_ok=True)
    record = dict(schema=1, build_exit_code=exit_code,
                  source_hashes=before, binary_hashes=binaries,
                  source_unchanged_during_build=before == after, build_command=commands[-1], build_commands=commands,
                  installed=False, benchmark_started=False)
    record[kind + "_bin"] = str(output)
    write_json(evidence, record)
    (output.parent / (kind + "-build.log")).write_bytes(log)
    if exit_code != 0 or before != after:
        raise RuntimeError("daily_build_failed_or_source_changed")
    print(json.dumps({"kind": kind, "build_exit_code": 0, "source_files": len(before),
                      "binary_files": len(binaries), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
