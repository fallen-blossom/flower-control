"""Build one existing native project and record the exact source/binary bytes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from tools.prepare_high_broker_install import digest, write_json


ROOT = Path(__file__).resolve().parents[1]


def sources(directory, kind):
    extensions = {".cs", ".csproj", ".manifest"} if kind == "native" else {".cs", ".csproj"}
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in directory.iterdir()
            if p.suffix in extensions or p.name == "packages.lock.json"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("native", "app"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    options = parser.parse_args()
    kind = options.kind
    directory = ROOT / "flower_control/drivers" / ("high_helper" if kind == "native" else "app_native")
    project = directory / ("Flower.HighHelper.csproj" if kind == "native" else "Flower.AppWorker.csproj")
    output, evidence = options.output.resolve(), options.evidence.resolve()
    if output.exists() or evidence.exists():
        raise RuntimeError("daily_build_destination_exists")
    before = sources(directory, kind)
    command = ["dotnet", "build", str(project), "-c", "Release", "--no-restore",
               "--no-incremental", "-o", str(output)]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    after = sources(directory, kind)
    names = ("Flower.HighHelper.exe", "Flower.HighHelper.dll", "Flower.HighHelper.deps.json",
             "Flower.HighHelper.runtimeconfig.json")
    binaries = ({name: digest(output / name) for name in names} if kind == "native" else
                {p.name: digest(p) for p in output.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}) if completed.returncode == 0 else {}
    evidence.parent.mkdir(parents=True, exist_ok=True)
    record = dict(schema=1, build_exit_code=completed.returncode,
                  source_hashes=before, binary_hashes=binaries,
                  source_unchanged_during_build=before == after, build_command=command,
                  installed=False, benchmark_started=False)
    record[kind + "_bin"] = str(output)
    write_json(evidence, record)
    (output.parent / (kind + "-build.log")).write_bytes(completed.stdout + completed.stderr)
    if completed.returncode != 0 or before != after:
        raise RuntimeError("daily_build_failed_or_source_changed")
    print(json.dumps({"kind": kind, "build_exit_code": 0, "source_files": len(before),
                      "binary_files": len(binaries), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
