"""Measure repeated local bundle checks on real self-contained publish bytes.

This uses an owned TEMP installation fixture. Only its ACL admission is
synthetic; no production registry, helper, process, Stop or input is touched.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from flower_control.drivers import high_helper as helper


def probe(native_bin, samples=8):
    with tempfile.TemporaryDirectory(prefix="flower-local-immutable-probe-") as temporary:
        root = Path(temporary) / "Program"
        version = "a" * 32
        target = root / "versions" / version
        target.mkdir(parents=True)
        for path in Path(native_bin).iterdir():
            if path.is_file() and path.suffix.lower() in {".exe", ".dll", ".json"}:
                if path.is_symlink() or path.is_junction():
                    raise ValueError("probe_input_link_rejected")
                shutil.copyfile(path, target / path.name)
        nested = {"runtime/probe.txt": hashlib.sha256(b"owned probe metadata").hexdigest()}
        manifest = dict(schema=1, files=nested, dependency_inventory_sha256="1" * 64, downloads=False, data_migrated=False)
        (target / "runtime-inventory.json").write_text(json.dumps(manifest))
        hashes = {path.name: helper._digest(path) for path in target.iterdir() if path.is_file()}
        active = dict(schema=1, version=version, hashes=hashes, runtime_hashes=nested)
        (root / "active.json").write_text(json.dumps(active))
        (target / "installation.json").write_text(json.dumps(active))
        before, after = [], []
        with patch.object(helper, "program_root", return_value=root), patch.object(helper, "require_protected_path"):
            immutable = helper._immutable_dotnet_dependencies(target, active)
            # Warm both paths, then alternate to reduce cache/order bias.
            helper._installed_bundle()
            with patch.object(helper, "_immutable_dotnet_dependencies", return_value=frozenset()):
                helper._installed_bundle()
            for _ in range(samples):
                started = time.perf_counter()
                with patch.object(helper, "_immutable_dotnet_dependencies", return_value=frozenset()):
                    helper._installed_bundle()
                before.append(time.perf_counter() - started)
                started = time.perf_counter()
                helper._installed_bundle()
                after.append(time.perf_counter() - started)
        return dict(schema=1, probe="local_repeated_installed_bundle", samples=samples,
            flat_files=len(hashes), immutable_runtimepack_files=len(immutable),
            immutable_bytes=sum((target / name).stat().st_size for name in immutable),
            before_seconds=before, after_seconds=after,
            before_median_seconds=statistics.median(before), after_median_seconds=statistics.median(after),
            before_range_seconds=[min(before), max(before)], after_range_seconds=[min(after), max(after)],
            admission="synthetic TEMP ACL boundary; real publish bytes and source bundle checker",
            subprocess_started=False, production_accessed=False,
            interpretation="bundle hashing cost only; not full MCP connection or foreground latency")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.native_bin)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
