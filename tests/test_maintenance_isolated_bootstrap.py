"""Real no-site Python child: the CLI must initialize pywin32 DLLs itself."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import win32api
from tools import settings_portability as portable

ROOT = Path(__file__).resolve().parents[1]


class MaintenanceIsolatedBootstrapTests(unittest.TestCase):
    def test_fixed_maintenance_clis_bootstrap_dlls_with_site_disabled_and_clean_path(self):
        base = Path(sys.base_prefix)
        site = Path(win32api.__file__).parent.parent
        with tempfile.TemporaryDirectory(prefix="flower-maintenance-isolated-") as temporary:
            root = Path(temporary)
            executable = root / "flower-python.exe"
            shutil.copyfile(base / "python.exe", executable)
            for name in (f"python{sys.version_info.major}{sys.version_info.minor}.dll", "python3.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
                if (base / name).is_file():
                    shutil.copyfile(base / name, root / name)
            dlls = root / "Lib/site-packages/pywin32_system32"
            dlls.mkdir(parents=True)
            for path in (site / "pywin32_system32").glob("*.dll"):
                shutil.copyfile(path, dlls / path.name)
            paths = [base / "Lib", base / "DLLs", site, site / "win32", site / "win32/lib", site / "pythonwin", ROOT]
            (root / "flower-python._pth").write_text("\n".join(map(str, paths)) + "\n", encoding="utf-8")
            source = root / "backup.json"
            source.write_text(json.dumps(dict(schema=1, kind=portable.KIND, created_utc="fixture", settings={}, preferences={},
                fixed_shortcuts=portable.SHORTCUTS, excluded=portable.EXCLUDED)))
            code = r'''
import importlib.util, pathlib, sys
try:
    import win32api
except ImportError:
    pass
else:
    raise AssertionError('pywin32 unexpectedly available before explicit initialization')
from flower_control.drivers import worker_bootstrap
original = worker_bootstrap.initialize_dlls
def checked_initialize():
    original()
    import win32api
    sys.stderr.write('explicit_dll_bootstrap_passed\n')
worker_bootstrap.initialize_dlls = checked_initialize
path = pathlib.Path(sys.argv[1])
owned_root = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('isolated_maintenance_cli', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if path.name == 'storage_maintenance.py':
    from flower_control.install_location import prepare_location
    module.discover_installation = lambda: prepare_location(owned_root / 'fake-install', 'S-1-5-21-1-2-3-1001')
    sys.argv = [str(path), 'usage']
else:
    sys.argv = [str(path), 'review', '--input', str(pathlib.Path(sys.argv[2]) / 'backup.json'), '--output', str(pathlib.Path(sys.argv[2]) / 'review.json')]
module.main()
'''
            environment = {**os.environ, "PATH": str(Path(os.environ["SystemRoot"]) / "System32")}
            for name in ("settings_portability.py", "storage_maintenance.py"):
                with self.subTest(name=name):
                    result = subprocess.run([str(executable), "-I", "-S", "-B", "-c", code, str(ROOT / "tools" / name), str(root)],
                        capture_output=True, text=True, env=environment, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("explicit_dll_bootstrap_passed", result.stderr)


if __name__ == "__main__":
    unittest.main()
