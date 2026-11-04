"""Finite launch/provenance checks; no server, install, control or network call."""
from copy import deepcopy
import json
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import stdio_contract_check as check


class StdioContractCheckTests(unittest.TestCase):
    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def assert_code(self, code, function, *args):
        with self.assertRaises(check.ContractFailure) as caught:
            function(*args)
        self.assertEqual(str(caught.exception), code)

    def manifest(self, command, fixed=False):
        return {"mcpServers": {channel: {"command": str(command), "cwd": str(check.ROOT),
                "args": ["--flower-client", channel] if fixed else ["-m", module]}
                for channel, module in check.CHANNELS.items()}}

    def test_source_legacy_contract_and_all_entries_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "entries.json"
            value = self.manifest(check.ROOT / ".venv/Scripts/flower-python.exe")
            self.write(manifest, value)
            spec = check.launch_spec("flower-web", check.CHANNELS["flower-web"], "source", manifest)
            self.assertEqual(spec["args"], ["-m", "flower_control.web"])
            for field, invalid in (("args", ["-c", "anything"]), ("command", str(check.ROOT / "other.exe")),
                                   ("cwd", temporary), ("env", {"PYTHONPATH": temporary})):
                changed = deepcopy(value)
                changed["mcpServers"]["flower-app"][field] = invalid
                self.write(manifest, changed)
                self.assert_code("manifest_launch_boundary_changed", check.launch_spec,
                                 "flower-web", check.CHANNELS["flower-web"], "source", manifest)

    def test_fixed_manifest_only_replaces_fixed_client_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "entries.json"
            launcher = Path(temporary) / "Flower.HighHelper.exe"
            value = self.manifest(launcher, fixed=True)
            self.write(manifest, value)
            with patch.object(check, "installed_entry", return_value=(launcher, {"version": "a" * 32})):
                spec = check.launch_spec("flower-app", check.CHANNELS["flower-app"], "installed-fixed", manifest)
                self.assertEqual(spec["args"], ["--flower-probe", "flower-app"])
                self.assertEqual(spec["installation"]["version"], "a" * 32)
                value["mcpServers"]["flower-app"]["args"] = ["--flower-probe", "flower-app", "extra"]
                self.write(manifest, value)
                self.assert_code("manifest_launch_boundary_changed", check.launch_spec,
                                 "flower-app", check.CHANNELS["flower-app"], "installed-fixed", manifest)

    def test_duplicate_json_and_non_object_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema":1,"schema":1}', encoding="utf-8")
            self.assert_code("duplicate_manifest_key", check.read_json, path)
            path.write_text("[]", encoding="utf-8")
            self.assert_code("manifest_not_object", check.read_json, path)

    def test_guard_requires_first_record_current_root_channel_and_true_bool(self):
        record = {"flower_bootstrap": 1, "probe_guard_active": True, "channel": "flower-web",
                  "source_root": str(check.ROOT), "cwd": str(check.ROOT), "pid": 42}
        self.assertEqual(check.guard_provenance(json.dumps(record) + "\nlater diagnostic", "flower-web"), record)
        for field, invalid in (("probe_guard_active", False), ("probe_guard_active", 1),
                               ("flower_bootstrap", True), ("channel", "flower-app"),
                               ("cwd", str(check.ROOT.parent)), ("source_root", "."), ("pid", True), ("pid", 0)):
            changed = {**record, field: invalid}
            self.assert_code("fixed_probe_guard_provenance_mismatch", check.guard_provenance,
                             json.dumps(changed), "flower-web")
        for text in ("", "ordinary stderr\n" + json.dumps(record), "\n" + json.dumps(record)):
            self.assert_code("fixed_probe_bootstrap_missing", check.guard_provenance, text, "flower-web")

    def test_hashes_reject_escape_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            file = directory / "fixed.exe"
            file.write_bytes(b"fixture only")
            hashes = {file.name: check.digest(file)}
            check.verify_hashes(directory, hashes)
            for name in ("../fixed.exe", "..\\fixed.exe", "C:fixed.exe", ".", ".."):
                self.assert_code("fixed_installation_hashes_invalid", check.verify_hashes,
                                 directory, {name: "a" * 64})
            file.write_bytes(b"changed fixture")
            self.assert_code("fixed_installation_hash_mismatch", check.verify_hashes, directory, hashes)

    def fixed_fixture(self, directory):
        repository = directory / "repository"
        source = repository / "flower_control/drivers/high_helper.py"
        source.parent.mkdir(parents=True)
        source.write_text('_BUNDLE_NAMES = ("Flower.HighHelper.exe", "Flower.HighHelper.dll", '
                          '"Flower.HighHelper.deps.json", "Flower.HighHelper.runtimeconfig.json")\n', encoding="utf-8")
        bootstrap = source.parent / "high_helper/flower_bootstrap.py"
        bootstrap.parent.mkdir()
        bootstrap.write_text("# fixture, never executed\n", encoding="utf-8")
        production = directory / "program-files/FlowerControl/HighHelper"
        version = "a" * 32
        installed = production / "versions" / version
        installed.mkdir(parents=True)
        names = ["Flower.HighHelper.exe", "Flower.HighHelper.dll", "Flower.HighHelper.deps.json",
                 "Flower.HighHelper.runtimeconfig.json", "flower-python.exe", "flower-python._pth"]
        for name in names:
            (installed / name).write_bytes(b"fixture, never executed")
        (installed / "flower_bootstrap.py").write_bytes(bootstrap.read_bytes())
        app = installed / "app/Flower.AppWorker.exe"
        app.parent.mkdir()
        app.write_bytes(b"fixture, never executed")
        sources = {p.relative_to(repository).as_posix(): check.digest(p)
                   for p in (repository / "flower_control").rglob("*.py")}
        sources["@bootstrap"] = check.digest(bootstrap)
        policy = {"Schema": 1, "Version": version, "Repository": str(repository), "Mode": "high",
                  "Python": {"Path": str(installed / "flower-python.exe"), "Sha256": check.digest(installed / "flower-python.exe")},
                  "SourceHashes": sources, "AppWorkerHashes": {app.name: check.digest(app)}}
        self.write(installed / "broker.json", policy)
        active = {"schema": 1, "version": version,
                  "hashes": {p.name: check.digest(p) for p in installed.iterdir() if p.is_file()}}
        self.write(production / "active.json", active)
        self.write(installed / "installation.json", active)
        return repository, production, installed, active

    def test_fixed_installation_actual_hash_inventory_and_source_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, production, installed, active = self.fixed_fixture(Path(temporary))
            with patch.object(check, "ROOT", repository), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                launcher, found = check.installed_entry()
                self.assertEqual(launcher, installed / "Flower.HighHelper.exe")
                self.assertEqual(found, active)
                (repository / "flower_control/new.py").write_text("# source changed\n", encoding="utf-8")
                self.assert_code("fixed_installation_source_changed", check.installed_entry)

    def test_missing_required_hash_and_installation_manifest_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, production, installed, active = self.fixed_fixture(Path(temporary))
            with patch.object(check, "ROOT", repository), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                self.write(installed / "installation.json", {**active, "version": "b" * 32})
                self.assert_code("fixed_installation_manifest_mismatch", check.installed_entry)
                del active["hashes"]["flower-python._pth"]
                self.write(production / "active.json", active)
                self.assert_code("fixed_installation_required_hashes_missing", check.installed_entry)

    def test_unlisted_installed_file_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, production, installed, _ = self.fixed_fixture(Path(temporary))
            with patch.object(check, "ROOT", repository), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                (installed / "unlisted.dll").write_bytes(b"fixture, never executed")
                self.assert_code("fixed_installation_inventory_mismatch", check.installed_entry)

    def frozen_fixture(self, directory):
        repository, production, installed, active = self.fixed_fixture(directory)
        actual = installed / "python-source"
        shutil.copytree(repository, actual)
        source_bootstrap = actual / "flower_control/drivers/high_helper/flower_hook_bootstrap.py"
        source_bootstrap.write_text("# fixed fake hook, never run\n", encoding="utf-8")
        (installed / "flower_hook_bootstrap.py").write_bytes(source_bootstrap.read_bytes())
        hook = actual / "hooks/pre_tool_use.py"
        hook.parent.mkdir()
        hook.write_text("# source hook is hashed, never executed\n", encoding="utf-8")
        registry = actual / "flower_control/authorization/hook_bridge.py"
        registry.parent.mkdir()
        registry.write_text("WEB_TOOLS=('frozen_only',)\nAPP_TOOLS=('frozen_app',)\nAPP_TOOLS+=('another_app',)\nCOMPUTER_TOOLS=('frozen_computer',)\n", encoding="utf-8")
        status = actual / "flower_control/_status.py"
        status.write_text("@server.tool(name='flower_status',description='Frozen status')\ndef status():pass\n", encoding="utf-8")
        for name in ("web", "app", "computer"):
            (actual / "flower_control" / (name + ".py")).write_text(
                ("" if name == "web" else status.read_text()) +
                "@server.tool(name='" + ("frozen_only" if name == "web" else "frozen_" + name) +
                "',description='Frozen declaration')\ndef fake():pass\n", encoding="utf-8")
        runtime = installed / "runtime/Lib/fake.py"
        runtime.parent.mkdir(parents=True)
        runtime.write_text("# fake stdlib bytes, never executed\n", encoding="utf-8")
        wgc = installed / "wgc/Flower.ComputerWgc.exe"
        wgc.parent.mkdir()
        wgc.write_bytes(b"fake WGC, never executed")
        policy = check.read_json(installed / "broker.json")
        policy["Repository"] = str(actual)
        policy["SourceHashes"] = {p.relative_to(actual).as_posix():check.digest(p)
            for p in (actual / "flower_control").rglob("*.py")}
        policy["SourceHashes"]["hooks/pre_tool_use.py"] = check.digest(hook)
        policy["SourceHashes"]["@bootstrap"] = check.digest(actual / "flower_control/drivers/high_helper/flower_bootstrap.py")
        policy["WgcWorkerHashes"] = {wgc.name:check.digest(wgc)}
        site = installed / "python-source/.venv/Lib/site-packages"
        (installed / "flower-python._pth").write_text("\n".join(map(str, (installed / "runtime/Lib", installed / "runtime/DLLs", site,
                   site / "win32", site / "win32/lib", site / "pythonwin", actual))) + "\n", encoding="utf-8")
        active["runtime_hashes"] = {p.relative_to(installed).as_posix():check.digest(p)
            for subtree in (actual, installed / "runtime") for p in subtree.rglob("*") if p.is_file()}
        runtime_manifest = {"schema":1,"files":active["runtime_hashes"],
            "dependency_inventory_sha256":hashlib.sha256(json.dumps(active["runtime_hashes"],sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "downloads":False,"data_migrated":False}
        self.write(installed / "runtime-inventory.json", runtime_manifest)
        policy["RuntimeInventorySha256"] = check.digest(installed / "runtime-inventory.json")
        self.reseal_fixture(production, installed, active, policy)
        return repository, production, installed, active, policy

    def reseal_fixture(self, production, installed, active, policy):
        self.write(installed / "broker.json", policy)
        active["hashes"] = {p.name:check.digest(p) for p in installed.iterdir()
                            if p.is_file() and p.name != "installation.json"}
        self.write(production / "active.json", active)
        self.write(installed / "installation.json", active)

    def test_frozen_pth_cannot_import_site_or_point_at_moving_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            moving, production, installed, active, policy = self.frozen_fixture(Path(temporary))
            (installed / "flower-python._pth").write_text(str(moving) + "\nimport site\n", encoding="utf-8")
            self.reseal_fixture(production, installed, active, policy)
            with patch.object(check, "ROOT", moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                self.assert_code("fixed_runtime_python_path_invalid", check.installed_entry)

    def test_frozen_pth_accepts_windows_slash_spelling_for_the_same_fixed_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            moving, production, installed, active, policy = self.frozen_fixture(Path(temporary))
            path = installed / "flower-python._pth"
            path.write_text(path.read_text().replace("\\", "/"), encoding="utf-8")
            self.reseal_fixture(production, installed, active, policy)
            with patch.object(check, "ROOT", moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                self.assertEqual(check.installed_entry()[1], active)

    def test_frozen_actual_repository_and_nested_inventory_survive_moving_root_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            moving, production, installed, active, _ = self.frozen_fixture(Path(temporary))
            with patch.object(check,"ROOT",moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                self.assertEqual(check.installed_entry(), (installed / "Flower.HighHelper.exe", active))
                actual = installed / "python-source"
                entrypoint, declared = check.source_contract("flower-web",check.CHANNELS["flower-web"],actual)
                before = check.loaded_source(str(entrypoint))
                self.assertEqual(set(declared), {"flower_status","frozen_only"})
                (moving / "flower_control/changed.py").write_text("# moving source must not be guessed\n",encoding="utf-8")
                self.assertEqual(check.installed_entry()[1], active)
                self.assertEqual(check.loaded_source(str(entrypoint)), before)
                manifest = Path(temporary) / "entries.json"
                value = self.manifest(installed / "Flower.HighHelper.exe", fixed=True)
                for row in value["mcpServers"].values():
                    row["cwd"] = str(actual)
                self.write(manifest,value)
                spec = check.launch_spec("flower-web",check.CHANNELS["flower-web"],"installed-fixed",manifest)
                self.assertEqual(spec["cwd"],str(actual))
                record = {"flower_bootstrap":1,"probe_guard_active":True,"channel":"flower-web","source_root":str(actual),"cwd":str(actual),"pid":42}
                check.guard_provenance(json.dumps(record),"flower-web",actual)
                self.assert_code("fixed_probe_guard_provenance_mismatch",check.guard_provenance,json.dumps({**record,"cwd":str(moving)}),"flower-web",actual)
                value["mcpServers"]["flower-app"]["cwd"] = str(moving)
                self.write(manifest,value)
                self.assert_code("manifest_launch_boundary_changed",check.launch_spec,"flower-web",check.CHANNELS["flower-web"],"installed-fixed",manifest)

    def test_frozen_rejects_changed_nested_bytes_missing_and_extra_companions(self):
        cases = (("changed", "fixed_runtime_hash_mismatch"), ("extra", "fixed_installation_inventory_mismatch"),
                 ("missing-wgc", "fixed_installation_hash_mismatch"), ("extra-app", "fixed_installation_inventory_mismatch"))
        for case, code in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                moving, production, installed, _, _ = self.frozen_fixture(Path(temporary))
                if case == "changed":
                    (installed / "runtime/Lib/fake.py").write_text("changed",encoding="utf-8")
                elif case == "extra":
                    (installed / "runtime/Lib/unlisted.dll").write_bytes(b"unlisted")
                elif case == "missing-wgc":
                    (installed / "wgc/Flower.ComputerWgc.exe").unlink()
                else:
                    (installed / "app/unlisted.dll").write_bytes(b"unlisted")
                with patch.object(check,"ROOT",moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                    self.assert_code(code,check.installed_entry)

    def test_frozen_rejects_arbitrary_repository_runtime_escape_and_manifest_pin(self):
        for case, code in (("repo","fixed_installation_policy_binding_mismatch"),
                           ("pin","fixed_runtime_manifest_pin_mismatch"),
                           ("files","fixed_runtime_manifest_mismatch"),
                           ("hook","fixed_installation_hook_source_changed")):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                moving, production, installed, active, policy = self.frozen_fixture(Path(temporary))
                if case == "repo":
                    policy["Repository"] = str(moving)
                elif case == "pin":
                    policy["RuntimeInventorySha256"] = "a" * 64
                elif case == "hook":
                    (installed / "flower_hook_bootstrap.py").write_text("# wrong source hook",encoding="utf-8")
                else:
                    manifest = check.read_json(installed / "runtime-inventory.json")
                    manifest["files"] = {}
                    self.write(installed / "runtime-inventory.json",manifest)
                    policy["RuntimeInventorySha256"] = check.digest(installed / "runtime-inventory.json")
                self.reseal_fixture(production,installed,active,policy)
                with patch.object(check,"ROOT",moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                    self.assert_code(code,check.installed_entry)
        for name in ("../outside", "runtime/../outside", "runtime//fake", "runtime/./fake", "runtime\\fake", "C:/fake", "app/escape"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                moving, production, installed, active, policy = self.frozen_fixture(Path(temporary))
                active["runtime_hashes"][name] = "a" * 64
                self.reseal_fixture(production,installed,active,policy)
                with patch.object(check,"ROOT",moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                    self.assert_code("fixed_runtime_hashes_invalid",check.installed_entry)

    def test_frozen_source_hooks_and_registry_are_version_local(self):
        with tempfile.TemporaryDirectory() as temporary:
            moving, production, installed, active, policy = self.frozen_fixture(Path(temporary))
            actual = installed / "python-source"
            # Deliberately remove only the policy source binding; runtime still
            # verifies the exact original hook bytes, exposing the missing gate.
            del policy["SourceHashes"]["hooks/pre_tool_use.py"]
            self.reseal_fixture(production,installed,active,policy)
            with patch.object(check,"ROOT",moving), patch("flower_control.install_location.discover_installation", return_value=SimpleNamespace(program_root=production, legacy=True)):
                self.assert_code("fixed_installation_source_changed",check.installed_entry)
            registry = actual / "flower_control/authorization/hook_bridge.py"
            registry.write_text("WEB_TOOLS=dynamic()\nAPP_TOOLS=()\nCOMPUTER_TOOLS=()\n",encoding="utf-8")
            self.assert_code("fixed_source_hook_registry_invalid",check.hook_registry,actual)


if __name__ == "__main__":
    unittest.main()
