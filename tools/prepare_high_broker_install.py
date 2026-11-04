"""Prepare a reviewable local package. Never installs, elevates or registers."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

# Allow `python tools/prepare_high_broker_install.py` from the repository root
# without requiring the caller to set PYTHONPATH or use -m.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.windows_hook_command import hook_command

NATIVE_BUNDLE_NAMES = ("Flower.HighHelper.exe", "Flower.HighHelper.dll",
                       "Flower.HighHelper.deps.json", "Flower.HighHelper.runtimeconfig.json")
UAC_NATIVE_NAME = "Flower.UacNative.dll"
UAC_ALLOWLIST_FIXTURE_SOURCES = ("tests/fixtures/uac_allowlist_runtime/fixture.cpp",
                                 "tests/fixtures/uac_allowlist_runtime/build.ps1")
UAC_ALLOWLIST_FIXTURE_NAMES = ("Flower.UacAllowlistFixture.exe", "Flower.UacAllowlistFixture.changed.exe")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def media_encoder_license(media_encoder: Path) -> Path:
    """Resolve the already-admitted GPL text beside an installed ffmpeg.exe.

    Current frozen versions place LICENSE beside ffmpeg.exe. Retain the older
    parent-of-bin layout as a read-only compatibility fallback; never search
    PATH or accept an unrelated file supplied by the caller.
    """
    encoder = Path(media_encoder)
    for candidate in (encoder.parent / "LICENSE", encoder.parent.parent / "LICENSE"):
        if candidate.is_file():
            return candidate
    raise ValueError("media_encoder_license_required")


def render_high_task(user_sid: str, target: Path) -> str:
    """Keep the interactive broker at Normal priority, rather than Task Scheduler's background default."""
    command = str(target / "Flower.HighHelper.exe")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <RegistrationInfo><Description>Flower Control 当前用户交互登录会话的全局 High 执行器</Description></RegistrationInfo>
 <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(user_sid)}</UserId></LogonTrigger></Triggers>
 <Principals><Principal id="FlowerUser"><UserId>{escape(user_sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled><Priority>6</Priority></Settings>
 <Actions Context="FlowerUser"><Exec><Command>{escape(command)}</Command><Arguments>--serve</Arguments><WorkingDirectory>{escape(str(target))}</WorkingDirectory></Exec></Actions>
</Task>
"""


class ExistingNativeHostPins:
    """Retain protected old identity metadata; never enroll current image bytes."""
    def __init__(self, production, user_sid):
        from tools.runtime_snapshot import reject_links
        self.active_path = Path(production) / "active.json"
        self.active_bytes = self._read(self.active_path, 16 * 1024 * 1024)
        active = self._decode(self.active_bytes)
        version = active.get("version")
        if (type(active.get("schema")) is not int or active["schema"] != 1
                or type(version) is not str or not re.fullmatch("[a-f0-9]{32}", version)
                or type(active.get("hashes")) is not dict):
            raise ValueError("existing_native_host_metadata_rejected")
        self.policy_path = Path(production) / "versions" / version / "broker.json"
        self.policy_bytes = self._read(self.policy_path, 256000)
        policy = self._decode(self.policy_bytes)
        if (active["hashes"].get("broker.json") != hashlib.sha256(self.policy_bytes).hexdigest()
                or type(policy.get("Schema")) is not int or policy["Schema"] != 1
                or policy.get("Version") != version or policy.get("UserSid") != user_sid
                or policy.get("Mode") != "high" or policy.get("FixturePipe", "") != ""
                or policy.get("FixturePeers", []) != [] or policy.get("AdditionalAgents", []) != []):
            raise ValueError("existing_native_host_metadata_rejected")
        data_root = policy.get("DataRoot")
        if (type(data_root) is not str or not data_root or not Path(data_root).is_absolute()
                or data_root.startswith("\\\\") or "*" in data_root or "?" in data_root):
            raise ValueError("existing_native_host_metadata_rejected")
        hosts = policy.get("NativeHosts")
        if type(hosts) is not list or len(hosts) > 16:
            raise ValueError("existing_native_host_metadata_rejected")
        for host in hosts:
            if (type(host) is not dict or not {"Kind", "Path", "Sha256"}.issubset(host)
                    or set(host) - {"Kind", "Path", "Sha256", "RuntimeSha256"}
                    or type(host["Kind"]) is not str or type(host["Path"]) is not str or type(host["Sha256"]) is not str
                    or not re.fullmatch("[a-f0-9]{64}", host["Sha256"])):
                raise ValueError("existing_native_host_metadata_rejected")
            image = Path(host["Path"])
            expected = {"claude-code": "claude.exe", "antigravity": "antigravity.exe",
                "dsh-desktop": "deepseek harness.exe", "local-mcp": image.name.lower()}.get(host["Kind"])
            if (expected is None or not image.is_absolute() or str(image).startswith("\\\\")
                    or ".." in image.parts or any(value in str(image) for value in "*?")
                    or image.name.lower() != expected or not image.is_file()
                    or host["Kind"] == "local-mcp" and expected not in
                        {"cursor.exe", "code.exe", "code - insiders.exe", "opencode.exe", "antigravity.exe", "claude.exe"}
                    or (host["Kind"] == "dsh-desktop" and (type(host.get("RuntimeSha256")) is not str
                        or not re.fullmatch("[a-f0-9]{64}", host["RuntimeSha256"])))
                    or host["Kind"] != "dsh-desktop" and host.get("RuntimeSha256") is not None):
                raise ValueError("existing_native_host_metadata_rejected")
            reject_links(image)
            if host["Kind"] == "dsh-desktop":
                runtime = image.parent / "resources/app.asar"
                reject_links(runtime)
                if not runtime.is_file():
                    raise ValueError("existing_native_host_metadata_rejected")
        if len({host["Path"].casefold() for host in hosts}) != len(hosts):
            raise ValueError("existing_native_host_metadata_rejected")
        self.hosts = hosts  # Preserve every old field/value/order, including stale hashes.
        self.data_root = data_root
        self.version = version
        self.require_unchanged()

    @staticmethod
    def _decode(data):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("existing_native_host_metadata_rejected")
                result[key] = value
            return result
        value = json.loads(data, object_pairs_hook=unique)
        if type(value) is not dict:
            raise ValueError("existing_native_host_metadata_rejected")
        return value

    @staticmethod
    def _read(path, maximum):
        from tools.runtime_snapshot import reject_links
        reject_links(path)
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        reject_links(path)
        if not 1 <= len(data) <= maximum:
            raise ValueError("existing_native_host_metadata_rejected")
        return data

    def require_unchanged(self):
        if (self._read(self.active_path, 16 * 1024 * 1024) != self.active_bytes
                or self._read(self.policy_path, 256000) != self.policy_bytes):
            raise RuntimeError("existing_native_host_metadata_changed")

    def evidence(self):
        return dict(version=self.version, active_sha256=hashlib.sha256(self.active_bytes).hexdigest(),
            policy_sha256=hashlib.sha256(self.policy_bytes).hexdigest(), native_host_count=len(self.hosts),
            current_image_bytes_enrolled=False, current_host_connectivity_verified=False)


def native_source_hashes(repository):
    """Native build inputs, including the fixed optional UAC compile script."""
    repository = Path(repository)
    directory = repository / "flower_control/drivers/high_helper"
    identity_only = (directory / "program_identity_native.cpp").is_file()
    retired_native = {"uac_native.cpp", "uac_scan_capture.h", "uac_scan_shadow.h"} if identity_only else set()
    result = {p.relative_to(repository).as_posix(): digest(p) for p in directory.iterdir()
              if p.is_file() and (p.suffix in {".cs", ".csproj", ".manifest", ".cpp", ".h"}
                                  or p.name == "packages.lock.json") and p.name not in retired_native}
    # Track the actual resources consumed by this version's project. Keeping
    # only the old tray-states directory misses later icon generations.
    project = ET.parse(directory / "Flower.HighHelper.csproj").getroot()
    resources = [item.text for item in project.findall(".//ApplicationIcon") if item.text]
    resources += [item.attrib["Include"] for item in project.findall(".//EmbeddedResource") if "Include" in item.attrib]
    for value in resources:
        if any(token in value for token in ("$(", ";", "**", "?")):
            raise RuntimeError("native_resource_expression_unsupported")
        path = Path(os.path.normpath(directory / value))
        paths = sorted(path.parent.glob(path.name)) if "*" in path.name else [path]
        if not paths:
            raise RuntimeError("native_resource_missing")
        for resource in paths:
            if not resource.is_relative_to(repository) or not resource.is_file():
                raise RuntimeError("native_resource_path_rejected")
            for item in (resource, *resource.parents):
                if item.is_symlink() or item.is_junction():
                    raise RuntimeError("native_resource_link_rejected")
            result[resource.relative_to(repository).as_posix()] = digest(resource)
    icon = repository / "assets/branding/flower-control-icon.ico"
    result[icon.relative_to(repository).as_posix()] = digest(icon)
    for item in sorted((repository / "assets/branding/tray-states").glob("*.ico")):
        result[item.relative_to(repository).as_posix()] = digest(item)
    script = repository / ("tools/build_identity_native.ps1" if identity_only else "tools/build_uac_native.ps1")
    if ((directory / "uac_native.cpp").is_file() or identity_only) and not script.is_file():
        raise RuntimeError("uac_native_build_script_required")
    if script.is_file():
        result[script.relative_to(repository).as_posix()] = digest(script)
    for name in (() if identity_only else ("tools/uac_program_witness.cpp", "tools/build_uac_witnesses.ps1")):
        witness_source = repository / name
        if witness_source.is_file():
            result[name] = digest(witness_source)
    if not identity_only and (directory / "uac_native.cpp").is_file():
        for name in UAC_ALLOWLIST_FIXTURE_SOURCES:
            fixture_source = repository / name
            if not fixture_source.is_file():
                raise RuntimeError("uac_allowlist_fixture_sources_required")
            result[name] = digest(fixture_source)
    return result


def native_binary_hashes(repository, directory, bundle_names=NATIVE_BUNDLE_NAMES):
    """Keep the old four-file runtime bundle; UAC is a separately sealed DLL."""
    names = tuple(bundle_names)
    if any((Path(repository) / "flower_control/drivers/high_helper" / name).is_file()
           for name in ("program_identity_native.cpp", "uac_native.cpp")):
        names += (UAC_NATIVE_NAME,)
    return {name: digest(Path(directory) / name) for name in names}


def require_identity_only_exports(path):
    """Inspect PE exports without loading a candidate DLL into this process."""
    import struct
    expected = {"FlowerUacInspectProgram", "FlowerUacPublisher", "FlowerUacPublisherDetails"}
    try:
        path = Path(path)
        if not 512 <= path.stat().st_size <= 16 * 1024 * 1024:
            raise ValueError()
        data = path.read_bytes()
        if len(data) < 512 or len(data) > 16 * 1024 * 1024 or data[:2] != b"MZ":
            raise ValueError()
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError()
        machine, sections, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
        optional = pe + 24
        if machine != 0x8664 or not 1 <= sections <= 96 or optional_size < 120 or struct.unpack_from("<H", data, optional)[0] != 0x20b:
            raise ValueError()
        export_rva, export_size = struct.unpack_from("<II", data, optional + 112)
        table = optional + optional_size
        regions = []
        for index in range(sections):
            section = table + index * 40
            virtual_size, address, raw_size, raw = struct.unpack_from("<IIII", data, section + 8)
            if raw + raw_size > len(data):
                raise ValueError()
            regions.append((address, max(virtual_size, raw_size), raw, raw_size))
        def offset(rva, size):
            for address, virtual_size, raw, raw_size in regions:
                delta = rva - address
                if 0 <= delta and delta + size <= virtual_size and delta + size <= raw_size:
                    return raw + delta
            raise ValueError()
        export = offset(export_rva, 40)
        functions, names, address_functions, address_names, address_ordinals = struct.unpack_from("<IIIII", data, export + 20)
        if functions != 3 or names != 3 or export_size < 40:
            raise ValueError()
        function_offsets = offset(address_functions, functions * 4)
        name_offsets = offset(address_names, names * 4)
        ordinal_offsets = offset(address_ordinals, names * 2)
        if set(struct.unpack_from("<" + "H" * names, data, ordinal_offsets)) != set(range(functions)):
            raise ValueError()
        for rva in struct.unpack_from("<" + "I" * functions, data, function_offsets):
            if not rva or export_rva <= rva < export_rva + export_size:
                raise ValueError()  # Forwarders are not locally implemented exports.
            offset(rva, 1)
        found = set()
        for rva in struct.unpack_from("<" + "I" * names, data, name_offsets):
            start = offset(rva, 1)
            end = data.find(b"\0", start, min(len(data), start + 129))
            if end < 0:
                raise ValueError()
            found.add(data[start:end].decode("ascii"))
        if found != expected:
            raise ValueError()
    except (OSError, ValueError, UnicodeError, struct.error, OverflowError):
        raise RuntimeError("identity_native_exports_rejected") from None


def validate_identity_build(repository, native_bin, source_hashes, binary_hashes):
    """Bind the extracted DLL to its own build evidence and exact exports."""
    source = "flower_control/drivers/high_helper/program_identity_native.cpp"
    script = "tools/build_identity_native.ps1"
    evidence_path = native_bin / "build-evidence.json"
    try:
        evidence = json.loads(evidence_path.read_bytes())
        if (evidence.get("schema") != 1 or evidence.get("build_exit_code") != 0
                or evidence.get("source_unchanged") is not True or evidence.get("installed") is not False
                or Path(evidence.get("source", "")).resolve() != (repository / source).resolve()
                or Path(evidence.get("dll", "")).resolve() != (native_bin / UAC_NATIVE_NAME).resolve()
                or evidence.get("source_sha256") != source_hashes[source]
                or evidence.get("build_script_sha256") != source_hashes[script]
                or evidence.get("dll_sha256") != binary_hashes[UAC_NATIVE_NAME]):
            raise ValueError()
        require_identity_only_exports(native_bin / UAC_NATIVE_NAME)
        return evidence_path
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise RuntimeError("identity_native_build_evidence_rejected") from None


def add_native_snapshot_inputs(repository, source_hashes, rows):
    """Extend an existing runtime inventory without changing its global contract."""
    from tools.runtime_snapshot import reject_links
    for name, expected in source_hashes.items():
        relative = "python-source/" + name
        if relative in rows:
            if rows[relative]["sha256"] != expected:
                raise RuntimeError("preparation_input_changed_before_seal")
            continue
        original = Path(repository) / name
        reject_links(original)
        if digest(original) != expected:
            raise RuntimeError("preparation_input_changed_before_seal")
        rows[relative] = dict(path=original, sha256=expected, size=original.stat().st_size)
    return rows


def render_install_scripts(package, production, version, task_name):
    """Fixed scripts only; no execution or caller-supplied PowerShell code."""
    values = {"PACKAGE": package, "BROKER": production, "VERSION": version, "TASK": task_name,
              "TASKXMLHASH": digest(package / "task.xml")}
    templates = Path(__file__).with_name("high_broker_install")
    scripts = {}
    for name in ("InstallCommon.ps1", "ApplyInstall.ps1", "Disable.ps1", "CheckRollbackSource.ps1"):
        content = (templates / (name + ".template")).read_text(encoding="utf-8")
        content = content.replace("@@RECOVERY_PROTECTION_TYPE@@", (templates / "RecoveryProtection.cs").read_text(encoding="utf-8"))
        for key, value in values.items():
            content = content.replace("@@" + key + "@@", "'" + str(value).replace("'", "''") + "'")
        scripts[name] = content
    return scripts


def save_source_snapshot(repository, package, sources):
    """Preserve exact dirty policy/build source bytes; never restore them."""
    hashes = {key: value for key, value in sources.items() if key != "@bootstrap"}
    for name in ("pyproject.toml", "requirements.lock", "requirements-web.lock"):
        path = repository / name
        if path.is_file():
            hashes[name] = digest(path)
    for name, expected in hashes.items():
        original = repository / name
        cursor = original
        while cursor != repository:
            if cursor.is_symlink() or cursor.is_junction():
                raise RuntimeError("snapshot_source_link_rejected")
            cursor = cursor.parent
        saved = package / "source-snapshot" / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, saved)
        if digest(saved) != expected:
            raise RuntimeError("snapshot_source_changed")
    if any(digest(repository / name) != expected for name, expected in hashes.items()):
        raise RuntimeError("snapshot_source_changed")
    write_json(package / "source-snapshot.json", dict(schema=1, source_root=str(repository),
        hashes=hashes, dirty_source_preserved=True, automatically_restored=False,
        runtime_dependency_tree_fully_hash_pinned=False))


def validate_build_evidence(evidence_path, binary_directory, source_hashes, binary_hashes, *, kind):
    if kind not in {"native", "app", "wgc"}:
        raise ValueError("build_evidence_kind_rejected")
    evidence = json.loads(evidence_path.read_bytes())
    if (evidence.get("schema") != 1 or evidence.get("build_exit_code") != 0
            or evidence.get("source_unchanged_during_build", True) is not True
            or Path(evidence.get(kind + "_bin", "")).resolve() != binary_directory
            or evidence.get("source_hashes") != source_hashes
            or evidence.get("binary_hashes") != binary_hashes):
        raise RuntimeError("current_" + kind + "_build_evidence_required")
    return evidence


def verify_sealed_inputs(pairs):
    """Copied bytes must still match the original version/build basis.

    A correct copy of a binary modified during the long runtime snapshot is
    still the wrong build. Verify both sides against the pre-copy digest.
    """
    for original, saved, expected in pairs:
        if digest(original) != expected or digest(saved) != expected:
            raise RuntimeError("preparation_input_changed_before_seal")


def build_uac_allowlist_fixture(repository, package, source_hashes):
    """Build only the two fixed ordinary fixtures; never run or install them."""
    from tools.runtime_snapshot import reject_links
    paths = [repository / name for name in UAC_ALLOWLIST_FIXTURE_SOURCES]
    if any(name not in source_hashes for name in UAC_ALLOWLIST_FIXTURE_SOURCES):
        raise RuntimeError("uac_allowlist_fixture_sources_required")
    for path in paths:
        reject_links(path)
    if any(digest(repository / name) != expected for name, expected in source_hashes.items()):
        raise RuntimeError("preparation_input_changed_before_seal")
    log = package / "uac-allowlist-build.log"
    if log.exists():
        raise RuntimeError("uac_allowlist_fixture_destination_exists")
    # The producer has no user-selectable program, source, command or fixture
    # path. Retain the owned temporary build for diagnostics; copy only the
    # exact two outputs into this newly prepared version.
    built = Path(tempfile.mkdtemp(prefix="flower-uac-allowlist-build-")).resolve()
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    command = [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(paths[1]),
               "-OutputDirectory", str(built)]
    try:
        build = subprocess.run(command, cwd=repository, capture_output=True, timeout=180,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired as error:
        log.write_bytes((error.stdout or b"") + (error.stderr or b"") + b"\nfixture_build_timeout\n")
        raise RuntimeError("uac_allowlist_fixture_build_timeout") from error
    except OSError as error:
        log.write_bytes(("fixture_build_start_failed:" + type(error).__name__ + "\n").encode("ascii"))
        raise RuntimeError("uac_allowlist_fixture_build_start_failed") from error
    log.write_bytes(build.stdout + build.stderr)
    if build.returncode != 0 or any(digest(repository / name) != expected for name, expected in source_hashes.items()):
        raise RuntimeError("uac_allowlist_fixture_build_failed_or_source_changed")
    hashes = {}
    for name in UAC_ALLOWLIST_FIXTURE_NAMES:
        original = built / name
        reject_links(original)
        if not original.is_file():
            raise RuntimeError("uac_allowlist_fixture_binary_missing")
        hashes[name] = digest(original)
    if len(set(hashes.values())) != len(UAC_ALLOWLIST_FIXTURE_NAMES):
        raise RuntimeError("uac_allowlist_fixture_changed_hash_required")
    return built, dict(schema=1, installed=False, executed=False,
        source_hashes={name: source_hashes[name] for name in UAC_ALLOWLIST_FIXTURE_SOURCES},
        hashes=hashes, build_exit_code=build.returncode, source_unchanged_during_build=True,
        windows_powershell=str(powershell), build_log_sha256=digest(log))


def copy_uac_allowlist_fixture(built, evidence, source, version, target):
    """Copy the already-versioned bytes; no second compilation after basis."""
    from tools.runtime_snapshot import reject_links
    destination = source / "uac-allowlist-build-evidence.json"
    if set(evidence["hashes"]) != set(UAC_ALLOWLIST_FIXTURE_NAMES):
        raise RuntimeError("uac_allowlist_fixture_binary_inventory_rejected")
    if any(path.exists() for path in [destination, *(source / name for name in UAC_ALLOWLIST_FIXTURE_NAMES)]):
        raise RuntimeError("uac_allowlist_fixture_destination_exists")
    pairs = [(built / name, source / name, evidence["hashes"][name]) for name in UAC_ALLOWLIST_FIXTURE_NAMES]
    for original, _, _ in pairs:
        reject_links(original)
    for original, saved, _ in pairs:
        shutil.copyfile(original, saved)
    verify_sealed_inputs(pairs)
    write_json(destination, {**evidence, "version": version, "installed_directory": str(target)})
    return pairs


def prepare(native_bin, repository, app_bin, app_build_evidence, native_build_evidence, output=None, codex_roots=(), claude_images=(), antigravity_images=(), local_mcp_images=(), runtime_repository=None, data_root=None, freeze_runtime=False, media_encoder=None, wgc_bin=None, wgc_build_evidence=None, dsh_images=(), preserve_existing_native_host_pins=False):
    if preserve_existing_native_host_pins and any((claude_images, antigravity_images, local_mcp_images, dsh_images)):
        raise ValueError("preserved_native_hosts_conflict_with_new_images")
    sys.path.insert(0, str(repository))
    from flower_control.drivers.high_helper import _process, _BUNDLE_NAMES, _KERNEL
    from flower_control.data_paths import resolve_data_root
    from ctypes import wintypes
    import win32api
    import win32con
    peer, _ = _process(win32api.GetCurrentProcessId())
    preserved_hosts = (ExistingNativeHostPins(Path(os.environ.get("ProgramFiles", "C:/Program Files")) /
        "FlowerControl/HighHelper", peer["User"]) if preserve_existing_native_host_pins else None)
    # A frozen package carries the recipient's complete runtime and therefore
    # needs a concrete local data root. An update must retain the existing
    # ledger/profile root; switching roots would split user permissions and
    # browser state even though the version directory changed.
    if preserved_hosts is not None:
        inherited = str(resolve_data_root({"FLOWER_DATA_ROOT": preserved_hosts.data_root}))
        if data_root and str(resolve_data_root({"FLOWER_DATA_ROOT": str(data_root)})) != inherited:
            raise ValueError("existing_data_root_changed")
        pinned_data_root = inherited
    elif data_root:
        pinned_data_root = str(resolve_data_root({"FLOWER_DATA_ROOT": str(data_root)}))
    elif freeze_runtime:
        pinned_data_root = str(resolve_data_root())
    else:
        pinned_data_root = ""
    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, peer["Pid"])
    try:
        image, size = ctypes.create_unicode_buffer(2048), wintypes.DWORD(2048)
        if not _KERNEL.QueryFullProcessImageNameW(int(handle), 0, image, ctypes.byref(size)):
            raise RuntimeError("python_image_unavailable")
        python_image = Path(image.value)
    finally:
        handle.Close()
    runtime = Path(sys.base_prefix).resolve(strict=True)
    runtime_repository = (runtime_repository or repository).resolve(strict=True)
    if not runtime_repository.is_dir() or runtime_repository.is_symlink() or runtime_repository.is_junction():
        raise RuntimeError("runtime_repository_rejected")
    site = runtime_repository / ".venv" / "Lib" / "site-packages"
    current_native_source = native_source_hashes(repository)
    current_native_binary = native_binary_hashes(repository, native_bin, _BUNDLE_NAMES)
    validate_build_evidence(native_build_evidence, native_bin, current_native_source, current_native_binary, kind="native")
    identity_evidence = (validate_identity_build(repository, native_bin, current_native_source, current_native_binary)
        if (repository / "flower_control/drivers/high_helper/program_identity_native.cpp").is_file() else None)
    app = app_bin.resolve(strict=True)
    current_app_source = {p.relative_to(repository).as_posix(): digest(p)
                         for p in (repository / "flower_control/drivers/app_native").iterdir()
                         if p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"}
    current_app_binary = {p.name: digest(p) for p in app.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}
    evidence = validate_build_evidence(app_build_evidence, app, current_app_source, current_app_binary, kind="app")
    build_evidence_hashes = {native_build_evidence: digest(native_build_evidence),
                             app_build_evidence: digest(app_build_evidence)}
    if identity_evidence is not None:
        build_evidence_hashes[identity_evidence] = digest(identity_evidence)
    wgc, current_wgc_source, wgc_files, wgc_evidence = None, {}, {}, None
    if freeze_runtime and (wgc_bin is None or wgc_build_evidence is None):
        raise RuntimeError("frozen_wgc_build_evidence_required")
    if (wgc_bin is None) != (wgc_build_evidence is None):
        raise ValueError("fixed_wgc_build_required")
    if wgc_bin is not None:
        wgc = Path(wgc_bin).resolve(strict=True)
        if not wgc.is_dir() or wgc.is_symlink() or wgc.is_junction():
            raise RuntimeError("preparation_source_rejected")
        current_wgc_source = {p.relative_to(repository).as_posix(): digest(p)
            for p in (repository / "flower_control/drivers/computer_wgc").iterdir()
            if p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"}
        wgc_files = {p.name: digest(p) for p in wgc.iterdir()
                     if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}
        if "Flower.ComputerWgc.exe" not in wgc_files:
            raise RuntimeError("fixed_wgc_build_required")
        wgc_evidence = validate_build_evidence(wgc_build_evidence, wgc, current_wgc_source, wgc_files, kind="wgc")
        build_evidence_hashes[wgc_build_evidence] = digest(wgc_build_evidence)
    if not (app / "Flower.AppWorker.exe").is_file():
        raise RuntimeError("fixed_app_worker_build_required")
    for path in (repository, native_bin, site, runtime, app):
        if not path.is_dir() or path.is_symlink() or path.is_junction():
            raise RuntimeError("preparation_source_rejected")
    for root in codex_roots:
        if not Path(root).is_absolute() or len(str(root).rstrip("\\")) < 16 or any(c in str(root) for c in "*?"):
            raise ValueError("codex_install_root_rejected")
    native_hosts = preserved_hosts.hosts if preserved_hosts is not None else []
    for kind, image in ([('claude-code', image) for image in claude_images]
                        + [('antigravity', image) for image in antigravity_images]
                        + [('local-mcp', image) for image in local_mcp_images]
                        + [('dsh-desktop', image) for image in dsh_images]):
        image = Path(image)
        expected_name = {'claude-code': 'claude.exe', 'antigravity': 'antigravity.exe',
                         'dsh-desktop': 'deepseek harness.exe'}.get(kind, image.name.lower())
        if kind == 'local-mcp' and expected_name not in {'cursor.exe', 'code.exe', 'code - insiders.exe', 'opencode.exe', 'antigravity.exe', 'claude.exe'}:
            raise ValueError("native_mcp_client_required_not_interpreter")
        if not image.is_absolute() or image.name.lower() != expected_name or not image.is_file():
            raise ValueError("native_host_image_required")
        for item in (image, *image.parents):
            if item.is_symlink() or item.is_junction():
                raise ValueError("native_host_image_link_rejected")
        with image.open("rb") as stream:
            header = stream.read(64)
            if len(header) != 64 or header[:2] != b"MZ":
                raise ValueError("native_host_image_required")
            offset = int.from_bytes(header[60:64], "little")
            if offset < 64 or offset > image.stat().st_size - 4:
                raise ValueError("native_host_image_required")
            stream.seek(offset)
            if stream.read(4) != b"PE\0\0":
                raise ValueError("native_host_image_required")
        host = {"Kind": kind, "Path": str(image.resolve(strict=True)), "Sha256": digest(image)}
        if kind == 'dsh-desktop':
            runtime_package = image.parent / 'resources/app.asar'
            if not runtime_package.is_file():
                raise ValueError("dsh_desktop_runtime_required")
            for item in (runtime_package, *runtime_package.parents):
                if item.is_symlink() or item.is_junction():
                    raise ValueError("dsh_desktop_runtime_link_rejected")
            host["RuntimeSha256"] = digest(runtime_package)
        native_hosts.append(host)
    if (1 + len(codex_roots) + len(native_hosts) > 16
            or len({p["Path"].casefold() for p in native_hosts}) != len(native_hosts)):
        raise ValueError("native_host_inventory_rejected")
    bootstrap = repository / "flower_control/drivers/high_helper/flower_bootstrap.py"
    sources = {p.relative_to(repository).as_posix(): digest(p)
               for p in (repository / "flower_control").rglob("*.py") if "__pycache__" not in p.parts}
    sources.update({p.relative_to(repository).as_posix(): digest(p)
                    for p in (repository / "hooks").glob("*.py")})
    sources["tools/open_flower_browser.py"] = digest(repository / "tools/open_flower_browser.py")
    sources["@bootstrap"] = digest(bootstrap)
    app_files = dict(current_app_binary)
    python_files = [runtime / f"python{sys.version_info.major}{sys.version_info.minor}.dll", runtime / "python3.dll"]
    python_files += sorted(runtime.glob("vcruntime*.dll"))
    if any(not p.is_file() or p.is_symlink() for p in python_files):
        raise RuntimeError("fixed_python_runtime_required")
    pth = "\n".join(map(str, [runtime / "Lib", runtime / "DLLs", site, site / "win32", site / "win32/lib", site / "pythonwin", runtime_repository])) + "\n"
    runtime_rows = None
    media_hash = ""
    if media_encoder and not freeze_runtime:
        raise ValueError("media_encoder_requires_frozen_runtime")
    if freeze_runtime:
        from tools.runtime_snapshot import inventory_runtime, inventory_digest, copy_runtime
        runtime_rows = inventory_runtime(repository, runtime, site)
        add_native_snapshot_inputs(repository, current_native_source, runtime_rows)
        if media_encoder:
            from tools.runtime_snapshot import reject_links
            media_encoder = Path(media_encoder).resolve(strict=True)
            reject_links(media_encoder)
            if media_encoder.name.lower() != "ffmpeg.exe":
                raise ValueError("fixed_media_encoder_required")
            with media_encoder.open("rb") as stream:
                header = stream.read(64)
                if len(header) != 64 or header[:2] != b"MZ":
                    raise ValueError("fixed_media_encoder_required")
                stream.seek(int.from_bytes(header[60:64], "little"))
                if stream.read(4) != b"PE\0\0":
                    raise ValueError("fixed_media_encoder_required")
            license_path = media_encoder_license(media_encoder)
            reject_links(license_path)
            media_hash = digest(media_encoder)
            for name, original in (("ffmpeg.exe", media_encoder), ("LICENSE", license_path)):
                runtime_rows["runtime/encoder/" + name] = dict(path=original, sha256=digest(original), size=original.stat().st_size)
        # The actual absolute version path is rendered after deriving version.
        pth = "@version/runtime/Lib\n@version/runtime/DLLs\n@version/python-source/.venv/Lib/site-packages\n@version/python-source/.venv/Lib/site-packages/win32\n@version/python-source/.venv/Lib/site-packages/win32/lib\n@version/python-source/.venv/Lib/site-packages/pythonwin\n@version/python-source\n"
    package = Path(output).resolve() if output else Path(tempfile.mkdtemp(prefix="flower-high-install-"))
    if output:
        package.mkdir(parents=True, exist_ok=False)
    save_source_snapshot(repository, package, {**sources, **current_native_source})
    identity_only = (repository / "flower_control/drivers/high_helper/program_identity_native.cpp").is_file()
    allowlist_build = (build_uac_allowlist_fixture(repository, package, current_native_source)
                       if UAC_NATIVE_NAME in current_native_binary and not identity_only else None)
    # Codex is admitted from its official Authenticode signer at runtime. A
    # release package must not pin one Store package family or versioned cache
    # root; callers may still opt into an explicit legacy image root.
    basis = dict(broker=current_native_binary, native_source=current_native_source, source=sources, app=app_files,
                 python=digest(python_image), dlls={p.name: digest(p) for p in python_files}, pth=pth,
                 sid=peer["User"], codex_families=[], codex_roots=list(map(str, codex_roots)),
                 native_hosts=native_hosts, data_root=pinned_data_root)
    if allowlist_build is not None:
        # MSVC/Link outputs can contain timestamps. Bind the actual two
        # compiled binaries before deriving this version, not just source.
        basis["uac_allowlist_fixture"] = allowlist_build[1]
    if runtime_rows is not None:
        basis["runtime_inventory_sha256"] = inventory_digest(runtime_rows)
    if wgc_files:
        basis.update(wgc=wgc_files, wgc_source=current_wgc_source)
    version = hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()[:32]
    source = package / "versions" / version
    source.mkdir(parents=True)
    production = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper"
    target = production / "versions" / version
    actual_repository = target / "python-source" if freeze_runtime else runtime_repository
    runtime_hashes, runtime_manifest_hash = ({}, "")
    if runtime_rows is not None:
        runtime_hashes, runtime_manifest_hash = copy_runtime(runtime_rows, source)
        pth = pth.replace("@version", str(target))
    for name in current_native_binary:
        shutil.copyfile(native_bin / name, source / name)
    shutil.copyfile(native_build_evidence, source / "native-build-evidence.json")
    if identity_evidence is not None:
        shutil.copyfile(identity_evidence, source / "identity-build-evidence.json")
    shutil.copyfile(python_image, source / "flower-python.exe")
    for file in python_files:
        shutil.copyfile(file, source / file.name)
    shutil.copyfile(bootstrap, source / "flower_bootstrap.py")
    shutil.copyfile(repository / "flower_control/drivers/high_helper/flower_hook_bootstrap.py", source / "flower_hook_bootstrap.py")
    (source / "flower-python._pth").write_text(pth, encoding="utf-8")
    (source / "app").mkdir()
    for name in app_files:
        shutil.copyfile(app / name, source / "app" / name)
    if wgc_files:
        (source / "wgc").mkdir()
        for name in wgc_files:
            shutil.copyfile(wgc / name, source / "wgc" / name)
        write_json(source / "wgc-build-evidence.json", wgc_evidence)
    pairs = [(native_bin / name, source / name, expected)
             for name, expected in current_native_binary.items()]
    pairs += [(app / name, source / "app" / name, expected) for name, expected in app_files.items()]
    pairs += [(wgc / name, source / "wgc" / name, expected) for name, expected in wgc_files.items()]
    pairs += [(python_image, source / "flower-python.exe", basis["python"])]
    pairs += [(file, source / file.name, basis["dlls"][file.name]) for file in python_files]
    pairs += [(bootstrap, source / "flower_bootstrap.py", sources["@bootstrap"]),
              (repository / "flower_control/drivers/high_helper/flower_hook_bootstrap.py",
               source / "flower_hook_bootstrap.py",
               sources["flower_control/drivers/high_helper/flower_hook_bootstrap.py"])]
    pairs += [(native_build_evidence, source / "native-build-evidence.json", build_evidence_hashes[native_build_evidence])]
    if identity_evidence is not None:
        pairs.append((identity_evidence, source / "identity-build-evidence.json", build_evidence_hashes[identity_evidence]))
    pairs += [(repository / name, package / "source-snapshot" / name, expected)
              for name, expected in current_native_source.items()]
    if freeze_runtime:
        pairs += [(repository / name, source / "python-source" / name, expected)
                   for name, expected in {**sources, **current_native_source, **current_app_source,
                                          **current_wgc_source}.items() if name != "@bootstrap"]
    verify_sealed_inputs(pairs)
    if (any(digest(repository / name) != expected for name, expected in sources.items() if name != "@bootstrap")
            or any(digest(repository / name) != expected for name, expected in current_native_source.items())
            or any(digest(repository / name) != expected for name, expected in current_app_source.items())
            or any(digest(repository / name) != expected for name, expected in current_wgc_source.items())
            or any(digest(path) != expected for path, expected in build_evidence_hashes.items())):
        raise RuntimeError("preparation_input_changed_before_seal")
    if not identity_only and (repository / "flower_control/drivers/high_helper/UacProgramQualification.cs").is_file():
        script = repository / "tools/build_uac_witnesses.ps1"
        if not script.is_file() or "tools/uac_program_witness.cpp" not in current_native_source:
            raise RuntimeError("uac_qualification_witness_sources_required")
        witness_build = package / "uac-witness-build"
        command = [str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script), "-OutputDirectory", str(witness_build),
            "-InstalledVersionDirectory", str(target), "-HelperExecutablePath", str(source / "Flower.HighHelper.exe")]
        build = subprocess.run(command, cwd=repository, capture_output=True, timeout=180, creationflags=subprocess.CREATE_NO_WINDOW)
        (package / "uac-witness-build.log").write_bytes(build.stdout + build.stderr)
        if build.returncode != 0 or any(digest(repository / name) != expected for name, expected in current_native_source.items()):
            raise RuntimeError("uac_qualification_witness_build_failed_or_source_changed")
        witness_names = ("uac-witness-baseline.exe", "uac-witness-moved.exe", "uac-witness-decoy.exe")
        built = json.loads((witness_build / "uac-witness-build-evidence.json").read_bytes())
        built_hashes = {row["name"]: row["sha256"] for row in built["witnesses"]}
        if set(built_hashes) != set(witness_names) or built["helper_sha256"] != digest(source / "Flower.HighHelper.exe"):
            raise RuntimeError("uac_qualification_witness_build_binding_changed")
        for name in witness_names:
            shutil.copyfile(witness_build / name, source / name)
        verify_sealed_inputs([(witness_build / name, source / name, built_hashes[name]) for name in witness_names])
        write_json(source / "uac-witness-build-evidence.json", dict(schema=1, installed=False, executed=False,
            version=version, installed_directory=str(target), source_hashes={name: current_native_source[name]
                for name in ("tools/uac_program_witness.cpp", "tools/build_uac_witnesses.ps1")},
            helper_sha256=digest(source / "Flower.HighHelper.exe"), hashes={name: digest(source / name) for name in witness_names}))
    if allowlist_build is not None:
        fixture_pairs = copy_uac_allowlist_fixture(*allowlist_build, source, version, target)
        verify_sealed_inputs([*pairs, *fixture_pairs])
        if (any(digest(repository / name) != expected for name, expected in sources.items() if name != "@bootstrap")
                or any(digest(repository / name) != expected for name, expected in current_native_source.items())
                or any(digest(repository / name) != expected for name, expected in current_app_source.items())
                or any(digest(repository / name) != expected for name, expected in current_wgc_source.items())
                or any(digest(path) != expected for path, expected in build_evidence_hashes.items())):
            raise RuntimeError("preparation_input_changed_before_seal")
    if preserved_hosts is not None:
        preserved_hosts.require_unchanged()
    policy = dict(Schema=1, Version=version, UserSid=peer["User"], Mode="high", FixturePipe="",
        Python={"Path": str(target / "flower-python.exe"), "Sha256": digest(source / "flower-python.exe")},
        CodexPackageFamilies=basis["codex_families"], CodexImageRoots=list(map(str, codex_roots)),
        AdditionalAgents=[], NativeHosts=native_hosts, Repository=str(actual_repository), DataRoot=pinned_data_root,
        RuntimeInventorySha256=runtime_manifest_hash,
        MediaEncoder=({"Path": str(target / "runtime/encoder/ffmpeg.exe"), "Sha256": media_hash} if media_hash else None),
        SourceHashes=sources, FixturePeers=[], AppWorkerHashes=app_files, WgcWorkerHashes=wgc_files)
    write_json(source / "broker.json", policy)
    write_json(source / "app-build-evidence.json", evidence)
    active = dict(schema=1, version=version, hashes={p.name: digest(p) for p in source.iterdir() if p.is_file()})
    if freeze_runtime:
        active["runtime_hashes"] = runtime_hashes
    write_json(package / "active.json", active)
    write_json(source / "installation.json", active)
    task_name = "FlowerControl.HighBroker." + hashlib.sha256(peer["User"].encode()).hexdigest()[:16]
    command = str(target / "Flower.HighHelper.exe")
    xml = render_high_task(peer["User"], target)
    (package / "task.xml").write_text(xml, encoding="utf-16")
    write_json(package / "mcp-entries.json", {"mcpServers": {c: {"command": command, "args": ["--flower-client", c],
        "cwd": str(actual_repository)} for c in ("flower-web", "flower-app", "flower-computer")}})
    from flower_control.authorization.hook_bridge import WEB_TOOLS, APP_TOOLS, COMPUTER_TOOLS
    from flower_control.authorization.uac_preflight import PREFLIGHT_HOOK_TIMEOUT
    matcher = "^mcp__(" + "|".join(channel + "__(" + "|".join(names) + ")" for channel, names in
        (("flower[-_]web", WEB_TOOLS), ("flower[-_]app", APP_TOOLS), ("flower[-_]computer", COMPUTER_TOOLS))) + ")$"
    hook_entries = {"hooks": {"PreToolUse": [{"matcher": matcher, "hooks": [{
        "type": "command", "command": hook_command(target / "flower-python.exe", str(target / "flower_hook_bootstrap.py")),
        "timeout": PREFLIGHT_HOOK_TIMEOUT}]}], "UserPromptSubmit": [{"hooks": [{"type": "command",
            "command": hook_command(target / "Flower.HighHelper.exe", "--uac-host-event"), "timeout": 10}]}]}}
    from tools.host_phase_hooks import add_phase_hooks
    write_json(package / "hooks-entries.json", add_phase_hooks(hook_entries,
        hook_command(target / "flower-python.exe", str(target / "flower_hook_bootstrap.py"), "--host-phase")))
    if freeze_runtime and pinned_data_root:
        write_json(package / "normal-user-entries.json", {"schema": 1, "version": version,
            "installed": False, "shortcuts_created": False, "task_grant_created": False,
            "profiles": {kind: {"command": str(target / "flower-python.exe"),
                "args": ["-B", str(actual_repository / "tools/open_flower_browser.py"),
                         "--kind", kind, "--window-mode", "visible", "--data-root", pinned_data_root],
                "cwd": str(actual_repository)} for kind in ("ai", "luohua", "temporary")}})
    for name, content in render_install_scripts(package, production, version, task_name).items():
        (package / name).write_text(content, encoding="utf-8-sig")
    write_json(package / "preparation.json", dict(schema=1, version=version, package=str(package), production_root=str(production),
        source_root=str(repository), source_files=len(sources)-1, task_name=task_name, system_changed=False,
        installed=False, elevated=False, ui_access=False, codex_hard_sha_pinned=False, app_worker_files=len(app_files),
        existing_runtime=str(runtime), existing_site_packages=str(site), fresh_injection_verified=False,
        runtime_dependency_tree_fully_hash_pinned=freeze_runtime, native_hosts=native_hosts,
        runtime_source_root=str(actual_repository), runtime_snapshot_files=len(runtime_hashes),
        wgc_worker_files=len(wgc_files), media_encoder_pinned=bool(media_hash),
        uac_native_binary_pinned=UAC_NATIVE_NAME in current_native_binary,
        role_lifecycle_supported=all('flower_control/drivers/high_helper/' + name in current_native_source
            for name in ('ExecutionRoleLease.cs', 'LocalUiWriter.cs', 'OrdinaryMaintenance.cs')),
        **({"preserved_native_host_pins": preserved_hosts.evidence()} if preserved_hosts is not None else {})))
    runtime_note = ("flower-python._pth 仅指向版本内部的 Python 标准库、DLLs、site-packages（含 win32、win32/lib、pythonwin）和 Flower 源；私有 worker 在导入 pywin32 前各自初始化固定 pywin32_system32 DLL。"
                    if freeze_runtime else "flower-python._pth 固定本机既有 Python 标准库、DLLs、仓库 site-packages 和源根；共享传递树未全量 hash pin，维护后须重验入口与锁。")
    rollback_note = ("本版本冻结的 Python 源／依赖和 App／WGC 字节位于自己的只读版本目录，回退到同样冻结的旧版本无需恢复任何工作目录；非冻结旧版本须先从其 SourceHashes 和实际入口核实匹配源码，保留 dirty 后才提出恢复。"
                     if freeze_runtime else "本版本仍依赖固定的既有工作目录，回退前须保留当前 dirty，并核实旧 broker.SourceHashes 对应源码；仅切入口不能使旧源可用。")
    (package / "README.md").write_text(f"""# 全局 High 安装准备

版本 {version}；当前仅生成文件，未安装／注册／提权／启动。候选源码根 {repository}；安装后运行源码和 MCP cwd 为 {actual_repository}。

本包冻结 Python 运行源码与既有依赖树：{freeze_runtime}。启用时 runtime-inventory.json 和 active.runtime_hashes 固定源代码、标准库、DLLs、site-packages 的逐文件哈希；仅复制已准入字节，不复制 profiles、授权账本、凭据、测试和临时产物。App／WGC 原生 companion 单独绑定成功构建、源 SHA 和全部 exe/dll/json。安装校验全部字节并应用固定只读 ACL，启动使用版本内部路径。Windows、既有 .NET runtime 和 Brave 仍是系统／本机依赖，未复制或迁移。

固定 Flower Python 是实际 CPython backend 改名副本，避开 venv redirector；实际客户端父进程是固定 launcher。{runtime_note} 无 PYTHONPATH、user site、sitecustomize 或自由 argv。没有下载／升级／联网安装依赖。可选固定 MP4 encoder：{bool(media_hash)}，只使用版本内已核 ffmpeg 字节与 LICENSE，不搜索 PATH，不处理远程媒体。

根审查 active/broker/task/ApplyInstall.ps1、最终源 SHA 与 Program Files 父链无 reparse。ApplyInstall 默认仅首次安装，已有同名任务或版本拒绝；若 active 发布后注册任务失败，保留全部文件，-CompleteTaskRegistration 只在任务确实缺失、同版本字节与固定 ACL 全部匹配时续完注册；InteractiveToken/Highest，非 SYSTEM，无 UIAccess。注册后仍须根显式启动并验实际 token/session。非管理员当前用户不能获得 High，必须失败，不伪造 ready。

F5 的固定 --flower-probe flower-web|flower-app|flower-computer 走实际 Codex 来源及同一隔离 bootstrap；内置 Python audit 拒外联／子进程，允许 asyncio 回环。stderr 首条含 probe_guard_active:true、source_root/cwd/PID；stdout 为原 MCP。它不验证生产输入／浏览器／UIA，也不是全路径网络监测。

更新／回退由根先全局 pause、核 active_requests=0 并正常 shutdown，确认精确 PID/ctime 已结束；保留旧版本、task XML、active 备份和本包 source-snapshot/。{rollback_note} 执行匹配旧包 CheckRollbackSource.ps1 确认后才改精确 task action、active 和三个 MCP 入口。任何脚本都不自动 git reset 或覆盖 dirty。source-snapshot.json 保存源与现有锁字节，不是私人配置备份。首次 apply 不能用于更新，已有安装须单独核实本次固定更新控制器；不能强杀用户应用／通配符进程。Disable.ps1 先禁用并读回精确登录任务，再查询当前 broker 并 pause/shutdown，读回原 PID/ctime 的真实退出；broker 不存在或管道不可用不阻断禁用，保留 unknown，不能据此称实例已停止；卸载删除仍须精确盘点确认，产物不做删除。

冻结包额外保留准确 tools/open_flower_browser.py。固定 DataRoot 时 normal-user-entries.json 给出 AI／落花／临时态正常人工启动的 command/args/cwd，可先加 --dry-run 只读核登记，再由安装后的精确快捷方式使用。它使用同一已登记资料，不创建 Codex task/grant，不授予 AI 私人访问；本准备只生成入口清单，没有创建系统快捷方式或打开浏览器。既有快捷方式仍需在实际升级阶段精确盘点／备份／更新，不能让它继续调用旧工作目录。

原生托盘提供状态、暂停／恢复、正常退出；Shell 尚未就绪或图标注册失败时保留桌面/Stop 监听并有限重试，Explorer TaskbarCreated 后重新注册，状态如实报告 tray_available；MCP EOF 仅关闭本连接。安装 ACL、真实 High/App/多客户端与新聊天注入仍待根。
""", encoding="utf-8")
    if preserved_hosts is not None:
        preserved_hosts.require_unchanged()
    return package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-bin", type=Path, default=Path(tempfile.gettempdir()) / "flower-high-global-core/bin")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--runtime-repository", type=Path,
                        help="Pin the existing install repository while building from an isolated candidate; does not copy source or install anything.")
    parser.add_argument("--data-root", type=Path,
                        help="Pin an existing verified physical user-data root without migrating profiles or ledger.")
    parser.add_argument("--freeze-runtime", action="store_true",
                        help="Copy and hash existing admitted source, stdlib and dependencies into the fixed protected version; no download or install.")
    parser.add_argument("--media-encoder", type=Path,
                        help="Explicitly pin an admitted existing ffmpeg.exe and its adjacent GPL LICENSE into a frozen version; no PATH search/download.")
    parser.add_argument("--app-bin", type=Path, required=True)
    parser.add_argument("--app-build-evidence", type=Path, required=True)
    parser.add_argument("--native-build-evidence", type=Path, required=True)
    parser.add_argument("--wgc-bin", type=Path,
                        help="Fixed existing WGC companion build; required for a frozen full runtime.")
    parser.add_argument("--wgc-build-evidence", type=Path,
                        help="Current WGC source and binary build evidence; no acquisition or installation.")
    parser.add_argument("--codex-root", type=Path, action="append", default=[],
                        help="Optional legacy image root; Codex is normally admitted by its official signature.")
    parser.add_argument("--claude-image", type=Path, action="append", default=[],
                        help="Opt in one exact native Windows claude.exe path and SHA-256; no install or start.")
    parser.add_argument("--antigravity-image", type=Path, action="append", default=[],
                        help="Opt in an exact Windows Antigravity.exe path and SHA-256; no install or start.")
    parser.add_argument("--local-mcp-image", type=Path, action="append", default=[],
                        help="Pin an exact native Cursor, VS Code or OpenCode executable; no general interpreter.")
    parser.add_argument("--dsh-image", type=Path, action="append", default=[],
                        help="Pin the exact Desktop executable and app.asar for per-chat DSH connections; no install/start.")
    parser.add_argument("--preserve-existing-native-host-pins", action="store_true",
                        help="Preserve only exact NativeHosts from the hash-bound existing active policy; never enroll current updated images. Mutually exclusive with image options.")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    package = prepare(args.native_bin.resolve(strict=True), repository, args.app_bin, args.app_build_evidence,
                      args.native_build_evidence, args.output, args.codex_root, args.claude_image, args.antigravity_image, args.local_mcp_image,
                      runtime_repository=args.runtime_repository, data_root=args.data_root, freeze_runtime=args.freeze_runtime,
                      media_encoder=args.media_encoder, wgc_bin=args.wgc_bin, wgc_build_evidence=args.wgc_build_evidence,
                      dsh_images=args.dsh_image, preserve_existing_native_host_pins=args.preserve_existing_native_host_pins)
    print(json.dumps({"package": str(package), "system_changed": False, "installed": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
