"""Prepare a reviewable local package. Never installs, elevates or registers."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from xml.sax.saxutils import escape


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def render_install_scripts(package, production, version, task_name):
    """Fixed scripts only; no execution or caller-supplied PowerShell code."""
    values = {"PACKAGE": package, "BROKER": production, "VERSION": version, "TASK": task_name,
              "TASKXMLHASH": digest(package / "task.xml")}
    templates = Path(__file__).with_name("high_broker_install")
    scripts = {}
    for name in ("InstallCommon.ps1", "ApplyInstall.ps1", "Disable.ps1", "CheckRollbackSource.ps1"):
        content = (templates / (name + ".template")).read_text(encoding="utf-8")
        for key, value in values.items():
            content = content.replace("@@" + key + "@@", "'" + str(value).replace("'", "''") + "'")
        scripts[name] = content
    return scripts


def save_source_snapshot(repository, package, sources):
    """Preserve the exact dirty Python bytes required by this version's policy."""
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
    if kind not in {"native", "app"}:
        raise ValueError("build_evidence_kind_rejected")
    evidence = json.loads(evidence_path.read_bytes())
    if (evidence.get("schema") != 1 or evidence.get("build_exit_code") != 0
            or Path(evidence.get(kind + "_bin", "")).resolve() != binary_directory
            or evidence.get("source_hashes") != source_hashes
            or evidence.get("binary_hashes") != binary_hashes):
        raise RuntimeError("current_" + kind + "_build_evidence_required")
    return evidence


def prepare(native_bin, repository, app_bin, app_build_evidence, native_build_evidence, output=None, codex_roots=(), claude_images=(), antigravity_images=()):
    sys.path.insert(0, str(repository))
    from flower_control.drivers.high_helper import _process, _BUNDLE_NAMES, _KERNEL
    from ctypes import wintypes
    import win32api
    import win32con
    peer, _ = _process(win32api.GetCurrentProcessId())
    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, peer["Pid"])
    try:
        image, size = ctypes.create_unicode_buffer(2048), wintypes.DWORD(2048)
        if not _KERNEL.QueryFullProcessImageNameW(int(handle), 0, image, ctypes.byref(size)):
            raise RuntimeError("python_image_unavailable")
        python_image = Path(image.value)
    finally:
        handle.Close()
    runtime = Path(sys.base_prefix).resolve(strict=True)
    site = repository / ".venv" / "Lib" / "site-packages"
    current_native_source = {p.relative_to(repository).as_posix(): digest(p)
        for p in (repository / "flower_control/drivers/high_helper").iterdir()
        if p.suffix in {".cs", ".csproj", ".manifest"} or p.name == "packages.lock.json"}
    current_native_binary = {name: digest(native_bin / name) for name in _BUNDLE_NAMES}
    validate_build_evidence(native_build_evidence, native_bin, current_native_source, current_native_binary, kind="native")
    app = app_bin.resolve(strict=True)
    current_app_source = {p.relative_to(repository).as_posix(): digest(p)
                         for p in (repository / "flower_control/drivers/app_native").iterdir()
                         if p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"}
    current_app_binary = {p.name: digest(p) for p in app.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}
    evidence = validate_build_evidence(app_build_evidence, app, current_app_source, current_app_binary, kind="app")
    if not (app / "Flower.AppWorker.exe").is_file():
        raise RuntimeError("fixed_app_worker_build_required")
    for path in (repository, native_bin, site, runtime, app):
        if not path.is_dir() or path.is_symlink() or path.is_junction():
            raise RuntimeError("preparation_source_rejected")
    for root in codex_roots:
        if not Path(root).is_absolute() or len(str(root).rstrip("\\")) < 16 or any(c in str(root) for c in "*?"):
            raise ValueError("codex_install_root_rejected")
    native_hosts = []
    for kind, image in ([('claude-code', image) for image in claude_images]
                        + [('antigravity', image) for image in antigravity_images]):
        image = Path(image)
        expected_name = 'claude.exe' if kind == 'claude-code' else 'antigravity.exe'
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
        native_hosts.append({"Kind": kind, "Path": str(image.resolve(strict=True)), "Sha256": digest(image)})
    if (1 + len(codex_roots) + len(native_hosts) > 16
            or len({p["Path"].casefold() for p in native_hosts}) != len(native_hosts)):
        raise ValueError("native_host_inventory_rejected")
    bootstrap = repository / "flower_control/drivers/high_helper/flower_bootstrap.py"
    sources = {p.relative_to(repository).as_posix(): digest(p)
               for p in (repository / "flower_control").rglob("*.py") if "__pycache__" not in p.parts}
    sources["@bootstrap"] = digest(bootstrap)
    app_files = {p.name: digest(p) for p in app.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}}
    python_files = [runtime / f"python{sys.version_info.major}{sys.version_info.minor}.dll", runtime / "python3.dll"]
    python_files += sorted(runtime.glob("vcruntime*.dll"))
    if any(not p.is_file() or p.is_symlink() for p in python_files):
        raise RuntimeError("fixed_python_runtime_required")
    pth = "\n".join(map(str, [runtime / "Lib", runtime / "DLLs", site, site / "win32", site / "win32/lib", repository])) + "\n"
    basis = dict(broker=current_native_binary, native_source=current_native_source, source=sources, app=app_files,
                 python=digest(python_image), dlls={p.name: digest(p) for p in python_files}, pth=pth,
                 sid=peer["User"], codex_families=["OpenAI.Codex_2p2nqsd0c76g0"], codex_roots=list(map(str, codex_roots)),
                 native_hosts=native_hosts)
    version = hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()[:32]
    package = Path(output).resolve() if output else Path(tempfile.mkdtemp(prefix="flower-high-install-"))
    if output:
        package.mkdir(parents=True, exist_ok=False)
    save_source_snapshot(repository, package, sources)
    source = package / "versions" / version
    source.mkdir(parents=True)
    production = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper"
    target = production / "versions" / version
    for name in _BUNDLE_NAMES:
        shutil.copyfile(native_bin / name, source / name)
    shutil.copyfile(native_build_evidence, source / "native-build-evidence.json")
    shutil.copyfile(python_image, source / "flower-python.exe")
    for file in python_files:
        shutil.copyfile(file, source / file.name)
    shutil.copyfile(bootstrap, source / "flower_bootstrap.py")
    (source / "flower-python._pth").write_text(pth, encoding="utf-8")
    (source / "app").mkdir()
    for name in app_files:
        shutil.copyfile(app / name, source / "app" / name)
    policy = dict(Schema=1, Version=version, UserSid=peer["User"], Mode="high", FixturePipe="",
        Python={"Path": str(target / "flower-python.exe"), "Sha256": digest(source / "flower-python.exe")},
        CodexPackageFamilies=basis["codex_families"], CodexImageRoots=list(map(str, codex_roots)),
        AdditionalAgents=[], NativeHosts=native_hosts, Repository=str(repository), SourceHashes=sources, FixturePeers=[], AppWorkerHashes=app_files)
    write_json(source / "broker.json", policy)
    write_json(source / "app-build-evidence.json", evidence)
    active = dict(schema=1, version=version, hashes={p.name: digest(p) for p in source.iterdir() if p.is_file()})
    write_json(package / "active.json", active)
    write_json(source / "installation.json", active)
    task_name = "FlowerControl.HighBroker." + hashlib.sha256(peer["User"].encode()).hexdigest()[:16]
    command = str(target / "Flower.HighHelper.exe")
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <RegistrationInfo><Description>Flower Control 当前用户交互登录会话的全局 High 执行器</Description></RegistrationInfo>
 <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(peer["User"])}</UserId></LogonTrigger></Triggers>
 <Principals><Principal id="FlowerUser"><UserId>{escape(peer["User"])}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
 <Actions Context="FlowerUser"><Exec><Command>{escape(command)}</Command><Arguments>--serve</Arguments><WorkingDirectory>{escape(str(target))}</WorkingDirectory></Exec></Actions>
</Task>
"""
    (package / "task.xml").write_text(xml, encoding="utf-16")
    write_json(package / "mcp-entries.json", {"mcpServers": {c: {"command": command, "args": ["--flower-client", c],
        "cwd": str(repository)} for c in ("flower-web", "flower-app", "flower-computer")}})
    for name, content in render_install_scripts(package, production, version, task_name).items():
        (package / name).write_text(content, encoding="utf-8-sig")
    write_json(package / "preparation.json", dict(schema=1, version=version, package=str(package), production_root=str(production),
        source_root=str(repository), source_files=len(sources)-1, task_name=task_name, system_changed=False,
        installed=False, elevated=False, ui_access=False, codex_hard_sha_pinned=False, app_worker_files=len(app_files),
        existing_runtime=str(runtime), existing_site_packages=str(site), fresh_injection_verified=False,
        runtime_dependency_tree_fully_hash_pinned=False, native_hosts=native_hosts))
    (package / "README.md").write_text(f"""# 全局 High 安装准备

版本 {version}；当前仅生成文件，未安装／注册／提权／启动。源根 {repository}，MCP cwd 相同。

固定 Flower Python 是实际 CPython backend 改名副本，避开 venv redirector；实际客户端父进程是固定 launcher。flower-python._pth 固定本机既有 Python 标准库／DLLs、仓库既有 site-packages 和源根，无 PYTHONPATH、user site、sitecustomize 或自由 argv。没有下载／新增依赖；共享运行时／site-packages 传递树未全量 hash pin，维护这些既有依赖后须重验入口和依赖锁。

根审查 active/broker/task/ApplyInstall.ps1、最终源 SHA 与 Program Files 父链无 reparse。ApplyInstall 默认仅首次安装，已有同名任务或版本拒绝；若 active 发布后注册任务失败，保留全部文件，-CompleteTaskRegistration 只在任务确实缺失、同版本字节与固定 ACL 全部匹配时续完注册；InteractiveToken/Highest，非 SYSTEM，无 UIAccess。注册后仍须根显式启动并验实际 token/session。非管理员当前用户不能获得 High，必须失败，不伪造 ready。

F5 的固定 --flower-probe flower-web|flower-app|flower-computer 走实际 Codex 来源及同一隔离 bootstrap；内置 Python audit 拒外联／子进程，允许 asyncio 回环。stderr 首条含 probe_guard_active:true、source_root/cwd/PID；stdout 为原 MCP。它不验证生产输入／浏览器／UIA，也不是全路径网络监测。

更新／回退由根先全局 pause、核 active_requests=0 并正常 shutdown，确认精确 PID/ctime 已结束；保留旧版本、task XML、active 备份和本包 source-snapshot/。回退前先保留并审查当前 dirty，在原仓库恢复与旧 broker.SourceHashes 匹配的 Python 源码（可以来自本包保存的精确源码或已核验 commit），执行旧包 CheckRollbackSource.ps1 确认，随后才改精确 task action、active 和三个 MCP 入口。仅切入口不能使旧版本可用；任何脚本都不自动 git reset 或覆盖 dirty。source-snapshot.json 同时保存现有依赖锁字节，既有运行时和 site-packages 仍需复核；它不是完整运行时或私人配置备份。首次 apply 不能用于更新，不能强杀用户应用／通配符进程。源码／依赖变化使旧 SourceHashes 拒绝，新包须重新准备。Disable.ps1 先禁用并读回精确登录任务，再查询当前 broker 并 pause/shutdown，读回原 PID/ctime 的真实退出；broker 不存在或管道不可用不阻断禁用，保留 unknown，不能据此称实例已停止；卸载删除仍须精确盘点确认，产物不做删除。

原生托盘提供状态、暂停／恢复、正常退出；Shell 尚未就绪或图标注册失败时保留桌面/Stop 监听并有限重试，Explorer TaskbarCreated 后重新注册，状态如实报告 tray_available；MCP EOF 仅关闭本连接。安装 ACL、真实 High/App/多客户端与新聊天注入仍待根。
""", encoding="utf-8")
    return package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-bin", type=Path, default=Path(tempfile.gettempdir()) / "flower-high-global-core/bin")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--app-bin", type=Path, required=True)
    parser.add_argument("--app-build-evidence", type=Path, required=True)
    parser.add_argument("--native-build-evidence", type=Path, required=True)
    parser.add_argument("--codex-root", type=Path, action="append", default=[])
    parser.add_argument("--claude-image", type=Path, action="append", default=[],
                        help="Opt in one exact native Windows claude.exe path and SHA-256; no install or start.")
    parser.add_argument("--antigravity-image", type=Path, action="append", default=[],
                        help="Opt in an exact Windows Antigravity.exe path and SHA-256; no install or start.")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    package = prepare(args.native_bin.resolve(strict=True), repository, args.app_bin, args.app_build_evidence,
                      args.native_build_evidence, args.output, args.codex_root, args.claude_image, args.antigravity_image)
    print(json.dumps({"package": str(package), "system_changed": False, "installed": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
