"""Read-only capability and loaded-source status for each Flower MCP channel."""

from __future__ import annotations

import hashlib
import asyncio
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib

from mcp.server.fastmcp import FastMCP
from ._executor_metadata import executor_metadata


_CHANNELS = {"flower-web", "flower-app", "flower-computer"}
_LIMITATIONS = {
    "flower-web": [
        "新增编辑器、上传下载、等待与诊断已有实现；完整日常开发任务仍需运行复核。",
        "使用落花 profile 需本聊天授权；状态查询不检查登录态。",
    ],
    "flower-app": [
        "启动/正常关闭、模态/虚拟化和录制入口已有实现；WPF 小试通过，日常 provider 尚未整体覆盖。UIA 写动作参与前台排期。",
        "已列出的工具仍需可信聊天和新近选择的目标才能控制窗口。",
    ],
    "flower-computer": [
        "UIA 候选和可见停止提示已有实现；纯画布仍依赖宿主视觉，完整连续任务尚未整体通过。",
        "已列出的工具仍需可信聊天、新鲜目标和前台核对才能输入。",
        "全局 desktop 工具无需预选窗口；截图为逐个获准窗口脱敏后的合成，透明/瞬态窗口可能不同或黑色，不是逐像素全屏等价。窗口锁定入口保留。",
    ],
}


def loaded_source(source_path: str) -> dict[str, str | None]:
    """Capture the source file at server construction, without starting a driver."""
    path = Path(source_path).resolve()
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = None
    package_hash = hashlib.sha256()
    source_count = 0
    try:
        # Entrypoint alone misses driver changes. Bind the package's source
        # snapshot too; these hashes describe construction, not hot reload.
        package_root = path.parent
        for item in sorted(package_root.rglob("*")):
            relative = item.relative_to(package_root)
            native_source = (item.suffix in {".cs", ".cpp"} and not
                             {"bin", "obj"}.intersection(part.lower() for part in relative.parts[:-1]))
            if item.is_file() and (item.suffix == ".py" or native_source):
                package_hash.update(relative.as_posix().encode("utf-8") + b"\0")
                package_hash.update(hashlib.sha256(item.read_bytes()).digest())
                source_count += 1
        package_digest = package_hash.hexdigest()
    except OSError:
        package_digest = None
    try:
        package_version = version("flower-control")
    except PackageNotFoundError:
        package_version = None
    try:
        project = tomllib.loads((path.parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
        source_version = project["project"]["version"]
    except (OSError, ValueError, KeyError, TypeError):
        source_version = None
    return {"source_project_version": source_version,
            "installed_distribution_version": package_version,
            "entrypoint_path": str(path),
            "entrypoint_sha256_at_server_creation": digest,
            "package_source_sha256_at_server_creation": package_digest,
            "package_source_files": str(source_count)}


def status_details(channel: str, source: dict[str, str | None], *,
                   registered_tools: list[str], channel_usable: bool) -> dict[str, object]:
    """Describe this loaded process; neither inspect targets nor open state."""
    if channel not in _CHANNELS:
        raise ValueError(f"Unknown Flower channel: {channel}")
    broker = high_broker_status(channel)
    on_disk = None
    if source.get("entrypoint_path"):
        current = loaded_source(source["entrypoint_path"])
        on_disk = {"entrypoint_sha256": current["entrypoint_sha256_at_server_creation"],
                   "package_source_sha256": current["package_source_sha256_at_server_creation"],
                   "package_source_files": current["package_source_files"],
                   "source_project_version": current["source_project_version"]}
    return {"overall_complete": False,
            "channel_usable": channel_usable,
            "channel_usable_meaning": "入口已加载；具体目标、授权和动作结果须在实际调用时核对。",
            "registered_tools": registered_tools,
            "loaded_source": source,
            "executor": executor_metadata(),
            "on_disk_source": on_disk,
            "high_broker": broker,
            "effective_control": effective_control_state(channel, broker),
            "limitations": list(_LIMITATIONS[channel])}


def effective_control_state(channel, broker):
    """Explain existing switches; this snapshot never admits an operation."""
    status = broker.get("status") if isinstance(broker, dict) else None
    if not isinstance(status, dict) or broker.get("connected") is not True:
        return {"state": "unknown", "channel_writes": "unknown", "authority_granted": False,
                "reason": "current_control_switches_unavailable"}
    tier = status.get("authority_tier")
    stopped, computer_paused = status.get("global_write_stopped"), status.get("computer_paused")
    if type(tier) is not int or tier not in {-1, 0, 1, 2} or type(stopped) is not bool or type(computer_paused) is not bool:
        return {"state": "unknown", "channel_writes": "unknown", "authority_granted": False,
                "reason": "current_control_switches_unavailable"}
    disabled = tier == -1
    state = ("disabled_by_tier" if disabled else "all_writes_stopped" if stopped
             else "computer_paused" if computer_paused else "enabled")
    blocked = disabled or stopped
    executor_reasons = [key for key in ("paused", "stopping", "desktop_locked", "release_fault", "role_transition")
                        if status.get(key) is True]
    incomplete = any(type(status.get(key)) is not bool for key in ("paused", "stopping", "desktop_locked", "release_fault"))
    if not blocked and executor_reasons:
        state = "executor_unavailable"
        # DOM work is independent of native focus/input. The actual Web call
        # still checks its own shared Stop, profile and page authority.
        blocked = channel != "flower-web"
    writes = "blocked" if blocked else "unknown" if incomplete else "requires_target_checks"
    if incomplete and state == "enabled":
        state = "unknown"
    return {"state": state, "authority_tier": tier, "all_writes_stopped": stopped,
            "computer_paused": computer_paused,
            "computer_input_writes": ("blocked" if disabled or stopped or computer_paused or executor_reasons
                                      else "unknown" if incomplete else "requires_target_checks"),
            "non_computer_writes": writes,
            "channel_writes": writes, "executor_unavailable_reasons": executor_reasons,
            "authority_granted": False,
            "computer_pause_affects_web_or_app": False,
            "meaning": "仅说明 Flower 开关状态；具体操作仍检查目标、权限、Stop 和实际结果。"}


def high_broker_status(channel):
    try:
        from .drivers.high_helper import ActiveHelperClient
        return ActiveHelperClient(channel=channel).probe_status()
    except Exception:
        return {"state": "unknown", "reason": "broker_status_probe_unavailable",
                "installed": None, "running": None, "connected": False,
                "high_token_verified": None, "source_admitted": None, "high_control_available": False}


def create_server(channel: str, *, source_path: str) -> FastMCP:
    if channel not in _CHANNELS:
        raise ValueError(f"Unknown Flower channel: {channel}")

    from flower_control.tool_guidance import task_method_instructions
    server = FastMCP(channel, instructions=task_method_instructions(channel))
    source = loaded_source(source_path)

    def build_status() -> dict[str, object]:
        names = [tool.name for tool in server._tool_manager.list_tools()]
        return {"channel": channel,
                "ready": False,
                "phase": "partial_web_control",
                "available_actions": [name.removeprefix("flower_web_")
                                      for name in names if name.startswith("flower_web_")],
                **status_details(channel, source, registered_tools=names, channel_usable=True)}

    @server.tool(name="flower_status", description="Report registered Web capabilities, loaded source and current limits without opening a browser.")
    async def flower_status() -> dict[str, object]:
        return await asyncio.to_thread(build_status)

    return server
