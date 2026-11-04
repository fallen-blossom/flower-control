"""One read-only language snapshot per HUD, with closed authored labels only."""
from __future__ import annotations
import re

_ENGLISH = {
    "执行阶段": "Executing", "准备目标": "Preparing target", "等待执行": "Queued",
    "输入阶段": "Sending input", "核对结果": "Verifying result", "读取窗口": "Reading window",
    "等待下一步": "Idle", "等待目标变化": "Waiting for target change",
    "已阻止后续输入": "Further input blocked", "已停止，释放已确认": "Stopped; release confirmed",
    "释放未确认": "Release unconfirmed", "等待首次接管": "Waiting for takeover",
    "停止请求已收到": "Stop requested", "当前：": "Current: ", "状态：": "Status: ",
    "目的：": "Purpose: ", "下一步：": "Next: ", "接管等待：": "Takeover: ",
    "准备开始": "Preparing to start", "已停止": "Stopped", "释放待确认": "Check release",
    "控制已中止": "Control ended", "立即停止": "Stop now", "停止本次控制": "Stop control",
    "停止本次操作": "Stop this operation", "接管等待": "Takeover wait", "控制累计": "Elapsed",
    "耗时": "Elapsed", "{label} {seconds:.1f} 秒": "{label} {seconds:.1f} s",
    " · 预计 {seconds:.1f} 秒": " · estimate {seconds:.1f} s",
    "{name} · {operator} 已停止": "{name} · {operator} stopped",
    "{name} · {operator} 已中止控制": "{name} · {operator} control ended",
    "{name} · {operator} 等待确认释放": "{name} · {operator} awaiting release confirmation",
    "{name} · {operator} 待命": "{name} · {operator} idle",
    "{name} 等待 {operator} 接管": "{name} awaiting {operator} takeover",
    "{name} 准备由 {operator} 操作": "{name} preparing for {operator}",
    "{name} 正在由 {operator} 观察": "{name} observed by {operator}",
    "{name} 正在由 {operator} 操作": "{name} controlled by {operator}",
    "本次控制已结束": "This control session ended",
    "确认原执行器的按键释放": "Confirm release from the original executor",
    "全局停止，关闭本次显示": "Global stop; closing this display", "未知": "Unknown",
    "输入释放尚未确认": "Input release not yet confirmed",
    "写入已停止": "Writing stopped",
    "停止请求已收到，核对实际动作状态": "Stop requested; checking action state",
    "准备目标后执行，再重新观察结果": "Prepare target, execute, then observe again",
    "本次操作结束后重新观察结果": "Observe the result after this operation",
    "切换目标到前台": "Bring the target to the foreground",
    "本次输入已停止": "Input stopped",
    "本次输入已结束，键鼠已释放": "Input ended; keys and mouse released",
    "观察已完成，当前未发送输入": "Observation complete; no input sent",
    "等待目标条件满足": "Waiting for target condition",
    "读取目标窗口": "Read target window",
    "读取操作后的窗口": "Read the window after the operation",
    "激活目标并取得新截图": "Activate target and capture a new screenshot",
    "重查目标与输入位置": "Recheck target and input position",
    "输入已结束，读取新状态": "Input ended; read the new state",
    "重查目标与窗口外框": "Recheck target and window frame",
}


def snapshot_language():
    """No writes, retries, background polling or permission/Stop reads."""
    from flower_control.data_paths import DataPathError, resolve_data_root
    from flower_control.display_preferences import DEFAULT_LANGUAGE, read_preferences
    from flower_control.control.state import ControlError
    try:
        return read_preferences(resolve_data_root())[0]["language"]
    except (ControlError, DataPathError, OSError):
        return DEFAULT_LANGUAGE


def hud_text(authored, language="zh-CN"):
    # Callers pass only their own fixed literals, never task/window/user text.
    return _ENGLISH.get(authored, authored) if language == "en" else authored


_CHECKPOINTS = frozenset({
    "输入释放尚未确认", "写入已停止", "停止请求已收到，核对实际动作状态",
    "准备目标后执行，再重新观察结果", "本次操作结束后重新观察结果",
    "切换目标到前台", "本次输入已停止", "本次输入已结束，键鼠已释放",
    "观察已完成，当前未发送输入", "等待目标条件满足", "读取目标窗口",
    "读取操作后的窗口", "激活目标并取得新截图", "重查目标与输入位置",
    "输入已结束，读取新状态", "本次控制已结束", "确认原执行器的按键释放",
    "全局停止，关闭本次显示", "重查目标与窗口外框",
})


_OPERATIONS = {
    "输入文本": "Enter text", "发送按键": "Send keys", "点击目标": "Click target",
    "双击目标": "Double-click target", "点击所选控件": "Click selected control",
    "点击所选区域": "Click selected region", "选择并点击区域": "Select and click region",
    "拖动目标": "Drag target", "滚动内容": "Scroll content", "移动指针": "Move pointer",
    "组合键鼠操作": "Combined keyboard and mouse input", "按住鼠标": "Hold mouse button",
    "移动窗口": "Move window", "调整窗口大小": "Resize window",
    "切换到目标窗口": "Switch to target window", "执行连续操作": "Execute sequence",
    "执行窗口操作": "Execute window operation", "设置控件文本": "Set control text",
    "设置开关状态": "Set toggle", "选择项目": "Select item", "展开或折叠项目": "Expand or collapse item",
    "滚动控件": "Scroll control", "显现虚拟项目": "Realize virtual item", "调用控件": "Invoke control",
    "正常关闭窗口": "Close window", "执行当前 App 操作": "Execute App operation",
}


def hud_checkpoint_text(value, language="zh-CN"):
    if language != "en" or not isinstance(value, str):
        return value
    if value in _CHECKPOINTS:
        return hud_text(value, language)
    if value in _OPERATIONS:
        return _OPERATIONS[value]
    step = re.fullmatch(r"复查步骤 ([0-9]{1,6})", value)
    if step:
        return f"Verify step {step.group(1)}"
    sequence = re.fullmatch(r"(准备)?(.+?) · ([0-9]{1,6})/([0-9]{1,6})", value)
    if sequence and sequence.group(2) in _OPERATIONS:
        operation = _OPERATIONS[sequence.group(2)]
        return f"{'Prepare: ' if sequence.group(1) else ''}{operation} · {sequence.group(3)}/{sequence.group(4)}"
    return value


def hud_takeover_checkpoint(checkpoint, language="zh-CN"):
    """Translate only the two exact program-authored countdown patterns."""
    if language != "en" or type(checkpoint) is not str:
        return checkpoint
    for suffix, template in (
        (" 秒后开始；可点停止拒绝", "Starting in {seconds}s; press Stop to cancel"),
        (" 秒后开始；等待你操作完；可点停止拒绝",
         "Starting in {seconds}s; waiting for you; press Stop to cancel"),
    ):
        if checkpoint.endswith(suffix):
            seconds = checkpoint[:-len(suffix)]
            if seconds in {"1", "2"}:
                return template.format(seconds=seconds)
    return checkpoint


def hud_stop_text(authored, language="zh-CN", compact=False):
    if language == "en" and compact:
        # The original compact hit area remains 72 logical pixels wide.
        return {"释放待确认": "Pending", "控制已中止": "Ended"}.get(authored, hud_text(authored, language))
    return hud_text(authored, language)
