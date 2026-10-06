"""App-only explanations; no provider text, external calls or automatic retry."""
from flower_control.control.errors import explain_error as _shared_explanation


_LOCAL = {
    "app_foreground_indicator_unavailable": ("runtime_unavailable", "本次 App 操作的停止提示无法启动，尚未调用目标控件。",
        "检查窗口是否仍有效及本地停止提示状态，再重新观察；本次没有派发目标操作。"),
    "invalid_item_observation": ("invalid_request", "局部项目观察参数无效。",
        "使用 Realize 后新观察的 observation_id 和 realized_item_ref；局部范围仍限 192 节点、深度 8。"),
    "item_observation_unavailable": ("stale_observation", "项目局部观察、目标或授权范围已失效。",
        "重新观察已选窗口内的容器，定位当前项目并取得新观察；不要继续使用旧 ref。"),
    "local_item_scope_changed": ("stale_observation", "项目身份、名称或所属容器与局部观察不一致。",
        "重新观察当前容器和项目；不要将同名替代项目当作原项目继续操作。"),
    "local_item_scope_limit": ("control_unavailable", "项目嵌套范围已达到 8 层局部锚点上限。",
        "重新观察当前窗口选择更直接的容器，或在现有授权下做视觉观察。"),
    "realized_item_scope_unavailable": ("control_unavailable", "项目显现后无法确认其所属容器和精确身份。",
        "先重新观察实际可见区域；确认本次显现结果后再继续，不重复派发。"),
    "invalid_text_request": ("invalid_request", "文本分页参数无效。",
        "首次读取使用当前观察和控件 ref；续页使用上一页 cursor，每页最多 4096 字符。"),
    "text_control_unavailable": ("control_unavailable", "当前观察中的控件不能读取文本。",
        "重新观察并选择支持 TextPattern 的非密码控件。"),
    "text_pattern_unavailable": ("control_unavailable", "目标应用当前没有提供可用的 TextPattern。",
        "重新观察确认控件能力；也可使用当前授权下的值读取或截图检查。"),
    "text_cursor_or_observation_unavailable": ("stale_observation", "文本续页或首次观察已失效。",
        "重新观察同一目标，从新控件 ref 开始读取；不要把新旧版本的页拼在一起。"),
    "text_changed_during_read": ("stale_observation", "读取过程中目标文本发生了变化。",
        "待文本稳定后重新观察并从第一页读取，避免混合不同版本。"),
    "text_embedded_privacy_unavailable": ("privacy_boundary", "文本范围包含已知的受保护内容，未返回文本。",
        "选择不含密码内容的文本控件；不要通过其他读取路径绕过该限制。"),
    "text_return_not_authorized": ("authorization_context", "返回文本前目标或授权范围发生了变化。",
        "核对当前任务选中的窗口和内容范围，重新观察后再读取。"),
    "parent_context_unavailable": ("stale_observation", "返回父窗口的上下文已失效。",
        "重新观察当前任务选中的根窗口，再定位后续控件。"),
    "selected_parent_changed": ("target_changed", "任务当前选中的父窗口已经变化。",
        "重新观察当前选中的窗口，不再使用旧对话框的父窗口引用。"),
    "invalid_parent_context": ("invalid_request", "父窗口观察缺少有效的上下文标识。",
        "使用子窗口观察返回的 parent_context 标识，或直接观察当前选中的根窗口。"),
    "menu_pattern_unavailable": ("control_unavailable", "所选菜单项没有可用的菜单操作模式。",
        "重新观察菜单项的能力和 ref；只有实际支持的模式才能执行。"),
    "scroll_axis_unavailable": ("control_unavailable", "所选控件不支持请求方向的滚动。",
        "重新观察并选择对应方向可滚动的容器。"),
}


def explain_app_error(reason, *, state=None, dispatched=None):
    if type(reason) is not str or reason not in _LOCAL:
        return _shared_explanation(reason, state=state, dispatched=dispatched)
    if state in {"observed", "verified"}:
        return None
    category, summary, next_step = _LOCAL[reason]
    uncertain = state == "outcome_uncertain" or (state == "not_verified" and dispatched is not False)
    if uncertain:
        next_step = "先核对目标应用当前状态，再重新观察并决定下一步，避免重复派发。"
    return {"category": category, "severity": "error" if uncertain else "warning",
            "summary": summary, "next_step": next_step, "automatic_retry": False}
