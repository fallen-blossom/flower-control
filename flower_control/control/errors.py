"""Static local explanations for stable Flower control error codes.

Unknown reasons deliberately have no generated explanation. This module never
uses exception messages, user input, or provider text to explain a failure.
"""
from __future__ import annotations

import re


def _entry(category: str, severity: str, summary: str, next_step: str) -> dict:
    return {"category": category, "severity": severity, "summary": summary,
            "next_step": next_step, "automatic_retry": False}


_ERRORS = {
    "invalid_app_request": _entry(
        "invalid_request", "warning", "App 工具请求格式无效。",
        "检查目标、操作参数和 action_id 后重新发起。"),
    "invalid_target_encoding": _entry(
        "invalid_request", "warning", "App 目标标识格式无效。",
        "重新选择目标窗口，并使用该工具返回的目标标识。"),
    "ordinary_window_selection_unavailable": _entry(
        "target_unavailable", "warning", "当前没有可用的普通 App 窗口选择器。",
        "确认目标窗口已打开并可见，再重新列出窗口。"),
    "invalid_launch_request": _entry(
        "invalid_request", "warning", "App 启动请求不符合当前工具格式。",
        "检查可执行文件路径、启动参数和启动模式后重新发起。"),
    "invalid_action_id": _entry(
        "invalid_request", "warning", "action_id 缺失或格式无效。",
        "为这次独立操作提供稳定且长度有效的 action_id。"),
    "launch_outcome_uncertain": _entry(
        "runtime_failure", "error", "App 启动请求没有返回可确认的结果。",
        "检查目标进程和窗口是否已经启动，再决定是否再次发起。"),
    "visual_return_not_authorized": _entry(
        "authorization_context", "warning", "截图未通过返回前的目标和授权复查。",
        "重新确认目标窗口和当前内容授权后，再重新观察。"),
    "invalid_app_observation_view": _entry(
        "invalid_request", "warning", "App 观察视图或附带参数无效。",
        "检查 view、content 和 limits 的组合后重新观察。"),
    "app_native_worker_missing": _entry(
        "runtime_unavailable", "error", "Flower App 的本机 UI 自动化组件不可用。",
        "检查当前安装是否包含 App native worker；修复后再重新发起。"),
    "app_content_scope_mismatch": _entry(
        "authorization_context", "warning", "当前调用的目标窗口或任务来源与现有本地授权范围不匹配。",
        "检查目标是否仍为当前任务选中的窗口；仅在现有授权仍对应时重新发起，不创建新的授权卡。"),
    "trusted_call_expired": _entry(
        "authorization_context", "warning", "当前调用的短期授权已过期。",
        "检查当前任务和目标窗口仍一致，再从当前任务重新发起；不需要新增授权卡。"),
    "trusted_origin_unavailable": _entry(
        "authorization_context", "warning", "无法把这次 App 调用关联到可信的当前任务。",
        "从当前 Codex 任务重新调用 App 工具。"),
    "origin_missing_or_invalid": _entry(
        "authorization_context", "warning", "App 工具没有收到有效的当前任务来源信息。",
        "从当前 Codex 任务重新调用 App 工具。"),
    "target_not_approved": _entry(
        "target_changed", "warning", "目标窗口不是当前任务已选择的窗口。",
        "重新选择预期窗口，并基于该窗口的新观察发起操作。"),
    "target_changed": _entry(
        "target_changed", "warning", "执行前检查发现目标窗口或进程实例已变化。",
        "重新选择目标窗口并重新观察；确认目标正确后再继续。"),
    "target_changed_before_dispatch": _entry(
        "target_changed", "warning", "派发前目标窗口或控件发生变化，因此没有执行本次操作。",
        "重新观察目标控件，再基于新观察发起操作。"),
    "window_identity_changed": _entry(
        "target_changed", "warning", "目标窗口身份与选择时不一致。",
        "重新选择预期窗口并重新观察。"),
    "process_instance_changed": _entry(
        "target_changed", "warning", "目标进程实例已变化。",
        "重新选择仍然打开的目标窗口并重新观察。"),
    "uia_root_mismatch": _entry(
        "stale_observation", "warning", "观察到的 UI 自动化根窗口与当前目标不一致。",
        "重新观察当前目标窗口，再选择要操作的控件。"),
    "root_version_changed": _entry(
        "stale_observation", "warning", "观察后目标窗口的 UI 结构已经变化。",
        "重新观察目标，并从新结果中选择控件。"),
    "observation_stale": _entry(
        "stale_observation", "warning", "本次操作使用的 UI 观察已过期。",
        "重新观察目标控件，再根据当前结果发起操作。"),
    "reference_changed": _entry(
        "stale_observation", "warning", "观察到的控件引用已变化。",
        "重新观察目标控件并确认新的控件身份。"),
    "control_changed_before_dispatch": _entry(
        "stale_observation", "warning", "派发前控件状态已变化，因此没有执行本次操作。",
        "重新观察控件当前状态，再决定下一步。"),
    "control_unavailable": _entry(
        "control_unavailable", "warning", "目标控件当前不可用。",
        "重新观察窗口；确认控件已显示、启用且适合该操作。"),
    "control_ambiguous_or_missing": _entry(
        "control_unavailable", "warning", "无法唯一定位请求的控件。",
        "重新观察并提供可唯一识别的控件信息。"),
    "uia_access_denied": _entry(
        "access_denied", "error", "Windows UI 自动化无法访问目标窗口。",
        "确认目标窗口允许 UI 自动化访问；若窗口受系统或权限边界保护，请改用可访问的目标窗口。"),
    "uia_element_unavailable": _entry(
        "target_unavailable", "warning", "目标 UI 元素在操作期间变得不可用。",
        "重新观察目标窗口和控件，再判断是否继续。"),
    "uia_timeout": _entry(
        "timeout", "warning", "Windows UI 自动化调用超时。",
        "先检查目标窗口是否仍在响应；若操作可能已派发，核对当前状态后再决定是否继续。"),
    "native_call_timeout": _entry(
        "timeout", "warning", "本机 UI 自动化调用超时。",
        "先核对目标应用当前状态；确认操作没有发生后，再决定是否重新发起。"),
    "native_worker_failed": _entry(
        "runtime_failure", "error", "本机 UI 自动化进程未能正常完成。",
        "先核对目标应用当前状态；确认操作没有发生后，再检查 Flower App 组件。"),
    "native_response_invalid": _entry(
        "protocol_failure", "error", "本机 UI 自动化进程返回了无法识别的结果。",
        "先核对目标应用当前状态；确认操作没有发生后，再重新观察并决定下一步。"),
    "worker_start_failed": _entry(
        "runtime_failure", "error", "App worker 没有正常启动。",
        "确认 Flower App 组件已正确安装并可运行，然后重新发起操作。"),
    "worker_identity_missing": _entry(
        "runtime_failure", "error", "无法确认 App worker 的进程身份。",
        "检查 Flower App 组件状态；不要在身份无法确认时继续派发。"),
    "worker_response_unavailable": _entry(
        "protocol_failure", "error", "App worker 没有返回完整结果。",
        "先核对目标应用当前状态；确认操作没有发生后，再决定是否重新发起。"),
    "worker_rejected_or_invalid": _entry(
        "protocol_failure", "error", "App worker 拒绝了请求或返回了无效结果。",
        "先核对目标应用当前状态；确认操作没有发生后，再重新观察并决定下一步。"),
    "worker_result_invalid": _entry(
        "protocol_failure", "error", "App worker 返回了无效的操作状态。",
        "先核对目标应用当前状态；确认操作没有发生后，再重新观察并决定下一步。"),
    "worker_call_failed_or_timed_out": _entry(
        "runtime_failure", "error", "App worker 调用失败或超时。",
        "先核对目标应用当前状态；确认操作没有发生后，再检查 Flower App 组件。"),
    "app_worker_failed": _entry(
        "runtime_failure", "error", "App worker 遇到未分类的内部错误。",
        "先核对目标应用当前状态；确认操作没有发生后，再检查 Flower App 组件。"),
    "app_adapter_failed": _entry(
        "runtime_failure", "error", "App 操作适配器未能完成调用。",
        "先核对目标应用当前状态；确认操作没有发生后，再检查当前窗口和 Flower App 状态。"),
    "computer_adapter_failed": _entry(
        "runtime_failure", "error", "Computer 执行器未能完成调用，操作结果暂不明确。",
        "先重新观察目标并核对当前状态；确认结果后再继续，避免重放可能已发生的动作。"),
    "observation_unavailable": _entry(
        "stale_observation", "warning", "当前目标的有效 UI 观察不可用。",
        "重新观察当前目标窗口后再选择下一步。"),
    "foreground_required": _entry(
        "foreground_required", "warning", "目标应用需要处于前台才能执行这项操作。",
        "确认目标窗口，并显式发起需要前台的操作。"),
    "window_disabled": _entry(
        "target_unavailable", "warning", "目标窗口当前处于禁用状态。",
        "确认目标应用已就绪并重新观察窗口。"),
    "native_preflight_timeout": _entry(
        "timeout", "warning", "本机 UI 自动化进程未能在预检阶段及时响应。",
        "确认目标应用仍在响应后重新观察；本次尚未派发具体 UI 操作。"),
    "native_preflight_failed": _entry(
        "runtime_failure", "error", "本机 UI 自动化进程在预检阶段退出。",
        "确认目标应用和 Flower App 组件状态后重新观察。"),
    "native_protocol_invalid": _entry(
        "protocol_failure", "error", "本机 UI 自动化预检结果无法识别。",
        "重新观察目标；若再次出现，请导出本机诊断信息。"),
    "native_exit_timeout": _entry(
        "timeout", "error", "本机 UI 自动化进程没有及时退出。",
        "先核对目标应用当前状态；确认操作没有发生后，再检查 Flower App 组件。"),
    "permit_revoked_before_native_call": _entry(
        "authorization_context", "warning", "操作派发前当前任务授权已撤销。",
        "重新确认当前任务、目标窗口和本地授权后再发起。"),
    "permit_revoked_during_native_call": _entry(
        "authorization_context", "warning", "操作期间当前任务授权被撤销。",
        "先核对目标应用当前状态；授权撤销后不要自动重发。"),
    "foreground_phase_interrupted": _entry(
        "foreground_interrupted", "info", "当前前台操作因用户活动而中断。",
        "当前阶段已中断；重新观察目标后，任务会在下一短阶段自动激活目标继续，不会恢复旧焦点或重放旧操作。"),
    # These codes are namespaced: a bare timeout/rate_limited code is not
    # assumed to come from Jev or App.
    "jev_timeout": _entry(
        "scheduler_timeout", "warning", "Jev 调度请求超时。",
        "查看本次调度决策是否已由本地候选完成；若要再请求 Jev，检查本机连接后重新发起调度。"),
    "jev_rate_limited": _entry(
        "scheduler_rate_limited", "warning", "Jev 服务暂时限制了请求频率。",
        "查看本次调度决策；稍后再请求 Jev，避免连续重试。"),
    "jev_authentication_failed": _entry(
        "scheduler_authentication", "error", "Jev 未接受本次本地身份验证。",
        "检查本地 Jev 配置和凭据是否仍有效；不要把凭据内容放入诊断信息。"),
    "jev_transport_failed": _entry(
        "scheduler_transport", "warning", "无法完成与 Jev 的本地调度连接。",
        "检查本机到 Jev 服务端点的连接；查看本次调度是否已按本地决策完成。"),
}

_UNCERTAIN_NEXT_STEP = (
    "先重新观察并在目标应用核对操作是否已发生；确认当前状态后再决定下一步，避免重复派发。"
)

# Stages describe the reported condition, not an inferred exception cause.
_CONDITION_STAGES: dict[str, str] = {}


def _register(codes: str, category: str, stage: str, summary: str, next_step: str,
              severity: str = "warning") -> None:
    for code in codes.split():
        _ERRORS[code] = _entry(category, severity, summary, next_step)
        _CONDITION_STAGES[code] = stage


_register("dialog_pending chooser_pending", "pending_interaction", "交互等待",
          "页面有待处理的对话框或文件选择器。", "重新观察待处理交互，使用当前引用处理后再继续原任务。")
_register("dialog_reference_stale chooser_reference_stale", "stale_observation", "交互引用复查",
          "对话框或文件选择器引用已失效。", "重新观察当前交互并取得新引用；不要沿用旧引用。")
_register("invalid_dialog_argument prompt_dialog_required", "invalid_request", "对话框参数检查",
          "对话框类型与当前操作参数不匹配。", "核对当前对话框类型；仅在文本提示框中提交文本。")
_register("web_browser_close_pending new_pages_detected", "close_pending", "正常关闭",
          "浏览器正常关闭尚未完成，仍有待处理页面或确认交互。",
          "核对已关闭与待关闭页面，处理当前确认交互后再决定继续关闭；不要强制结束进程或重放整批关闭。")
_register("browser_close_unavailable browser_context_missing", "runtime_unavailable", "浏览器关闭准备",
          "当前浏览器上下文无法完成正常关闭请求。", "核对受管浏览器是否仍存在及当前页面状态，再决定下一步。")
_register("element_reference_stale element_changed observation_changed page_changed page_content_changed page_changed_during_wait semantic_selection_expired semantic_selection_expired_or_not_permitted",
          "stale_observation", "页面目标复查", "页面或元素与选择时的观察不再一致。",
          "重新观察页面并选择当前元素；不要重用旧元素引用或旧选择。")
_register("target_closed page_not_owned_by_chat", "target_unavailable", "页面归属复查",
          "页面已关闭或不属于当前聊天的控制范围。", "核对当前聊天可控制的页面并重新选择目标。")
_register("condition_timeout wait_target_ambiguous", "wait_unverified", "页面等待核验",
          "等待条件未得到确认，或无法唯一确定等待目标。", "重新观察当前页面并核对条件；等待失败不能证明此前操作未发生。")
_register("terminal_target_unidentified terminal_focus_failed terminal_focus_changed_after_input",
          "terminal_focus", "终端焦点核对", "无法确认终端输入目标或输入期间焦点已变化。",
          "核对终端当前内容与焦点，再重新观察；不要重复提交可能已输入的命令。")
_register("secret_input_requires_user_takeover", "user_takeover", "敏感输入边界",
          "此输入需要用户接管。", "由用户在目标页面完成敏感输入，再观察任务是否可以继续。")
_register("user_paused_or_cancelled input_stopped task_revoked_or_missing task_authorization_required owner_expired_or_missing resource_paused_or_quarantined dispatcher_dead",
          "execution_stopped", "执行停止", "当前操作已停止，或继续执行所需的任务、资源与授权条件不再有效。",
          "保留已派发回执并核对当前状态；暂停、取消或撤销后不要自动恢复或重发。")
_register("web_write_not_dispatched", "dispatch_unavailable", "页面派发检查",
          "Web 写操作未取得本次派发确认。", "核对派发回执与当前页面状态，重新观察后再决定下一步。")
_register("web_dispatch_or_reply_failed worker_command_failed", "runtime_failure", "Web 调用结果检查",
          "Web 调用未取得可确认的结果，派发效果须以回执为准。",
          "先核对当前页面与动作回执并重新观察；不要重复可能已发生的操作。", "error")
_register("invalid_worker_argument invalid_web_arguments", "invalid_request", "Web 请求参数检查",
          "Web 请求参数的类型、必需字段或组合不符合工具合同。",
          "检查当前工具的 arguments，保留有效的 page_id 和引用，修正参数后使用新的 action_id；派发事实以回执为准。")
_register("invalid_computer_request", "invalid_request", "Computer 请求参数检查",
          "Computer 请求的操作或参数不符合工具合同。",
          "核对操作、目标和参数；根据当前观察修正请求并使用新的 action_id，旧动作不重放。")
_register("invalid_window_mode", "invalid_request", "浏览器窗口模式检查",
          "浏览器窗口模式参数无效。",
          "按当前工具合同选择 window_mode；显式文本必须是支持的模式，不把文本 null 当作省略参数。")
_register("web_read_unavailable", "observation_unavailable", "Web 页面读取",
          "Web 本次读取没有取得有效结果。",
          "核对受管会话与页面是否仍可用，再重新观察；本次读取失败不代表此前写操作失败。")
_register("web_permit_not_issued", "dispatch_unavailable", "Web 派发授权准备",
          "本次 Web 请求未取得工作进程派发凭据。",
          "核对当前会话、任务授权和动作回执，再基于当前状态发起新计划；旧请求不自动重发。")
_register("web_cancelled_before_write", "execution_cancelled", "Web 执行取消",
          "本次 Web 请求已取消，写入派发情况以动作回执为准。",
          "不重放旧动作；在原授权范围内重新观察并开始新计划，取消单个动作不会持久暂停任务。", "info")
_register("web_worker_unavailable", "runtime_unavailable", "Web 工作进程准备",
          "当前 Web 会话的工作进程不可用。",
          "读取会话状态并核对浏览器是否仍存在；持久 profile 使用其明确重连入口，临时会话核对正常关闭回执，不自动新建或重放旧动作。", "error")
_register("owned_browser_exited", "target_unavailable", "Web 浏览器实例检查",
          "原 Web 浏览器进程已退出。退出原因须以留存的生命周期证据为准。",
          "读取原会话的退出和清理回执；不猜测是否由用户关闭，不自动重开或重放旧动作。", "error")
_register("web_transport_poisoned", "runtime_unavailable", "Web 控制连接检查",
          "Web 控制连接已失去可靠的请求与回包对应关系，浏览器可能仍在。",
          "保留窗口和未知动作状态，核对原会话；可按已有选择交同聊天 App/Computer 接续或显式正常关闭，不重放旧动作或自动重开。", "error")
_register("session_closing_or_closed", "target_unavailable", "Web 会话准备",
          "当前 Web 会话正在关闭或已经关闭。",
          "读取会话和关闭回执；若正常关闭仍待确认，处理当前交互后再决定下一步，不向旧会话继续派发。")
_register("ticket_call_mismatch ticket_task_mismatch session_binding_mismatch", "authorization_context", "调用来源匹配",
          "本次工具、参数或聊天来源与一次性来源票据不匹配。",
          "从当前聊天按当前工具合同发起完整的新调用，由正常 Hook 路径生成对应票据；若仍拒绝，核对 Hook 与 MCP 源码指纹和默认参数规则，不复用或修改旧票据。")
_register("ticket_missing ticket_expired ticket_replayed", "authorization_context", "调用来源票据检查",
          "本次一次性来源票据缺失、过期或已经使用。",
          "从当前聊天重新发起完整调用，由正常 Hook 路径取得新票据；不复用旧票据，也不新增内容授权卡。")
_register("invalid_window_listing_options", "invalid_request", "窗口列表参数检查",
          "窗口列表选项的类型无效。", "按工具合同提供窗口列表选项，再重新列出窗口。")
_register("invalid_tool_input tool_input_too_large", "invalid_request", "调用参数来源检查",
          "调用参数无法按来源票据合同编码，或超过了本地大小边界。",
          "按当前工具合同修正或缩小请求，并从正常 Hook 路径发起完整的新调用，不截断或重用旧票据。")
_register("window_listing_cancelled", "execution_cancelled", "窗口列表取消",
          "本次窗口列表已取消，新的候选列表没有提交。",
          "不沿用本次未返回的候选；在原授权范围内重新列出窗口，取消本次请求不会持久暂停任务。", "info")
_register("window_selection_cancelled", "execution_cancelled", "窗口选择取消",
          "本次窗口选择已取消，目标选择没有提交。",
          "不重放旧选择；在原授权范围内重新列出窗口并选择当前候选，取消本次请求不会持久暂停任务。", "info")
_register("candidate_not_found candidate_changed", "target_changed", "窗口候选复查",
          "窗口候选已过期、已使用，或没有通过当前身份与请求状态复查。",
          "重新列出窗口并选择预期候选；不要猜测替代窗口或重用旧 candidate_id。")
_register("replacement_process_changed", "target_changed", "替换窗口复查",
          "替换候选不符合已选进程实例和新窗口的要求。",
          "重新列出窗口；仅在同一进程实例的新窗口符合 replacement 合同时替换，否则显式选择新的目标。")
_register("target_not_selected selected_window_unavailable handoff_target_unavailable", "target_unavailable", "已选窗口复查",
          "当前聊天没有可用的已选窗口，或已选、交接窗口没有通过当前身份检查。",
          "重新列出并显式选择预期窗口；跨通道交接须取得当前 App 观察返回的新交接标识。")
_register("window_binding_busy window_binding_queued", "queue_wait", "窗口身份绑定调度",
          "本次窗口身份绑定尚未取得可执行的调度位置。",
          "核对当前动作和窗口状态；旧绑定请求不重放，后续选择使用新列出的候选。")
_register("window_binding_failed window_binding_not_verified owned_window_binding_unavailable", "runtime_failure", "窗口身份绑定检查",
          "窗口身份绑定未取得可确认的结果。",
          "核对本机 Flower 组件与窗口身份，再重新列出并选择目标；未确认绑定前不继续控制。", "error")
_register("app_host_stopping computer_host_stopping", "runtime_unavailable", "MCP 服务关闭",
          "当前 MCP 服务正在关闭，无法接受这次新请求。",
          "先核对在途动作与输入释放回执；待服务重新加载后，从当前聊天重新观察并开始新计划，不重放旧动作。", "info")
_register("invalid_control_reference observation_target_mismatch", "stale_observation", "App 引用复查",
          "App 控件引用与当前窗口观察不匹配。", "重新观察已选窗口，并从新观察选择控件。")
_register("menu_pattern_unavailable invoke_pattern_unavailable expand_collapse_pattern_unavailable selection_item_pattern_unavailable toggle_pattern_unavailable value_pattern_unavailable scroll_pattern_unavailable virtualized_item_pattern_unavailable",
          "pattern_unavailable", "App 操作能力检查", "目标控件未提供本次操作所需的 UI 自动化模式。",
          "重新观察控件支持的操作模式，选择适用的入口；若需改用其他通道，先核对该通道的目标与授权。")
_register("text_pattern_unavailable text_control_unavailable text_cursor_or_observation_unavailable",
          "text_unavailable", "App 文本读取准备", "当前控件没有可用的文本读取模式、游标或观察。",
          "重新观察并选择支持文本读取的控件；不能据此宣称已读取全文。")
_register("text_version_changed text_changed_during_read", "text_version_changed", "App 文本版本核对",
          "读取期间文档版本发生变化。", "重新观察并从新版本开始读取；不要拼接不同版本的分页结果。")
_register("text_document_limit_exceeded", "text_incomplete", "App 全文读取边界",
          "文档超过本次读取上限，返回内容不能当作完整全文。",
          "检查 truncated、document_complete 与分页游标；按工具允许的范围读取，明确保留未读取部分。")
_register("text_response_invalid", "protocol_failure", "App 文本结果检查",
          "文本读取结果不符合当前协议。", "保留不完整状态，重新观察文本控件；不要用无效分页结果拼接全文。")
_register("text_return_not_authorized text_embedded_privacy_unavailable content_scope_not_approved",
          "authorization_context", "App 内容返回边界", "文本内容未满足当前返回授权或隐私检查条件。",
          "核对当前内容范围与本地授权；检查通过前不要读取或返回该内容。")
_register("uia_initialization_failed uia_read_failed uia_preflight_failed uia_write_failed uia_readback_failed",
          "provider_failure", "App UI 自动化调用", "UI 自动化调用未能在报告阶段完成。",
          "根据回执阶段核对当前控件与应用状态；失败代码本身不能确定提供方故障原因。", "error")
_register("uia_provider_identity_unavailable", "pattern_unavailable", "App 控件身份读取",
          "应用未提供可绑定的控件身份，App 无法操作这部分界面。",
          "使用 Computer 通道接续当前窗口，并先取得新截图；不要重放已派发的动作。")
_register("input_partial_or_blocked", "partial_input", "Computer 输入派发",
          "本次输入未完整派发；已发送数量须以回执为准。",
          "先确认已派发前缀和按键释放状态，再重新观察；不要重放整个序列或旧的未派发后缀。", "error")
_register("input_release_unconfirmed", "input_release_uncertain", "Computer 输入释放",
          "无法确认本次持有输入已完成释放。",
          "先由当前输入持有者完成受控释放并核对结果；释放未确认前停止新增输入，不要重放序列。", "error")
_register("external_input_held", "external_input", "Computer 输入准备",
          "检测到外部输入仍被按住。", "等待用户释放外部输入并重新观察；不要替用户释放不属于本次操作的按键。")
_register("foreground_watch_unavailable foreground_watch_failed", "runtime_unavailable", "前台短阶段监听",
          "本次短阶段没有取得可靠的前台事件监听；实际派发情况以回执为准。",
          "核对已执行前缀和输入释放，再重新观察并开始新阶段；若仍失败，核对助手版本和监听诊断，不重放旧动作。", "error")
_register("origin_ledger_busy control_ledger_busy", "ledger_busy", "来源与任务账本",
          "本机账本仍被另一笔事务占用，本次调用尚未进入控制操作。",
          "等待账本事务结束，再由宿主发起新调用；旧票据可能已被消费，不复用它，不重放已执行动作。")
_register("origin_ledger_unavailable control_ledger_unavailable", "ledger_unavailable", "来源与任务账本",
          "本机来源或任务账本不可用，本次调用尚未进入控制操作。",
          "核对 Flower 本机状态、数据库可读写及版本；修复后由宿主发起新调用，不披露数据库异常文本或复用旧票据。", "error")
_register("foreground_watch_release_unconfirmed", "runtime_cleanup_uncertain", "前台监听退出",
          "本次前台事件监听的退出尚未确认；这不等于键鼠一定未释放。",
          "分别核对监听退出和回执里的键鼠释放状态；输入释放未确认时停止新增输入，不重放旧动作。", "error")
_register("shell_desktop_identity_changed", "target_changed", "桌面目标复查",
          "所选窗口不再是本次绑定的 Windows Shell 桌面。",
          "重新列出并选择当前桌面目标，核对身份后发起新计划，不以普通文件夹窗口代替。")
_register("shell_activation_unavailable shell_activation_failed", "activation_incomplete", "Shell 显示桌面",
          "Shell 的显示桌面调用未完成；已经发生的窗口变化须另行观察。",
          "读取激活回执和当前桌面状态，再决定新计划；在途 Shell 调用不能靠关闭客户端宣称已撤销。")
_register("shell_worker_parent_rejected shell_worker_identity_rejected shell_worker_ready_rejected "
          "shell_worker_go_rejected shell_worker_result_rejected", "runtime_protocol_failure", "Shell 固定执行核验",
          "显示桌面的固定执行身份、准备阶段或回包没有通过核验。",
          "核对助手和工作进程版本、动作回执及实际派发阶段；不要复用被拒绝的 go 或自动重发结果未知的旧请求。", "error")
_register("shell_worker_disconnected shell_desktop_cleanup_unconfirmed", "runtime_cleanup_uncertain", "Shell 执行退出",
          "显示桌面的固定执行连接或退出没有取得完整确认；窗口变化和键鼠释放是独立事实。",
          "读取动作及助手状态，观察当前桌面并核对输入释放；go 后可能已经调用 Shell，不重放旧请求。", "error")
_register("desktop_topology_changed geometry_changed geometry_target_mismatch", "geometry_changed", "Computer 坐标复查",
          "桌面拓扑或目标几何与观察时不一致。", "重新观察目标及当前显示布局，基于新截图重新计算坐标。")
_register("activation_access_denied window_identity_access_denied", "access_denied", "Computer 窗口访问",
          "Windows 拒绝了本次窗口访问调用；具体原因尚未确定。",
          "核对目标身份与可交互状态；不要仅凭此代码认定 UIPI、提升权限或关闭系统保护。")
_register("activation_foreground_protected authorization_window_protected", "protected_window", "Computer 前台保护",
          "当前前台窗口触发了控制保护边界。", "保留该保护，待用户离开受保护交互后重新观察目标。")
_register("activation_input_incomplete activation_interrupted", "activation_incomplete", "Computer 前台激活",
          "目标激活过程未完整完成；激活输入与释放结果须以回执为准。",
          "核对当前前台窗口和激活输入释放状态；释放确认后可在原授权范围内重新观察并提出新的激活计划，若仍无法激活再由用户切换，旧动作不重放。")
_register("activation_not_authorized", "authorization_context", "Computer 激活准备",
          "当前调用未满足激活所需的执行条件。", "核对任务是否已停止、目标及当前授权；不要自动恢复已取消的操作。")
_register("user_activation_required", "activation_incomplete", "窗口前台激活",
          "目标前台激活未获确认，本次操作未完成。",
          "重新观察目标与当前前台，在原授权范围内提出新计划；若仍无法激活，可由用户切到目标后再观察，旧动作不重放。")
_register("dispatch_interrupted", "dispatch_interrupted", "执行派发",
          "本次派发被中断。",
          "先核对当前目标和已派发前缀，再基于新观察提出不重复原效果的新计划；不要重放旧动作。")
_register("target_minimized target_not_visible target_not_captureable foreground_target_not_interactive target_unresponsive",
          "target_unavailable", "Computer 窗口准备", "目标当前不可见、不可交互、不可捕获或未及时响应。",
          "核对目标窗口当前状态；在原授权范围内可提出恢复或激活目标的新计划，若仍不可交互再由用户处理，旧操作不重放。")
_register("capture_target_changed capture_session_stale_frame", "stale_observation", "Computer 截图复查",
          "截图目标或帧与当前观察绑定不一致。", "重新观察目标并取得新截图，不要依据旧帧继续输入。")
_register("capture_timeout capture_cancelled capture_wgc_unavailable capture_session_eof capture_session_expired capture_session_invalid_bitmap capture_session_invalid_header capture_worker_empty capture_worker_invalid_header capture_worker_invalid_length capture_worker_invalid_bitmap capture_worker_failed capture_worker_too_large capture_worker_wrong_backend observation_image_unavailable window_capture_too_large",
          "capture_unavailable", "Computer 截图读取", "当前截图读取未取得有效图像。",
          "核对截图回执与目标状态，再重新观察；截图失败不能证明先前激活或输入失败，也不能据此认定窗口受图形保护。")

_REPORTED_STAGES = {
    "preflight": "执行准备", "transport_preflight": "传输准备",
    "runtime_preflight": "运行时请求检查",
    "native_validation": "本机请求检查", "native_preflight": "本机执行准备",
    "uia_initialization": "UI 自动化初始化", "uia_read": "UI 自动化读取",
    "uia_preflight": "UI 自动化执行准备", "uia_write": "UI 自动化派发",
    "uia_readback": "UI 自动化结果读取", "native_call": "本机调用",
    "worker_request_read": "工作进程请求读取", "worker_request_validation": "工作进程请求检查",
    "worker_permit_check": "工作进程授权检查",
}
for _stage in ("fill click press select_option set_checked drag upload editor_replace terminal_focus "
               "close_browser new_page close_page hover navigate history element_scroll scroll "
               "download_click dialog_action chooser_upload").split():
    _REPORTED_STAGES[_stage] = "页面操作阶段"

_STOP_CODES = {code for code, item in _ERRORS.items() if item["category"] == "execution_stopped"}
for _code, _description in {
        "native_preflight_timeout": "本机执行准备", "native_preflight_failed": "本机执行准备",
        "native_protocol_invalid": "本机预检协议检查", "native_exit_timeout": "本机进程退出",
        "permit_revoked_before_native_call": "本机调用前授权复查",
        "permit_revoked_during_native_call": "本机调用期间授权复查",
        "foreground_phase_interrupted": "前台操作阶段", "launch_outcome_uncertain": "App 启动",
}.items():
    _CONDITION_STAGES[_code] = _description
for _code, _item in _ERRORS.items():
    if _code in _CONDITION_STAGES:
        continue
    if _code.startswith("jev_"):
        _CONDITION_STAGES[_code] = "Jev 调度请求"
    elif _item["category"] in {"invalid_request", "authorization_context", "target_changed", "stale_observation"}:
        _CONDITION_STAGES[_code] = {
            "invalid_request": "请求检查", "authorization_context": "来源与授权复查",
            "target_changed": "目标复查", "stale_observation": "观察与引用复查",
        }[_item["category"]]


def _effect_metadata(value: object) -> dict:
    """Retain only supplied effect facts; no payload, inference or mutation."""
    if type(value) is not dict:
        return {}
    result = {}
    for key in ("activation_dispatched", "business_dispatched", "held_released"):
        fact = value.get(key)
        if key in value and (type(fact) is bool or fact is None):
            result[key] = fact
    for key in ("input_release", "activation_input_release"):
        fact = value.get(key)
        if type(fact) is str and fact in {"not_used", "released", "unknown", "unconfirmed", "release_pending"}:
            result[key] = fact
    return result


def explain_error(reason: object, *, state: object = None,
                  dispatched: object = None, stage: object = None,
                  source: object = None, effects: object = None) -> dict | None:
    """Explain a known code, adding only allowlisted receipt metadata.

    Old callers remain valid. Original receipts remain authoritative: this
    explanation is not an effect receipt or permission to resume/retry.
    """
    if type(reason) is not str:
        return None
    if state in ("verified", "observed"):
        return None
    explanation = _ERRORS.get(reason)
    if explanation is None:
        return None
    result = dict(explanation)
    result["occurrence_stage"] = _CONDITION_STAGES.get(reason, "阶段未提供")
    if type(stage) is str and stage in _REPORTED_STAGES:
        result["stage"] = stage
        result["occurrence_stage"] = _REPORTED_STAGES[stage]
    if type(source) is str and source in {"web", "app", "computer", "jev"}:
        result["source"] = source
    facts = _effect_metadata(effects)
    if facts:
        result["reported_effects"] = facts
    release_uncertain = facts.get("held_released") is False or any(facts.get(key) in {"unknown", "unconfirmed", "release_pending"}
                            for key in ("input_release", "activation_input_release"))
    business_unsent = facts.get("business_dispatched") is False
    uncertain = (state == "outcome_uncertain" or
                 (not business_unsent and state == "not_verified" and dispatched is not False) or
                 (not business_unsent and state is None and dispatched is True) or
                 ("business_dispatched" in facts and facts["business_dispatched"] is not False))
    if reason == "foreground_phase_interrupted" and not release_uncertain and state != "outcome_uncertain":
        return result
    if uncertain:
        result["severity"] = "error"
        # Preserve specific recovery boundaries rather than flattening them.
        if reason not in _STOP_CODES and explanation["category"] not in {
                "partial_input", "input_release_uncertain", "close_pending", "terminal_focus"}:
            result["next_step"] = _UNCERTAIN_NEXT_STEP + " " + explanation["next_step"]
        if "没有执行本次操作" in result["summary"]:
            result["summary"] = "目标或控件检查报告变化；此前效果须以实际派发回执为准。"
    if release_uncertain:
        result["severity"] = "error"
        result["next_step"] = _ERRORS["input_release_unconfirmed"]["next_step"]
        if reason in _STOP_CODES:
            result["next_step"] += " 暂停、取消或撤销后不要自动恢复。"
    return result


_CODE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_STAGE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+]{0,79}$")


def safe_app_diagnostic(value: object) -> dict:
    """Copy only fixed, bounded worker metadata; never retain arbitrary text."""
    if type(value) is not dict:
        return {}
    result: dict = {}
    state = value.get("state")
    if type(state) is str and state in {
            "observed", "verified", "not_verified", "rejected", "outcome_uncertain"}:
        result["state"] = state
    reason = value.get("reason")
    if type(reason) is str and _CODE.fullmatch(reason):
        result["reason"] = reason
    stage = value.get("stage")
    if type(stage) is str and _STAGE.fullmatch(stage):
        result["stage"] = stage
    exception_type = value.get("exception_type")
    if type(exception_type) is str and _EXCEPTION_TYPE.fullmatch(exception_type):
        result["exception_type"] = exception_type
    hresult = value.get("hresult")
    if type(hresult) is int and -(1 << 31) <= hresult < (1 << 31):
        result["hresult"] = hresult
    dispatched = value.get("dispatched")
    if type(dispatched) is bool or dispatched is None:
        result["dispatched"] = dispatched
    return result
