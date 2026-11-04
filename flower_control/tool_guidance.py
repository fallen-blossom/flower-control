"""Concise task routing delivered through MCP initialization."""

TASK_METHOD_INSTRUCTIONS = (
    "Prefer an authorized trusted API, CLI or file for ordinary development and "
    "system work when suitable; prefer Web DOM or App UIA for suitable GUI work. "
    "These are preferences, not bans, approval gates or a requirement to exhaust "
    "alternatives. Choose a suitable authorized route, including Computer for "
    "convenience, reliability, verification or an explicit user choice. A "
    "structured API under the Computer namespace is not screen or keyboard input. "
    "Actual UI and input-method acceptance requires the requested interaction; "
    "files or paste do not replace a real typing test. Computer-only pause stops "
    "Computer mouse/keyboard input; independently authorized App, Web and "
    "structured admin APIs can continue. Respect actual denial, privacy and "
    "global Stop; never replay an uncertain write. Verify the result."
)

CHANNEL_EXECUTION_INSTRUCTIONS = {
    "flower-web": "Web supports page DOM actions and bounded flows.",
    "flower-app": "App supports UIA controls and bounded flows.",
    "flower-computer": "Computer also exposes structured local APIs alongside visual and physical input.",
}

def task_method_instructions(channel: str) -> str:
    if channel not in CHANNEL_EXECUTION_INSTRUCTIONS:
        raise ValueError("unknown_flower_channel")
    return TASK_METHOD_INSTRUCTIONS + " " + CHANNEL_EXECUTION_INSTRUCTIONS[channel]
