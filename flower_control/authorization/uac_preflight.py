"""Synchronize administrator-work calls with this native host's transcript.

No transcript text reaches Python, no source paths come from tool arguments,
and this fixed child never requests elevation or opens a window.
"""
import json
import re
import subprocess
from .origin import OriginError

WORK_TOOLS = {f"mcp__flower{separator}app__{name}"
              for separator in ("_", "-")
              for name in ("flower_app_work_authority", "flower_app_launch_admin")}

# Both fields are closed diagnostic vocabularies. Never turn arbitrary native
# exception text, paths or a caller-supplied stage into Hook output.
PREFLIGHT_STAGES = frozenset({"policy", "own_identity", "admission", "settings", "decode",
    "pipe_connect", "server_identity", "hello_write", "hello_read", "record_write", "record_read", "reference"})
PREFLIGHT_REASONS = frozenset({"deadline_expired", "schema_rejected", "pipe_disconnected",
    "object_access_denied", "resource_object_unavailable", "file_not_found", "helper_failure",
    "client_user_session_rejected", "flower_entry_rejected", "codex_launch_chain_unverified",
    "native_host_image_changed", "dsh_direct_host_required", "process_unavailable",
    "message_too_large", "partial_message"})
PREFLIGHT_PROCESS_TIMEOUT = 10  # Native has an 8s monotonic budget; allow child startup/exit.
PREFLIGHT_HOOK_TIMEOUT = 12  # Also leave time for Python startup and normal source-ticket issuance.


def _failure_code(reply):
    reason = reply.get("Reason") if isinstance(reply, dict) else None
    if isinstance(reason, str) and re.fullmatch(r"(?:uac|work|semantic_delegation)_[a-z_]{1,70}", reason):
        return reason
    stage = reply.get("Stage") if isinstance(reply, dict) else None
    if isinstance(reason, str) and reason in PREFLIGHT_REASONS and isinstance(stage, str) and stage in PREFLIGHT_STAGES:
        return "uac_preflight_" + stage + "_" + reason
    return "uac_transcript_preflight_unavailable"


def _synchronize(event, *, host="codex"):
    if host != "codex" or not isinstance(event, dict) or event.get("tool_name") not in WORK_TOOLS:
        return None
    arguments = event.get("tool_input")
    if event["tool_name"] in WORK_TOOLS and isinstance(arguments, dict):
        default_command = "list" if event["tool_name"].endswith("__flower_app_launch_admin") else "status"
        if arguments.get("command", default_command) in {"status", "source_status", "list", "recover", "revoke", "close", "cancel"}:
            return None  # Reading/reducing an existing work never needs a new message.
    from flower_control.drivers.high_helper import _installed_bundle
    bundle, _ = _installed_bundle()
    payload = {key: event.get(key) for key in
               ("hook_event_name", "session_id", "turn_id", "transcript_path", "tool_name")}
    # Lookup only: the native broker must verify the protected, committed
    # work before using its old message digest to recover a cold source cache.
    # No caller text, path or approval is forwarded from tool_input.
    if isinstance(arguments, dict) and arguments.get("work_id") is not None:
        payload["work_id"] = arguments["work_id"]
    result = subprocess.run([str(bundle.directory / "Flower.HighHelper.exe"), "--uac-host-preflight"],
        input=json.dumps(payload, ensure_ascii=True).encode("ascii"), capture_output=True,
        timeout=PREFLIGHT_PROCESS_TIMEOUT, creationflags=subprocess.CREATE_NO_WINDOW)
    if len(result.stdout) > 8192: raise OriginError("uac_transcript_preflight_unavailable")
    reply = json.loads(result.stdout)
    if result.returncode:
        raise OriginError(_failure_code(reply))
    if reply == {}: return None  # Saved mode off keeps its prior behavior.
    reference = reply.get("MessageRef") if isinstance(reply, dict) else None
    if not isinstance(reply, dict) or reply.get("State") != "verified" or not isinstance(reference, str) or len(reference) not in {32, 64} or any(c not in "0123456789abcdef" for c in reference):
        raise ValueError("uac_transcript_preflight_unavailable")
    return "Flower task source reference: " + reference + ". Review any new user restriction before acting; this reference itself grants no permission."


def synchronize(event, *, host="codex"):
    try: return _synchronize(event, host=host)
    except OriginError: raise
    except subprocess.TimeoutExpired:
        raise OriginError("uac_preflight_process_timeout") from None
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise OriginError("uac_transcript_preflight_unavailable") from None
