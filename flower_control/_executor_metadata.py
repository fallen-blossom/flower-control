"""Cheap read-only identity facts for the calling MCP process, with no targets."""
import win32api
import win32con
import win32security


def executor_metadata():
    result = {"pid": win32api.GetCurrentProcessId(), "session_id": None,
              "integrity_rid": None, "integrity_level": None, "ui_access": None,
              "metadata_available": False, "error": None}
    token = None
    try:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        value = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
        sid = value[0] if isinstance(value, tuple) else value
        rid = int(win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[1])
        result.update(session_id=win32security.GetTokenInformation(token, win32security.TokenSessionId),
                      integrity_rid=rid, integrity_level={4096: "low", 8192: "medium", 12288: "high", 16384: "system"}.get(rid, "other"),
                      ui_access=bool(win32security.GetTokenInformation(token, win32security.TokenUIAccess)),
                      metadata_available=True)
    except Exception:
        result["error"] = "executor_token_probe_failed"
    finally:
        if token is not None:
            token.Close()
    return result
