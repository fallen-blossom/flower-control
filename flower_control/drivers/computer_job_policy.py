"""Read the calling process's documented immediate Job policy, never alter it."""
import win32api
import win32job


def current_job_policy():
    result = {"in_job": bool(win32job.IsProcessInJob(win32api.GetCurrentProcess(), None)),
              "scope": "calling_process_immediate_job", "parent_jobs_inspected": False}
    if not result["in_job"]:
        return {**result, "child_creation": "ordinary", "limit_flags": None}
    try:
        flags = win32job.QueryInformationJobObject(None, win32job.JobObjectExtendedLimitInformation)[
            "BasicLimitInformation"]["LimitFlags"]
    except Exception as error:
        return {**result, "child_creation": "unverified", "query_error": getattr(error, "winerror", None)}
    silent = bool(flags & win32job.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
    explicit = bool(flags & win32job.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
    return {**result, "limit_flags": flags, "silent_breakaway_ok": silent, "breakaway_ok": explicit,
            "child_creation": "ordinary" if silent else "explicit_breakaway" if explicit else "blocked"}
