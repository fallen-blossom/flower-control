"""Fixed local timings, with no application content or scheduling estimates."""
import time
from contextlib import contextmanager


NATIVE_EXECUTION_FIELDS = frozenset({"native_uia_initialize",
                    "native_local_resolve", "native_go_rebind", "native_pattern_call",
                    "native_internal_readback", "native_uia_dispose", "native_control_lookup",
                    "native_observation_read"})
FIELDS = NATIVE_EXECUTION_FIELDS | frozenset({"worker_total", "worker_startup", "worker_response", "worker_cleanup",
                    "native_spawn", "native_preflight", "native_result", "native_cleanup",
                    "native_reply_wait", "native_exit_wait"})


def safe_timings(value):
    return {key: fact for key, fact in value.items()
            if key in FIELDS and type(fact) is int and fact >= 0} if type(value) is dict else {}


@contextmanager
def timed_phase(timings, name):
    start = time.perf_counter()
    try:
        yield
    finally:
        timings[name] = max(0, round((time.perf_counter() - start) * 1000))
