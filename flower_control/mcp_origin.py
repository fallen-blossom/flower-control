"""Keep origin ledger waits outside the MCP event loop.

Origin association still uses the existing atomic single-consumption contract.
Cancellation may leave a consumed ticket; it never dispatches a business action
or creates a profile grant. The caller opens its diagnostic context on its own
event loop after awaiting this helper.
"""
from __future__ import annotations

import asyncio
import sqlite3

from .authorization.hook_bridge import consume_from_mcp
from .authorization.origin import OriginError


def ledger_error_code(error: sqlite3.Error, *, prefix: str) -> str:
    """Classify local SQLite failures without retaining SQL or exception text."""
    code = getattr(error, "sqlite_errorcode", None)
    busy = type(code) is int and (code & 0xff) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
    return prefix + ("_busy" if busy else "_unavailable")


async def consume_origin_async(ledger_provider, *, tool_name, arguments, origin):
    def consume():
        try:
            ledger = ledger_provider()
            task = consume_from_mcp(ledger, tool_name=tool_name,
                                    arguments=arguments, origin=origin)
            return task, ledger
        except sqlite3.Error as error:
            raise OriginError(ledger_error_code(error, prefix="origin_ledger")) from None
    return await asyncio.to_thread(consume)
