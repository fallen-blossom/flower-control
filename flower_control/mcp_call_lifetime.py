"""Forward host cancellation without cancelling a running native thread."""
import asyncio
import inspect
from importlib.metadata import version
import anyio
from mcp import types
from .control.call_cancellation import current_call_cancel, CallCancellation


def install_call_cancellation(server):
    low = server._mcp_server
    if getattr(low, "_flower_call_cancellation", False):
        return
    # This thin adapter deliberately targets the project's pinned SDK. The
    # SDK owns wire parsing, responder cancellation and transport teardown.
    if (version("mcp") != "1.30.0" or tuple(inspect.signature(low._handle_request).parameters)
            != ("message", "req", "session", "lifespan_context", "raise_exceptions")):
        raise RuntimeError("mcp_call_lifetime_sdk_contract_changed")
    original = low.request_handlers[types.CallToolRequest]
    original_handle = low._handle_request

    def completed(task):
        if not task.cancelled():
            task.exception()

    async def withdraw(event):
        event.set()
        with anyio.CancelScope(shield=True):
            cleanup = asyncio.create_task(asyncio.to_thread(event.withdraw))
            cleanup.add_done_callback(completed)
            await asyncio.wait({cleanup}, timeout=2)

    async def handle(message, req, session, lifespan_context, raise_exceptions):
        if not isinstance(req, types.CallToolRequest):
            return await original_handle(message, req, session, lifespan_context, raise_exceptions)
        event = CallCancellation()
        token = current_call_cancel.set(event)
        delivered = False
        original_respond = message.respond

        async def respond(response):
            nonlocal delivered
            await original_respond(response)
            delivered = not message.cancelled

        message.respond = respond
        try:
            return await original_handle(message, req, session, lifespan_context, raise_exceptions)
        finally:
            try:
                # _completed is set before SDK send; it does not prove send
                # returned. Broken/closed transport may be swallowed by SDK.
                if not delivered or message.cancelled:
                    await withdraw(event)
            finally:
                message.respond = original_respond
                current_call_cancel.reset(token)

    async def call(request):
        event = current_call_cancel.get()
        if not isinstance(event, CallCancellation):
            event = CallCancellation()
        token = current_call_cancel.set(event)
        worker = asyncio.create_task(original(request))
        worker.add_done_callback(completed)
        try:
            await asyncio.wait({worker})
            return worker.result()
        except anyio.get_cancelled_exc_class():
            event.set()
            worker.cancel()
            # Signal before inner lifetimes await their executor cleanup.
            # A late native result remains owned by those lifetimes and ledger.
            try:
                with anyio.CancelScope(shield=True):
                    cleanup = asyncio.create_task(asyncio.to_thread(event.withdraw))
                    cleanup.add_done_callback(completed)
                    await asyncio.wait({worker, cleanup}, timeout=2)
            except anyio.get_cancelled_exc_class():
                pass
            raise
        finally:
            current_call_cancel.reset(token)

    low.request_handlers[types.CallToolRequest] = call
    low._handle_request = handle
    low._flower_call_cancellation = True
