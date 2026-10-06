"""Bounded Playwright page observations and exact-reference actions.

The session owner supplies authorization, resource locks and at-most-once
receipts. This module never attaches to a browser by URL or discovers profiles.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from playwright.async_api import ElementHandle, Frame, Page, TimeoutError as PlaywrightTimeoutError

from flower_control.control.state import ControlError
from .web_effects import mark_write
from .web_workflow import WebWorkflow
from .web_discovery import describe_frames, source_origin
from .web_batch import validate_condition


_DESCRIBE = """e => ({connected:e.isConnected, tag:e.tagName,
 visible:!!(e.getClientRects().length && e.ownerDocument.defaultView.getComputedStyle(e).visibility !== 'hidden'),
 type:e.tagName === 'INPUT' ? e.type : e.getAttribute('type'), role:e.getAttribute('role'),
 name:e.getAttribute('aria-label') || e.getAttribute('name') || '',
 id:e.id, disabled:!!e.disabled, editable:e.isContentEditable,
 checked:e.matches('input[type=checkbox],input[type=radio]') ? !!e.checked : null,
 options:e.tagName === 'SELECT' ? Array.from(e.options).slice(0,50)
   .map(o=>({value:o.value.slice(0,256),label:o.label.slice(0,256)})) : null,
 option_total:e.tagName === 'SELECT' ? e.options.length : null,
 text:(e.innerText || e.textContent || '').slice(0,2048),
 text_truncated:(e.innerText || e.textContent || '').length > 2048,
 value:e.type === 'password' ? null : ('value' in e ? e.value : null)})"""


_MONACO = """(element, request) => {
  let writeAttempted = false;
  const outcome = (() => {
  const api = element.ownerDocument.defaultView.monaco?.editor;
  if (!api || typeof api.getEditors !== 'function')
    return {error:'editor_api_unavailable'};
  const editors = api.getEditors().filter(editor => {
    const node = editor.getDomNode();
    return node && (node === element || element.contains(node));
  });
  if (editors.length !== 1) return {error:'editor_target_ambiguous'};
  const editor = editors[0], model = editor.getModel();
  if (!model || model.isDisposed()) return {error:'editor_model_missing'};
  const uri = model.uri.toString(), version = model.getVersionId();
  // Only resource URIs identify a file/document for this generic adapter.
  if (!['file','http','https','vscode-remote'].includes(model.uri.scheme) ||
      !model.uri.path || model.uri.path === '/')
    return {error:'editor_document_unidentified'};
  if (request.kind === 'replace') {
    if (uri !== request.expected_uri || version !== request.expected_version)
      return {error:'editor_model_changed'};
    writeAttempted = true;
    editor.pushUndoStop();
    const accepted = editor.executeEdits('flower-control',
      [{range:model.getFullModelRange(),text:request.text,forceMoveMarkers:true}]);
    editor.pushUndoStop();
    if (!accepted) return {error:'editor_edit_rejected'};
  }
  const value = model.getValue();
  if (request.kind === 'read') {
    const points = Array.from(value);
    return {uri,version:model.getVersionId(),text:points.slice(request.offset,request.offset+request.limit).join(''),total:points.length};
  }
  return {uri,version:model.getVersionId(),length:Array.from(value).length,
    exact:request.kind === 'replace' ? value === request.text : undefined};
  })();
  return {...outcome, flower_write_attempted:writeAttempted};
}"""


_CODEMIRROR = """(element, request) => {
  let writeAttempted = false;
  const outcome = (() => {
  const roots = [element, element.closest('.CodeMirror,.cm-editor'),
                 ...element.querySelectorAll('.CodeMirror,.cm-editor')].filter(Boolean);
  const found = [];
  for (const root of roots) {
    if (root.CodeMirror && !found.some(item => item.api === root.CodeMirror))
      found.push({kind:'codemirror5',api:root.CodeMirror,root});
    if (root.classList?.contains('cm-editor')) {
      const content = root.querySelector('.cm-content');
      const View = root.ownerDocument.defaultView.EditorView;
      // Bundled CM6 usually does not publish EditorView on window. These DOM
      // links are the ones used by findFromDOM in upstream CM6 releases:
      // cmView in 6.30, cmTile in the current upstream source.
      let publicView = null;
      try { publicView = View?.findFromDOM?.(root); } catch {}
      for (const view of [publicView, content?.cmView?.rootView?.view,
                          content?.cmTile?.root?.view]) {
        if (view && view.dom === root && view.contentDOM === content &&
            typeof view.dispatch === 'function' && view.state?.doc &&
            !found.some(item => item.api === view))
          found.push({kind:'codemirror6',api:view,root});
      }
    }
  }
  if (found.length !== 1) return {error:found.length ? 'editor_target_ambiguous' : 'editor_api_unavailable'};
  const {kind,api,root} = found[0];
  const content = kind === 'codemirror6' ? root.querySelector('.cm-content') : null;
  const sourceURI = root.getAttribute('data-document-uri') || element.getAttribute('data-document-uri');
  let uri = null;
  if (sourceURI !== null) {
    let parsed;
    try { parsed = new URL(sourceURI); } catch { return {error:'editor_document_unidentified'}; }
    if (!['file:','http:','https:','vscode-remote:'].includes(parsed.protocol) ||
        !parsed.pathname || parsed.pathname === '/') return {error:'editor_document_unidentified'};
    uri = sourceURI;
  }
  if (kind === 'codemirror5' && typeof api.getDoc !== 'function')
    return {error:'editor_api_unavailable'};
  const doc = kind === 'codemirror5' ? api.getDoc() : api.state.doc;
  if (!doc || (kind === 'codemirror5' && typeof doc.getValue !== 'function'))
    return {error:'editor_model_missing'};
  const value = kind === 'codemirror5' ? doc.getValue() : doc.toString();
  const state = kind === 'codemirror5' ? doc : api.state;
  const host = root.ownerDocument.defaultView;
  const versions = host[Symbol.for('flower-control-codemirror-versions')] ||
    (host[Symbol.for('flower-control-codemirror-versions')] = new WeakMap());
  const identities = host[Symbol.for('flower-control-codemirror-identities')] ||
    (host[Symbol.for('flower-control-codemirror-identities')] = new WeakMap());
  const model = kind === 'codemirror5' ? doc : api;
  let identity = uri;
  if (!identity) {
    identity = identities.get(model);
    if (!identity) {
      const bytes = new Uint8Array(16);
      host.crypto.getRandomValues(bytes);
      identity = 'model-object:' + Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
      identities.set(model, identity);
    }
  }
  const identityKind = uri ? 'document_uri' : 'model_object';
  let record = versions.get(api);
  if (!record) { record = {model,state,value,version:1}; versions.set(api,record); }
  else if (record.model !== model || record.state !== state || record.value !== value) {
    record.model = model; record.state = state; record.value = value; record.version++;
  }
  if (request.kind === 'replace') {
    if (identity !== request.expected_uri || record.version !== request.expected_version)
      return {error:'editor_model_changed'};
    if (kind === 'codemirror5') {
      if (api.getOption?.('readOnly') || api.isReadOnly?.()) return {error:'editor_read_only'};
      if (typeof doc.replaceRange !== 'function' || typeof doc.firstLine !== 'function' ||
          typeof doc.lastLine !== 'function' || typeof doc.getLine !== 'function')
        return {error:'editor_api_unavailable'};
      writeAttempted = true;
      doc.replaceRange(request.text, {line:doc.firstLine(),ch:0},
                       {line:doc.lastLine(),ch:doc.getLine(doc.lastLine()).length},
                       'flower-control');
    } else {
      if (api.state.readOnly || content?.getAttribute('contenteditable') === 'false')
        return {error:'editor_read_only'};
      writeAttempted = true;
      api.dispatch({changes:{from:0,to:doc.length,insert:request.text}});
    }
    if ((kind === 'codemirror5' && api.getDoc() !== doc) ||
        (kind === 'codemirror6' && api.dom !== root) ||
        (root.getAttribute('data-document-uri') || element.getAttribute('data-document-uri')) !== sourceURI)
      return {error:'editor_model_changed'};
    record.model = kind === 'codemirror5' ? api.getDoc() : api;
    record.state = kind === 'codemirror5' ? record.model : api.state;
    record.value = kind === 'codemirror5' ? record.state.getValue() : record.state.doc.toString();
    record.version++;
  }
  const current = record.value;
  if (request.kind === 'read') {
    const points = Array.from(current);
    return {editor:kind,uri,identity,identityKind,version:record.version,
            text:points.slice(request.offset,request.offset+request.limit).join(''),total:points.length};
  }
  return {editor:kind,uri,identity,identityKind,version:record.version,length:Array.from(current).length,
          exact:request.kind === 'replace' ? current === request.text : undefined};
  })();
  return {...outcome, flower_write_attempted:writeAttempted};
}"""


def _fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


@dataclass
class Reference:
    handle: ElementHandle
    frame: Frame
    generation: int
    descriptor: dict
    fingerprint: str
    expires: float


class PageDriver:
    def __init__(self, page: Page, *, clock=time.monotonic,
                 event_filter: Callable[[str], bool] | None = None):
        self.page = page
        self.clock = clock
        self.event_filter = event_filter
        self.generation = 0
        self.navigation_version = 0
        self.refs: dict[str, Reference] = {}
        self.diagnostics: list[dict] = []
        self._next_diagnostic_seq = 1
        self._diagnostics_started_utc = datetime.now(timezone.utc).isoformat()
        self.pending_dialog = None
        self.pending_dialog_id = None
        self.pending_chooser = None
        self.pending_chooser_id = None
        self.workflow = WebWorkflow(self)
        page.on("framenavigated", self._navigation)
        page.on("console", self._console)
        page.on("pageerror", self._page_error)
        page.on("requestfailed", self._request_failed)
        page.on("response", self._response)
        page.on("dialog", self._dialog)

    def _dialog(self, dialog):
        # Holding the dialog preserves confirmation semantics; never silently
        # accept/dismiss a task's alert, prompt or unsaved-document confirmation.
        self.pending_dialog = dialog
        self.pending_dialog_id = secrets.token_urlsafe(18)

    def dialog_snapshot(self):
        dialog = self.pending_dialog
        if dialog is None:
            return None
        return {"dialog_id": self.pending_dialog_id, "type": dialog.type,
                "message": dialog.message[:2000], "message_truncated": len(dialog.message) > 2000,
                "default_value": dialog.default_value[:2000], "generation": self.generation}

    async def dialog_state(self, *, check):
        await check()
        result = {"dialog": self.dialog_snapshot()}
        await check()
        return result

    async def dialog_action(self, dialog_id: str, accept: bool, *, prompt_text=None, check):
        if type(accept) is not bool or (prompt_text is not None and
                (type(prompt_text) is not str or len(prompt_text) > 64000 or "\x00" in prompt_text)):
            raise ControlError("invalid_dialog_argument")
        await check()
        dialog = self.pending_dialog
        if dialog is None or dialog_id != self.pending_dialog_id:
            raise ControlError("dialog_reference_stale")
        if prompt_text is not None and (not accept or dialog.type != "prompt"):
            raise ControlError("prompt_dialog_required")
        mark_write("dialog_action")
        if accept:
            await dialog.accept(prompt_text=prompt_text)
        else:
            await dialog.dismiss()
        if self.pending_dialog is dialog:
            self.pending_dialog = None
            self.pending_dialog_id = None
        await check()
        return {"state": "not_verified", "verification": "dialog_resolved_postcondition_required",
                "dialog_id": dialog_id, "accepted": accept,
                "business_result_verified": False}

    def chooser_snapshot(self):
        if self.pending_chooser is None:
            return None
        return {"chooser_id": self.pending_chooser_id, "multiple": self.pending_chooser.is_multiple(),
                "generation": self.generation, "selection": "not_changed"}

    async def chooser_state(self, *, check):
        await check()
        result = {"chooser": self.chooser_snapshot()}
        await check()
        return result

    async def chooser_cancel(self, chooser_id: str, *, check):
        await check()
        if self.pending_chooser is None or chooser_id != self.pending_chooser_id:
            raise ControlError("chooser_reference_stale")
        # The action-scoped Playwright listener intercepted the native chooser.
        # Dropping it preserves the original FileList; set_files([]) would
        # incorrectly clear an existing selection and emit change events.
        self.pending_chooser = None
        self.pending_chooser_id = None
        await check()
        return {"state": "verified", "verification": "chooser_cancelled_selection_preserved",
                "business_result_verified": False}

    async def chooser_upload(self, chooser_id: str, *, name: str, mime_type: str, content: bytes, check):
        if (type(name) is not str or not 1 <= len(name) <= 255 or
                any(ch in name for ch in "/\\\x00") or name in {".", ".."} or
                type(mime_type) is not str or not 1 <= len(mime_type) <= 127 or
                any(ord(ch) < 33 or ord(ch) > 126 for ch in mime_type) or
                type(content) is not bytes or len(content) > 2_000_000):
            raise ControlError("invalid_upload_payload")
        await check()
        chooser = self.pending_chooser
        if chooser is None or chooser_id != self.pending_chooser_id:
            raise ControlError("chooser_reference_stale")
        descriptor = await chooser.element.evaluate(_DESCRIBE)
        if not descriptor["connected"] or descriptor["tag"] != "INPUT" or descriptor["type"] != "file":
            raise ControlError("file_input_required")
        await check()
        mark_write("chooser_upload")
        await chooser.set_files({"name": name, "mimeType": mime_type, "buffer": content}, timeout=5000)
        selected = await chooser.element.evaluate("""e => Array.from(e.files || [],
          f => ({name:f.name,size:f.size,type:f.type}))""")
        if self.pending_chooser is chooser:
            self.pending_chooser = None
            self.pending_chooser_id = None
        await check()
        exact = len(selected) == 1 and selected[0]["name"] == name and selected[0]["size"] == len(content)
        return {"state": "verified" if exact else "not_verified", "selected": selected,
                "verification": "file_input_selection", "business_result_verified": False}

    async def _dispatch_input(self, awaitable, *, check, expect_chooser=False):
        chooser_event = asyncio.get_running_loop().create_future()
        def on_chooser(chooser):
            self.pending_chooser = chooser
            self.pending_chooser_id = secrets.token_urlsafe(18)
            if not chooser_event.done():
                chooser_event.set_result(True)
        if expect_chooser:
            self.page.on("filechooser", on_chooser)
        try:
            try:
                await awaitable
            except PlaywrightTimeoutError:
                if self.pending_dialog is None:
                    raise
            await check()
            if expect_chooser and self.pending_dialog is None and self.pending_chooser is None:
                try:
                    await asyncio.wait_for(chooser_event, timeout=0.5)
                except asyncio.TimeoutError:
                    pass
            await check()
            if self.pending_dialog is not None:
                return {"state": "not_verified", "verification": "dialog_pending",
                        "dialog": self.dialog_snapshot(), "business_result_verified": False}
            if self.pending_chooser is not None:
                return {"state": "not_verified", "verification": "chooser_pending",
                        "chooser": self.chooser_snapshot(), "business_result_verified": False}
            if expect_chooser:
                return {"state": "not_verified", "verification": "chooser_not_observed",
                        "business_result_verified": False}
            return None
        finally:
            if expect_chooser:
                self.page.remove_listener("filechooser", on_chooser)

    def _navigation(self, _frame):
        # Conservative: any frame navigation invalidates the current snapshot.
        self.generation += 1
        if _frame is getattr(self.page, "main_frame", None):
            self.navigation_version += 1

    def _accept_event(self, source_url: str | None = None) -> bool:
        if self.event_filter is None:
            return True
        return self.event_filter(source_url if source_url and source_url != "about:blank"
                                 else self.page.url)

    def _record_diagnostic(self, kind: str, **fields: str) -> None:
        self.diagnostics.append({"seq": self._next_diagnostic_seq, "kind": kind,
                                 **fields})
        self._next_diagnostic_seq += 1
        del self.diagnostics[:-100]

    def _console(self, message):
        if message.type not in {"error", "warning"}:
            return
        location = message.location or {}
        if self._accept_event(location.get("url")):
            self._record_diagnostic("console", level=message.type,
                                    message=message.text[:1000])

    def _page_error(self, error):
        if self._accept_event():
            self._record_diagnostic("pageerror", message=str(error)[:1000])

    def _request_failed(self, request):
        # URLs can carry tokens; only a failure category is retained by default.
        if self._accept_event(request.url):
            self._record_diagnostic("requestfailed",
                                    failure=str(request.failure or "unknown")[:200])

    def _response(self, response):
        if not self._accept_event(response.url):
            return
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            return
        request = response.request
        method = request.method
        resource_type = request.resource_type
        # No headers, body, status text, URL path or arbitrary method strings.
        self._record_diagnostic("response", status=status, http_error=status >= 400,
            method=method if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"} else "OTHER",
            resource_type=resource_type if resource_type in {"document", "stylesheet", "image", "media", "font", "script", "texttrack", "xhr", "fetch", "eventsource", "websocket", "manifest", "other"} else "other",
            source_origin=source_origin(response.url), generation=self.generation,
            navigation_version=self.navigation_version)

    async def page_diagnostics(self, *, check: Callable[[], Awaitable[None]],
                               after_seq: int = 0, limit: int = 30) -> dict:
        if (type(after_seq) is not int or after_seq < 0 or
                type(limit) is not int or not 1 <= limit <= 50):
            raise ControlError("invalid_diagnostic_bounds")
        await check()
        latest = self._next_diagnostic_seq - 1
        if after_seq > latest:
            raise ControlError("diagnostic_cursor_invalid")
        oldest = self.diagnostics[0]["seq"] if self.diagnostics else latest + 1
        entries = [entry for entry in self.diagnostics
                   if entry["seq"] > after_seq][:limit]
        next_after = entries[-1]["seq"] if entries else after_seq
        await check()
        return {"entries": entries, "next_after": next_after,
                "latest_seq": latest, "oldest_available": oldest,
                "gap": after_seq < oldest - 1,
                "capture_started_utc": self._diagnostics_started_utc,
                "coverage": "since_page_bound_to_current_worker",
                "complete": next_after == latest}

    async def dispose(self):
        refs, self.refs = self.refs, {}
        for ref in refs.values():
            try:
                await ref.handle.dispose()
            except Exception:
                pass
        self.page.remove_listener("framenavigated", self._navigation)
        self.page.remove_listener("console", self._console)
        self.page.remove_listener("pageerror", self._page_error)
        self.page.remove_listener("requestfailed", self._request_failed)
        self.page.remove_listener("response", self._response)
        self.page.remove_listener("dialog", self._dialog)

    async def observe(self, *, check: Callable[[], Awaitable[None]], frame_index: int = 0,
                      selector: str = "button,input,textarea,select,a,[role],[contenteditable]",
                      offset: int = 0, limit: int = 100, ttl: float = 15):
        if not 1 <= limit <= 200 or offset < 0 or not 0 < ttl <= 30:
            raise ControlError("invalid_observation_bounds")
        await check()
        frames = self.page.frames
        if not 0 <= frame_index < len(frames):
            raise ControlError("frame_not_found")
        # Release expired handles without invalidating still-live paginated refs.
        for key, ref in list(self.refs.items()):
            if ref.expires <= self.clock() or ref.generation != self.generation:
                self.refs.pop(key)
                await ref.handle.dispose()
        if len(self.refs) + limit > 1000:
            raise ControlError("observation_reference_limit")
        frame = frames[frame_index]
        generation = self.generation
        locator = frame.locator(selector)
        count = await locator.count()
        entries = []
        for index in range(offset, min(offset + limit, count)):
            handle = await locator.nth(index).element_handle(timeout=2000)
            if handle is None:
                raise ControlError("observation_changed")
            descriptor = await handle.evaluate(_DESCRIBE)
            reference = secrets.token_urlsafe(18)
            self.refs[reference] = Reference(handle, frame, generation, descriptor,
                                             _fingerprint(descriptor), self.clock() + ttl)
            # Full values are read separately; do not silently truncate completeness.
            public = dict(descriptor)
            value = public.pop("value")
            public["value_length"] = len(value) if value is not None else None
            entries.append({"ref": reference, **public})
        if generation != self.generation:
            raise ControlError("observation_changed")
        await check()
        if generation != self.generation or list(self.page.frames) != list(frames):
            raise ControlError("observation_changed")
        return {"generation": generation, "frame_index": frame_index, "entries": entries,
                "total_at_start": count, "next_offset": offset + limit if offset + limit < count else None,
                "complete": offset == 0 and count <= limit,
                "text_limit_per_entry": 2048, "frames": len(frames), **describe_frames(frames)}

    async def _fresh(self, reference: str) -> Reference:
        ref = self.refs.get(reference)
        if not ref or ref.expires <= self.clock() or ref.generation != self.generation:
            raise ControlError("element_reference_stale")
        if self.page.is_closed() or ref.frame.is_detached():
            raise ControlError("target_closed")
        descriptor = await ref.handle.evaluate(_DESCRIBE)
        if not descriptor["connected"] or _fingerprint(descriptor) != ref.fingerprint:
            raise ControlError("element_changed")
        if descriptor["type"] == "password":
            raise ControlError("secret_input_requires_user_takeover")
        return ref

    async def read_text(self, reference: str, *, check: Callable[[], Awaitable[None]],
                        offset: int = 0, limit: int = 16000):
        if offset < 0 or not 1 <= limit <= 64000:
            raise ControlError("invalid_read_bounds")
        await check()
        ref = await self._fresh(reference)
        result = await ref.handle.evaluate("""(e,a)=>{
          const s=Array.from('value' in e?e.value:e.innerText||e.textContent||'');
          return {text:s.slice(a.offset,a.offset+a.limit).join(''),total:s.length};
        }""", {"offset": offset, "limit": limit})
        result["next_offset"] = offset + limit if offset + limit < result["total"] else None
        result["complete"] = offset == 0 and result["next_offset"] is None
        result["offset_unit"] = "unicode_codepoints"
        await check()
        return result

    async def page_state(self, *, check: Callable[[], Awaitable[None]],
                         offset: int = 0, limit: int = 16000,
                         expected_digest: str | None = None) -> dict:
        """Bounded fresh page context for deciding the next ordinary Web step."""
        if (type(offset) is not int or offset < 0 or type(limit) is not int
                or not 1 <= limit <= 64000 or
                (expected_digest is not None and
                 (type(expected_digest) is not str or len(expected_digest) != 64
                  or any(ch not in "0123456789abcdef" for ch in expected_digest)))):
            raise ControlError("invalid_read_bounds")
        await check()
        if self.page.is_closed():
            raise ControlError("target_closed")
        body = await asyncio.wait_for(self.page.evaluate("""async ({offset, limit}) => {
          const value = document.body?.innerText || '';
          const url = location.href;
          const bound = url + '\\0' + value;
          const digest = globalThis.crypto?.subtle
            ? await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bound)) : null;
          const hex = digest ? Array.from(new Uint8Array(digest),
            b => b.toString(16).padStart(2, '0')).join('') : null;
          const chars = Array.from(value);
          return {url, title: document.title, text: chars.slice(offset, offset + limit).join(''),
                  total: chars.length, digest: hex, full_text: digest ? null : bound};
        }""", {"offset": offset, "limit": limit}), timeout=4)
        await check()
        if body["url"] != self.page.url:
            raise ControlError("page_changed")
        if body["digest"] is None:
            body["digest"] = hashlib.sha256(body.pop("full_text").encode("utf-8")).hexdigest()
        if expected_digest is not None and body["digest"] != expected_digest:
            raise ControlError("page_content_changed")
        return {"url": body["url"], "title": body["title"],
                "generation": self.generation, "navigation_version": self.navigation_version,
                "text": body["text"], "text_total": body["total"],
                "text_truncated": offset + limit < body["total"],
                "text_digest": body["digest"], "offset": offset,
                "next_offset": offset + limit if offset + limit < body["total"] else None,
                "complete": offset == 0 and offset + limit >= body["total"],
                "offset_unit": "unicode_codepoints"}

    async def fill(self, reference: str, text: str, *, check: Callable[[], Awaitable[None]]):
        if not isinstance(text, str) or len(text) > 1_000_000 or "\x00" in text:
            raise ControlError("invalid_text")
        ref = await self._fresh(reference)
        await check()
        # ElementHandle binds the observed DOM node, not a selector that may retarget.
        mark_write("fill")
        await ref.handle.fill(text, timeout=3000)
        actual = await ref.handle.evaluate("e => 'value' in e ? e.value : e.textContent")
        await check()  # suppress result publication following takeover/revocation
        await self._advance_input_reference(reference, "fill")
        return {"state": "verified" if actual == text else "not_verified",
                "verification": "exact_element_text", "business_result_verified": False}

    async def _advance_input_reference(self, reference, operation):
        # Advance only the exact node and fields this write owns. Rebuilt nodes,
        # changed identity, navigation and expired observations still refuse.
        ref = await self._result_reference(reference, operation)
        descriptor = await ref.handle.evaluate(_DESCRIBE)
        mutable = ({"value", "text", "text_truncated"} if operation == "fill" else
                   {"checked"} if operation == "set_checked" else {"value"})
        if (ref.generation != self.generation or not descriptor["connected"] or
                {key: value for key, value in ref.descriptor.items() if key not in mutable} !=
                {key: value for key, value in descriptor.items() if key not in mutable}):
            raise ControlError("element_changed")
        ref.descriptor = descriptor
        ref.fingerprint = _fingerprint(descriptor)

    async def type_text(self, reference, text, *, replace=False, check):
        """Legacy focus/insertText algorithm adapted to owned Playwright handles."""
        if type(text) is not str or len(text) > 1_000_000 or "\x00" in text or type(replace) is not bool:
            raise ControlError("invalid_text")
        await check()
        ref = await self._fresh(reference)
        if ref.descriptor["disabled"] or not (ref.descriptor["editable"] or ref.descriptor["tag"] in {"INPUT", "TEXTAREA"}):
            raise ControlError("editable_target_required")
        session = await self.page.context.new_cdp_session(self.page)
        emulated = False
        try:
            if await self.page.evaluate("document.visibilityState") == "hidden":
                await session.send("Emulation.setFocusEmulationEnabled", {"enabled": True})
                emulated = True
            await check()
            ref = await self._fresh(reference)
            mark_write("type")
            async with asyncio.timeout(3):
                await ref.handle.focus()
            if replace:
                await check()
                mark_write("type")
                await ref.handle.press("ControlOrMeta+A", timeout=3000)
            await check()
            if not await ref.handle.evaluate("e => (e.getRootNode().activeElement || e.ownerDocument.activeElement) === e"):
                raise ControlError("input_focus_changed")
            mark_write("type")
            await session.send("Input.insertText", {"text": text})
            await check()
            actual = await ref.handle.evaluate("e => 'value' in e ? e.value : (e.innerText || e.textContent || '')")
            await self._advance_input_reference(reference, "fill")
            return {"state": "verified" if replace and actual == text else "not_verified",
                    "input_dispatched": True, "inserted_chars": len(text), "replaced": replace,
                    "verification": "exact_element_text" if replace and actual == text else "input_postcondition_required",
                    "business_result_verified": False}
        finally:
            try:
                if emulated:
                    await session.send("Emulation.setFocusEmulationEnabled", {"enabled": False})
            finally:
                await session.detach()

    async def _condition_value(self, frame, selector, condition, expected):
        if condition == "url":
            value = frame.url
            return {"matched": value == expected, "text": value}
        locator = frame.locator(selector)
        count = await locator.count()
        if count > 1:
            raise ControlError("wait_target_ambiguous")
        if condition == "detached":
            return {"matched": count == 0, "text": None}
        if count == 0:
            return {"matched": condition == "hidden", "text": None}
        if condition in {"enabled", "disabled"}:
            enabled = await locator.is_enabled()
            return {"matched": enabled if condition == "enabled" else not enabled, "text": None}
        if condition in {"checked", "unchecked"}:
            checked = await locator.is_checked()
            return {"matched": checked if condition == "checked" else not checked, "text": None}
        if condition == "value":
            value = await locator.evaluate("e => e.type === 'password' ? null : ('value' in e ? e.value : (e.innerText || e.textContent || ''))")
            return {"matched": value == expected, "text": value}
        if condition == "attribute":
            value = await locator.get_attribute(expected["name"], timeout=1000)
            return {"matched": value == expected["value"], "text": value}
        if condition == "class":
            value = await locator.get_attribute("class", timeout=1000) or ""
            return {"matched": expected in value.split(), "text": value}
        if condition in {"media_playing", "media_paused"}:
            value = await locator.evaluate("e => /^(AUDIO|VIDEO)$/.test(e.tagName) ? {paused:e.paused,ended:e.ended,ready:e.readyState} : null")
            return {"matched": value is not None and (value["paused"] if condition == "media_paused" else not value["paused"] and not value["ended"] and value["ready"] >= 2), "text": None}
        if condition in {"visible", "hidden"}:
            visible = await locator.is_visible()
            return {"matched": visible if condition == "visible" else not visible, "text": None}
        if condition == "attached" and expected is None:
            return {"matched": True, "text": None}
        text = await locator.inner_text(timeout=1000)
        return {"matched": expected is None or expected in text, "text": text}

    async def _wait_baseline(self, wait_for: dict | None, *, check, transition=True):
        if wait_for is None:
            return None
        validate_condition(wait_for)
        if (type(wait_for) is not dict or not {"selector", "timeout_ms"} <= set(wait_for)
                or not set(wait_for) <= {"selector", "timeout_ms", "expected_text", "condition", "frame_index", "expected_value", "attribute"}
                or type(wait_for.get("selector")) is not str
                or not 1 <= len(wait_for["selector"]) <= 2000
                or type(wait_for.get("timeout_ms")) is not int
                or not 1 <= wait_for["timeout_ms"] <= 10000
                or wait_for.get("condition", "text_changed") not in
                   {"text_changed", "attached", "detached", "visible", "hidden", "enabled", "disabled", "checked", "unchecked", "value", "attribute", "class", "url", "media_playing", "media_paused"}
                or type(wait_for.get("frame_index", 0)) is not int
                or ("expected_text" in wait_for and
                    (type(wait_for["expected_text"]) is not str or
                     not 1 <= len(wait_for["expected_text"]) <= 1000))):
            raise ControlError("invalid_wait_condition")
        condition = wait_for.get("condition", "text_changed")
        expected = wait_for.get("expected_text")
        if expected is not None and condition not in {"text_changed", "attached"}:
            raise ControlError("invalid_wait_condition")
        if condition in {"value", "attribute", "class", "url"}:
            expected = wait_for.get("expected_value")
            if type(expected) is not str or len(expected) > 8192 or (condition in {"class", "url"} and not expected):
                raise ControlError("invalid_wait_condition")
            if condition == "attribute":
                name = wait_for.get("attribute")
                if type(name) is not str or not 1 <= len(name) <= 120 or any(ch.isspace() for ch in name):
                    raise ControlError("invalid_wait_condition")
                expected = {"name": name, "value": expected}
        elif "expected_value" in wait_for or "attribute" in wait_for:
            raise ControlError("invalid_wait_condition")
        await check()
        frames = self.page.frames
        index = wait_for.get("frame_index", 0)
        if not 0 <= index < len(frames):
            raise ControlError("invalid_frame_index")
        frame = frames[index]
        value = await self._condition_value(frame, wait_for["selector"], condition, expected)
        if condition == "text_changed" and value["text"] is None:
            raise ControlError("wait_target_ambiguous")
        if transition and ((condition == "text_changed" and expected is not None and value["matched"])
                           or (condition != "text_changed" and value["matched"])):
            raise ControlError("wait_condition_already_true")
        await check()
        return {"selector": wait_for["selector"], "timeout_ms": wait_for["timeout_ms"],
                "before": value["text"], "expected": expected, "frame": frame,
                "condition": condition, "generation": self.generation, "url": self.page.url,
                "transition": transition}

    async def _wait_text_change(self, baseline: dict | None, *, check):
        if baseline is None:
            return None
        deadline = self.clock() + baseline["timeout_ms"] / 1000
        while True:
            await check()
            if self.pending_dialog is not None:
                return {"observed": False, "reason": "dialog_pending", "dialog": self.dialog_snapshot()}
            independent_url = baseline["condition"] == "url" and not baseline.get("transition", True)
            if independent_url:
                baseline["frame"] = self.page.main_frame
            if (self.page.is_closed() or (not independent_url and (self.generation != baseline["generation"]
                    or self.page.url != baseline["url"] or baseline["frame"].is_detached()))):
                return {"observed": False, "reason": "page_changed_during_wait"}
            try:
                value = await self._condition_value(baseline["frame"], baseline["selector"],
                                                    baseline["condition"], baseline["expected"])
            except PlaywrightTimeoutError:
                value = {"matched": False, "text": None}
            matched = value["matched"]
            if baseline["condition"] == "text_changed":
                matched = value["text"] is not None and matched and (
                    (not baseline.get("transition", True) and baseline["expected"] is not None)
                    or value["text"] != baseline["before"])
            if matched:
                await check()
                text = value["text"]
                return {"observed": True, "condition": baseline["condition"],
                        "text": text[:16000] if text is not None else None,
                        "text_truncated": text is not None and len(text) > 16000}
            if self.clock() >= deadline:
                return {"observed": False, "reason": "condition_timeout"}
            await asyncio.sleep(min(0.1, max(0, deadline - self.clock())))

    async def wait_condition(self, condition: dict, *, check):
        baseline = await self._wait_baseline(condition, check=check, transition=False)
        result = await self._wait_text_change(baseline, check=check)
        return {"state": "verified" if result["observed"] else "not_verified",
                "wait": result, "generation": self.generation, "business_result_verified": False}

    async def result_probe(self, arguments, *, check):
        """A separate bounded DOM read, with no action receipt as evidence."""
        async with asyncio.timeout(3):
            await check()
            generation = self.generation
            if self.pending_dialog is not None:
                raise ControlError("result_dialog_pending")
            operation = arguments.get("operation")
            if operation in {"fill", "set_checked", "select_option"}:
                reference = arguments.get("reference")
                if type(reference) is not str or len(reference) > 100:
                    raise ControlError("invalid_result_probe")
                ref = await self._result_reference(reference, operation)
                actual = await ref.handle.evaluate("""(e,op) => {
                    if (op === 'set_checked') return {checked:e.matches('input[type=checkbox],input[type=radio]') ? !!e.checked : null};
                    if (op === 'select_option') return {selected:Array.from(e.selectedOptions || []).map(o=>o.value)};
                    const value = 'value' in e ? e.value : e.textContent;
                    return typeof value === 'string' && value.length <= 1000000 ? {value} : {error:'result_value_too_large'};
                }""", operation)
                if "error" in actual:
                    raise ControlError(actual["error"])
                # Ensure the same connected node remains bound after readback.
                await self._result_reference(reference, operation)
                if operation == "fill":
                    value = actual.pop("value")
                    actual = {"value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                              "value_length": len(value)}
                elif operation == "select_option":
                    values = actual.pop("selected")
                    if len(values) > 50 or any(len(value) > 256 for value in values):
                        raise ControlError("result_value_too_large")
                    actual = {"selected_sha256": hashlib.sha256(json.dumps(values, sort_keys=True,
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()}
            elif operation in {"wait_condition", "click", "press"}:
                if arguments.get("expected_generation") != generation:
                    raise ControlError("result_page_changed")
                baseline = await self._wait_baseline(arguments.get("condition"), check=check, transition=False)
                if baseline is None:
                    raise ControlError("invalid_result_probe")
                value = await self._condition_value(baseline["frame"], baseline["selector"],
                                                    baseline["condition"], baseline["expected"])
                actual = {"matched": value["matched"], "condition": baseline["condition"],
                    "text_sha256": hashlib.sha256(value["text"].encode("utf-8")).hexdigest()
                                   if value["text"] is not None else None}
            else:
                raise ControlError("invalid_result_probe")
            await check()
            if generation != self.generation:
                raise ControlError("result_page_changed")
            return {"operation": operation, "generation": generation, **actual,
                "observed_at": time.monotonic(), "evidence_digest": hashlib.sha256(json.dumps(
                    {"operation": operation, "generation": generation, **actual}, sort_keys=True,
                    ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()}

    async def _result_reference(self, reference, operation):
        ref = self.refs.get(reference)
        if not ref or ref.expires <= self.clock() or ref.generation != self.generation:
            raise ControlError("element_reference_stale")
        if self.page.is_closed() or ref.frame.is_detached():
            raise ControlError("target_closed")
        descriptor = await ref.handle.evaluate(_DESCRIBE)
        if descriptor["type"] == "password":
            raise ControlError("secret_input_requires_user_takeover")
        # The original exact handle remains bound. Ignore only the fields this
        # command intentionally changes; never refresh a write reference.
        mutable = ({"value", "text", "text_truncated"} if operation == "fill" else
                   {"checked"} if operation == "set_checked" else {"value"})
        before = {key: value for key, value in ref.descriptor.items() if key not in mutable}
        after = {key: value for key, value in descriptor.items() if key not in mutable}
        if not descriptor["connected"] or before != after:
            raise ControlError("element_changed")
        return ref

    async def wait_navigation(self, after_navigation_version: int, timeout_ms: int,
                              *, expected_url=None, check):
        if (type(after_navigation_version) is not int or after_navigation_version < 0
                or after_navigation_version > self.navigation_version
                or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000
                or (expected_url is not None and
                    (type(expected_url) is not str or not 1 <= len(expected_url) <= 8192))):
            raise ControlError("invalid_wait_condition")
        deadline = self.clock() + timeout_ms / 1000
        while True:
            await check()
            if self.page.is_closed():
                return {"state": "not_verified", "observed": False, "reason": "target_closed"}
            if self.pending_dialog is not None:
                return {"state": "not_verified", "observed": False, "reason": "dialog_pending",
                        "dialog": self.dialog_snapshot()}
            if self.navigation_version > after_navigation_version and (
                    expected_url is None or self.page.url == expected_url):
                await check()
                return {"state": "verified", "observed": True, "url": self.page.url,
                        "navigation_version": self.navigation_version,
                        "business_result_verified": False}
            if self.clock() >= deadline:
                return {"state": "not_verified", "observed": False, "reason": "condition_timeout"}
            await asyncio.sleep(0.05)

    async def click(self, reference: str, *, check: Callable[[], Awaitable[None]],
                    wait_for: dict | None = None, expect_chooser: bool = False,
                    button: str = "left", click_count: int = 1,
                    modifiers: list[str] | None = None, read_page_state: bool = True):
        if type(read_page_state) is not bool:
            raise ControlError("invalid_readback_option")
        if type(button) is not str or button not in {"left", "right", "middle"}:
            raise ControlError("invalid_click_button")
        if type(click_count) is not int or not 1 <= click_count <= 3:
            raise ControlError("invalid_click_count")
        if modifiers is not None and (
                type(modifiers) is not list or len(modifiers) > 4 or
                any(type(item) is not str or item not in {
                    "Alt", "Control", "ControlOrMeta", "Meta", "Shift"} for item in modifiers) or
                len(set(modifiers)) != len(modifiers)):
            raise ControlError("invalid_click_modifiers")
        if type(expect_chooser) is not bool:
            raise ControlError("invalid_chooser_expectation")
        ref = await self._fresh(reference)
        baseline = await self._wait_baseline(wait_for, check=check)
        await check()
        mark_write("click")
        pending = await self._dispatch_input(ref.handle.click(
            timeout=3000, button=button, click_count=click_count, modifiers=modifiers),
            check=check, expect_chooser=expect_chooser)
        if pending:
            return pending
        waited = await self._wait_text_change(baseline, check=check)
        try:
            fresh = await self.page_state(check=check) if read_page_state else None
        except ControlError:
            raise
        except Exception:
            fresh = {"state": "unavailable"}
        return {"state": "verified" if waited and waited["observed"] else "not_verified",
                "verification": ("specified_text_change" if waited["condition"] == "text_changed" else "specified_condition")
                if waited and waited["observed"] else "postcondition_required",
                "wait": waited, "page_state": fresh, "business_result_verified": False}

    async def press(self, reference: str, key: str, *, check: Callable[[], Awaitable[None]],
                    wait_for: dict | None = None, expect_chooser: bool = False, read_page_state: bool = True):
        if type(read_page_state) is not bool:
            raise ControlError("invalid_readback_option")
        if (type(key) is not str or not 1 <= len(key) <= 80 or
                "\r" in key or "\n" in key or "\x00" in key):
            raise ControlError("invalid_key")
        if type(expect_chooser) is not bool:
            raise ControlError("invalid_chooser_expectation")
        ref = await self._fresh(reference)
        baseline = await self._wait_baseline(wait_for, check=check)
        await check()
        mark_write("press")
        pending = await self._dispatch_input(ref.handle.press(key, timeout=3000), check=check, expect_chooser=expect_chooser)
        if pending:
            return pending
        waited = await self._wait_text_change(baseline, check=check)
        try:
            fresh = await self.page_state(check=check) if read_page_state else None
        except ControlError:
            raise
        except Exception:
            fresh = {"state": "unavailable"}
        return {"state": "verified" if waited and waited["observed"] else "not_verified",
                "verification": ("specified_text_change" if waited["condition"] == "text_changed" else "specified_condition")
                if waited and waited["observed"] else "postcondition_required",
                "wait": waited, "page_state": fresh, "business_result_verified": False}

    async def select_option(self, reference: str, value: str, *,
                            check: Callable[[], Awaitable[None]]):
        if type(value) is not str or len(value) > 256:
            raise ControlError("invalid_option_value")
        ref = await self._fresh(reference)
        if ref.descriptor["tag"] != "SELECT":
            raise ControlError("select_target_required")
        await check()
        mark_write("select_option")
        selected = await ref.handle.select_option(value=value, timeout=3000)
        await check()
        await self._advance_input_reference(reference, "select_option")
        return {"state": "verified" if value in selected else "not_verified",
                "selected_values": selected, "business_result_verified": False}

    async def set_checked(self, reference: str, checked: bool, *,
                          check: Callable[[], Awaitable[None]]):
        if type(checked) is not bool:
            raise ControlError("invalid_checked_state")
        ref = await self._fresh(reference)
        if ref.descriptor["checked"] is None:
            raise ControlError("checkable_target_required")
        await check()
        mark_write("set_checked")
        await ref.handle.set_checked(checked, timeout=3000)
        actual = await ref.handle.evaluate("e => !!e.checked")
        await check()
        await self._advance_input_reference(reference, "set_checked")
        return {"state": "verified" if actual is checked else "not_verified",
                "checked": actual, "business_result_verified": False}

    async def drag(self, source_reference: str, target_reference: str, *, check):
        source = await self._fresh(source_reference)
        target = await self._fresh(target_reference)
        if source.frame is target.frame and await source.handle.evaluate("(node, other) => node === other", target.handle):
            raise ControlError("drag_distinct_targets_required")
        await check()
        source = await self._fresh(source_reference)
        target = await self._fresh(target_reference)
        source_box = await source.handle.bounding_box()
        target_box = await target.handle.bounding_box()
        if not source_box or not target_box:
            raise ControlError("drag_target_not_visible")
        start = (source_box["x"] + source_box["width"] / 2,
                 source_box["y"] + source_box["height"] / 2)
        finish = (target_box["x"] + target_box["width"] / 2,
                  target_box["y"] + target_box["height"] / 2)
        await check()
        mark_write("drag")
        await self.page.mouse.move(*start)
        pressed = False
        try:
            await self.page.mouse.down()
            pressed = True
            await self.page.mouse.move(*finish, steps=8)
        finally:
            if pressed:
                await self.page.mouse.up()
        await check()
        try:
            fresh = await self.page_state(check=check)
        except ControlError:
            raise
        except Exception:
            fresh = {"state": "unavailable"}
        return {"state": "not_verified", "verification": "drop_postcondition_required",
                "page_state": fresh, "business_result_verified": False}

    async def upload(self, reference: str, *, name: str, mime_type: str,
                     content: bytes, check):
        if (type(name) is not str or not 1 <= len(name) <= 255 or
                any(ch in name for ch in "/\\\x00") or name in {".", ".."} or
                type(mime_type) is not str or not 1 <= len(mime_type) <= 127 or
                any(ord(ch) < 33 or ord(ch) > 126 for ch in mime_type) or
                type(content) is not bytes or len(content) > 2_000_000):
            raise ControlError("invalid_upload_payload")
        ref = await self._fresh(reference)
        if ref.descriptor["tag"] != "INPUT" or ref.descriptor["type"] != "file":
            raise ControlError("file_input_required")
        await check()
        mark_write("upload")
        await ref.handle.set_input_files({"name": name, "mimeType": mime_type,
                                          "buffer": content}, timeout=5000)
        selected = await ref.handle.evaluate("""e => Array.from(e.files || [],
          f => ({name:f.name,size:f.size,type:f.type}))""")
        await check()
        exact = len(selected) == 1 and selected[0]["name"] == name and selected[0]["size"] == len(content)
        return {"state": "verified" if exact else "not_verified",
                "verification": "file_input_selection", "selected": selected,
                "business_result_verified": False}

    async def _editor(self, reference: str, request: dict, *, check):
        await check()
        ref = await self._fresh(reference)
        await check()
        replacing = request["kind"] == "replace"
        zero_write_errors = {"editor_api_unavailable", "editor_target_ambiguous",
            "editor_model_missing", "editor_document_unidentified", "editor_model_changed", "editor_read_only"}

        async def evaluate(script):
            try:
                result = await ref.handle.evaluate(script, request)
            except BaseException:
                if replacing:
                    mark_write("editor_replace")
                raise
            # Same error may occur either before or after a write (CM model_changed).
            # Only a typed marker from the completed adapter plus a known preflight
            # refusal proves zero adapter writes. Missing evidence stays conservative.
            if replacing and not (isinstance(result, dict)
                    and result.get("flower_write_attempted") is False
                    and result.get("error") in zero_write_errors):
                mark_write("editor_replace")
            return result

        result = await evaluate(_MONACO)
        if (result.get("error") in {"editor_api_unavailable", "editor_target_ambiguous"}
                and (not replacing or result.get("flower_write_attempted") is False)):
            await check()
            ref = await self._fresh(reference)
            alternative = await evaluate(_CODEMIRROR)
            if alternative.get("error") != "editor_api_unavailable":
                result = alternative
        await check()
        if "error" in result:
            raise ControlError(result["error"])
        result.pop("flower_write_attempted", None)
        return result

    async def editor_inspect(self, reference: str, *, check):
        result = await self._editor(reference, {"kind": "inspect"}, check=check)
        return {"editor": result.get("editor", "monaco"), "document_uri": result["uri"],
                "document_identity": result.get("identity", result["uri"]),
                "document_identity_kind": result.get("identityKind", "document_uri"),
                "model_version": result["version"], "length": result["length"]}

    async def editor_read(self, reference: str, *, offset: int = 0,
                          limit: int = 64000, check):
        if offset < 0 or not 1 <= limit <= 64000:
            raise ControlError("invalid_read_bounds")
        result = await self._editor(reference,
                                    {"kind": "read", "offset": offset, "limit": limit}, check=check)
        result["document_identity"] = result.pop("identity", result["uri"])
        result["document_identity_kind"] = result.pop("identityKind", "document_uri")
        result["document_uri"] = result.pop("uri")
        result["model_version"] = result.pop("version")
        result["next_offset"] = offset + limit if offset + limit < result["total"] else None
        result["complete"] = offset == 0 and result["next_offset"] is None
        result["offset_unit"] = "unicode_codepoints"
        return result

    async def editor_replace(self, reference: str, text: str, expected_uri: str,
                             expected_version: int, *, check):
        # expected_uri is the legacy worker field name. Callers pass the
        # document_identity from inspect, which may be an opaque model object.
        if (not isinstance(text, str) or len(text) > 1_000_000 or "\x00" in text
                or not isinstance(expected_uri, str) or not 1 <= len(expected_uri) <= 2048
                or type(expected_version) is not int or expected_version < 1):
            raise ControlError("invalid_editor_argument")
        result = await self._editor(reference, {"kind": "replace", "text": text,
                                                "expected_uri": expected_uri,
                                                "expected_version": expected_version}, check=check)
        return {"state": "verified" if result["exact"] else "not_verified",
                "verification": "exact_editor_model", "editor": result.get("editor", "monaco"),
                "document_uri": result["uri"],
                "document_identity": result.get("identity", result["uri"]),
                "document_identity_kind": result.get("identityKind", "document_uri"),
                "model_version": result["version"], "length": result["length"],
                "business_result_verified": False}

    async def terminal_input(self, reference: str, text: str, submit: bool, *, check):
        if (not isinstance(text, str) or not 1 <= len(text) <= 64000 or "\x00" in text
                or "\r" in text or "\n" in text or type(submit) is not bool):
            raise ControlError("invalid_terminal_argument")
        ref = await self._fresh(reference)
        target = await ref.handle.evaluate("""e => e.tagName === 'TEXTAREA' &&
          e.classList.contains('xterm-helper-textarea') && !!e.closest('.xterm')""")
        if not target:
            raise ControlError("terminal_target_unidentified")
        await check()
        mark_write("terminal_focus")
        await ref.handle.focus()
        focused = await ref.handle.evaluate("e => e.ownerDocument.activeElement === e")
        if not focused:
            raise ControlError("terminal_focus_failed")
        await check()
        # CDP insertText sends one input event. It does not use the OS clipboard
        # or generate one key event per character.
        await self.page.keyboard.insert_text(text)
        await check()
        if submit:
            focused = await ref.handle.evaluate("e => e.ownerDocument.activeElement === e")
            if not focused:
                raise ControlError("terminal_focus_changed_after_input")
            await ref.handle.press("Enter", timeout=3000)
        await check()
        return {"state": "not_verified", "verification": "terminal_application_result_required",
                "input_dispatched": True, "submit_dispatched": submit,
                "business_result_verified": False}
