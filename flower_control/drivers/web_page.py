"""Bounded Playwright page observations and exact-reference actions.

The session owner supplies authorization, resource locks and at-most-once
receipts. This module never attaches to a browser by URL or discovers profiles.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from playwright.async_api import ElementHandle, Frame, Page, TimeoutError as PlaywrightTimeoutError

from flower_control.control.state import ControlError
from .web_effects import mark_write, require_write_admission, record_write_attempt
from .web_workflow import WebWorkflow
from .web_discovery import describe_frames, source_origin
from .web_batch import validate_condition
from .web_diagnostics import safe_failure_facts
from .web_uploads import validate_files, selection_matches
from .web_text import dom_text_digest, textencoder_digest


_DESCRIBE = r"""e => ({connected:e.isConnected, tag:e.tagName,
 visible:!!(e.getClientRects().length && e.ownerDocument.defaultView.getComputedStyle(e).visibility !== 'hidden'),
 type:(e.type === 'password' || /\b(?:current-password|new-password)\b/.test(e.autocomplete || '')) ? 'password' : (e.tagName === 'INPUT' ? e.type : e.getAttribute('type')), role:e.getAttribute('role'),
 name:(e.type === 'password' || /\b(?:current-password|new-password)\b/.test(e.autocomplete || '')) ? '' : (e.getAttribute('aria-label') || e.getAttribute('name') || ''),
 id:e.id, disabled:!!e.disabled, editable:e.isContentEditable,
 checked:e.matches('input[type=checkbox],input[type=radio]') ? !!e.checked : null,
 options:e.tagName === 'SELECT' ? Array.from(e.options).slice(0,50)
   .map(o=>({value:o.value.slice(0,256),label:o.label.slice(0,256)})) : null,
 option_total:e.tagName === 'SELECT' ? e.options.length : null,
 text:(e.type === 'password' || /\b(?:current-password|new-password)\b/.test(e.autocomplete || '')) ? '' : (e.innerText || e.textContent || '').slice(0,2048),
 text_truncated:(e.innerText || e.textContent || '').length > 2048,
 value:(e.type === 'password' || /\b(?:current-password|new-password)\b/.test(e.autocomplete || '')) ? null : ('value' in e ? String(e.value) : null)})"""


_SCOPED_DESCRIBE = """(node, root) => {
  if (!node.isConnected || !root.isConnected || !root.contains(node)) return null;
  const describe = __FLOWER_DESCRIBE__;
  return describe(node);
}""".replace('__FLOWER_DESCRIBE__',_DESCRIBE)


OBSERVATION_FIELDS = frozenset({'ref','connected','tag','visible','type','role','name','id',
    'disabled','editable','checked','options','option_total','text','text_truncated','value_length','depth'})


def validate_observation_projection(projection):
    """Select public fields only; full descriptors/fingerprints stay private."""
    if projection is None: return None
    if (type(projection) is not list or not 1 <= len(projection) <= len(OBSERVATION_FIELDS)
            or any(type(field) is not str or field not in OBSERVATION_FIELDS for field in projection)
            or len(set(projection)) != len(projection)):
        raise ControlError('invalid_observation_projection')
    return tuple(projection)


def validate_observation_root(root_ref):
    if root_ref is not None and (type(root_ref) is not str or not 1 <= len(root_ref) <= 100):
        raise ControlError('invalid_observation_root')


def validate_observation_max_chars(max_chars):
    if max_chars is not None and (type(max_chars) is not int or not 256 <= max_chars <= 1000000):
        raise ControlError('invalid_observation_max_chars')


def observation_node_limit(limit, max_nodes):
    if max_nodes is None: return limit
    if type(max_nodes) is not int or not 1 <= max_nodes <= 500:
        raise ControlError('invalid_observation_max_nodes')
    if limit != 100 and limit != max_nodes:
        raise ControlError('observation_node_budget_conflict')
    return max_nodes


def _observation_entry_chars(entry):
    # Match the old browser JSON.stringify(item).length character budget,
    # including ref and escaped JSON, measured in UTF-16 rather than bytes.
    text = json.dumps(entry,ensure_ascii=False,separators=(',',':'),allow_nan=False)
    units = len(text.encode('utf-16-le',errors='surrogatepass')) // 2
    # Modern JSON.stringify escapes lone UTF-16 surrogates as six ASCII
    # characters. Valid explicit pairs and normal astral scalars stay two.
    for index,char in enumerate(text):
        code = ord(char)
        if 0xd800 <= code <= 0xdbff:
            if index+1 == len(text) or not 0xdc00 <= ord(text[index+1]) <= 0xdfff:
                units += 5
        elif 0xdc00 <= code <= 0xdfff:
            if index == 0 or not 0xd800 <= ord(text[index-1]) <= 0xdbff:
                units += 5
    return units


_SCOPED_NODES = """(root, a) => {
  if (!root.isConnected) throw new Error('observation_root_detached');
  const matches = root.querySelectorAll(a.selector), nodes = [];
  for (let i=a.offset; i<Math.min(a.offset+a.limit,matches.length); i++) {
    if (!root.contains(matches[i])) throw new Error('observation_scope_changed');
    nodes.push(matches[i]);
  }
  return {total:matches.length,nodes};
}"""


async def _scoped_observation_handles(root, selector, offset, limit):
    """Materialize only the requested slice as handles, not all DOM matches."""
    auxiliary,owned = [],[]
    success = False
    try:
        result = await root.evaluate_handle(_SCOPED_NODES,dict(selector=selector,offset=offset,limit=limit))
        auxiliary.append(result)
        count = await result.evaluate('result => result.total')
        if type(count) is not int or count<0: raise ControlError('observation_changed')
        nodes = await result.get_property('nodes')
        auxiliary.append(nodes)
        properties = await nodes.get_properties()
        owned.extend(properties.values())
        expected = max(0,min(offset+limit,count)-offset)
        if set(properties) != {str(n) for n in range(expected)}:
            raise ControlError('observation_changed')
        elements = tuple(properties[str(n)].as_element() for n in range(expected))
        if any(element is None for element in elements): raise ControlError('observation_changed')
        # Auxiliary object/array handles are not references. Finish disposing
        # them before transferring ownership of the exact element handles.
        while auxiliary:
            await auxiliary[-1].dispose()
            auxiliary.pop()
        success = True
        return count,elements
    finally:
        if not success:
            for handle in owned:
                try: await handle.dispose()
                except Exception: pass
        for handle in reversed(auxiliary):
            try: await handle.dispose()
            except Exception: pass


_EDITOR_OLD_TEXT_UNSET = object()
_EDITOR_PATCH_TEXT = """(before, request) => {
  if (!Object.prototype.hasOwnProperty.call(request, 'old_text')) return {text:request.text};
  if (typeof request.old_text !== 'string' || !request.old_text.length)
    return {error:'invalid_editor_argument'};
  const start = before.indexOf(request.old_text);
  if (start < 0) return {error:'editor_patch_not_found'};
  if (before.indexOf(request.old_text, start + 1) >= 0)
    return {error:'editor_patch_ambiguous'};
  const text = before.slice(0,start) + request.text + before.slice(start + request.old_text.length);
  if (Array.from(text).length > 1000000) return {error:'editor_patch_result_too_large'};
  return {text};
}"""

_MONACO = """(element, request) => {
  let writeAttempted = false;
  const outcome = (() => {
  let desired = request.text;
  const patchText = __FLOWER_EDITOR_PATCH__;
  const api = element.ownerDocument.defaultView.monaco?.editor;
  if (!api || typeof api.getEditors !== 'function')
    return {error:'editor_api_unavailable'};
  const editors = api.getEditors().filter(editor => {
    const node = editor.getDomNode();
    return node && (node === element || element.contains(node) || node.contains?.(element));
  });
  if (editors.length !== 1) return {error:'editor_target_ambiguous'};
  const editor = editors[0], editorNode = editor.getDomNode(), model = editor.getModel();
  if (!model || model.isDisposed()) return {error:'editor_model_missing'};
  const uri = model.uri.toString(), version = model.getVersionId();
  // Only resource URIs identify a file/document for this generic adapter.
  if (!['file','http','https','vscode-remote'].includes(model.uri.scheme) ||
      !model.uri.path || model.uri.path === '/')
    return {error:'editor_document_unidentified'};
  if (request.kind === 'replace') {
    if (uri !== request.expected_uri || version !== request.expected_version)
      return {error:'editor_model_changed'};
    if (typeof api.EditorOption?.readOnly === 'number' &&
        editor.getOption?.(api.EditorOption.readOnly))
      return {error:'editor_read_only'};
    const patch = patchText(Object.prototype.hasOwnProperty.call(request, 'old_text') ? model.getValue() : '', request);
    if (patch.error) return patch;
    desired = patch.text;
    writeAttempted = true;
    editor.pushUndoStop();
    const accepted = editor.executeEdits('flower-control',
      [{range:model.getFullModelRange(),text:desired,forceMoveMarkers:true}]);
    editor.pushUndoStop();
    if (!accepted) return {error:'editor_edit_rejected'};
    // Content listeners can synchronously switch/dispose a model or its host.
    // The old model's matching value cannot verify the newly active document.
    if (element.isConnected === false || editorNode?.isConnected === false ||
        element.ownerDocument.defaultView.monaco?.editor !== api ||
        !api.getEditors().includes(editor) || editor.getModel() !== model || model.isDisposed() ||
        model.uri.toString() !== uri || editor.getDomNode() !== editorNode ||
        editorNode !== element && !element.contains(editorNode) && !editorNode.contains?.(element))
      return {error:'editor_model_changed'};
  }
  const value = model.getValue();
  if (request.kind === 'read') {
    const points = Array.from(value);
    return {uri,version:model.getVersionId(),text:points.slice(request.offset,request.offset+request.limit).join(''),total:points.length};
  }
  return {uri,version:model.getVersionId(),length:Array.from(value).length,
    exact:request.kind === 'replace' ? value === desired : undefined};
  })();
  return {...outcome, flower_write_attempted:writeAttempted};
}""".replace('__FLOWER_EDITOR_PATCH__', _EDITOR_PATCH_TEXT)


_CODEMIRROR = """(element, request) => {
  let writeAttempted = false;
  const outcome = (() => {
  let desired = request.text;
  const patchText = __FLOWER_EDITOR_PATCH__;
  const roots = [element, element.closest('.CodeMirror,.cm-editor'),
                 ...element.querySelectorAll('.CodeMirror,.cm-editor')].filter(Boolean);
  function currentViews(root, content) {
    const View = root.ownerDocument.defaultView.EditorView;
    let publicView = null;
    try { publicView = View?.findFromDOM?.(root); } catch {}
    return [publicView, content?.cmView?.rootView?.view, content?.cmTile?.root?.view];
  }
  const found = [];
  for (const root of roots) {
    if (root.CodeMirror && !found.some(item => item.api === root.CodeMirror))
      found.push({kind:'codemirror5',api:root.CodeMirror,root});
    if (root.classList?.contains('cm-editor')) {
      const content = root.querySelector('.cm-content');
      // Bundled CM6 usually does not publish EditorView on window. These DOM
      // links are the ones used by findFromDOM in upstream CM6 releases:
      // cmView in 6.30, cmTile in the current upstream source.
      for (const view of currentViews(root, content)) {
        if (view && view.dom === root && view.contentDOM === content &&
            typeof view.dispatch === 'function' && view.state?.doc &&
            !found.some(item => item.api === view))
          found.push({kind:'codemirror6',api:view,root});
      }
    }
  }
  if (found.length !== 1) return {error:found.length ? 'editor_target_ambiguous' : 'editor_api_unavailable'};
  const {kind,api,root} = found[0];
  const rootContainsElement = root === element || root.contains(element);
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
    const patch = patchText(value, request);
    if (patch.error) return patch;
    desired = patch.text;
    if (kind === 'codemirror5') {
      if (api.getOption?.('readOnly') || api.isReadOnly?.()) return {error:'editor_read_only'};
      if (typeof doc.replaceRange !== 'function' || typeof doc.firstLine !== 'function' ||
          typeof doc.lastLine !== 'function' || typeof doc.getLine !== 'function')
        return {error:'editor_api_unavailable'};
      writeAttempted = true;
      doc.replaceRange(desired, {line:doc.firstLine(),ch:0},
                       {line:doc.lastLine(),ch:doc.getLine(doc.lastLine()).length},
                       'flower-control');
    } else {
      if (api.state.readOnly || content?.getAttribute('contenteditable') === 'false')
        return {error:'editor_read_only'};
      writeAttempted = true;
      api.dispatch({changes:{from:0,to:doc.length,insert:desired}});
    }
    if (element.isConnected === false || root.isConnected === false ||
        root.ownerDocument.defaultView !== host ||
        (rootContainsElement ? root !== element && !root.contains(element) : !element.contains(root)) ||
        (kind === 'codemirror5' && (root.CodeMirror !== api || api.getDoc() !== doc)) ||
        (kind === 'codemirror6' && (api.dom !== root || api.contentDOM !== content ||
          content?.isConnected === false || api.destroyed === true ||
          root.querySelector('.cm-content') !== content || !currentViews(root, content).includes(api))) ||
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
          exact:request.kind === 'replace' ? current === desired : undefined};
  })();
  return {...outcome, flower_write_attempted:writeAttempted};
}""".replace('__FLOWER_EDITOR_PATCH__', _EDITOR_PATCH_TEXT)


def _fingerprint(value: dict) -> str:
    # A DOM string may contain a lone surrogate, including text.slice cutting
    # an emoji at the descriptor limit. Escape it losslessly inside JSON;
    # every previously valid UTF-8 descriptor retains its original digest.
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False)
        .encode('utf-8',errors='backslashreplace')).hexdigest()


@dataclass
class Reference:
    handle: ElementHandle
    frame: Frame
    generation: int
    descriptor: dict
    fingerprint: str
    expires: float
    documents: tuple = ()


class _PageObservation(dict):
    """Wire-compatible dictionary carrying only local document bindings."""
    def __init__(self, value, documents):
        super().__init__(value)
        self.documents = documents


class PageDriver:
    def __init__(self, page: Page, *, clock=time.monotonic,
                 event_filter: Callable[[str], bool] | None = None, diagnostic_sink=None):
        self.page = page
        self.clock = clock
        self.event_filter = event_filter
        self.diagnostic_sink = diagnostic_sink
        self.generation = 0
        self._frame_versions: dict[Frame, int] = {}
        self.navigation_version = 0
        self.refs: dict[str, Reference] = {}
        self._message_baselines: dict[str, dict] = {}
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

    async def chooser_upload(self, chooser_id: str, *, name=None, mime_type=None, content=None,
                             files=None, check):
        payload = validate_files(files if files is not None else [
            {"name": name, "mime_type": mime_type, "content": content}])
        await check()
        chooser = self.pending_chooser
        if chooser is None or chooser_id != self.pending_chooser_id:
            raise ControlError("chooser_reference_stale")
        if len(payload) > 1 and not chooser.is_multiple():
            raise ControlError("file_input_multiple_required")
        descriptor = await chooser.element.evaluate(_DESCRIBE)
        if not descriptor["connected"] or descriptor["tag"] != "INPUT" or descriptor["type"] != "file":
            raise ControlError("file_input_required")
        await check()
        mark_write("chooser_upload")
        await chooser.set_files(payload, timeout=5000)
        selected = await chooser.element.evaluate("""e => Array.from(e.files || [],
          f => ({name:f.name,size:f.size,type:f.type}))""")
        if self.pending_chooser is chooser:
            self.pending_chooser = None
            self.pending_chooser_id = None
        await check()
        exact = selection_matches(selected, payload)
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
        self._frame_versions[_frame] = self._frame_versions.get(_frame, 0) + 1
        if _frame is getattr(self.page, "main_frame", None):
            self.generation += 1
            self.navigation_version += 1

    def _documents(self, frame):
        """Bind the owning document and its ancestors, never sibling frames."""
        chain, seen = [], set()
        available = list(self.page.frames)
        while frame is not None:
            if id(frame) in seen or len(chain) >= 64:
                raise ControlError("observation_changed")
            seen.add(id(frame))
            chain.append((frame, self._frame_versions.get(frame, 0)))
            parent = getattr(frame, "parent_frame", None)
            frame = parent if any(parent is item for item in available) else None
        return tuple(chain)

    def _documents_current(self, documents):
        return all(not frame.is_detached() and self._frame_versions.get(frame, 0) == version
                   for frame, version in documents)

    def _reference_current(self, ref):
        return (self._documents_current(ref.documents) if ref.documents
                else ref.generation == self.generation)

    def _accept_event(self, source_url: str | None = None) -> bool:
        if self.event_filter is None:
            return True
        return self.event_filter(source_url if source_url and source_url != "about:blank"
                                 else self.page.url)

    def _record_diagnostic(self, kind: str, **fields: str) -> None:
        # This is the cache boundary; every producer, including future ones,
        # must lose arbitrary page text before it can reach a diagnostic bundle.
        if "message" in fields:
            fields["message"] = "[content hidden]"
        if "failure" in fields:
            fields["failure"] = "network_request_failed"
        self.diagnostics.append({"seq": self._next_diagnostic_seq, "kind": kind,
                                 **fields})
        self._next_diagnostic_seq += 1
        del self.diagnostics[:-100]
        if self.diagnostic_sink is not None:
            self.diagnostic_sink(dict(self.diagnostics[-1]))

    def _console(self, message):
        if message.type not in {"error", "warning", "log", "info", "debug"}:
            return
        location = message.location or {}
        if self._accept_event(location.get("url")):
            self._record_diagnostic("console", level=message.type,
                                    message="[content hidden]")

    def _page_error(self, error):
        if self._accept_event():
            self._record_diagnostic("pageerror", message="[content hidden]")

    def _request_failed(self, request):
        # URLs can carry tokens; only a failure category is retained by default.
        if self._accept_event(request.url):
            self._record_diagnostic("requestfailed",
                                    failure="network_request_failed")

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
        self._message_baselines.clear()
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
                      selector: str = "button,input,textarea,select,a,video,audio,[role],[contenteditable]",
                      offset: int = 0, limit: int = 100, ttl: float = 15,
                      projection: list[str] | None = None, root_ref: str | None = None,
                      max_chars: int | None = None, max_nodes: int | None = None,
                      max_depth: int | None = None):
        from .web_tree import validate_tree_depth,tree_handles,descriptor_script
        validate_tree_depth(max_depth)
        fields = validate_observation_projection(projection)
        if fields is not None and 'depth' in fields and max_depth is None:
            raise ControlError('observation_depth_requires_tree')
        validate_observation_root(root_ref)
        validate_observation_max_chars(max_chars)
        limit = observation_node_limit(limit,max_nodes)
        if not 1 <= limit <= (500 if max_nodes is not None else 200) or offset < 0 or not 0 < ttl <= 30:
            raise ControlError("invalid_observation_bounds")
        await check()
        frames = self.page.frames
        if not 0 <= frame_index < len(frames):
            raise ControlError("frame_not_found")
        # Release expired handles without invalidating still-live paginated refs.
        for key, ref in list(self.refs.items()):
            if ref.expires <= self.clock() or not self._reference_current(ref):
                self.refs.pop(key)
                await ref.handle.dispose()
        if len(self.refs) + limit > 1000:
            raise ControlError("observation_reference_limit")
        frame = frames[frame_index]
        documents = self._documents(frame)
        generation = self.generation
        root = None
        scoped_handles = None
        tree_anchor = None
        tree_facts = None
        tree_frames = None
        tree_documents = None
        if max_depth is not None:
            if root_ref is not None:
                root=await self._fresh(root_ref)
                if root.frame is not frame:raise ControlError('observation_root_frame_mismatch')
            # Capture versions before collecting handles. Pin the entire bounded
            # frame set, including empty/unreturned/cross-origin documents;
            # explicit tree mode may conservatively invalidate on sibling nav.
            tree_frames=tuple(self.page.frames)
            if len(tree_frames)>256:raise ControlError('observation_tree_budget')
            tree_documents={f:self._documents(f) for f in tree_frames}
            documents=documents+tuple((f,self._frame_versions.get(f,0)) for f in tree_frames)
            tree_facts,scoped_handles,tree_anchor=await tree_handles(frame,
                None if root is None else root.handle,selector,offset,limit,max_depth)
            count=tree_facts['total']
        elif root_ref is None:
            locator = frame.locator(selector)
            count = await locator.count()
        else:
            root = await self._fresh(root_ref)
            if root.frame is not frame: raise ControlError('observation_root_frame_mismatch')
            count,scoped_handles = await _scoped_observation_handles(root.handle,selector,offset,limit)
        entries, acquired, pending = [], [], {}
        released = set()
        used_chars, next_entry_chars = 0, None
        if scoped_handles is not None: acquired.extend(scoped_handles)
        try:
            for index in range(offset, min(offset + limit, count)):
                handle = (await locator.nth(index).element_handle(timeout=2000) if scoped_handles is None
                          else scoped_handles[index-offset])
                if handle is None:
                    raise ControlError("observation_changed")
                # Own the handle before the first fallible read. Nothing from
                # this observation is addressable until every final gate passes.
                if scoped_handles is None: acquired.append(handle)
                node_frame,node_documents=frame,documents
                if max_depth is not None:
                    node_frame=await handle.owner_frame()
                    if (node_frame not in tree_documents or node_frame.is_detached()
                            or not self._documents_current(documents)):
                        raise ControlError('observation_changed')
                    node_documents=tree_documents[node_frame]
                    value=await handle.evaluate(descriptor_script(_DESCRIBE),dict(root=tree_anchor,max_depth=max_depth))
                    if type(value) is not dict or type(value.get('depth')) is not int:
                        raise ControlError('observation_changed')
                    descriptor=value['descriptor']
                    node_depth=value['depth']
                    if await handle.owner_frame() is not node_frame:raise ControlError('observation_changed')
                else:
                    descriptor = (await handle.evaluate(_DESCRIBE) if scoped_handles is None
                        else await handle.evaluate(_SCOPED_DESCRIBE,root.handle))
                if scoped_handles is not None and type(descriptor) is not dict:
                    raise ControlError('observation_changed')
                reference = secrets.token_urlsafe(18)
                # Full values are read separately; do not silently truncate completeness.
                public = dict(descriptor)
                value = public.pop("value")
                public["value_length"] = len(value) if value is not None else None
                if max_depth is not None:public['depth']=node_depth
                if fields is not None:
                    public = {key:public[key] for key in fields if key != 'ref' and key in public}
                entry = {"ref": reference, **public}
                if max_chars is not None:
                    entry_chars = _observation_entry_chars(entry)
                    if used_chars + entry_chars > max_chars:
                        next_entry_chars = entry_chars
                        break
                    used_chars += entry_chars
                pending[reference] = Reference(handle, node_frame, generation, descriptor,
                    _fingerprint(descriptor), self.clock() + ttl, node_documents)
                entries.append(entry)
            if tree_anchor is not None:
                await tree_anchor.dispose()
                tree_anchor=None
            if max_chars is not None:
                # A root slice owns even its not-yet-described handles. Keep
                # only accepted entries; release the blocked entry and suffix
                # before the final document/root/authority checks.
                accepted = {id(ref.handle) for ref in pending.values()}
                for handle in acquired:
                    if id(handle) not in accepted:
                        await handle.dispose()
                        released.add(id(handle))
            if root is not None and await self._fresh(root_ref) is not root:
                raise ControlError('observation_changed')
            if (not self._documents_current(documents) or
                    tree_frames is not None and tuple(self.page.frames)!=tree_frames):
                raise ControlError("observation_changed")
            await check()
            if (not self._documents_current(documents) or
                    tree_frames is not None and tuple(self.page.frames)!=tree_frames):
                raise ControlError("observation_changed")
            if root is not None and (self.refs.get(root_ref) is not root
                    or root.expires <= self.clock() or not self._reference_current(root)):
                raise ControlError('observation_changed')
            if max_depth is not None and any(not self._reference_current(ref) for ref in pending.values()):
                raise ControlError('observation_changed')
            result = _PageObservation({"generation": generation, "frame_index": frame_index, "entries": entries,
                "total_at_start": count, "next_offset": offset + limit if offset + limit < count else None,
                "complete": offset == 0 and count <= limit,
                "text_limit_per_entry": 2048, "frames": len(frames), **describe_frames(frames)}, documents)
            if fields is not None:
                result['projection'] = ['ref',*(field for field in fields if field != 'ref')]
            if max_chars is not None:
                next_offset = offset + len(entries)
                result.update(max_chars=max_chars,used_chars=used_chars,char_units='utf16_json_entries',
                    budget_trigger=('max_chars' if next_entry_chars is not None else None),
                    next_entry_chars=next_entry_chars,
                    next_offset=(next_offset if next_offset < count else None),
                    complete=(offset == 0 and count == len(entries)))
            if root is not None:
                result['root_ref'] = root_ref
                result.scope_reference = (root_ref,root)
            if max_nodes is not None:
                result['max_nodes'] = max_nodes
                if not result.get('budget_trigger'):
                    result['budget_trigger'] = 'max_nodes' if offset + len(entries) < count else None
            if tree_facts is not None:
                result.tree_frames=tree_frames
                result.update(max_depth=max_depth,tree_scope='dom_open_shadow_same_origin_frames',
                    tree_document_binding='all_page_frames',
                    depth_truncated=tree_facts['depth_truncated'],
                    cross_origin_frames_skipped=tree_facts['cross_origin_frames_skipped'])
                if tree_facts['depth_truncated'] or tree_facts['cross_origin_frames_skipped']:
                    result['complete']=False
                if tree_facts['depth_truncated'] and not result.get('budget_trigger'):
                    result['budget_trigger']='max_depth'
            # Another observation may have committed while this one awaited.
            if len(self.refs) + len(pending) > 1000:
                raise ControlError("observation_reference_limit")
        except BaseException:
            # Cancellation is an abort too. Disposal is best effort after a
            # browser/transport failure; retain the original failure and keep
            # trying the remaining handles rather than publishing partial refs.
            for handle in acquired:
                if id(handle) in released:
                    continue
                try:
                    await handle.dispose()
                except Exception:
                    pass
            if tree_anchor is not None:
                try:await tree_anchor.dispose()
                except Exception:pass
            raise
        self.refs.update(pending)
        return result

    def verify_observation(self, result):
        """Recheck document bindings after the worker's last awaited gate."""
        tree_frames=getattr(result,'tree_frames',None)
        if tree_frames is not None and tuple(self.page.frames)!=tree_frames:
            raise ControlError('observation_changed')
        scope = getattr(result,'scope_reference',None)
        if (scope is not None and (self.refs.get(scope[0]) is not scope[1]
                or scope[1].expires <= self.clock() or not self._reference_current(scope[1]))):
            raise ControlError('observation_changed')
        if (self.page.is_closed() or not self._documents_current(result.documents) or any(
                (ref := self.refs.get(entry["ref"])) is None
                or ref.expires <= self.clock() or not self._reference_current(ref)
                for entry in result["entries"])):
            raise ControlError("observation_changed")

    async def discard_observation(self, result):
        """Release only the exact reference keys returned by an aborted call."""
        # Remove all keys before awaiting remote disposal, which may itself be
        # cancelled or lose its browser connection.
        refs = [self.refs.pop(entry["ref"], None) for entry in result["entries"]]
        for ref in refs:
            if ref is not None:
                try:
                    await ref.handle.dispose()
                except Exception:
                    pass

    async def _fresh(self, reference: str) -> Reference:
        ref = self.refs.get(reference)
        if not ref or ref.expires <= self.clock() or not self._reference_current(ref):
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
          const s=Array.from('value' in e?String(e.value):e.innerText||e.textContent||'');
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
          let editorCandidate = false;
          try { editorCandidate = !!document.querySelector('.monaco-editor,.CodeMirror,.cm-editor'); }
          catch {} // Optional guidance must not break ordinary page text reads.
          return {url, title: document.title, text: chars.slice(offset, offset + limit).join(''),
                  total: chars.length, digest: hex, full_text: digest ? null : bound,
                  editor_candidate: editorCandidate};
        }""", {"offset": offset, "limit": limit}), timeout=4)
        await check()
        if body["url"] != self.page.url:
            raise ControlError("page_changed")
        if body["digest"] is None:
            body["digest"] = textencoder_digest(body.pop("full_text"))
        if expected_digest is not None and body["digest"] != expected_digest:
            raise ControlError("page_content_changed")
        return {"url": body["url"], "title": body["title"],
                "generation": self.generation, "navigation_version": self.navigation_version,
                "text": body["text"], "text_total": body["total"],
                "text_truncated": offset + limit < body["total"],
                "text_digest": body["digest"], "offset": offset,
                "next_offset": offset + limit if offset + limit < body["total"] else None,
                "complete": offset == 0 and offset + limit >= body["total"],
                "offset_unit": "unicode_codepoints",
                **({"editor_hint": {"kind": "virtualized_editor_candidate",
                    "text_order": "rendered_dom_only", "document_verified": False,
                    "suggested_commands": ["editor_inspect", "editor_read"],
                    "reference_required": True}} if body.get("editor_candidate") is True else {})}

    async def mark_tab(self, marker="[Flower]", *, check):
        if type(marker) is not str or len(marker) > 64 or "\x00" in marker:
            raise ControlError("invalid_page_marker")
        await check()
        generation = self.generation
        before = await self.page.title()
        if len(before) > 4096 or self.page.is_closed():
            raise ControlError("page_title_unavailable")
        base = re.sub(r"^\[Flower[^\]]*\]\s*", "", before)
        updated = (marker.strip() + " " + base).strip() if marker.strip() else base
        await check()
        if generation != self.generation:
            raise ControlError("page_changed")
        mark_write("mark_tab")
        confirmed = await self.page.evaluate("title => {document.title=title;return document.title;}", updated)
        await check()
        return {"state": "verified" if confirmed == updated and generation == self.generation else "not_verified",
                "verification": "exact_tab_title", "marked": bool(marker.strip()), "marker": marker.strip(),
                "title_before": before[:256], "title_after": confirmed[:256],
                "title_truncated": len(before) > 256 or len(confirmed) > 256, "business_result_verified": False}

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
        if (not self._reference_current(ref) or not descriptor["connected"] or
                {key: value for key, value in ref.descriptor.items() if key not in mutable} !=
                {key: value for key, value in descriptor.items() if key not in mutable}):
            raise ControlError("element_changed")
        ref.descriptor = descriptor
        ref.fingerprint = _fingerprint(descriptor)

    async def type_text(self, reference, text, *, replace=False, input_mode="insert_text", check):
        """Legacy focus/insertText algorithm adapted to owned Playwright handles."""
        if type(text) is not str or len(text) > 1_000_000 or "\x00" in text or type(replace) is not bool:
            raise ControlError("invalid_text")
        if input_mode not in ("insert_text", "paste_event"):
            raise ControlError("invalid_text_input_mode")
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
            if input_mode == "paste_event":
                # Editor paste handlers receive the exact multiline text. This
                # event-local DataTransfer never accesses the OS clipboard.
                # Do not fall back/replay if a site ignores an untrusted event.
                await ref.handle.evaluate("""(e,text) => {
                    const w=e.ownerDocument.defaultView;
                    const data=new w.DataTransfer(); data.setData('text/plain',text);
                    e.dispatchEvent(new w.ClipboardEvent('paste', {
                        clipboardData:data,bubbles:true,cancelable:true}));
                }""", text)
            else:
                await session.send("Input.insertText", {"text": text})
            await check()
            actual = await ref.handle.evaluate("e => 'value' in e ? e.value : (e.innerText || e.textContent || '')")
            await self._advance_input_reference(reference, "fill")
            return {"state": "verified" if replace and actual == text else "not_verified",
                    "input_dispatched": True, "supplied_chars": len(text), "replaced": replace,
                    "input_mode": input_mode,
                    **({"inserted_chars": len(text)} if input_mode == "insert_text" else {}),
                    "verification": "exact_element_text" if replace and actual == text else "input_postcondition_required",
                    "business_result_verified": False}
        finally:
            try:
                if emulated:
                    await session.send("Emulation.setFocusEmulationEnabled", {"enabled": False})
            finally:
                await session.detach()

    def _prune_message_baselines(self):
        for key, record in list(self._message_baselines.items()):
            if record["expires"] <= self.clock() or not self._documents_current(record["documents"]):
                self._message_baselines.pop(key, None)

    def _message_binding(self, baseline, selector, frame=None):
        self._prune_message_baselines()
        record = self._message_baselines.get(baseline["container_identity"])
        if record is None:
            raise ControlError("message_baseline_unavailable")
        if (selector != record["selector"] or frame is not None and frame is not record["frame"]
                or baseline["count"] != record["count"] or baseline.get("last_message_hash") != record["last_message_hash"]
                or self.refs.get(record["reference"]) is not record["ref"]):
            raise ControlError("message_baseline_binding_changed")
        if self.page.is_closed() or record["frame"].is_detached():
            raise ControlError("message_baseline_unavailable")
        return record

    def verify_message_baseline(self, result):
        """Keep an unpublished identity bound through the worker's last gate."""
        baseline = result["baseline"]
        record = self._message_baselines.get(baseline["container_identity"])
        if record is None:
            raise ControlError("message_baseline_unavailable")
        self._message_binding(baseline, record["selector"])

    def discard_message_baseline(self, result):
        # A baseline borrows its observed container handle; it does not own it.
        self._message_baselines.pop(result["baseline"]["container_identity"], None)

    async def _bound_message_sample(self, record, baseline_count):
        # One evaluation keeps selection inside the original ElementHandle.
        # Do not re-resolve a selector for the container or add DOM markers.
        value = await record["handle"].evaluate(r"""(container,a) => {
            if (!container.isConnected) return {disconnected:true};
            const secret=e=>e.type==='password'||/\b(?:current-password|new-password)\b/.test(e.autocomplete||'');
            if (secret(container)||Array.from(container.querySelectorAll('input,textarea')).some(secret)) return {secret:true};
            const items=Array.from(container.querySelectorAll(a.selector));
            if(items.length>10000) return {oversized:true};
            if(items.some(secret)) return {secret:true};
            const text=e=>String(e.innerText||e.textContent||'');
            const last=items.length?text(items[items.length-1]):'';
            const prefix_last=a.count&&items.length>=a.count?text(items[a.count-1]):'';
            return last.length>16000||prefix_last.length>16000?{oversized:true}:{count:items.length,last,prefix_last};
        }""", {"selector":record["selector"],"count":baseline_count})
        if value.get("disconnected"):
            raise ControlError("message_container_replaced")
        if value.get("secret"):
            raise ControlError("secret_input_requires_user_takeover")
        if value.get("oversized"):
            raise ControlError("condition_evidence_too_large")
        return value

    async def _check_message_container(self, record):
        value=await record["handle"].evaluate(r"""e=>({connected:e.isConnected,secret:
            e.type==='password'||/\b(?:current-password|new-password)\b/.test(e.autocomplete||'')||
            Array.from(e.querySelectorAll('input,textarea')).some(n=>n.type==='password'||/\b(?:current-password|new-password)\b/.test(n.autocomplete||''))})""")
        if not value["connected"]:
            raise ControlError("message_container_replaced")
        if value["secret"]:
            raise ControlError("secret_input_requires_user_takeover")
        if record["expires"]<=self.clock() or not self._documents_current(record["documents"]):
            raise ControlError("message_baseline_unavailable")

    async def message_baseline(self, container_reference, selector, *, ttl=15, check):
        if (type(container_reference) is not str or not 1<=len(container_reference)<=100
                or type(selector) is not str or not 1<=len(selector)<=2000 or "\x00" in selector
                or type(ttl) not in (int,float) or not 0<ttl<=30):
            raise ControlError("invalid_message_baseline")
        await check()
        self._prune_message_baselines()
        if len(self._message_baselines)>=128:
            raise ControlError("message_baseline_limit")
        ref=await self._fresh(container_reference)
        record={"reference":container_reference,"ref":ref,"handle":ref.handle,"frame":ref.frame,
            "documents":self._documents(ref.frame),"selector":selector,"expires":min(ref.expires,self.clock()+ttl)}
        value=await self._bound_message_sample(record,0)
        await check()
        if not self._documents_current(record["documents"]) or self.refs.get(container_reference) is not ref:
            raise ControlError("message_baseline_binding_changed")
        # Verify connection/secrecy once more before publishing identity. Do not
        # persist the sampled message strings in refs, logs or the baseline map.
        current=await self._bound_message_sample(record,0)
        await check()
        if current!=value or record["expires"]<=self.clock() or not self._documents_current(record["documents"]):
            raise ControlError("message_baseline_binding_changed")
        await self._check_message_container(record)
        record.update(count=value["count"],last_message_hash=dom_text_digest(" ".join(value["last"].split())) if value["count"] else None)
        identity="mbase:"+secrets.token_hex(16)
        self._message_baselines[identity]=record
        return {"state":"verified","baseline":{"count":record["count"],"last_message_hash":record["last_message_hash"],"container_identity":identity},
            "ttl_ms":max(0,int((record["expires"]-self.clock())*1000)),"business_result_verified":False}

    async def _condition_value(self, frame, selector, condition, expected):
        if condition in {"url", "url_contains"}:
            value = frame.url
            return {"matched": value == expected if condition == "url" else expected in value, "text": value}
        locator = frame.locator(selector)
        if condition == "message_appended":
            # Only aggregate identity crosses the boundary, never message text.
            binding = self._message_binding(expected["baseline"],selector,frame) if "container_identity" in expected["baseline"] else None
            if binding:
                values=await self._bound_message_sample(binding,expected["baseline"]["count"])
                self._message_binding(expected["baseline"],selector,frame)
            else:
                values = await locator.evaluate_all("""(items, baselineCount) => {
                if (items.length > 10000) return {oversized:true};
                if (items.some(e => e.type === 'password' || /\\b(?:current-password|new-password)\\b/.test(e.autocomplete || '')))
                    return {secret:true};
                const last = items.length ? String(items[items.length-1].innerText || items[items.length-1].textContent || '') : '';
                const prefixLast = baselineCount && items.length >= baselineCount ? String(items[baselineCount-1].innerText || items[baselineCount-1].textContent || '') : '';
                return last.length > 16000 || prefixLast.length > 16000 ? {oversized:true} : {count:items.length,last,prefix_last:prefixLast};
                }""", expected["baseline"]["count"])
            if values.get("secret"):
                raise ControlError("secret_input_requires_user_takeover")
            if values.get("oversized"):
                raise ControlError("condition_evidence_too_large")
            last_hash = dom_text_digest(" ".join(values["last"].split())) if values["count"] else None
            desired_hash = dom_text_digest(" ".join(expected["text"].split()))
            baseline_hash = expected["baseline"].get("last_message_hash")
            prefix_hash = dom_text_digest(" ".join(values.get("prefix_last", "").split())) if expected["baseline"]["count"] else None
            prefix_matches = "last_message_hash" not in expected["baseline"] or prefix_hash == baseline_hash
            return {"matched": values["count"] > expected["baseline"]["count"] and last_hash == desired_hash and prefix_matches,
                    "text": None, "evidence": {"count": values["count"], "last_message_hash": last_hash}}
        count = await locator.count()
        if count > 1:
            raise ControlError("wait_target_ambiguous")
        if condition == "detached":
            return {"matched": count == 0, "text": None}
        if count == 0:
            return {"matched": condition == "hidden", "text": None}
        content_read = condition in {"value", "attribute", "attribute_contains", "text_changed"} or (condition == "attached" and expected is not None)
        if content_read:
            # Resolve the current node, check secrecy, and read in one browser
            # evaluation. Two awaited locator calls can see different nodes.
            content = await locator.evaluate(r"""(e,a) => {
                if (e.type === 'password' || /\b(?:current-password|new-password)\b/.test(e.autocomplete || ''))
                    return {secret:true};
                const value = /^(attribute|attribute_contains)$/.test(a.condition) ? e.getAttribute(a.attribute)
                    : a.condition === 'value' ? ('value' in e ? String(e.value) : (e.innerText || e.textContent || ''))
                    : (e.innerText || e.textContent || '');
                return {secret:false,value};
            }""", {"condition": condition, "attribute": expected["name"] if condition in {"attribute", "attribute_contains"} else None})
            if content["secret"]:
                raise ControlError("secret_input_requires_user_takeover")
            value = content["value"]
            if condition in {"attribute", "attribute_contains"}:
                return {"matched": value == expected["value"] if condition == "attribute" else isinstance(value, str) and expected["value"] in value, "text": value}
            if condition == "value":
                return {"matched": value == expected, "text": value}
            return {"matched": expected is None or expected in value, "text": value}
        if condition in {"enabled", "disabled"}:
            enabled = await locator.is_enabled()
            return {"matched": enabled if condition == "enabled" else not enabled, "text": None}
        if condition in {"checked", "unchecked"}:
            checked = await locator.is_checked()
            return {"matched": checked if condition == "checked" else not checked, "text": None}
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
                or not set(wait_for) <= {"selector", "timeout_ms", "expected_text", "condition", "frame_index", "expected_value", "attribute", "baseline"}
                or type(wait_for.get("selector")) is not str
                or not 1 <= len(wait_for["selector"]) <= 2000
                or type(wait_for.get("timeout_ms")) is not int
                or not 1 <= wait_for["timeout_ms"] <= 10000
                or wait_for.get("condition", "text_changed") not in
                   {"text_changed", "attached", "detached", "visible", "hidden", "enabled", "disabled", "checked", "unchecked", "value", "attribute", "attribute_contains", "class", "url", "url_contains", "media_playing", "media_paused", "message_appended"}
                or type(wait_for.get("frame_index", 0)) is not int
                or ("expected_text" in wait_for and
                    (type(wait_for["expected_text"]) is not str or
                     not 1 <= len(wait_for["expected_text"]) <= 1000))):
            raise ControlError("invalid_wait_condition")
        condition = wait_for.get("condition", "text_changed")
        expected = wait_for.get("expected_text")
        if expected is not None and condition not in {"text_changed", "attached", "message_appended"}:
            raise ControlError("invalid_wait_condition")
        if condition in {"value", "attribute", "attribute_contains", "class", "url", "url_contains"}:
            expected = wait_for.get("expected_value")
            if type(expected) is not str or len(expected) > 8192 or (condition in {"class", "url", "url_contains", "attribute_contains"} and not expected):
                raise ControlError("invalid_wait_condition")
            if condition in {"attribute", "attribute_contains"}:
                name = wait_for.get("attribute")
                if type(name) is not str or not 1 <= len(name) <= 120 or any(ch.isspace() for ch in name):
                    raise ControlError("invalid_wait_condition")
                expected = {"name": name, "value": expected}
        elif "expected_value" in wait_for or "attribute" in wait_for:
            raise ControlError("invalid_wait_condition")
        if condition == "message_appended":
            expected = {"text": expected, "baseline": wait_for["baseline"]}
        await check()
        frames = self.page.frames
        index = wait_for.get("frame_index", 0)
        if not 0 <= index < len(frames):
            raise ControlError("invalid_frame_index")
        frame = frames[index]
        if condition == "message_appended" and "container_identity" in expected["baseline"]:
            binding=self._message_binding(expected["baseline"],wait_for["selector"])
            if "frame_index" in wait_for and frame is not binding["frame"]:
                raise ControlError("message_baseline_binding_changed")
            frame=binding["frame"]
        documents = self._documents(frame)
        generation, url = self.generation, self.page.url
        value = await self._condition_value(frame, wait_for["selector"], condition, expected)
        if condition == "text_changed" and value["text"] is None:
            raise ControlError("wait_target_ambiguous")
        if transition and ((condition == "text_changed" and expected is not None and value["matched"])
                           or (condition != "text_changed" and value["matched"])):
            raise ControlError("wait_condition_already_true")
        await check()
        if condition == "message_appended" and "container_identity" in expected["baseline"]:
            binding=self._message_binding(expected["baseline"],wait_for["selector"],frame)
            await self._check_message_container(binding)
        if not self._documents_current(documents) or self.generation != generation or self.page.url != url or frame.is_detached():
            raise ControlError("page_changed_during_wait")
        return {"selector": wait_for["selector"], "timeout_ms": wait_for["timeout_ms"],
                "before": value["text"], "expected": expected, "frame": frame,
                "condition": condition, "generation": self.generation, "url": self.page.url,
                "documents": documents,
                "main_frame": frame is self.page.main_frame,
                "transition": transition}

    async def _wait_text_change(self, baseline: dict | None, *, check):
        if baseline is None:
            return None
        deadline = self.clock() + baseline["timeout_ms"] / 1000
        while True:
            await check()
            if self.pending_dialog is not None:
                return {"observed": False, "reason": "dialog_pending", "dialog": self.dialog_snapshot()}
            # URL waits intentionally span the navigation they are waiting for.
            # Other conditions remain bound to their original document.
            independent_url = baseline["condition"] in {"url", "url_contains"}
            if independent_url and baseline.get("main_frame", baseline["frame"] is self.page.main_frame):
                baseline["frame"] = self.page.main_frame
            if (self.page.is_closed() or baseline["frame"].is_detached()
                    or independent_url and not self._documents_current(baseline.get("documents", ())[1:])
                    or (not independent_url and (not self._documents_current(baseline.get("documents", ()))
                    or self.generation != baseline["generation"]
                    or self.page.url != baseline["url"] or baseline["frame"].is_detached()))):
                return {"observed": False, "reason": "page_changed_during_wait"}
            try:
                documents = self._documents(baseline["frame"])
                generation, url = self.generation, self.page.url
                value = await self._condition_value(baseline["frame"], baseline["selector"],
                                                    baseline["condition"], baseline["expected"])
            except PlaywrightTimeoutError:
                value = {"matched": False, "text": None}
            await check()
            if baseline["condition"]=="message_appended" and "container_identity" in baseline["expected"]["baseline"]:
                bound=self._message_binding(baseline["expected"]["baseline"],baseline["selector"],baseline["frame"])
                await self._check_message_container(bound)
            if (self.page.is_closed() or baseline["frame"].is_detached() or not self._documents_current(documents)
                    or self.generation != generation or self.page.url != url):
                if independent_url and not self.page.is_closed() and self.clock() < deadline:
                    await asyncio.sleep(min(.05, max(0, deadline - self.clock())))
                    continue
                return {"observed": False, "reason": "page_changed_during_wait"}
            matched = value["matched"]
            if baseline["condition"] == "text_changed":
                matched = value["text"] is not None and matched and (
                    (not baseline.get("transition", True) and baseline["expected"] is not None)
                    or value["text"] != baseline["before"])
            if matched:
                text = value["text"]
                return {"observed": True, "condition": baseline["condition"],
                        "text": text[:16000] if text is not None else None,
                        "text_truncated": text is not None and len(text) > 16000,
                        **({"evidence": value["evidence"]} if "evidence" in value else {})}
            if self.clock() >= deadline:
                return {"observed": False, "reason": "condition_timeout"}
            await asyncio.sleep(min(0.1, max(0, deadline - self.clock())))

    async def wait_condition(self, condition: dict, *, check):
        baseline = await self._wait_baseline(condition, check=check, transition=False)
        result = await self._wait_text_change(baseline, check=check)
        return {"state": "verified" if result["observed"] else "not_verified",
                "wait": result, "generation": self.generation, "business_result_verified": False}

    async def assert_condition(self, condition: dict, *, check):
        baseline = await self._wait_baseline(condition, check=check, transition=False)
        value = await self._condition_value(baseline["frame"], baseline["selector"], baseline["condition"], baseline["expected"])
        await check()
        if baseline["condition"]=="message_appended" and "container_identity" in baseline["expected"]["baseline"]:
            bound=self._message_binding(baseline["expected"]["baseline"],baseline["selector"],baseline["frame"])
            await self._check_message_container(bound)
        if not self._documents_current(baseline["documents"]):
            raise ControlError("page_changed_during_assert")
        return {"state": "verified" if value["matched"] else "not_verified", "matched": value["matched"],
                "condition": baseline["condition"], "generation": self.generation,
                **({"evidence": value["evidence"]} if "evidence" in value else {}), "business_result_verified": False}

    async def transition(self, arguments: dict, *, check):
        if (not {"page_id", "reference", "action", "condition"} <= arguments.keys()
                or not arguments.keys() <= {"page_id", "reference", "action", "condition", "key"}
                or type(arguments["reference"]) is not str or not 1 <= len(arguments["reference"]) <= 100
                or type(arguments["action"]) is not str
                or arguments["action"] not in {"click", "press"}
                or (arguments["action"] == "press" and (type(arguments.get("key")) is not str
                    or not 1 <= len(arguments["key"]) <= 80 or any(c in arguments["key"] for c in "\r\n\t\x00")))
                or (arguments["action"] == "click" and "key" in arguments)):
            raise ControlError("invalid_web_transition")
        before = await self.assert_condition(arguments["condition"], check=check)
        if before["matched"]:
            return {**before, "input_dispatched": False, "verification": "desired_already_true"}
        original_check=check
        if arguments["condition"].get("condition")=="message_appended" and "container_identity" in arguments["condition"].get("baseline",{}):
            async def check():
                await original_check()
                bound=self._message_binding(arguments["condition"]["baseline"],arguments["condition"]["selector"])
                await self._check_message_container(bound)
        if arguments["action"] == "click":
            action = await self.click(arguments["reference"], check=check, read_page_state=False)
        else:
            action = await self.press(arguments["reference"], arguments["key"], check=check, read_page_state=False)
        if action.get("verification") in {"dialog_pending", "chooser_pending"}:
            return {**action, "input_dispatched": True}
        after = await self.wait_condition(arguments["condition"], check=check)
        return {**after, "input_dispatched": True, "verification": "desired_observed" if after["state"] == "verified" else "desired_unverified"}

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
                    actual = {"value_sha256": dom_text_digest(value),
                              "value_length": len(value)}
                elif operation == "select_option":
                    values = actual.pop("selected")
                    if len(values) > 50 or any(len(value) > 256 for value in values):
                        raise ControlError("result_value_too_large")
                    actual = {"selected_sha256": hashlib.sha256(json.dumps(values, sort_keys=True,
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8",errors='backslashreplace')).hexdigest()}
            elif operation in {"wait_condition", "click", "press"}:
                if arguments.get("expected_generation") != generation:
                    raise ControlError("result_page_changed")
                baseline = await self._wait_baseline(arguments.get("condition"), check=check, transition=False)
                if baseline is None:
                    raise ControlError("invalid_result_probe")
                value = await self._condition_value(baseline["frame"], baseline["selector"],
                                                    baseline["condition"], baseline["expected"])
                actual = {"matched": value["matched"], "condition": baseline["condition"],
                    "text_sha256": dom_text_digest(value["text"])
                                   if value["text"] is not None else None}
            else:
                raise ControlError("invalid_result_probe")
            await check()
            if (operation in {"wait_condition", "click", "press"}
                    and baseline["condition"]=="message_appended"
                    and "container_identity" in baseline["expected"]["baseline"]):
                bound=self._message_binding(baseline["expected"]["baseline"],baseline["selector"],baseline["frame"])
                await self._check_message_container(bound)
            if generation != self.generation:
                raise ControlError("result_page_changed")
            return {"operation": operation, "generation": generation, **actual,
                "observed_at": time.monotonic(), "evidence_digest": hashlib.sha256(json.dumps(
                    {"operation": operation, "generation": generation, **actual}, sort_keys=True,
                    ensure_ascii=False, separators=(",", ":")).encode("utf-8",errors='backslashreplace')).hexdigest()}

    async def _result_reference(self, reference, operation):
        ref = self.refs.get(reference)
        if not ref or ref.expires <= self.clock() or not self._reference_current(ref):
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
        # Visibility alone does not mean a target can receive pointer input.
        # Trial has no modifiers: Playwright otherwise presses them even for
        # trial=True. Only mark business dispatch after actionability passes.
        trial_started = self.clock()
        try:
            await ref.handle.click(trial=True, timeout=1000, button=button)
        except PlaywrightTimeoutError:
            error = ControlError("element_not_actionable")
            try:
                await check()
                details = await asyncio.wait_for(ref.handle.evaluate("""e => {
                  const r=e.getBoundingClientRect(),s=e.ownerDocument.defaultView.getComputedStyle(e);
                  const top=e.ownerDocument.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
                  const hit=!!top && (top===e || e.contains(top));
                  return {connected:e.isConnected,visible:!!(r.width && r.height && s.visibility!=='hidden'),
                    enabled:!e.disabled,covered:!!top&&!hit,receives_pointer:hit&&s.pointerEvents!=='none',
                    target_tag:e.tagName,blocking_tag:top?.tagName||'none',
                    blocking_role:top?.getAttribute('role')||'none'};
                }"""), timeout=0.5)
                await check()
                error.web_diagnostics = safe_failure_facts({**details, "phase": "actionability",
                    "elapsed_ms": max(0, round((self.clock()-trial_started)*1000))})
            except ControlError:
                raise
            except Exception:
                error.web_diagnostics = {"phase": "actionability", "exception_type": "TimeoutError"}
            raise error from None
        ref = await self._fresh(reference)
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
                "wait": waited, "page_state": fresh, "generation": self.generation,
                "business_result_verified": False}

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
                "wait": waited, "page_state": fresh, "generation": self.generation,
                "business_result_verified": False}

    async def media(self, reference: str, command: str, *, check):
        if command not in {"media_state", "play_media", "pause_media"}:
            raise ControlError("invalid_media_command")
        await check()
        ref = await self._fresh(reference)
        if ref.descriptor["tag"] not in {"VIDEO", "AUDIO"}:
            raise ControlError("media_target_required")
        await check()
        if command != "media_state":
            mark_write(command)
        result = await ref.handle.evaluate("""async (e, command) => {
            let failure = null;
            if (command === 'play_media') {
                globalThis.__flowerPausedMedia?.allow.add(e);
                try { await e.play(); } catch (error) { failure = error.name; }
            } else if (command === 'pause_media') e.pause();
            return {paused:e.paused, ended:e.ended, current_time:e.currentTime,
                duration:Number.isFinite(e.duration)?e.duration:null,
                ready_state:e.readyState, muted:e.muted, playback_error:failure};
        }""", command)
        await check()
        await self._fresh(reference)
        reached = (command == "media_state" or
                   (not result["paused"] if command == "play_media" else result["paused"]))
        return {**result, "state": "verified" if reached else "not_verified",
                "verification": "media_state_at_check", "business_result_verified": False}

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

    async def upload(self, reference: str, *, name=None, mime_type=None, content=None,
                     files=None, check):
        payload = validate_files(files if files is not None else [
            {"name": name, "mime_type": mime_type, "content": content}])
        ref = await self._fresh(reference)
        if ref.descriptor["tag"] != "INPUT" or ref.descriptor["type"] != "file":
            raise ControlError("file_input_required")
        if len(payload) > 1 and not await ref.handle.evaluate("e => !!e.multiple"):
            raise ControlError("file_input_multiple_required")
        await check()
        mark_write("upload")
        await ref.handle.set_input_files(payload, timeout=5000)
        selected = await ref.handle.evaluate("""e => Array.from(e.files || [],
          f => ({name:f.name,size:f.size,type:f.type}))""")
        await check()
        exact = selection_matches(selected, payload)
        return {"state": "verified" if exact else "not_verified",
                "verification": "file_input_selection", "selected": selected,
                "business_result_verified": False}

    async def _editor(self, reference: str, request: dict, *, check):
        await check()
        ref = await self._fresh(reference)
        await check()
        ref = await self._fresh(reference)
        replacing = request["kind"] == "replace"
        zero_write_errors = {"editor_api_unavailable", "editor_target_ambiguous",
            "editor_model_missing", "editor_document_unidentified", "editor_model_changed", "editor_read_only",
            "invalid_editor_argument", "editor_patch_not_found", "editor_patch_ambiguous", "editor_patch_result_too_large"}

        async def evaluate(script):
            if replacing:
                # Do this before the browser/IPC await. A typed completed
                # refusal can still prove zero writes without publishing one.
                require_write_admission()
            try:
                result = await ref.handle.evaluate(script, request)
            except BaseException:
                if replacing:
                    record_write_attempt("editor_replace")
                raise
            # Same error may occur either before or after a write (CM model_changed).
            # Only a typed marker from the completed adapter plus a known preflight
            # refusal proves zero adapter writes. Missing evidence stays conservative.
            if replacing and not (isinstance(result, dict)
                    and result.get("flower_write_attempted") is False
                    and result.get("error") in zero_write_errors):
                record_write_attempt("editor_replace")
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
                             expected_version: int, *, check, old_text=_EDITOR_OLD_TEXT_UNSET):
        # expected_uri is the legacy worker field name. Callers pass the
        # document_identity from inspect, which may be an opaque model object.
        if (not isinstance(text, str) or len(text) > 1_000_000 or "\x00" in text
                or not isinstance(expected_uri, str) or not 1 <= len(expected_uri) <= 2048
                or type(expected_version) is not int or expected_version < 1):
            raise ControlError("invalid_editor_argument")
        request = {"kind": "replace", "text": text, "expected_uri": expected_uri,
                   "expected_version": expected_version}
        if old_text is not _EDITOR_OLD_TEXT_UNSET:
            if type(old_text) is not str or not 1 <= len(old_text) <= 64000 or '\x00' in old_text:
                raise ControlError('invalid_editor_argument')
            request['old_text'] = old_text
        result = await self._editor(reference, request, check=check)
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
        async def terminal_reference(*, after_input=False):
            ref = (await self._result_reference(reference, "terminal_input") if after_input
                   else await self._fresh(reference))
            target = await ref.handle.evaluate("""e => e.isConnected && !e.disabled && !e.readOnly &&
              e.tagName === 'TEXTAREA' && e.classList.contains('xterm-helper-textarea') && !!e.closest('.xterm')""")
            if not target:
                raise ControlError("terminal_target_unidentified")
            return ref
        ref = await terminal_reference()
        await check()
        ref = await terminal_reference()
        mark_write("terminal_focus")
        await ref.handle.focus()
        focused = await ref.handle.evaluate("e => e.ownerDocument.activeElement === e")
        if not focused:
            raise ControlError("terminal_focus_failed")
        await check()
        ref = await terminal_reference()
        focused = await ref.handle.evaluate("e => e.ownerDocument.activeElement === e")
        if not focused:
            raise ControlError("terminal_focus_changed_before_input")
        # CDP insertText sends one input event. It does not use the OS clipboard
        # or generate one key event per character.
        mark_write("type")
        await self.page.keyboard.insert_text(text)
        await check()
        ref = await terminal_reference(after_input=True)
        if submit:
            focused = await ref.handle.evaluate("e => e.ownerDocument.activeElement === e")
            if not focused:
                raise ControlError("terminal_focus_changed_after_input")
            mark_write("press")
            await ref.handle.press("Enter", timeout=3000)
        await check()
        await terminal_reference(after_input=True)
        return {"state": "not_verified", "verification": "terminal_application_result_required",
                "input_dispatched": True, "submit_dispatched": submit,
                "business_result_verified": False}
