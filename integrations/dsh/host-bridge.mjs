import { execFile, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {openSync, writeSync, ftruncateSync, fsyncSync, closeSync, unlinkSync} from 'node:fs';
import { chatAgent, validateConfig } from './plugin.mjs';

const PRIVILEGED = /^mcp__flower[-_]app__flower_app_(?:work_authority|launch_admin)$/;
const user = message => message?.source?.kind === 'user' && typeof message.source.rpcId === 'string';
const key = value => Number.isSafeInteger(value?.turn) && value.turn >= 0 && Number.isSafeInteger(value?.step) && value.step >= 0
  ? `${value.turn}:${value.step}` : null;
function signature(message) {
  if (typeof message?.id !== 'string' || !message.id.length || message.id.length > 512 || !user(message)) return null;
  try { return createHash('sha256').update(JSON.stringify([message.id, message.role, message.source.rpcId, message.content])).digest('hex'); }
  catch { return null; }
}
function retiredUacAccept(exec) {
  if (!/^mcp__flower[-_]computer__flower_computer_uac$/.test(exec.name)) return false;
  return (exec.arguments ?? {}).command === 'accept';
}
function sourceRequired(exec) {
  if (!PRIVILEGED.test(exec.name)) return false;
  const args = exec.arguments ?? {};
  if (exec.name.endsWith('__flower_app_work_authority'))
    return !['status', 'source_status', 'revoke', 'close'].includes(args.command ?? 'status');
  if (exec.name.endsWith('__flower_app_launch_admin'))
    return !['list', 'status', 'cancel'].includes(args.command ?? 'list');
  return false;
}

export function installHostBridge(ctx, input) {
  const config = validateConfig(input);
  const records = new Map();
  const models = new Map();
  const tokens = new Map();
  let closing = false;

  function locate(agent) {
    const root = chatAgent(ctx, agent);
    const location = ctx.sessionPersistence.locate(root.session.header);
    if (location?.kind !== 'jsonl' || typeof location.path !== 'string') throw new Error('flower_dsh_persistence_unsupported');
    let record = records.get(root.session);
    if (!record) {
      record = {root, path: location.path, sequence: -1, revision: 0, invalidated: -2,
        instance: randomBytes(16).toString('hex'), opened: false, closed: false,
        active: false, broken: false, poisoned: false, submission: 0, pendingUsers: new Map(), latestUser: null,
        phaseSerial: 0, phasePending: false, phaseEver: false, phaseWarning: false, phaseLastRootEvent: -1};
      records.set(root.session, record);
    }
    if (record.root !== root || record.path !== location.path) throw new Error('flower_dsh_session_changed');
    return record;
  }

  function model(agent) {
    if (closing) throw new Error('flower_dsh_unloading');
    if (!agent || ctx.agents.get(agent.id) !== agent) throw new Error('flower_dsh_agent_identity_unavailable');
    const record = locate(agent);
    let state = models.get(agent.session);
    if (!state) {
      // Only a live, currently executing parent may seed an owned child's
      // scope. A historical header or a resumed/forked agent grants nothing.
      const owner = agent === record.root ? null : ctx.agents.get(agent.session.header.parentSession);
      const parent = owner && ctx.agents.isOwnedBy(agent.id, owner) ? models.get(owner.session) : null;
      const parents = [...tokens.values()].filter(value => value.agent === owner);
      const inherited = parent && !parent.foreignUser && covered(record, parent.readUsers) && parents.length &&
        parents.every(value => value.revision === record.revision && parent.calls.get(value.call.callId) === value.call)
        ? parent.readUsers : [];
      state = {agent, record, readUsers: new Map(inherited), steps: new Map(), calls: new Map(), active: null,
        inboxes: new Map([['next-turn', []], ['next-step', []]]), claiming: [], claimed: [], foreignUser: false};
      models.set(agent.session, state);
    }
    if (state.agent !== agent || state.record !== record) throw new Error('flower_dsh_agent_identity_unavailable');
    return state;
  }

  function requirements(record) {
    const required = new Map([...record.pendingUsers].map(([token, entry]) => [token, entry.digest]));
    if (record.latestUser) required.set(record.latestUser.token, record.latestUser.digest);
    return required;
  }
  function covered(record, users) {
    // A queued/claimed submission is not read, even when its id/content equals
    // an earlier submission. Only actual admission consumes that occurrence.
    return record.latestUser !== null && record.pendingUsers.size === 0 &&
      users.get(record.latestUser.token) === record.latestUser.digest;
  }
  function submission(state, message) {
    const digest = signature(message);
    if (!digest || state.record.pendingUsers.size >= 4096) {
      state.record.poisoned = true; invalidate(state.record); return null;
    }
    if (state.agent !== state.record.root) {
      // Native admission reads the root transcript. A child's direct human
      // message cannot be represented by that source, nor renew its scope.
      state.foreignUser = true; invalidate(state.record); return null;
    }
    const entry = {id: message.id, digest, token: ++state.record.submission};
    state.record.pendingUsers.set(entry.token, entry);
    return entry;
  }
  function requireSource(state, call) {
    live(state.record, state.agent);
    if (state.foreignUser || state.record.poisoned || !call || state.calls.get(call.callId) !== call || call.revision !== state.record.revision
        || call.revision < 0 || !covered(state.record, call.users))
      throw new Error('flower_dsh_model_source_changed');
  }
  function retire(state) {
    state.steps.clear(); state.calls.clear(); state.active = null;
    for (const [token, value] of tokens) if (value.agent === state.agent) tokens.delete(token);
    if (models.get(state.agent.session) === state) models.delete(state.agent.session);
  }

  function packet(record, command) {
    return JSON.stringify({Phase: 'dsh_host_event', Command: command, SessionId: record.root.id,
      TranscriptPath: record.path, Sequence: record.sequence, InstanceId: record.instance, Revision: record.revision});
  }

  function barrier(record) {
    // Reduction-only local witness, written before calling the helper. Native
    // final creation reads it even if this notification's IPC times out.
    if (record.barrierFd === undefined) {
      record.barrierPath = record.path + '.flower-' + record.instance + '.source';
      record.barrierFd = openSync(record.barrierPath, 'wx');
    }
    const bytes = Buffer.from(JSON.stringify({InstanceId:record.instance, Revision:record.revision, Closed:record.closed})+'\n');
    ftruncateSync(record.barrierFd, 0);
    let position=0;
    while(position<bytes.length) {
      const written=writeSync(record.barrierFd, bytes, position, bytes.length-position, position);
      if(written<=0) throw new Error('flower_dsh_source_barrier_unavailable');
      position += written;
    }
    fsyncSync(record.barrierFd);
  }

  function syncRequest(record, command) {
    return parse(execFileSync(config.helperCommand, ['--dsh-host-event'], {
      input: packet(record, command), encoding: 'utf8', windowsHide: true,
      timeout: 5000, maxBuffer: 65536, stdio: ['pipe', 'pipe', 'pipe']}));
  }

  function publishPhase(record, kind) {
    // DSH notification listeners are synchronous. Publish before returning to
    // the host so an old terminal cannot borrow a subsequent tool's watermark.
    // The original system monotonic time also rejects a late helper child.
    const event = {session_id: record.root.id, instance_id: record.instance,
      event_seq: ++record.phaseSerial, kind, observed_ns: process.hrtime.bigint().toString()};
    try {
      const reply = JSON.parse(execFileSync(config.helperCommand, ['--dsh-phase-event'], {
        input: JSON.stringify(event), encoding: 'utf8', windowsHide: true,
        timeout: 4000, maxBuffer: 4096, stdio: ['pipe', 'pipe', 'pipe']}));
      if (reply?.phase !== 'dsh_phase' || !['published', 'ignored'].includes(reply.state)) throw new Error('phase_unavailable');
      record.phasePending = false;
      if (kind === 'turn_end') record.phaseEver = false;
      record.phaseWarning = false;
    } catch {
      if (!record.phaseWarning) ctx.logger?.warn('Flower Computer lifecycle cleanup is unavailable; explicit finish remains available.');
      record.phaseWarning = true; // No ordinary host tool is rejected here.
    }
  }

  function live(record, agent) {
    if (closing || record.closed || records.get(record.root.session) !== record
        || ctx.agents.get(agent.id) !== agent || ctx.agents.get(record.root.id) !== record.root
        || chatAgent(ctx, agent) !== record.root) throw new Error('flower_dsh_unloading');
  }

  function parse(stdout) {
    const reply = JSON.parse(stdout);
    if (reply?.Phase !== 'dsh_host_event' || !['verified', 'invalidated', 'ignored'].includes(reply.State))
      throw new Error('flower_dsh_source_unavailable');
    return reply;
  }

  function request(record, signal) {
    return new Promise((resolve, reject) => {
      const child = execFile(config.helperCommand, ['--dsh-host-event'], {
        encoding: 'utf8', windowsHide: true, timeout: 20000, maxBuffer: 65536, signal},
      (error, stdout) => {
        if (error) { reject(new Error('flower_dsh_source_unavailable')); return; }
        try { resolve(parse(stdout)); } catch (failure) { reject(failure); }
      });
      child.stdin.on('error', () => reject(new Error('flower_dsh_source_unavailable')));
      child.stdin.end(packet(record, 'preflight'));
    });
  }

  function invalidate(record, command = 'invalidate') {
    ++record.revision;
    if (command === 'close') record.closed = true;
    if (!record.opened) {
      if (command === 'close' && record.barrierFd !== undefined) {
        let closedWitness=false;
        try { barrier(record); closedWitness=true; }
        catch { record.broken=true; }
        finally {
          try {closeSync(record.barrierFd);}catch{}
          record.barrierFd=undefined;
          if(closedWitness) {try {unlinkSync(record.barrierPath);}catch{}}
        }
      }
      return;
    }
    let acknowledged=false;
    try { barrier(record); }
    catch { record.broken=true; }
    try {
      // DSH notification publishers do not await promises. A synchronous,
      // reduction-only acknowledgement prevents an async listener from lending
      // the old source to native final creation after the user event returns.
      const reply = syncRequest(record, command);
      acknowledged=true;
      if (reply.State === 'ignored') record.active = false;
      record.invalidated = record.sequence;
      record.broken = false;
    } catch {
      record.broken = true;
      ctx.logger?.warn('Flower current-message invalidation is unavailable; new privileged calls remain blocked.');
    } finally {
      if (command === 'close' && record.barrierFd !== undefined) {
        try { closeSync(record.barrierFd); } catch {}
        record.barrierFd=undefined;
        // A failed acknowledgement retains the closed witness for High to
        // reject. Never delete its object while native ownership is unknown.
        if (acknowledged) { try {unlinkSync(record.barrierPath);}catch{} }
      }
    }
  }

  async function preflight(agent, signal, checkSource = () => {}) {
    if (closing) throw new Error('flower_dsh_unloading');
    const record = locate(agent);
    for (let attempt = 0; attempt < 2; ++attempt) {
      live(record, agent);
      checkSource();
      if (!record.opened) {
        barrier(record); syncRequest(record, 'open'); record.opened = true;
      }
      signal?.throwIfAborted();
      const revision = record.revision;
      const durable = await ctx.sessions.flush(record.root.session);
      signal?.throwIfAborted();
      live(record, agent);
      checkSource();
      if (durable !== true || chatAgent(ctx, agent) !== record.root) throw new Error('flower_dsh_source_not_flushed');
      if (record.revision !== revision) continue;
      barrier(record);
      const reply = await request(record, signal);
      signal?.throwIfAborted();
      live(record, agent);
      checkSource();
      if (record.revision !== revision) continue;
      if (reply.State !== 'verified' && reply.State !== 'ignored') throw new Error('flower_dsh_source_unavailable');
      record.active = reply.State === 'verified'; record.broken = false;
      return;
    }
    throw new Error('flower_dsh_source_changed');
  }

  ctx.on('agent/created', ({agent}) => { model(agent); });
  ctx.on('session/event', (session, event) => {
    const state = models.get(session);
    const record = state?.record ?? records.get(session);
    if (!record || state && ctx.agents.get(state.agent.id) !== state.agent) return;
    if (!Number.isSafeInteger(event.seq) || event.seq < 0) { record.poisoned = true; invalidate(record); return; }
    const currentRootPhase = session === record.root.session && event.seq > record.phaseLastRootEvent;
    if (currentRootPhase) record.phaseLastRootEvent = event.seq;
    // Child sessions have their own sequence space. Native admission reads the
    // root transcript; never replace its cursor with a child's event number.
    if (session === record.root.session) record.sequence = event.seq;
    if (event.type === 'agent/inbox/spliced') {
      if (!state) return;
      const {target, start, removedCount = 0, inserted, outcome} = event.data ?? {};
      const inbox = state.inboxes.get(target);
      if (!inbox || !Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(removedCount) || removedCount < 0 ||
          !Array.isArray(inserted) || start + removedCount > 4096 || inserted.length + inbox.length > 4096) {
        record.poisoned = true; invalidate(record); return;
      }
      // A hot-loaded observer may not have seen the old queue prefix. Keep
      // holes; later claimed events establish identities without guessing.
      while (inbox.length < start + removedCount) inbox.push(null);
      const entries = inserted.map(message => user(message) ? submission(state, message) : null);
      const removed = inbox.splice(start, removedCount, ...entries).filter(Boolean);
      if (outcome === 'canceled') for (const entry of removed) record.pendingUsers.delete(entry.token);
      else state.claiming.push(...removed);
      if (inserted.some(user) || outcome === 'canceled' && removed.length) invalidate(record);
    } else if (event.type === 'user/message' && user(event.data)) {
      const message = event.data, digest = signature(message);
      if (!digest) { record.poisoned = true; invalidate(record); return; }
      const step = state?.steps.get(state.active);
      const expected = step?.expected.get(message.id);
      const entry = expected?.digest === digest ? expected.entry : submission(state, message);
      if (!entry) return;
      if (expected?.entry !== entry) invalidate(record);
      // A genuinely admitted resubmission also covers identical, previously
      // claimed-but-filtered occurrences. Queued submissions are never swept.
      state.claimed = state.claimed.filter(old => {
        if (old.id !== entry.id || old.digest !== entry.digest) return true;
        record.pendingUsers.delete(old.token); return false;
      });
      record.pendingUsers.delete(entry.token); record.latestUser = entry;
      if (expected?.entry === entry) step.users.set(entry.token, digest);
    } else if (event.type === 'step/start' && state) {
      state.active = key(event.data);
    } else if (event.type === 'tool/call' && state) {
      const data = event.data, step = state.steps.get(key(data));
      if (!step || !step.started || typeof data.callId !== 'string' || typeof data.name !== 'string') return;
      if (state.calls.has(data.callId) || state.calls.size >= 4096) { retire(state); return; }
      state.calls.set(data.callId, {callId: data.callId, name: data.name, step: key(data),
        revision: step.revision, users: new Map(step.users), dispatched: false, children: new Set()});
    } else if ((event.type === 'step/end' || event.type === 'turn/end') && state) {
      for (const [id, call] of state.calls) if (event.type === 'turn/end' || call.step === key(event.data)) state.calls.delete(id);
      if (event.type === 'turn/end') { state.steps.clear(); state.active = null; }
      else { state.steps.delete(key(event.data)); if (state.active === key(event.data)) state.active = null; }
    }
    // An owned child's turn/end is not the root chat's terminal event.
    if (event.type === 'turn/end' && currentRootPhase && record.phaseEver)
      publishPhase(record, 'turn_end');
  });
  ctx.on('agent/inbox/claimed', ({agent, message}) => {
    if (!user(message)) return;
    const state = model(agent), digest = signature(message);
    const index = state.claiming.findIndex(entry => entry.id === message.id && entry.digest === digest);
    const entry = index >= 0 ? state.claiming.splice(index, 1)[0] : submission(state, message);
    if (entry) state.claimed.push(entry);
  });
  ctx.on('agent/inbox/discarded', ({agent, message}) => {
    // Splice already retired the exact old occurrence. Deleting by message id
    // here would accidentally delete a same-id replacement inserted before it.
    if (user(message)) invalidate(locate(agent));
  });
  ctx.on('agent/pre-step', async (input, next) => {
    const state = model(input.agent), stepKey = key(input);
    const history = new Map(state.readUsers);
    // Recover only observed source identities from the same session's model
    // history, before any await. Never read a transcript or retain its text.
    if (input.agent === state.record.root && !covered(state.record, history) &&
        state.record.pendingUsers.size === 0 && typeof input.agent.session.deriveMessages === 'function') {
      const latest = state.record.latestUser;
      if (latest) for (const message of input.agent.session.deriveMessages())
        if (message.id === latest.id && signature(message) === latest.digest) history.set(latest.token, latest.digest);
    }
    const decision = await next();
    if (decision?.kind !== 'enter' || !stepKey) return decision;
    live(state.record, input.agent);
    if (state.steps.has(stepKey) || state.steps.size >= 64) throw new Error('flower_dsh_model_step_conflict');
    const expected = new Map();
    for (const message of decision.messages ?? []) if (user(message)) {
      const digest = signature(message);
      if (!digest || expected.has(message.id)) throw new Error('flower_dsh_model_source_unavailable');
      const index = state.claimed.findLastIndex(entry => entry.id === message.id && entry.digest === digest);
      const entry = index >= 0 ? state.claimed.splice(index, 1)[0] : submission(state, message);
      if (entry) expected.set(message.id, {digest, entry});
    }
    state.steps.set(stepKey, {expected, users: history, started: false, revision: -1});
    return decision;
  });
  ctx.on('agent/assistant-stream', ({agent, frame}) => {
    if (frame?.type !== 'start') return;
    const state = models.get(agent.session), step = state?.steps.get(key(frame));
    if (!state || state.agent !== agent || ctx.agents.get(agent.id) !== agent || !step || state.active !== key(frame)) return;
    // Expected messages must actually have been admitted to this step before
    // the frozen model request starts. A queued next-turn message is not read.
    if ([...step.expected.values()].every(({digest, entry}) => step.users.get(entry.token) === digest) && covered(state.record, step.users)) {
      step.revision = state.record.revision;
      state.readUsers = new Map([...requirements(state.record)].map(([id]) => [id, step.users.get(id)]));
    } else step.revision = -1;
    step.started = true;
  });
  ctx.on('tools/execute', async (exec, next) => {
    const state = exec.agent ? model(exec.agent) : null;
    const nested = exec.parent !== undefined;
    const parent = nested ? tokens.get(exec.parent) : null;
    const call = state?.calls.get(exec.rootCallId);
    const linked = call && (nested ? parent?.call === call && parent.agent === exec.agent
      : exec.callId === exec.rootCallId && call.name === exec.name);
    if (linked) {
      if (nested ? call.children.has(exec.callId) || call.children.size >= 4096 : call.dispatched)
        throw new Error('flower_dsh_model_call_replayed');
      if (nested) call.children.add(exec.callId); else call.dispatched = true;
    }
    if (retiredUacAccept(exec)) throw new Error('flower_dsh_model_call_unavailable');
    if (sourceRequired(exec)) {
      if (!state) throw new Error('flower_dsh_agent_identity_unavailable');
      if (!linked) throw new Error('flower_dsh_model_call_unavailable');
      if (exec.token === undefined) throw new Error('flower_dsh_model_call_unavailable');
      const check = () => requireSource(state, call);
      check();
      await preflight(exec.agent, exec.signal, check);
      check();
      // The official registry permits replacing mutableExec.arguments; its
      // contents are frozen. Carry the original model epoch across MCP waits,
      // cancellation and late Python workers. This field grants no authority.
      exec.arguments = {...exec.arguments, flower_dsh_source: {
        instance_id: state.record.instance, revision: call.revision}};
    }
    if (linked && exec.token !== undefined) {
      if (tokens.has(exec.token)) throw new Error('flower_dsh_model_call_conflict');
      tokens.set(exec.token, {agent: exec.agent, call, revision: call.revision});
    }
    if (state) {
      if (/^mcp__flower[-_](?:app|computer)__flower_(?:app|computer)_(?:observe|input|activate|chain|plan|set_value|invoke|set_toggle|select_item|desktop_observe|desktop_input)$/.test(exec.name)) {
        state.record.phasePending = true; state.record.phaseEver = true;
      } else if (!/^mcp__flower[-_](?:web|app|computer)__/.test(exec.name) && state.record.phasePending) {
        publishPhase(state.record, 'idle');
      }
    }
    try { return await next(); }
    finally { if (linked) tokens.delete(exec.token); }
  });
  ctx.on('agent/disposed', ({agent}) => {
    const state = models.get(agent.session);
    if (state?.agent === agent) retire(state);
    const record = records.get(agent.session);
    if (record?.root === agent) { invalidate(record, 'close'); records.delete(agent.session); }
  });
  for (const agent of ctx.agents.list()) model(agent);
  ctx.effect(() => () => {
    closing = true;
    for (const record of records.values()) invalidate(record, 'close');
    records.clear(); models.clear(); tokens.clear();
  }, 'flower-dsh.message-source');
}
