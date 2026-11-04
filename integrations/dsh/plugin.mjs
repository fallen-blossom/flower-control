// The official MCP plugin owns transport, cancellation, images and teardown.
import {displayFileFor} from './metadata.mjs';
export const CHANNELS = Object.freeze(['flower-web', 'flower-app', 'flower-computer']);

export function chatAgent(ctx, agent) {
  const seen = new Set();
  let current = agent;
  while (current?.session?.header?.origin === 'subagent') {
    if (seen.has(current)) throw new Error('flower_dsh_agent_lineage_invalid');
    seen.add(current);
    const parentId = current.session.header.parentSession;
    const parent = typeof parentId === 'string' ? ctx.agents.get(parentId) : undefined;
    // A resumed historical child without that live owner is an independent
    // chat, just like a fork. Durable lineage alone never inherits grants.
    if (!parent || !ctx.agents.isOwnedBy(current.id, parent)) break;
    current = parent;
  }
  if (!current || current.id !== current.session?.id) throw new Error('flower_dsh_agent_identity_unavailable');
  return current;
}

export function validateConfig(config) {
  if (!config || typeof config.helperCommand !== 'string' ||
      !/^[A-Za-z]:[\\/].+[\\/]Flower\.HighHelper\.exe$/i.test(config.helperCommand) ||
      /[\r\n\0]/.test(config.helperCommand)) throw new Error('flower_dsh_fixed_helper_required');
  const timeout = config.toolCallTimeoutMs ?? 180000;
  if (!Number.isInteger(timeout) || timeout < 1000 || timeout > 300000)
    throw new Error('flower_dsh_timeout_invalid');
  return { helperCommand: config.helperCommand, toolCallTimeoutMs: timeout };
}

export function createFlowerPlugin(mcpClient, scheduler = {setTimeout, clearTimeout}) {
  return async function apply(ctx, input) {
    const config = validateConfig(input);
    const mounted = new Map();
    let closing = false;
    let shutdownPromise;

    function report(stage, channel, error) {
      // The MCP fiber retains its original startup error. Keep adapter diagnostics
      // local and metadata-only: no chat content, paths or provider error text.
      ctx.logger?.warn(`flower_dsh_${stage} channel=${channel ?? 'chat'} error=${error?.name ?? 'Error'}`);
    }
    function summary(record) {
      const channels = Object.fromEntries([...record.channels].map(([name, entry]) => [name, entry.state]));
      const states = Object.values(channels);
      return { state: record.closed ? states.includes('cleanup_failed') ? 'cleanup_failed' : 'closed'
        : states.every(state => state === 'ready') ? 'ready'
        : states.some(state => state === 'ready') ? 'partial' : 'failed', channels };
    }
    function disposeChannel(entry) {
      if (entry.disposal) return entry.disposal;
      // ctx.plugin() may synchronously trigger host disposal before it returns
      // the new fiber. Let that exact creation return before taking the handle.
      entry.disposal = Promise.resolve().then(async () => {
        if (!entry.fiber) { entry.disposed = true; return; }
        const errors = [];
        try { await entry.fiber.dispose(); } catch (error) { errors.push(error); }
        // Repeated Cordis dispose() can return early; drain its inertia too.
        try { await entry.fiber; } catch (error) {
          if (error !== entry.startupFailure) errors.push(error);
        }
        if (errors.length) {
          entry.state = 'cleanup_failed';
          throw new AggregateError(errors, 'flower_dsh_channel_disposal_failed');
        }
        entry.disposed = true;
      });
      // A parent Cordis scope may start disposal before this adapter awaits it.
      void entry.disposal.catch(() => {});
      return entry.disposal;
    }
    function dispose(record) {
      if (record.disposal) return record.disposal;
      record.closed = true;
      record.removeAbort?.();
      for (const entry of record.channels.values()) {
        if (entry.retryTimer !== null) scheduler.clearTimeout(entry.retryTimer);
        entry.retryTimer = null;
      }
      record.disposal = (async () => {
        const results = await Promise.allSettled([...record.channels.values()].map(async entry => {
          await disposeChannel(entry);
          await entry.inflight;
        }));
        await record.ready;
        const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (errors.length) throw new AggregateError(errors, 'flower_dsh_chat_disposal_failed');
      })();
      void record.disposal.catch(() => {});
      return record.disposal;
    }
    async function unmount(agent) {
      const record = mounted.get(agent);
      if (!record) return;
      await dispose(record);
      // A failed cleanup stays registered and cannot overlap a new connection.
      if (mounted.get(agent) === record) mounted.delete(agent);
    }
    function scheduleRetry(agent, record, channel, entry) {
      if (closing || record.closed || !entry.disposed || entry.state === 'cleanup_failed') return;
      if (entry.retries >= 10) {
        report('channel_startup_exhausted', channel, entry.startupFailure);
        return;
      }
      const delay = Math.min(500 * 2 ** entry.retries, 30000);
      entry.state = 'retry_wait';
      entry.retryTimer = scheduler.setTimeout(() => {
        entry.retryTimer = null;
        if (closing || record.closed) return;
        entry.retries++;
        entry.fiber = null;
        entry.disposal = null;
        entry.disposed = false;
        entry.startupFailure = null;
        entry.inflight = startChannel(agent, record, channel, entry);
        void entry.inflight.catch(error => report('channel_retry_failed', channel, error));
      }, delay);
      entry.retryTimer?.unref?.();
    }
    async function startChannel(agent, record, channel, entry) {
      if (closing || record.closed) { entry.state = 'closed'; return; }
      entry.state = 'connecting';
      try {
        const owner = chatAgent(ctx, agent);
        entry.fiber = agent.ctx.plugin(mcpClient, {
          serverName: channel,
          transport: 'stdio',
          command: config.helperCommand,
          args: ['--flower-connection-client', channel],
          env: { FLOWER_DSH_CHAT_ID: owner.id,
            ...(displayFileFor(agent) ? {FLOWER_DSH_DISPLAY:displayFileFor(agent)} : {}),
            ...(typeof owner.session.header?.cwd === 'string'
              ? {FLOWER_DSH_WORKSPACE: owner.session.header.cwd} : {}) },
          toolCallTimeoutMs: config.toolCallTimeoutMs,
          failOnStartupError: true,
          reconnect: { enabled: true, initialDelayMs: 500, maxDelayMs: 30000, maxAttempts: 10 },
        });
        try { await entry.fiber; } catch (error) { entry.startupFailure = error; throw error; }
        entry.state = record.closed ? 'closed' : 'ready';
      } catch (error) {
        entry.state = 'failed';
        report('channel_startup_failed', channel, error);
        try { await disposeChannel(entry); }
        catch (cleanupError) {
          entry.state = 'cleanup_failed';
          report('channel_cleanup_failed', channel, cleanupError);
        }
        scheduleRetry(agent, record, channel, entry);
      }
    }
    async function mount(agent, signal) {
      if (closing) throw new Error('flower_dsh_unloading');
      signal?.throwIfAborted();
      if (!agent || typeof agent.id !== 'string' || agent.id !== agent.session?.id ||
          !agent.id.length || agent.id.length > 256 || agent.id.trim() !== agent.id ||
          /[\x00-\x1f\x7f]/.test(agent.id) || typeof agent.ctx?.plugin !== 'function')
        throw new Error('flower_dsh_agent_identity_unavailable');
      let record = mounted.get(agent);
      if (record?.closed) return summary(record);
      if (record?.connecting) return record.ready;
      if (!record) {
        record = { channels: new Map(), closed: false, connecting: false, ready: Promise.resolve(), disposal: null };
        mounted.set(agent, record);
      }
      const pending = CHANNELS.filter(channel => !record.channels.has(channel) ||
        record.channels.get(channel).state === 'failed' && record.channels.get(channel).disposed);
      if (!pending.length) return summary(record);
      record.connecting = true;
      for (const channel of pending) record.channels.set(channel, { state: 'pending', fiber: null,
        startupFailure: null, disposal: null, disposed: false, retries: 0, retryTimer: null, inflight: null });
      // Defer the run until ready is assigned, including synchronous plugin errors.
      record.ready = Promise.resolve().then(async () => {
        try {
          await Promise.all(pending.map(channel => {
            const entry = record.channels.get(channel);
            entry.inflight = startChannel(agent, record, channel, entry);
            return entry.inflight;
          }));
          return summary(record);
        } finally { record.connecting = false; }
      });
      const cancelled = () => { void unmount(agent).catch(error => report('chat_cleanup_failed', null, error)); };
      record.removeAbort?.();
      signal?.addEventListener('abort', cancelled, { once: true });
      record.removeAbort = () => signal?.removeEventListener('abort', cancelled);
      // Abort may have happened between the first check and listener registration.
      if (signal?.aborted) cancelled();
      return await record.ready;
    }
    async function mountIsolated(agent, signal) {
      try { return await mount(agent, signal); }
      catch (error) { report('chat_startup_failed', null, error); return {state:'failed'}; }
    }
    ctx.on('agent/created', ({ agent, signal }) => mountIsolated(agent, signal));
    ctx.on('agent/disposed', ({ agent }) => unmount(agent).catch(error => {
      report('chat_cleanup_failed', null, error);
      return {state:'cleanup_failed'};
    }));
    function shutdown() {
      if (shutdownPromise) return shutdownPromise;
      closing = true;
      shutdownPromise = (async () => {
        const results = await Promise.allSettled([...mounted.keys()].map(unmount));
        const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (errors.length) throw new AggregateError(errors, 'flower_dsh_shutdown_incomplete');
      })();
      void shutdownPromise.catch(() => {});
      return shutdownPromise;
    }
    // Cordis has effect disposers, not a public "dispose" lifecycle event.
    // The early signal also aborts MCP startup while this apply() is awaiting it.
    ctx.on('internal/plugin', fiber => {
      if (fiber === ctx.fiber && fiber.uid === null) return shutdown();
    }, { global: true });
    ctx.effect(() => shutdown, 'flower-dsh.connections');
    // Every live chat and channel gets a startup attempt even if a peer fails.
    // Registration success is distinct from each channel's ready/failed state.
    await Promise.all(ctx.agents.list().map(agent => mountIsolated(agent)));
    // Cordis interprets a non-null apply result as a disposable effect.
    // Channel summaries belong to lifecycle diagnostics, not the apply return.
  };
}
