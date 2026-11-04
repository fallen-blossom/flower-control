import {mkdtempSync,writeFileSync,unlinkSync,rmdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const files = new WeakMap();
export const displayFileFor = agent => files.get(agent);
const text = value => typeof value === 'string' && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value) ? value : null;

// Display-only metadata from actual Session APIs/events. Never read another
// host's model configuration and never use a title/model to identify a task.
export function installDisplayMetadata(ctx, rootFor) {
  const records = new Map(), titles = new WeakMap();
  function update(record) {
    const root = rootFor(ctx,record.agent);
    const config = record.agent.session.requestHeader?.()?.config;
    const data={session_id:root.id, model:text(config?.model), provider:text(config?.provider),
      title:titles.get(root.session)??null, source:'dsh-session-request-header'};
    // A concurrent partial read yields unknown metadata, never an authority.
    try {writeFileSync(join(record.directory,'display.json'),JSON.stringify(data)+'\n');}
    catch {ctx.logger?.warn('Flower display metadata is unavailable.');}
  }
  function mount(agent) {
    if(records.has(agent))return;
    const directory=mkdtempSync(join(tmpdir(),'flower-dsh-display-'));
    const record={agent,directory};records.set(agent,record);
    files.set(agent,join(directory,'display.json'));update(record);
  }
  function unmount(agent) {
    const record=records.get(agent);if(!record)return;
    files.delete(agent);records.delete(agent);
    try {unlinkSync(join(record.directory,'display.json'));rmdirSync(record.directory);}catch{}
  }
  ctx.on('agent/created',({agent})=>mount(agent));
  ctx.on('agent/disposed',({agent})=>unmount(agent));
  ctx.on('session/event',(session,event)=>{
    if(event.type==='session/title')titles.set(session,text(event.data?.title));
    if(event.type==='session/title'||event.type==='request/header')
      for(const record of records.values())update(record);
  });
  for(const agent of ctx.agents.list())mount(agent);
  ctx.effect(()=>()=>{for(const agent of [...records.keys()])unmount(agent);},'flower-dsh.display');
}
