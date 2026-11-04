import * as mcpClient from '@deepseek-ai/dsh-mcp-client';
import { chatAgent, createFlowerPlugin, validateConfig } from './plugin.mjs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { installHostBridge } from './host-bridge.mjs';
import { installDisplayMetadata } from './metadata.mjs';

export const name = 'flower-control-dsh';
export const inject = ['agents', 'skills', 'sessions', 'sessionPersistence'];
const applyConnections = createFlowerPlugin(mcpClient);

export async function apply(ctx, config) {
  config = validateConfig(config);
  // Register the integration independently of the broker's current availability.
  // The canonical MCP launchers and each operation still verify the real host,
  // installed helper and permissions; a status timeout grants no capability.
  // Register the same packaged Skill that Codex receives. README text is not
  // model context; DSH's own registry owns discovery, loading and disposal.
  const source = new URL('./skills/flower-control/SKILL.md', import.meta.url);
  const text = await readFile(source, 'utf8');
  const parts = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(text);
  const skillName = /^name:\s*(.+)$/m.exec(parts?.[1] ?? '')?.[1];
  const description = /^description:\s*(.+)$/m.exec(parts?.[1] ?? '')?.[1];
  if (skillName !== 'flower-control' || !description) throw new Error('flower_dsh_skill_invalid');
  ctx.skills.register({name: skillName, description, content: parts[2],
    source: fileURLToPath(source), path: fileURLToPath(source),
    resourceBase: {kind: 'directory', path: fileURLToPath(new URL('./skills/flower-control/', import.meta.url))}});
  installDisplayMetadata(ctx, chatAgent);
  installHostBridge(ctx, config);
  return applyConnections(ctx, config);
}
