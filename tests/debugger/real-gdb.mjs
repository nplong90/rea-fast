#!/usr/bin/env node
// End-to-end GDB MI provider integration: real gdb subprocess and real MCP pipe.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const args = process.argv.slice(2);
const index = args.indexOf('--rust-bin');
if (index < 0 || !args[index + 1]) throw new Error('--rust-bin PATH required');
const child = spawn(args[index + 1], ['mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
const pending = new Map();
let sequence = 0, stderr = '';
child.stderr.on('data', (bytes) => { stderr = (stderr + bytes).slice(-2048); });
createInterface({ input: child.stdout }).on('line', (line) => {
  let data;
  try { data = JSON.parse(line); } catch (e) {
    for (const entry of pending.values()) entry.reject(e);
    pending.clear();
    return;
  }
  const entry = pending.get(data.id);
  if (!entry) return;
  pending.delete(data.id);
  clearTimeout(entry.timeout);
  entry.resolve(data);
});
child.on('error', (error) => {
  for (const entry of pending.values()) entry.reject(error);
  pending.clear();
});
async function invoke(name, arguments_) {
  const id = ++sequence;
  const message = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error('GDB MCP tool timed out: ' + name + ' ' + stderr));
    }, 15000);
    pending.set(id, { resolve, reject, timeout });
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id, method: 'tools/call',
      params: { name, arguments: arguments_ },
    }) + '\n');
  });
  assert.equal(message.result?.isError, false, JSON.stringify(message));
  return JSON.parse(message.result.content[0].text);
}
let sessionId;
try {
  const started = await invoke('start_gdb_session', {});
  assert.equal(started.status, 'active');
  sessionId = started.session_id;
  assert.ok(sessionId.startsWith('gdb_'));
  const response = await invoke('gdb_console', {
    session_id: sessionId, command: '-gdb-version',
  });
  assert.equal(response.status, 'complete', JSON.stringify(response));
  assert.equal(response.response_verified, true);
  assert.ok(response.records.some((record) => record.includes('^done')));
  const status = await invoke('gdb_session_status', { session_id: sessionId });
  assert.equal(status.status, 'active');
  const closed = await invoke('close_gdb_session', { session_id: sessionId });
  assert.equal(closed.status, 'closed');
  sessionId = null;
  const afterClose = await invoke('gdb_session_status', { session_id: closed.session_id });
  assert.equal(afterClose.status, 'closed');
  process.stdout.write(JSON.stringify({
    status: 'pass', provider: 'real_gdb_mi3',
    verified_mcp_routes: ['start_gdb_session', 'gdb_console', 'gdb_session_status', 'close_gdb_session'],
    command_completion_protocol_verified: true,
  }) + '\n');
} catch (error) {
  process.stderr.write(String(error.stack ?? error) + '\n');
  process.exitCode = 1;
} finally {
  if (sessionId) {
    try { await invoke('close_gdb_session', { session_id: sessionId }); } catch { /* cleanup */ }
  }
  child.kill();
}
