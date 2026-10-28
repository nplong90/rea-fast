#!/usr/bin/env node
// Fail-closed smoke for provider-dependent MCP routes when external CLIs are
// absent from PATH. This does not claim live-device/provider functionality.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const opt = (flag) => { const i = argv.indexOf(flag); return i < 0 ? null : argv[i + 1]; };
if (!opt('--rust-bin')) throw new Error('Usage: provider-offline.mjs --rust-bin path [--output path]');
const manifest = JSON.parse(readFileSync(fileURLToPath(new URL('route-contracts.json', import.meta.url))));
const routes = manifest.tools.filter((x) => x.route === 'external-provider');
assert.equal(routes.length, 53);
const child = spawn(resolve(opt('--rust-bin')), ['mcp'], {
  stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  env: { ...process.env, PATH: '', REA_MCP_PROFILE: 'full' },
});
let id = 0, stderr = '';
const pending = new Map();
child.stderr.on('data', (buf) => { stderr = (stderr + buf.toString()).slice(-2048); });
child.on('error', (error) => {
  for (const request of pending.values()) request.reject(error);
  pending.clear();
});
child.on('exit', (code) => {
  for (const request of pending.values()) request.reject(new Error(`MCP exited ${code}: ${stderr}`));
  pending.clear();
});
createInterface({ input: child.stdout }).on('line', (line) => {
  let response;
  try { response = JSON.parse(line); } catch (error) {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
    return;
  }
  const request = pending.get(response.id);
  if (request) {
    pending.delete(response.id);
    clearTimeout(request.timer);
    request.resolve(response);
  }
});
const rpc = (method, params) => new Promise((resolveResponse, reject) => {
  const current = ++id;
  const timer = setTimeout(() => {
    pending.delete(current);
    reject(new Error(`Timed out: ${method} id=${current}`));
  }, 10000);
  pending.set(current, { resolve: resolveResponse, reject, timer });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: current, method, params }) + '\n');
});

const rows = [];
let failure = null;
try {
  await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'provider-offline-test', version: '1.0' } });
  for (const route of routes) {
    // The host /proc interface is an available provider even without a CLI;
    // it cannot be tested for absence by stripping PATH.
    if (route.required_provider === 'operating-system-process-interface') {
      rows.push({ name: route.name, status: 'not-applicable-host-provider' });
      continue;
    }
    const args = {
      path: '__rea_fast_nonexistent_file__',
      target_path: '__rea_fast_nonexistent_file__',
      source_path: '__rea_fast_nonexistent_file__',
      serial: '__rea_fast_nonexistent_device__',
      device_serial: '__rea_fast_nonexistent_device__',
      package: '__rea_fast_nonexistent_package__',
      package_name: '__rea_fast_nonexistent_package__',
      session_id: '__rea_fast_nonexistent_session__',
      endpoint: 'http://127.0.0.1:1',
      url: 'http://127.0.0.1:1',
      command: 'version',
      arguments: [], args: [],
    };
    const response = await rpc('tools/call', { name: route.name, arguments: args });
    if (response.error) throw new Error(`${route.name}: RPC error ${JSON.stringify(response.error)}`);
    const result = response.result;
    let value = {};
    const content = result?.content?.find((item) => item.type === 'text');
    if (content) {
      try { value = JSON.parse(content.text); } catch { value = { _malformed: true }; }
    }
    const status = value.status || (result?.isError === true ? 'isError' : 'no-status');
    rows.push({ name: route.name, status, isError: result?.isError === true });
    assert.ok(result?.isError === true || ['unavailable', 'error', 'timeout', 'unverified', 'raw', 'closed'].includes(status),
      `${route.name}: fabricated provider-free success: ${JSON.stringify(value).slice(0, 300)}`);
  }
} catch (error) {
  failure = String(error.stack ?? error);
  process.exitCode = 1;
} finally {
  child.stdin.end();
  setTimeout(() => child.kill(), 1000).unref();
  const report = { status: failure ? 'failed' : 'pass', total_routes: routes.length,
    checks: rows.length, fail_closed: rows.filter((r) => r.status !== 'not-applicable-host-provider').length,
    failure, rows };
  const output = opt('--output');
  if (output) {
    mkdirSync(dirname(resolve(output)), { recursive: true });
    writeFileSync(resolve(output), JSON.stringify(report, null, 2) + '\n');
  }
  console.log(JSON.stringify({ status: report.status, total_routes: report.total_routes,
    checked: report.fail_closed, excluded_host_provider: report.checks - report.fail_closed,
    failure: report.failure }));
}
