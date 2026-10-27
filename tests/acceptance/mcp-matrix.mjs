#!/usr/bin/env node
// MCP runtime acceptance matrix. A route fixture is NOT upstream parity.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const opt = (flag) => { const i = argv.indexOf(flag); return i < 0 ? null : argv[i + 1]; };
if (!opt('--rust-bin')) throw new Error('Usage: --rust-bin path [--output path]');
const binary = resolve(opt('--rust-bin'));
const output = resolve(opt('--output') || 'acceptance-artifacts/mcp-matrix.json');
const dir = mkdtempSync(join(tmpdir(), 'rea-acceptance-'));
const child = spawn(binary, ['mcp'], {
  stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  env: { ...process.env, REA_MCP_PROFILE: 'full' },
});
let errorText = '', id = 0, failure = null;
const pending = new Map(), rows = [], verified = [];
child.stderr.on('data', (x) => { errorText = (errorText + x).slice(-2048); });
child.on('error', (e) => {
  for (const handler of pending.values()) handler.reject(e);
  pending.clear();
});
child.on('exit', (code) => {
  for (const handler of pending.values()) handler.reject(new Error('MCP exited ' + code + ' ' + errorText));
  pending.clear();
});
createInterface({ input: child.stdout }).on('line', (line) => {
  let response;
  try {
    if (line.length > 12 * 1024 * 1024) throw new Error('MCP response too large');
    response = JSON.parse(line);
  } catch (e) {
    for (const handler of pending.values()) handler.reject(e);
    pending.clear();
    return;
  }
  const h = pending.get(response.id);
  if (h) {
    pending.delete(response.id);
    clearTimeout(h.timer);
    h.resolve(response);
  }
});
const rpc = (method, params) => new Promise((resolveResult, reject) => {
  const requestId = ++id;
  const timer = setTimeout(() => {
    pending.delete(requestId);
    reject(new Error(method + ' timed out ' + errorText));
  }, 30000);
  pending.set(requestId, { resolve: resolveResult, reject, timer });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
});
async function call(name, arguments_, check) {
  const message = await rpc('tools/call', { name, arguments: arguments_ });
  assert.equal(message.error, undefined, name + ': transport failure');
  assert.equal(message.result?.isError, false, name + ': ' + JSON.stringify(message.result));
  const content = message.result?.content?.[0];
  assert.equal(content?.type, 'text', name + ': missing result');
  const value = JSON.parse(content.text);
  assert.notEqual(value.status, 'unavailable', name + ': unavailable');
  assert.notEqual(value.status, 'error', name + ': error');
  check(value);
  verified.push(name);
  return value;
}
function record(name) {
  const entry = rows.find((r) => r.tool === name);
  assert.ok(entry, 'Not in REA catalog: ' + name);
  assert.equal(entry.route, 'native', name + ' misclassified as non-native');
  entry.runtime = 'fixture_exercised';
  entry.proof = 'real_mcp_process_assertions';
}
try {
  const listed = await rpc('tools/list', {});
  assert.equal(listed.result?.tools?.length, 245, 'Full MCP catalog must have 245 entries');
  const result = await call('rea_search_tools', { query: '' }, (data) => {
    assert.equal(data.count, 245);
    assert.equal(data.tools.length, 245);
  });
  const found = new Map(result.tools.map((t) => [t.name, t]));
  assert.equal(found.size, 245, 'Duplicate tool in search result');
  for (const t of listed.result.tools) {
    const matching = found.get(t.name);
    assert.ok(matching, 'Missing discovered tool ' + t.name);
    const route = matching.rea_fast_capability?.category;
    assert.ok(['native', 'external-provider', 'unavailable'].includes(route), t.name);
    assert.equal(matching.rea_fast_capability.upstream_parity, 'not_verified');
    rows.push({ tool: t.name, route, runtime: 'not_tested', upstream_parity: 'not_verified' });
  }
  record('rea_search_tools');
  rows.sort((a, b) => a.tool.localeCompare(b.tool));

  const fixture = join(dir, 'sample.bin');
  const sample = Buffer.from('ACCEPTANCE_MATRIX_STRING_12345\0example\n');
  writeFileSync(fixture, sample);
  const wasm = join(dir, 'sample.wasm');
  writeFileSync(wasm, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  const source = join(dir, 'src');
  mkdirSync(source);
  writeFileSync(join(source, 'main.js'), 'console.log("acceptance");\n');
  const archive = join(dir, 'sample.asar');

  await call('analyze_electron_source', {
    path: 'fixture.js', source: "const {ipcMain}=require('electron');ipcMain.handle('matrix:read',()=>1);",
  }, (v) => { assert.equal(v.ipc[0].channel, 'matrix:read'); }); record('analyze_electron_source');
  await call('analyze_javascript_application', {
    input_path: fileURLToPath(new URL('../fixtures/parity/js-basic/', import.meta.url)),
  }, (v) => {
    assert.equal(v.schema, 'JavaScriptApplicationGraph');
    assert.ok(v.nodes.filter((n) => n.kind === 'source-module').length >= 2);
  }); record('analyze_javascript_application');
  await call('scan_secrets', { source: '-----BEGIN OPENSSH PRIVATE KEY-----', path: 'fixture.txt' }, (v) => {
    assert.equal(v.total_secrets, 1);
    assert.ok(!JSON.stringify(v).includes('-----BEGIN OPENSSH PRIVATE KEY-----'));
  }); record('scan_secrets');
  await call('compare_artifacts', { left: { x: 1 }, right: { x: 1 } }, (v) => {
    assert.equal(v.identical, true);
  }); record('compare_artifacts');
  const unknown = await call('record_unknown', {
    question: 'Does fixture preserve provenance?', domain: 'mcp-acceptance',
  }, (v) => { assert.equal(v.status, 'open'); }); record('record_unknown');
  await call('update_unknown', {
    unknown_id: unknown.unknown_id, expected_revision: 1, status: 'resolved',
  }, (v) => { assert.equal(v.revision, 2); }); record('update_unknown');
  await call('list_unknowns', { domain: 'mcp-acceptance' }, (v) => {
    assert.ok(v.total >= 1);
  }); record('list_unknowns');
  await call('get_evidence_bundle', { detail: 'summary' }, (v) => {
    assert.equal(v.status, 'complete');
  }); record('get_evidence_bundle');
  await call('export_environment_bundle', {}, (v) => {
    assert.equal(v.status, 'ready');
  }); record('export_environment_bundle');
  await call('inspect_binary_layout', { path: binary }, (v) => {
    assert.equal(v.sha256, createHash('sha256').update(readFileSync(binary)).digest('hex'));
    assert.ok(v.total_sections > 0);
  }); record('inspect_binary_layout');
  await call('inspect_byte_entropy', { path: fixture }, (v) => {
    assert.equal(v.total_bytes, sample.length);
  }); record('inspect_byte_entropy');
  await call('list_strings', { path: fixture }, (v) => {
    assert.ok(v.strings.some((x) => x.includes('ACCEPTANCE_MATRIX_STRING_12345')));
  }); record('list_strings');
  await call('search_strings', { path: fixture, query: 'ACCEPTANCE_MATRIX_STRING' }, (v) => {
    assert.equal(v.total_found, 1);
  }); record('search_strings');
  await call('inspect_artifact', { path: fixture }, (v) => {
    assert.equal(v.artifact_kind, 'file');
  }); record('inspect_artifact');
  await call('compare_wasm_interfaces', { left_path: wasm, right_path: wasm }, (v) => {
    assert.equal(v.is_identical, true);
  }); record('compare_wasm_interfaces');
  await call('pack_asar', { source_directory: source, output_path: archive }, () => {
    assert.ok(existsSync(archive));
  }); record('pack_asar');
  await call('inspect_asar', { path: archive }, (v) => {
    assert.equal(v.total_entries, 1);
    assert.equal(v.entries[0].path, 'main.js');
  }); record('inspect_asar');
  await call('list_segments', { path: binary }, (v) => {
    assert.ok(v.total_segments > 0);
  }); record('list_segments');
  await call('rea_execute_tool', {
    tool_name: 'compare_artifacts', arguments: { left: { x: 7 }, right: { x: 7 } },
  }, (v) => { assert.equal(v.identical, true); }); record('rea_execute_tool');
  // Expand offline route evidence across WASM, native object metadata,
  // semantic application graph diffing and platform inventory projections.
  await call('inspect_wasm_artifact', { path: wasm }, (v) => {
    assert.equal(v.is_wasm, true);
    assert.equal(v.version, 1);
  }); record('inspect_wasm_artifact');
  await call('inspect_rust_binary', { path: binary }, (v) => {
    assert.equal(typeof v.has_rust_auditable, 'boolean');
  }); record('inspect_rust_binary');
  await call('list_architectures', { path: binary }, (v) => {
    assert.equal(v.architecture_count, 1);
    assert.equal(v.architectures.length, 1);
  }); record('list_architectures');
  await call('inspect_native_exports', { path: binary }, (v) => {
    assert.ok(Array.isArray(v.exports));
    assert.equal(v.total_exports, v.exports.length);
  }); record('inspect_native_exports');
  await call('project_apple_application_graph', {
    inventory_evidence: [{ path: '/Applications/Example.app' }, { path: '/Applications/Example.app/Info.plist' }],
  }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.bundles_count, 2);
    assert.equal(v.plists_count, 1);
  }); record('project_apple_application_graph');
  await call('project_harmony_application_graph', {
    inventory_evidence: [{ path: '/entry/module.json' }, { path: '/entry/ets/modules.abc' }],
  }, (v) => {
    assert.equal(v.platform, 'harmonyos');
    assert.equal(v.packaging_model, 'stage');
    assert.equal(v.modules_count, 1);
    assert.equal(v.ark_bytecode_files.length, 1);
  }); record('project_harmony_application_graph');
  const leftGraph = { modules: [{ path: 'a.js', bytes: 1, lines: 1, exports: ['a'] }], edges: [] };
  const rightGraph = { modules: [{ path: 'a.js', bytes: 2, lines: 2, exports: ['a'] }], edges: [] };
  await call('diff_applications', { left: leftGraph, right: rightGraph }, (v) => {
    assert.equal(v.changed_modules.length, 1);
  }); record('diff_applications');
  await call('compare_source_to_bundle', { reference: leftGraph, application: rightGraph }, (v) => {
    assert.equal(v.changed_modules.length, 1);
  }); record('compare_source_to_bundle');
  await call('list_procedures', { path: binary, limit: 20 }, (v) => {
    assert.ok(Array.isArray(v.symbols));
    assert.equal(v.total_symbols, v.symbols.length);
  }); record('list_procedures');
  await call('list_names', { path: binary, limit: 20 }, (v) => {
    assert.ok(Array.isArray(v.symbols));
    assert.equal(v.total_symbols, v.symbols.length);
  }); record('list_names');
  assert.equal(rows.length, 245);
  assert.equal(verified.length, 30, '30 fixture executions expected');
} catch (e) {
  failure = String(e.stack ?? e);
  process.exitCode = 1;
} finally {
  const tally = (name) => rows.filter((r) => r.route === name).length;
  const summary = {
    status: failure ? 'fixture_failed' : 'partial_acceptance',
    full_product_parity: 'not_verified',
    release_gate: 'blocked_until_full_required_parity',
    git_commit: process.env.GITHUB_SHA || null,
    pr_head: process.env.PR_HEAD_SHA || null,
    platform: process.platform,
    binary_sha256: existsSync(binary) ? createHash('sha256').update(readFileSync(binary)).digest('hex') : null,
    tool_count: rows.length,
    route_counts: { native: tally('native'), 'external-provider': tally('external-provider'), unavailable: tally('unavailable') },
    fixture_exercised: rows.filter((x) => x.runtime === 'fixture_exercised').length,
    unverified: rows.filter((x) => x.runtime !== 'fixture_exercised').length,
    error: failure, tools: rows,
  };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify({
    status: summary.status, tool_count: summary.tool_count,
    route_counts: summary.route_counts, fixture_exercised: summary.fixture_exercised,
    unverified: summary.unverified, error: summary.error,
  }));
  child.kill();
  rmSync(dir, { recursive: true, force: true });
}
