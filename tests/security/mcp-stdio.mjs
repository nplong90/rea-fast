#!/usr/bin/env node
/**
 * Black-box MCP parser survival test: malformed JSON, invalid UTF-8, deep
 * nesting and (opt-in) >64 MiB untrusted input cannot end the stdio session.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const args = process.argv.slice(2);
const binaryIndex = args.indexOf('--rust-bin');
if (binaryIndex < 0 || !args[binaryIndex + 1]) {
  throw new Error('Usage: node tests/security/mcp-stdio.mjs --rust-bin PATH [--oversize]');
}
const testOversize = args.includes('--oversize');
const child = spawn(args[binaryIndex + 1], ['mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
let stderr = '';
let exited = false;
let observed = 0;
const received = [];
const listeners = [];
child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-2048); });
child.on('exit', () => { exited = true; });

createInterface({ input: child.stdout }).on('line', (line) => {
  observed += 1;
  if (line.length > 1024 * 1024) throw new Error('Unexpectedly large MCP response');
  const message = JSON.parse(line);
  const resolve = listeners.shift();
  if (resolve) resolve(message);
  else received.push(message);
});

async function write(bytes) {
  if (exited) throw new Error(`MCP process terminated: ${stderr}`);
  if (!child.stdin.write(bytes)) await once(child.stdin, 'drain');
}

async function nextResponse() {
  if (received.length) return received.shift();
  return Promise.race([
    new Promise((resolve) => listeners.push(resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`MCP response timed out: ${stderr}`)), 30_000).unref()),
  ]);
}

async function request(data, expectedCode, expectedId = null) {
  await write(data);
  const message = await nextResponse();
  assert.equal(message.jsonrpc, '2.0');
  assert.equal(message.id, expectedId);
  if (expectedCode === null) assert.ok(message.result !== undefined, JSON.stringify(message));
  else assert.equal(message.error?.code, expectedCode, JSON.stringify(message));
}

try {
  await request('{broken json\n', -32700);
  await request(Buffer.from([0xff, 0xfe, 0x0a]), -32700);
  await request(`${'['.repeat(512)}0${']'.repeat(512)}\n`, -32700);
  // Deterministic malformed JSON corpus of increasing length. Each response
  // must be a parse error, not a server crash or a fabricated success.
  for (let length = 1; length <= 32; length += 1) {
    await request(`{"${'x'.repeat(length)}\n`, -32700);
  }
  // Valid JSON but invalid JSON-RPC envelopes must never execute.
  await request('[]\n', -32600);
  await request('{"jsonrpc":"1.0","id":5,"method":"ping"}\n', -32600, 5);
  await request('{"jsonrpc":"2.0","id":true,"method":"ping"}\n', -32600);
  await request('{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scan_secrets","arguments":[]}}\n', -32602, 6);
  await request('{"jsonrpc":"2.0","id":1,"method":"ping"}\n', null, 1);
  // JSON-RPC notifications do not produce an output line.
  await write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
  await request('{"jsonrpc":"2.0","id":2,"method":"ping"}\n', null, 2);

  // Prove an advertised native route actually executes over MCP, not merely
  // that it appears in the tool catalog with a plausible description.
  await write(JSON.stringify({
    jsonrpc: '2.0', id: 4, method: 'tools/call', params: {
      name: 'analyze_electron_source', arguments: {
        path: 'fixture.js',
        source: "const { ipcMain } = require('electron'); ipcMain.handle('fixture:test', () => true);",
      },
    },
  }) + '\n');
  const nativeResult = await nextResponse();
  assert.equal(nativeResult.id, 4);
  assert.equal(nativeResult.result?.isError, false);
  const analysis = JSON.parse(nativeResult.result.content[0].text);
  assert.equal(analysis.ipc[0].channel, 'fixture:test');
  assert.equal(analysis.ipc[0].operation, 'handle');

  // An explicit unsupported engine must not be marked successful in MCP.
  await write(JSON.stringify({
    jsonrpc: '2.0', id: 7, method: 'tools/call',
    params: { name: 'decompile_jeb_item', arguments: {} },
  }) + '\n');
  const unavailableResult = await nextResponse();
  assert.equal(unavailableResult.id, 7);
  assert.equal(unavailableResult.result?.isError, true);
  assert.equal(JSON.parse(unavailableResult.result.content[0].text).status, 'unavailable');

  // Independently exercise the native JS analyzer over the actual MCP pipe.
  // This is route readiness on a fixture, not parity with upstream Evidence.
  await write(JSON.stringify({
    jsonrpc: '2.0', id: 8, method: 'tools/call',
    params: {
      name: 'analyze_javascript_application',
      arguments: {
        input_path: fileURLToPath(new URL('../fixtures/parity/js-basic/', import.meta.url)),
      },
    },
  }) + '\n');
  const jsResult = await nextResponse();
  assert.equal(jsResult.id, 8);
  assert.equal(jsResult.result?.isError, false, JSON.stringify(jsResult));
  const graph = JSON.parse(jsResult.result.content[0].text);
  assert.equal(graph.schema, 'JavaScriptApplicationGraph');
  assert.ok(graph.nodes.filter((node) => node.kind === 'source-module').length >= 2);

  async function callNative(id, name, arguments_) {
    await write(JSON.stringify({
      jsonrpc: '2.0', id, method: 'tools/call',
      params: { name, arguments: arguments_ },
    }) + '\n');
    const message = await nextResponse();
    assert.equal(message.id, id);
    assert.equal(message.result?.isError, false, JSON.stringify(message));
    return JSON.parse(message.result.content[0].text);
  }

  const secretResult = await callNative(9, 'scan_secrets', {
    source: '-----BEGIN OPENSSH PRIVATE KEY-----',
    path: 'synthetic-fixture.txt',
  });
  assert.equal(secretResult.total_secrets, 1);
  assert.equal(secretResult.secrets[0].rule, 'Private Key');
  assert.ok(!JSON.stringify(secretResult).includes('-----BEGIN OPENSSH PRIVATE KEY-----'));

  const comparable = await callNative(10, 'compare_artifacts', {
    left: { z: 1, a: [2, 3] }, right: { a: [2, 3], z: 1 },
  });
  assert.equal(comparable.status, 'complete');
  assert.equal(comparable.identical, true);

  const unknown = await callNative(11, 'record_unknown', {
    question: 'How does the fixture preserve evidence?',
    domain: 'mcp-smoke',
  });
  assert.equal(unknown.status, 'open');
  assert.ok(unknown.unknown_id);

  const updatedUnknown = await callNative(12, 'update_unknown', {
    unknown_id: unknown.unknown_id, expected_revision: 1, status: 'resolved',
  });
  assert.equal(updatedUnknown.status, 'resolved');
  assert.equal(updatedUnknown.revision, 2);

  // Inspect the actual compiled executable, not a synthetic capability label.
  // Verify the returned file digest against independent Node hashing.
  const binaryPath = args[binaryIndex + 1];
  const layout = await callNative(13, 'inspect_binary_layout', { path: binaryPath });
  assert.equal(layout.sha256, createHash('sha256').update(readFileSync(binaryPath)).digest('hex'));
  assert.ok(layout.total_sections > 0);
  assert.ok(typeof layout.architecture === 'string' && layout.architecture.length > 0);

  if (testOversize) {
    // Stream instead of allocating a 65 MiB string in the test process.
    const block = Buffer.alloc(1024 * 1024, 0x78);
    for (let i = 0; i < 65; i += 1) await write(block);
    await request('\n', -32600);
    await request('{"jsonrpc":"2.0","id":3,"method":"ping"}\n', null, 3);
  }

  assert.equal(observed, testOversize ? 51 : 49);
  child.stdin.end();
  const [code] = await once(child, 'exit');
  assert.equal(code, 0, stderr);
  process.stdout.write(JSON.stringify({ status: 'pass', malformed_inputs: 35,
    oversized_stream_tested: testOversize, subsequent_ping_survived: true,
    verified_mcp_native_routes: [
      'analyze_electron_source', 'analyze_javascript_application',
      'scan_secrets', 'compare_artifacts', 'record_unknown', 'update_unknown',
      'inspect_binary_layout',
    ],
    invalid_request_and_params_rejected: 4,
    unavailable_tool_reports_isError: true }) + '\n');
} catch (error) {
  child.kill();
  process.stderr.write(`${error.stack ?? error}\n${stderr}\n`);
  process.exitCode = 1;
}
