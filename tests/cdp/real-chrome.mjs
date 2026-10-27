#!/usr/bin/env node
/**
 * Real headless Chrome + rea-fast MCP integration smoke.
 * Requires a host Chrome executable; no pre-recorded CDP responses.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const idx = process.argv.indexOf('--rust-bin');
if (idx < 0 || !process.argv[idx + 1]) {
  throw new Error('Usage: node tests/cdp/real-chrome.mjs --rust-bin ABSOLUTE_PATH');
}
const chromeProgram = process.env.REA_CHROME_BIN || 'google-chrome';
const dir = mkdtempSync(join(tmpdir(), 'rea-cdp-integration-'));
const profile = join(dir, 'chrome-profile');
const screenshot = join(dir, 'screenshot.png');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const chrome = spawn(chromeProgram, [
  '--headless=new', '--no-sandbox', '--disable-dev-shm-usage',
  '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let chromeStderr = '';
chrome.stderr.on('data', (data) => { chromeStderr = (chromeStderr + data).slice(-2000); });
let mcp;
try {
  let port = null;
  for (let i = 0; i < 100; i += 1) {
    if (chrome.exitCode !== null) {
      throw new Error(`Chrome exited before CDP became ready: ${chromeStderr}`);
    }
    const activePort = join(profile, 'DevToolsActivePort');
    if (existsSync(activePort)) {
      const first = readFileSync(activePort, 'utf8').split(/\r?\n/)[0];
      port = Number(first);
      if (port > 0) break;
    }
    await sleep(200);
  }
  if (!port) throw new Error(`Chrome did not open a debugging port: ${chromeStderr}`);
  const endpoint = `http://127.0.0.1:${port}`;
  mcp = spawn(process.argv[idx + 1], ['mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let mcpStderr = '';
  mcp.stderr.on('data', (data) => { mcpStderr = (mcpStderr + data).slice(-2000); });
  const pending = new Map();
  createInterface({ input: mcp.stdout }).on('line', (line) => {
    try {
      const response = JSON.parse(line);
      const handlers = pending.get(response.id);
      if (handlers) {
        pending.delete(response.id);
        handlers.resolve(response);
      }
    } catch (error) {
      for (const handlers of pending.values()) handlers.reject(error);
      pending.clear();
    }
  });
  async function callTool(id, name, args) {
    const response = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP/MCP timed out for ${name}: ${mcpStderr}; ${chromeStderr}`));
      }, 15000);
      pending.set(id, {
        resolve: (value) => { clearTimeout(timeout); resolve(value); },
        reject: (error) => { clearTimeout(timeout); reject(error); },
      });
      mcp.stdin.write(JSON.stringify({
        jsonrpc: '2.0', id, method: 'tools/call',
        params: { name, arguments: args },
      }) + '\n');
    });
    assert.equal(response.id, id);
    assert.equal(response.result?.isError, false, JSON.stringify(response));
    return JSON.parse(response.result.content[0].text);
  }
  const targets = await callTool(1, 'list_browser_targets', { cdp_endpoint: endpoint });
  assert.equal(targets.status, 'complete');
  assert.ok(targets.target_count >= 1);
  const evaluated = await callTool(2, 'evaluate_web_script', {
    cdp_endpoint: endpoint, expression: '1 + 2',
  });
  assert.equal(evaluated.status, 'complete');
  assert.equal(evaluated.result, 3);
  const screenshotResult = await callTool(3, 'capture_web_screenshot', {
    cdp_endpoint: endpoint, output_path: screenshot, format: 'png',
  });
  assert.equal(screenshotResult.status, 'complete');
  assert.equal(screenshotResult.saved_path, screenshot);
  const bytes = readFileSync(screenshot);
  assert.ok(bytes.length > 8);
  assert.deepEqual([...bytes.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(screenshotResult.bytes, bytes.length);
  process.stdout.write(JSON.stringify({
    status: 'pass',
    provider: 'real_headless_chrome',
    verified_mcp_routes: [
      'list_browser_targets', 'evaluate_web_script', 'capture_web_screenshot',
    ],
    screenshot_bytes: bytes.length,
  }) + '\n');
} catch (error) {
  process.stderr.write(String(error.stack ?? error) + '\n');
  process.exitCode = 1;
} finally {
  if (mcp) {
    mcp.kill();
    if (mcp.exitCode === null) await Promise.race([once(mcp, 'exit'), sleep(2000)]);
  }
  chrome.kill();
  if (chrome.exitCode === null) await Promise.race([once(chrome, 'exit'), sleep(2000)]);
  rmSync(dir, { recursive: true, force: true });
}
