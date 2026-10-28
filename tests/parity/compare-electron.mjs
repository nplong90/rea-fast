#!/usr/bin/env node
/**
 * Compare narrow, observed Electron syntax facts from real rea-fast and
 * pinned REA. This does not equate their graph, provenance, or security claims.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = join(root, 'tests/fixtures/parity/electron-ipc');
const golden = JSON.parse(readFileSync(join(root, 'tests/parity/electron-ipc.expected.json'), 'utf8'));
const expectedUpstream = '6de60993b861266e63a4e70d5c6d9a8073f7cd92';
const options = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  if (!process.argv[i]?.startsWith('--') || !process.argv[i + 1]) {
    throw new Error('Usage: --rust-bin PATH --upstream DIR');
  }
  options.set(process.argv[i].slice(2), process.argv[i + 1]);
}

function exec(binary, args, cwd) {
  const result = spawnSync(binary, args, {
    cwd, encoding: 'utf8', timeout: 60_000, maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
  return { code: result.status, error: result.error?.message ?? null,
    stdout: result.stdout ?? '', diagnostic: (result.stderr ?? '').slice(-1000) };
}

const sortFacts = (facts, keys) => facts.sort((a, b) =>
  keys.map((key) => String(a[key]).localeCompare(String(b[key]))).find((value) => value !== 0) ?? 0);

function normalizedRust(main, preload) {
  const findings = [main, preload];
  return {
    ipc: sortFacts(findings.flatMap((item) => item.ipc ?? []).map((event) => ({
      side: event.process, operation: event.operation, channel: event.channel,
    })), ['side', 'operation', 'channel']),
    bridges: sortFacts(findings.flatMap((item) => item.context_bridge_apis ?? []).map((bridge) => ({
      api: bridge.api_name, methods: [...bridge.exposed_methods].sort(),
    })), ['api']),
    windows: sortFacts(findings.flatMap((item) => item.browser_windows ?? []).map((win) => ({
      preload: win.web_preferences.preload,
      contextIsolation: win.web_preferences.context_isolation,
      nodeIntegration: win.web_preferences.node_integration,
    })), ['preload']),
  };
}

function normalizedUpstream(doc) {
  const graph = doc?.normalized_result?.graph;
  if (doc?.operation !== 'analyze_javascript_application' || !Array.isArray(graph?.nodes)
      || !Array.isArray(graph?.edges)) {
    throw new Error('Upstream Electron application Evidence graph unavailable');
  }
  const nodes = graph.nodes;
  const props = (node) => node.observations?.[0]?.properties ?? {};
  const ofKind = (kind) => nodes.filter((node) => node.kind === kind).map(props);

  const ipc = sortFacts([
    ...ofKind('ipc-handler').map((item) => ({
      side: item.side, operation: item.operation, channel: item.channel,
    })),
    ...ofKind('ipc-channel').map((item) => ({
      side: item.side, operation: item.operation, channel: item.channel,
    })),
  ], ['side', 'operation', 'channel']);
  const bridges = sortFacts(ofKind('context-bridge-api').map((item) => ({
    api: item.api_key, methods: [...(item.members ?? [])].sort(),
  })), ['api']);
  const windows = sortFacts(ofKind('browser-window').map((item) => {
    const preferences = new Map((item.web_preferences ?? []).map((entry) =>
      [entry.name, entry.value?.value]));
    return { preload: preferences.get('preload'),
      contextIsolation: preferences.get('contextIsolation'),
      nodeIntegration: preferences.get('nodeIntegration') };
  }), ['preload']);

  // Require upstream to actually have observed the declared IPC relationship;
  // this is not an assertion that Rust represents the corresponding edges.
  if (!graph.edges.some((edge) => edge.relation === 'handles')
      || !graph.edges.some((edge) => edge.relation === 'exposes')) {
    throw new Error('Upstream IPC/bridge Evidence relationships were incomplete');
  }
  return { ipc, bridges, windows };
}

function finish(report, exitCode) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = exitCode;
}

const upstream = options.get('upstream');
const rustBin = options.get('rust-bin');
if (!upstream || !rustBin) throw new Error('Provide --rust-bin PATH and --upstream DIR');
const revision = exec('git', ['rev-parse', 'HEAD'], upstream);
if (revision.code !== 0 || revision.stdout.trim() !== expectedUpstream) {
  finish({ scenario: 'electron-ipc-static', status: 'not_comparable',
    reason: 'Upstream not at pinned revision', upstream_revision: revision.stdout.trim() }, 2);
} else {
  const rustMain = exec(rustBin, ['analyze-electron', join(fixture, 'main.js')], root);
  const rustPreload = exec(rustBin, ['analyze-electron', join(fixture, 'preload.js')], root);
  const source = exec(process.execPath, [join(upstream, 'scripts/rea.mjs'),
    'analyze-javascript-application', fixture, '--format', 'json'], upstream);

  try {
    if ([rustMain, rustPreload, source].some((result) => result.code !== 0 || result.error)) {
      throw new Error('One implementation failed: ' + [rustMain, rustPreload, source]
        .map((result) => result.error ?? result.diagnostic).filter(Boolean).join(' | '));
    }
    const rust = normalizedRust(JSON.parse(rustMain.stdout), JSON.parse(rustPreload.stdout));
    const rea = normalizedUpstream(JSON.parse(source.stdout));
    const matched = JSON.stringify(rust) === JSON.stringify(rea)
      && JSON.stringify(rust) === JSON.stringify(golden);
    finish({ scenario: 'electron-ipc-static', upstream_commit: expectedUpstream,
      status: matched ? 'fixture_match' : 'fixture_mismatch',
      scope: 'literal IPC directions/channels, contextBridge members and BrowserWindow options',
      facts: matched ? rust : { rust, upstream: rea, golden },
      excluded: ['full 25-node/33-edge Evidence graph', 'provenance', 'runtime execution',
        'sender-validation/security inference', 'preload relationship resolution'],
      performance: 'not_comparable' }, matched ? 0 : 1);
  } catch (error) {
    finish({ scenario: 'electron-ipc-static', status: 'not_comparable', reason: String(error) }, 2);
  }
}
