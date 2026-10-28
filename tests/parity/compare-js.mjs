#!/usr/bin/env node
/**
 * Opt-in, real-process parity fixture against pinned upstream morluto/rea.
 * Compares shared module/import/export facts, NOT full Evidence semantics.
 * A missing runtime or provider yields not_comparable rather than false pass.
 * Usage:
 *   node tests/parity/compare-js.mjs --rust-bin /path/rea-fast --upstream /path/rea
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = join(root, 'tests/fixtures/parity/js-basic');
const golden = JSON.parse(readFileSync(join(root, 'tests/parity/js-basic.expected.json'), 'utf8'));
const expectedUpstream = '6de60993b861266e63a4e70d5c6d9a8073f7cd92';

function exec(program, args, cwd) {
  const start = process.hrtime.bigint();
  const result = spawnSync(program, args, {
    cwd,
    encoding: 'utf8',
    timeout: 60_000,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  });
  return {
    elapsed_ms: Math.round(Number(process.hrtime.bigint() - start) / 1e6),
    exit_code: result.status,
    error: result.error?.message ?? null,
    stdout: result.stdout ?? '',
    diagnostic: (result.stderr ?? '').slice(-1500),
  };
}

const properties = (node) => node?.observations?.[0]?.properties ?? node?.properties ?? {};
const sortedUnique = (values) => [...new Set(values)].sort();

function normalizeRust(doc) {
  if (doc?.schema !== 'JavaScriptApplicationGraph' || !Array.isArray(doc.nodes)) {
    throw new Error('Rust output is not a JavaScriptApplicationGraph');
  }
  return doc.nodes.filter((node) => node.kind === 'source-module').map((node) => {
    const props = properties(node);
    const path = node.identity?.path;
    const sha256 = node.identity?.artifact_sha256;
    const exports = sortedUnique((props.exports ?? []).map((item) => item.name).filter(Boolean));
    const imports = sortedUnique((props.dependencies ?? [])
      .filter((item) => item.target)
      .map((item) => item.target));
    if (!path || !sha256) throw new Error('Rust module lacks path/digest evidence');
    return { path, sha256, exports, imports };
  }).sort((a, b) => a.path.localeCompare(b.path));
}

function normalizeUpstream(doc) {
  const graph = doc?.normalized_result?.graph;
  if (doc?.operation !== 'analyze_javascript_application' || !Array.isArray(graph?.nodes) || !Array.isArray(graph?.edges)) {
    throw new Error('Upstream did not return completed application graph Evidence');
  }
  const sourceModules = graph.nodes.filter((node) =>
    node.kind === 'javascript-module' && properties(node).semantic_role === 'source-module');
  const byId = new Map(sourceModules.map((node) => [node.node_id, node]));
  return sourceModules.map((node) => {
    const props = properties(node);
    const path = props.path;
    const sha256 = node.identity?.artifact_sha256;
    const imports = sortedUnique(graph.edges.filter((edge) =>
      edge.relation === 'imports' && edge.source_node_id === node.node_id && byId.has(edge.target_node_id))
      .map((edge) => properties(byId.get(edge.target_node_id)).path).filter(Boolean));
    if (!path || !sha256) throw new Error('Upstream source module lacks path/digest Evidence');
    return { path, sha256, exports: sortedUnique(props.export_names ?? []), imports };
  }).sort((a, b) => a.path.localeCompare(b.path));
}

function finish(report, exitCode = 0) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = exitCode;
}

function run() {
  const options = new Map();
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!process.argv[i]?.startsWith('--') || !process.argv[i + 1]) {
      throw new Error('Usage: --rust-bin PATH --upstream DIR');
    }
    options.set(process.argv[i].slice(2), process.argv[i + 1]);
  }
  
  const upstream = options.get('upstream');
  const rustBin = options.get('rust-bin');
  if (!upstream || !rustBin) throw new Error('Provide --rust-bin PATH and --upstream DIR');

  const revision = exec('git', ['rev-parse', 'HEAD'], upstream);
  if (revision.exit_code !== 0 || revision.stdout.trim() !== expectedUpstream) {
    return finish({ status: 'not_comparable', reason: 'Unpinned or unavailable upstream revision',
      expected_upstream: expectedUpstream, observed_upstream: revision.stdout.trim() }, 2);
  }

  const rust = exec(rustBin, ['analyze', fixture, '--format', 'json'], root);
  const source = exec(process.execPath, [join(upstream, 'scripts/rea.mjs'),
    'analyze-javascript-application', fixture, '--format', 'json'], upstream);
  const report = {
    scenario: 'js-basic-static-modules',
    upstream_commit: expectedUpstream,
    comparison_scope: 'source-module paths, content digests, static import targets and exported names',
    excluded: ['Evidence lifecycle and provenance', 'semantic call graph', 'Electron runtime and provider behavior'],
    rust: { exit_code: rust.exit_code, uncontrolled_single_run_ms: rust.elapsed_ms },
    upstream: { exit_code: source.exit_code, uncontrolled_single_run_ms: source.elapsed_ms },
  };

  if (rust.exit_code !== 0 || source.exit_code !== 0 || rust.error || source.error) {
    return finish({ ...report, status: 'not_comparable', reason: 'One implementation did not complete',
      rust_error: rust.error ?? rust.diagnostic, upstream_error: source.error ?? source.diagnostic }, 2);
  }

  let rustFacts;
  let upstreamFacts;
  try {
    rustFacts = normalizeRust(JSON.parse(rust.stdout));
    upstreamFacts = normalizeUpstream(JSON.parse(source.stdout));
  } catch (error) {
    return finish({ ...report, status: 'not_comparable', reason: String(error) }, 2);
  }
  const matched = JSON.stringify(rustFacts) === JSON.stringify(upstreamFacts)
    && JSON.stringify(rustFacts) === JSON.stringify(golden);
  finish({ ...report, status: matched ? 'fixture_match' : 'fixture_mismatch',
    golden_assertion: matched,
    upstream_parity: 'unverified_outside_listed_facts',
    facts: matched ? rustFacts : { rust: rustFacts, upstream: upstreamFacts },
    performance: 'not_comparable_until_correctness_and_resource_metrics_are_verified' }, matched ? 0 : 1);
}

export { normalizeRust, normalizeUpstream, expectedUpstream, fixture, golden };
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run();
