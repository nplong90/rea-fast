#!/usr/bin/env node
/** Compare genuine ASAR archive facts from rea-fast and pinned upstream REA. */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = join(root, 'tests/fixtures/parity/js-basic');
const golden = JSON.parse(readFileSync(join(root, 'tests/parity/asar-basic.expected.json'), 'utf8'));
const expectedUpstream = '6de60993b861266e63a4e70d5c6d9a8073f7cd92';
const opts = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  if (!process.argv[i]?.startsWith('--') || !process.argv[i + 1]) {
    throw new Error('Usage: --rust-bin PATH --upstream DIR');
  }
  opts.set(process.argv[i].slice(2), process.argv[i + 1]);
}

function exec(program, args, cwd) {
  const result = spawnSync(program, args, {
    cwd, encoding: 'utf8', timeout: 60_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true,
  });
  return { exit_code: result.status, error: result.error?.message ?? null,
    stdout: result.stdout ?? '', diagnostic: (result.stderr ?? '').slice(-1500) };
}

function parse(result) {
  if (result.exit_code !== 0 || result.error) {
    throw new Error(result.error ?? result.diagnostic ?? 'process failed');
  }
  return JSON.parse(result.stdout);
}

const sortEntries = (items) => items.sort((a, b) => a.path.localeCompare(b.path));
function rustFacts(inspect, files) {
  if (inspect.artifact_kind !== 'chromium_asar_archive' || files.truncated !== false
      || files.total_entries !== files.entries?.length
      || inspect.total_entries !== files.entries?.length) {
    throw new Error('Rust ASAR inventory incomplete or unexpected');
  }
  return { format: 'asar', archive_sha256: inspect.sha256, archive_bytes: inspect.file_size,
    entries: sortEntries(files.entries.map((entry) => ({ path: entry.path, size: entry.size,
      sha256: entry.integrity?.hash }))) };
}

function upstreamFacts(doc) {
  if (doc.operation !== 'inspect_artifact' || doc.normalized_result?.subject?.root_format !== 'asar') {
    throw new Error('Upstream did not produce ASAR inspection Evidence');
  }
  const inventory = doc.normalized_result.substeps?.find((step) => step.operation === 'inventory_artifact');
  const normalized = inventory?.evidence?.normalized_result;
  if (inventory?.status !== 'completed' || normalized?.coverage?.scope !== 'container-entries'
      || normalized.coverage.status !== 'complete' || !Array.isArray(normalized.occurrences)) {
    throw new Error('Upstream ASAR inventory Evidence was not complete');
  }
  const files = normalized.occurrences.filter((entry) => entry.entry_kind === 'file'
    && entry.logical_path !== '.');
  return { format: 'asar', archive_sha256: normalized.manifest.root_sha256,
    archive_bytes: normalized.occurrences.find((entry) => entry.logical_path === '.')?.declared_size,
    entries: sortEntries(files.map((entry) => ({ path: entry.logical_path,
      size: entry.declared_size, sha256: entry.declared_integrity?.digest }))) };
}

function finish(payload, code) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exitCode = code;
}

const upstream = opts.get('upstream');
const binary = opts.get('rust-bin');
if (!upstream || !binary) throw new Error('Provide --rust-bin PATH and --upstream DIR');

const revision = exec('git', ['rev-parse', 'HEAD'], upstream);
if (revision.exit_code !== 0 || revision.stdout.trim() !== expectedUpstream) {
  finish({ scenario: 'asar-basic-archive', status: 'not_comparable',
    reason: 'Missing or unpinned upstream REA', observed_revision: revision.stdout.trim() }, 2);
} else {
  const scratch = mkdtempSync(join(tmpdir(), 'rea-fast-asar-parity-'));
  try {
    const archive = join(scratch, 'basic.asar');
    const packed = parse(exec(binary, ['pack-asar', fixture, archive], root));
    const rustArtifact = parse(exec(binary, ['inspect-artifact', archive], root));
    const rustAsar = parse(exec(binary, ['inspect-asar', archive], root));
    const upstreamDoc = parse(exec(process.execPath, [join(upstream, 'scripts/rea.mjs'),
      'inspect-artifact', archive, '--format', 'json'], upstream));
    const rust = rustFacts(rustArtifact, rustAsar);
    const source = upstreamFacts(upstreamDoc);
    const matched = packed.sha256 === rust.archive_sha256
      && JSON.stringify(rust) === JSON.stringify(source)
      && JSON.stringify(rust) === JSON.stringify(golden);
    finish({ scenario: 'asar-basic-archive', upstream_commit: expectedUpstream,
      scope: 'container SHA-256/bytes and file path/size/declared digest; full Evidence graph excluded',
      status: matched ? 'fixture_match' : 'fixture_mismatch',
      facts: matched ? rust : { rust, upstream: source, golden },
      upstream_parity: 'unverified_outside_listed_facts', performance: 'not_comparable' }, matched ? 0 : 1);
  } catch (error) {
    finish({ scenario: 'asar-basic-archive', status: 'not_comparable', reason: String(error) }, 2);
  } finally {
    // Only the unique directory created above is removed; no user path is touched.
    rmSync(scratch, { recursive: true });
  }
}
