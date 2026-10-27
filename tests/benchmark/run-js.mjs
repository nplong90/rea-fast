#!/usr/bin/env node
/**
 * Opt-in, correctness-gated matched-task benchmark for pinned upstream REA.
 * Never report a speedup if even one run fails the golden-parity assertion.
 * Linux GNU time: direct command CPU/RSS, not complete descendant tree.
 * Usage: node tests/benchmark/run-js.mjs --rust-bin /abs/rea-fast --upstream /abs/rea
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeRust, normalizeUpstream, expectedUpstream, fixture, golden } from '../parity/compare-js.mjs';

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const EXPECTED = JSON.stringify(golden);
const TIME = '/usr/bin/time';
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
const args = process.argv.slice(2);
const option = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const report = (value, exit = 0) => {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
  process.exitCode = exit;
};
const parseTime = (text) => {
  const line = text.trim().split(/\r?\n/).find((l) => l.startsWith('rea-time '));
  if (!line) throw new Error('Missing GNU time resource measurements');
  const fields = line.split(' ');
  if (fields.length !== 5) throw new Error('Incomplete resource measurements');
  const [wall, user, sys, rssKiB] = fields.slice(1).map(Number);
  if (![wall, user, sys, rssKiB].every(Number.isFinite) || wall < 0 || user < 0 || sys < 0 || rssKiB < 1) {
    throw new Error('Invalid GNU time resource measurements');
  }
  return { elapsed_seconds: wall, user_cpu_seconds: user, system_cpu_seconds: sys, max_rss_kib_direct_command: rssKiB };
};
const matchFacts = (rust, upstream) => {
  const r = JSON.stringify(rust);
  return r === JSON.stringify(upstream) && r === EXPECTED;
};
if (args.includes('--self-test')) {
  assert.deepEqual(parseTime('rea-time 1.20 0.40 0.10 4096\n'), {
    elapsed_seconds: 1.2, user_cpu_seconds: 0.4,
    system_cpu_seconds: 0.1, max_rss_kib_direct_command: 4096,
  });
  assert.throws(() => parseTime(''), /Missing GNU time/);
  assert.throws(() => parseTime('rea-time 1.0 0 0 0'), /Invalid GNU time/);
  assert.ok(matchFacts(golden, structuredClone(golden)));
  assert.equal(matchFacts(golden, []), false);
  report({ status: 'pass', scenario: 'benchmark-parser-and-parity-gate-self-test' });
} else {
  const upstream = option('--upstream');
  const rustBin = option('--rust-bin');
  const warmCount = option('--warm-runs') === undefined ? 5 : Number(option('--warm-runs'));
  if (!upstream || !rustBin || !Number.isInteger(warmCount) || warmCount < 3 || warmCount > 20) {
    throw new Error('Provide --rust-bin ABS_PATH --upstream ABS_PATH [--warm-runs 3..20]');
  }
  const nonComparable = (reason, more = {}) => report({
    status: 'not_comparable', reason, upstream_commit: expectedUpstream,
    scenario: 'js-basic-static-module-facts', ...more,
  }, 2);
  if (process.platform !== 'linux') {
    nonComparable('Resource metrics require Linux GNU time on the same host');
  } else {
    const revision = spawnSync('git', ['rev-parse', 'HEAD'], {
      cwd: upstream, encoding: 'utf8', timeout: 15000,
    });
    if (revision.status !== 0 || revision.stdout?.trim() !== expectedUpstream) {
      nonComparable('Pinned upstream checkout is absent or has a different HEAD');
    } else {
      const dir = mkdtempSync(join(tmpdir(), 'rea-parity-bench-'));
      try {
        const binary = resolve(rustBin);
        const cmds = {
          rust: [binary, 'analyze', fixture, '--format', 'json'],
          upstream: [process.execPath, join(resolve(upstream), 'scripts/rea.mjs'),
            'analyze-javascript-application', fixture, '--format', 'json'],
        };
        const run = (implementation, phase, sample) => {
          const [program, ...argv] = cmds[implementation];
          const timings = join(dir, `${implementation}-${phase}-${sample}.txt`);
          const started = process.hrtime.bigint();
          const proc = spawnSync(TIME, ['-f', 'rea-time %e %U %S %M', '-o', timings,
            '--', program, ...argv], {
            cwd: implementation === 'rust' ? root : resolve(upstream),
            encoding: 'utf8', timeout: 90_000, maxBuffer: MAX_OUTPUT_BYTES,
            windowsHide: true,
          });
          const wall_ns = Number(process.hrtime.bigint() - started);
          if (proc.error || proc.status !== 0 || !proc.stdout) {
            throw new Error(`${implementation} ${phase} #${sample}: process did not complete (${proc.error?.message ?? proc.stderr?.slice(-350)})`);
          }
          const json = JSON.parse(proc.stdout);
          const facts = implementation === 'rust' ? normalizeRust(json) : normalizeUpstream(json);
          return { phase, sample, facts, wall_ms: wall_ns / 1e6,
            stdout_bytes: Buffer.byteLength(proc.stdout),
            ...parseTime(readFileSync(timings, 'utf8')) };
        };
        const samples = [];
        for (let sample = 0; sample <= warmCount; sample++) {
          // Alternate order to avoid always giving one program warmed caches.
          const order = sample % 2 ? ['upstream', 'rust'] : ['rust', 'upstream'];
          const entries = {};
          for (const implementation of order) {
            entries[implementation] = run(implementation, sample === 0 ? 'first' : 'subsequent', sample);
          }
          if (!matchFacts(entries.rust.facts, entries.upstream.facts)) {
            throw new Error(`Output mismatch at sample ${sample}; measurement invalid`);
          }
          for (const implementation of ['rust', 'upstream']) {
            const { facts, ...measurement } = entries[implementation];
            samples.push({ implementation, ...measurement });
          }
        }
        const median = (values) => {
          const ordered = [...values].sort((a, b) => a - b);
          return ordered[Math.floor(ordered.length / 2)];
        };
        const summary = Object.fromEntries(['rust', 'upstream'].map((id) => {
          const warm = samples.filter((x) => x.implementation === id && x.phase === 'subsequent');
          const first = samples.find((x) => x.implementation === id && x.phase === 'first');
          return [id, {
            first_wall_ms: first.wall_ms,
            subsequent_wall_median_ms: median(warm.map((x) => x.wall_ms)),
            subsequent_cpu_median_seconds: median(warm.map((x) => x.user_cpu_seconds + x.system_cpu_seconds)),
            subsequent_max_rss_median_kib: median(warm.map((x) => x.max_rss_kib_direct_command)),
            subsequent_stdout_median_bytes: median(warm.map((x) => x.stdout_bytes)),
          }];
        }));
        report({
          status: 'measured_equivalent_subset',
          scope: 'source-module paths, SHA-256, static imports, exports only',
          upstream_commit: expectedUpstream,
          warning: 'Direct-child peak RSS only; no full process-family peak. First run is not a cleared OS-cache cold start. Full P5 remains open.',
          environment: { platform: process.platform, arch: process.arch, node: process.version },
          warm_runs: warmCount, summary, samples,
          no_full_rea_parity_claim: true,
        });
      } catch (error) {
        nonComparable(String(error));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  }
}
