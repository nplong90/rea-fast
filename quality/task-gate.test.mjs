import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateReports, buildLocalReport, validateManifest } from './task-gate.mjs';

const SHA = 'a'.repeat(40);
const SHA_OTHER = 'b'.repeat(40);

function task(id, { platforms = ['linux', 'win32'], depends_on = [], blocker = null } = {}) {
  return {
    id, title: id, platforms, depends_on,
    checks: blocker ? [] : [{ name: 'check', argv: ['checker'], expect_stdout: 'VERIFIED' }],
    ...(blocker ? { blocker } : {}),
  };
}

function manifest(tasks = [task('first'), task('second', { depends_on: ['first'] })]) {
  return { schema_version: 1, goal: 'test-only', tasks };
}

const success = () => ({ stdout: 'VERIFIED', stderr: '', status: 0 });
const failure = () => ({ stdout: 'VERIFIED', stderr: 'bad exit', status: 1 });

test('rejects duplicate IDs, unknown dependencies, cycles, and untested assertions', () => {
  assert.throws(() => validateManifest(manifest([task('a'), task('a')])), /Duplicate/);
  assert.throws(() => validateManifest(manifest([task('a', { depends_on: ['missing'] })])), /missing dependency/);
  assert.throws(() => validateManifest(manifest([
    task('a', { depends_on: ['b'] }), task('b', { depends_on: ['a'] }),
  ])), /cycle/);
  const noChecks = task('a');
  noChecks.checks = [];
  assert.throws(() => validateManifest(manifest([noChecks])), /empty checks/);
  const deceptive = task('a');
  deceptive.blocker = 'still blocked';
  assert.throws(() => validateManifest(manifest([deceptive])), /blocked task/);
});

test('a successful local Linux check never becomes a two-platform DONE', () => {
  const m = manifest([task('first')]);
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success });
  assert.equal(linux.tasks[0].status, 'PASS_PLATFORM');
  const combined = aggregateReports(m, [linux]);
  assert.equal(combined.status, 'GOAL_IN_PROGRESS');
  assert.equal(combined.tasks[0].status, 'NOT_DONE');
  assert.deepEqual(combined.tasks[0].missing_platforms, ['win32']);
  assert.equal(combined.next_task, 'first');
});

test('all checks and dependencies on both platforms and exact SHA permit DONE', () => {
  const m = manifest();
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success });
  const windows = buildLocalReport(m, { platform: 'win32', sha: SHA, executor: success });
  const combined = aggregateReports(m, [linux, windows]);
  assert.equal(combined.status, 'GOAL_DONE');
  assert.deepEqual(combined.tasks.map((row) => row.status), ['DONE', 'DONE']);
  assert.equal(combined.next_task, null);
});

test('cross-platform task may depend on separately verified Linux-only and Windows-only gates', () => {
  const m = manifest([
    task('linux-only', { platforms: ['linux'] }),
    task('windows-only', { platforms: ['win32'] }),
    task('both', { depends_on: ['linux-only', 'windows-only'] }),
  ]);
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success });
  const windows = buildLocalReport(m, { platform: 'win32', sha: SHA, executor: success });
  assert.deepEqual(linux.tasks.map((row) => row.status),
    ['PASS_PLATFORM', 'NOT_APPLICABLE', 'PASS_PLATFORM']);
  assert.deepEqual(windows.tasks.map((row) => row.status),
    ['NOT_APPLICABLE', 'PASS_PLATFORM', 'PASS_PLATFORM']);
  assert.deepEqual(aggregateReports(m, [linux, windows]).tasks.map((row) => row.status),
    ['DONE', 'DONE', 'DONE']);
});

test('mixed commits and malformed, incomplete reports are rejected', () => {
  const m = manifest([task('first')]);
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success });
  const windows = buildLocalReport(m, { platform: 'win32', sha: SHA_OTHER, executor: success });
  assert.throws(() => aggregateReports(m, [linux, windows]), /Mixed commits/);
  windows.commit = SHA;
  assert.throws(() => aggregateReports(m, [linux, linux]), /Duplicate linux/);
  const tampered = { ...windows, tasks: [] };
  assert.throws(() => aggregateReports(m, [linux, tampered]), /missing or duplicate/);
});

test('failed or unavailable command cannot satisfy DONE and blocks downstream', () => {
  const m = manifest();
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: failure });
  assert.equal(linux.tasks[0].status, 'FAIL');
  assert.equal(linux.tasks[1].status, 'BLOCKED_DEPENDENCY');
  const windows = buildLocalReport(m, { platform: 'win32', sha: SHA,
    executor: () => ({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }) }) });
  assert.equal(windows.tasks[0].status, 'BLOCKED_ENV');
  const combined = aggregateReports(m, [linux, windows]);
  assert.equal(combined.status, 'GOAL_IN_PROGRESS');
  assert.equal(combined.tasks.filter((row) => row.status === 'DONE').length, 0);
});

test('explicit blockers stay open and become the next implementation task', () => {
  const m = manifest([
    task('gate'),
    task('blocked', { depends_on: ['gate'], blocker: 'manual proof missing' }),
    task('actionable', { depends_on: ['gate'] }),
  ]);
  const linux = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success });
  const windows = buildLocalReport(m, { platform: 'win32', sha: SHA, executor: success });
  const combined = aggregateReports(m, [linux, windows]);
  assert.deepEqual(combined.tasks.map((row) => row.status), ['DONE', 'NOT_DONE', 'DONE']);
  assert.deepEqual(combined.blocked_backlog, ['blocked']);
  assert.equal(combined.next_task, 'blocked');
  assert.match(combined.next_action, /^IMPLEMENT: manual proof missing/);
});

test('task filter cannot claim unrelated tasks were evaluated', () => {
  const m = manifest([task('first'), task('unrelated')]);
  const report = buildLocalReport(m, { platform: 'linux', sha: SHA, executor: success, taskFilter: 'first' });
  assert.equal(report.tasks[0].status, 'PASS_PLATFORM');
  assert.equal(report.tasks[1].status, 'NOT_EVALUATED');
});
