#!/usr/bin/env node
// A task gate is NOT an autonomous code fixer. It makes DONE a measured state
// with platform/commit evidence, and exposes the next incomplete task for an
// agent to fix. No recurring schedule, merge operation, or shell evaluation.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const defaultManifest = join(root, 'quality/task-gates.json');
const validPlatforms = new Set(['linux', 'win32']);

export function validateManifest(manifest) {
  assert.ok(manifest && typeof manifest === 'object');
  assert.equal(manifest.schema_version, 1, 'Unsupported task schema');
  assert.ok(typeof manifest.goal === 'string' && manifest.goal.trim().length > 0);
  assert.ok(Array.isArray(manifest.tasks) && manifest.tasks.length > 0);
  const tasks = new Map();
  for (const task of manifest.tasks) {
    assert.ok(task && typeof task === 'object');
    assert.match(task.id, /^[A-Za-z][A-Za-z0-9.-]*$/);
    assert.ok(!tasks.has(task.id), `Duplicate task: ${task.id}`);
    assert.ok(typeof task.title === 'string' && task.title.trim().length > 0);
    assert.ok(Array.isArray(task.depends_on));
    assert.ok(Array.isArray(task.platforms) && task.platforms.length > 0);
    assert.equal(new Set(task.platforms).size, task.platforms.length);
    for (const platform of task.platforms) assert.ok(validPlatforms.has(platform));
    assert.ok(Array.isArray(task.checks));
    assert.ok(task.checks.length || (typeof task.blocker === 'string' && task.blocker.trim()),
      `${task.id}: empty checks require a blocker`);
    assert.ok(!task.blocker || task.checks.length === 0,
      `${task.id}: a blocked task cannot declare passing checks`);
    for (const check of task.checks) {
      assert.ok(typeof check.name === 'string' && check.name.length > 0);
      assert.ok(Array.isArray(check.argv) && check.argv.length > 0);
      assert.ok(check.argv.every((part) => typeof part === 'string' && part.length > 0));
      assert.ok(typeof check.expect_stdout === 'string' && check.expect_stdout.length > 0);
    }
    tasks.set(task.id, task);
  }
  for (const task of manifest.tasks) {
    assert.equal(new Set(task.depends_on).size, task.depends_on.length);
    for (const dependency of task.depends_on) {
      assert.ok(tasks.has(dependency), `${task.id}: missing dependency ${dependency}`);
      assert.notEqual(dependency, task.id, `${task.id}: self dependency`);
    }
  }
  const done = new Set();
  const visiting = new Set();
  const ordered = [];
  function visit(id) {
    if (done.has(id)) return;
    assert.ok(!visiting.has(id), `Dependency cycle containing ${id}`);
    visiting.add(id);
    for (const dependency of tasks.get(id).depends_on) visit(dependency);
    visiting.delete(id);
    done.add(id);
    ordered.push(tasks.get(id));
  }
  for (const task of manifest.tasks) visit(task.id);
  return ordered;
}

function currentSha() {
  const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
  if (r.error || r.status !== 0) throw Error('Cannot resolve HEAD for task evidence');
  const sha = r.stdout.trim();
  assert.match(sha, /^[0-9a-f]{40}$/);
  return sha;
}

function runCheck(check, platform, executor) {
  const targetRoot = resolve(root, process.env.CARGO_TARGET_DIR ?? 'target');
  const binary = join(targetRoot, 'debug', platform === 'win32' ? 'rea-fast.exe' : 'rea-fast');
  const argv = check.argv.map((part) => part.replaceAll('${REA_FAST_BIN}', binary));
  const result = executor(argv[0], argv.slice(1), {
    cwd: root, encoding: 'utf8', timeout: 180000, maxBuffer: 2 * 1024 * 1024,
    shell: false, windowsHide: true,
  });
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  const ok = !result.error && result.status === 0 && stdout.includes(check.expect_stdout);
  return {
    name: check.name,
    status: ok ? 'PASS' : (result.error?.code === 'ENOENT' ? 'BLOCKED_ENV' : 'FAIL'),
    exit_code: result.status ?? null,
    error: result.error?.message ?? null,
    stdout_tail: stdout.slice(-1200), stderr_tail: stderr.slice(-1200),
  };
}

export function buildLocalReport(manifest, options = {}) {
  const platform = options.platform ?? process.platform;
  const sha = options.sha ?? currentSha();
  const executor = options.executor ?? spawnSync;
  const taskFilter = options.taskFilter ?? null;
  const ordered = validateManifest(manifest);
  assert.ok(validPlatforms.has(platform), `Unsupported platform: ${platform}`);
  if (taskFilter) assert.ok(ordered.some((task) => task.id === taskFilter), 'Unknown --task');
  const required = new Set();
  function requireTask(id) {
    required.add(id);
    for (const dependency of ordered.find((task) => task.id === id).depends_on) requireTask(dependency);
  }
  if (taskFilter) requireTask(taskFilter);
  const statuses = new Map();
  const rows = [];
  for (const task of ordered) {
    let status;
    let checks = [];
    let blocker = null;
    if (taskFilter && !required.has(task.id)) {
      status = 'NOT_EVALUATED';
    } else if (!task.platforms.includes(platform)) {
      status = 'NOT_APPLICABLE';
    } else if (task.blocker) {
      status = 'BLOCKED';
      blocker = task.blocker;
    } else if (task.depends_on.some((id) => statuses.get(id) !== 'PASS_PLATFORM')) {
      status = 'BLOCKED_DEPENDENCY';
      blocker = 'One or more dependencies have not passed on this platform';
    } else {
      checks = task.checks.map((check) => runCheck(check, platform, executor));
      status = checks.every((check) => check.status === 'PASS') ? 'PASS_PLATFORM' :
        checks.some((check) => check.status === 'FAIL') ? 'FAIL' : 'BLOCKED_ENV';
    }
    statuses.set(task.id, status);
    rows.push({ id: task.id, status, checks, blocker });
  }
  return { schema_version: 1, goal: manifest.goal, commit: sha, platform,
    meaning: 'PASS_PLATFORM is NOT globally DONE; aggregate required platforms on the same commit',
    tasks: rows };
}

export function aggregateReports(manifest, reports) {
  const ordered = validateManifest(manifest);
  assert.ok(reports.length > 0, 'Need platform reports');
  const sha = reports[0].commit;
  assert.match(sha, /^[0-9a-f]{40}$/);
  assert.ok(reports.every((report) => report.commit === sha), 'Mixed commits cannot prove DONE');
  const platforms = new Map();
  for (const report of reports) {
    assert.equal(report.schema_version, 1, 'Unexpected report schema');
    assert.equal(report.goal, manifest.goal, 'Report belongs to another goal');
    assert.ok(!platforms.has(report.platform), `Duplicate ${report.platform} report`);
    assert.ok(validPlatforms.has(report.platform));
    assert.ok(Array.isArray(report.tasks), 'Report has no tasks');
    assert.equal(new Set(report.tasks.map((row) => row.id)).size, ordered.length,
      'Report has missing or duplicate tasks');
    assert.ok(report.tasks.every((row) => ordered.some((task) => task.id === row.id)),
      'Report contains an unknown task');
    platforms.set(report.platform, new Map(report.tasks.map((row) => [row.id, row.status])));
  }
  const done = new Set();
  const rows = ordered.map((task) => {
    const checksPassed = !task.blocker && task.checks.length > 0 && task.platforms.every(
      (platform) => platforms.get(platform)?.get(task.id) === 'PASS_PLATFORM');
    const dependenciesDone = task.depends_on.every((id) => done.has(id));
    const status = checksPassed && dependenciesDone ? 'DONE' : 'NOT_DONE';
    if (status === 'DONE') done.add(task.id);
    return { id: task.id, status,
      missing_platforms: task.platforms.filter((platform) => platforms.get(platform)?.get(task.id) !== 'PASS_PLATFORM'),
      blocker: task.blocker ?? null };
  });
  const next = rows.find((row) => row.status !== 'DONE' &&
    ordered.find((task) => task.id === row.id).depends_on.every((id) => done.has(id)));
  return { schema_version: 1, commit: sha,
    status: rows.every((row) => row.status === 'DONE') ? 'GOAL_DONE' : 'GOAL_IN_PROGRESS',
    // A blocker describes the implementation needed, not an excuse to stop.
    // If all executable checks pass, select the first unfinished leaf instead
    // of declaring an idle/complete goal.
    next_task: next?.id ?? null,
    next_action: next?.blocker ? `IMPLEMENT: ${next.blocker}` :
      next ? `VERIFY: ${next.missing_platforms.join(', ')}` : null,
    blocked_backlog: rows.filter((row) => row.status !== 'DONE' && row.blocker).map((row) => row.id),
    tasks: rows };
}

function main() {
  const argv = process.argv.slice(2);
  const arg = (name) => { const i = argv.indexOf(name); return i < 0 ? null : argv[i + 1]; };
  const manifest = JSON.parse(readFileSync(arg('--manifest') ?? defaultManifest, 'utf8'));
  const ordered = validateManifest(manifest);
  if (argv.includes('--validate')) {
    console.log(JSON.stringify({ status: 'valid', goal: manifest.goal, tasks: ordered.length }));
    return;
  }
  let result;
  if (argv.includes('--aggregate')) {
    const i = argv.indexOf('--aggregate');
    const inputs = [];
    for (let n = i + 1; n < argv.length && !argv[n].startsWith('--'); n++) inputs.push(argv[n]);
    result = aggregateReports(manifest, inputs.map((path) => JSON.parse(readFileSync(path, 'utf8'))));
  } else if (argv.includes('--run')) {
    result = buildLocalReport(manifest, { taskFilter: arg('--task') });
  } else {
    throw Error('Usage: --validate | --run [--task ID] [--output path] | --aggregate linux.json windows.json');
  }
  const output = arg('--output');
  if (output) {
    mkdirSync(dirname(resolve(output)), { recursive: true });
    writeFileSync(resolve(output), JSON.stringify(result, null, 2) + '\n');
  }
  console.log(JSON.stringify({ status: result.status ?? 'platform_report', commit: result.commit,
    platform: result.platform ?? null, next_task: result.next_task ?? null,
    passes: result.tasks.filter((row) => row.status === 'DONE' || row.status === 'PASS_PLATFORM').length,
    total: result.tasks.length }));
  // This permits intentionally unfinished M1 tasks to remain visible while
  // ensuring that actual regressions in executable acceptance checks fail CI.
  if (argv.includes('--strict') && result.platform &&
    result.tasks.some((row) => row.status === 'FAIL' || row.status === 'BLOCKED_ENV')) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
