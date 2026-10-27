#!/usr/bin/env node
/** Stage traceable, verified candidate binaries without publishing a release. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const extension = process.platform === 'win32' ? '.exe' : '';
const name = `rea-fast${extension}`;
const source = join(root, 'target', 'release', name);
const output = join(root, 'dist-ci');
const destination = join(output, name);
mkdirSync(output, { recursive: true });
assert.ok(statSync(source).isFile(), 'Release executable is missing');
copyFileSync(source, destination);
const version = spawnSync(destination, ['--version'], {
  encoding: 'utf8', timeout: 15000, windowsHide: true,
});
assert.equal(version.error, undefined, String(version.error));
assert.equal(version.status, 0, version.stderr);
assert.match(version.stdout, /rea-fast\s+0\.1\.0/);
const data = readFileSync(destination);
const digest = createHash('sha256').update(data).digest('hex');
const manifest = {
  status: 'candidate_only',
  verification: 'binary --version passed; production parity not verified',
  git_commit: process.env.GITHUB_SHA ?? 'local-unpinned',
  operating_system: process.platform,
  architecture: process.arch,
  file: name,
  bytes: data.length,
  sha256: digest,
  version: version.stdout.trim(),
};
writeFileSync(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
process.stdout.write(JSON.stringify(manifest) + '\n');
