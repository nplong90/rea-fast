#!/usr/bin/env node
// Versioned, reproducible *routing* contract. It is deliberately not proof
// of upstream parity or an assertion that every catalog tool is supported.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const path = join(root, 'tests/acceptance/route-contracts.json');
const catalog = JSON.parse(gunzipSync(readFileSync(join(root, 'src/catalog.gz')))).tools;
const catalogSource = readFileSync(join(root, 'src/catalog.rs'), 'utf8');
const capabilitySource = readFileSync(join(root, 'src/capabilities.rs'), 'utf8');
const acceptanceSource = readFileSync(join(root, 'tests/acceptance/mcp-matrix.mjs'), 'utf8');

const sliceBetween = (text, start, end) => {
  const a = text.indexOf(start);
  const b = text.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, `Cannot identify source section: ${start}`);
  return text.slice(a, b);
};
const named = (text) => [...text.matchAll(/"name":\s*"([a-z][a-z0-9_]+)"/g)].map((m) => m[1]);
const quotedNames = (text) => [...text.matchAll(/"([a-z][a-z0-9_]+)"/g)].map((m) => m[1]);
const extra = named(sliceBetween(catalogSource, 'fn extra_native_tools()', '/// Load and merge catalog'));
const meta = named(sliceBetween(catalogSource, 'fn meta_tools()', '/// Sanitize tool schema'));
const native = new Set(quotedNames(sliceBetween(capabilitySource, 'match name {', '=> Native,')));
const external = new Set(quotedNames(sliceBetween(capabilitySource, '=> Native,', '=> External,')));
const fixtures = new Set([...acceptanceSource.matchAll(/\brecord\('([a-z][a-z0-9_]+)'\)/g)].map((m) => m[1]));

const provider = (name) => {
  if (/adb|android_device|android_package/.test(name)) return 'adb';
  if (/gdb/.test(name)) return 'gdb';
  if (/rizin/.test(name)) return 'rizin';
  if (/frida/.test(name)) return 'frida';
  if (/jeb/.test(name)) return 'jeb';
  if (/sigrok|signal_recording/.test(name)) return 'sigrok';
  if (/jadx|apktool/.test(name)) return 'jadx-or-apktool';
  if (/cdp|browser|web_page|web_script|screenshot|electron_page|electron_target/.test(name)) return 'cdp';
  if (/objdump/.test(name)) return 'objdump';
  if (/swift/.test(name)) return 'swift-toolchain';
  if (/live_process/.test(name)) return 'operating-system-process-interface';
  return 'external-provider-unspecified';
};

const all = [...catalog.map((tool) => tool.name), ...extra, ...meta];
assert.equal(new Set(all).size, 245, 'Catalog/extra/meta routes must be unique');
const entries = all.sort().map((name) => {
  const route = native.has(name) ? 'native' : external.has(name) ? 'external-provider' : 'unavailable';
  const hasFixture = fixtures.has(name);
  if (hasFixture) assert.equal(route, 'native', `Fixture misclassified: ${name}`);
  return {
    name,
    route,
    support_tier: hasFixture ? 'fixture-backed-candidate' : route === 'native' ? 'experimental' : route === 'external-provider' ? 'provider-dependent' : 'unavailable',
    required_provider: route === 'external-provider' ? provider(name) : null,
    platform: route === 'external-provider' ? 'provider-and-host-dependent' : 'cross-platform-not-yet-certified',
    evidence_contract: hasFixture ? 'black-box-MCP-assertions-only' : 'unverified',
    upstream_parity: 'not_verified',
  };
});
assert.equal(entries.filter((x) => x.route === 'native').length, 63);
assert.equal(entries.filter((x) => x.route === 'external-provider').length, 53);
assert.equal(entries.filter((x) => x.route === 'unavailable').length, 129);
assert.equal(entries.filter((x) => x.support_tier === 'fixture-backed-candidate').length, 63);

const manifest = {
  schema_version: 1,
  scope: 'M1-partial-not-upstream-drop-in',
  upstream_commit: '6de60993b861266e63a4e70d5c6d9a8073f7cd92',
  notice: 'A route and a passing narrow fixture do not establish full upstream parity.',
  tools: entries,
};
const output = JSON.stringify(manifest, null, 2) + '\n';
if (process.argv.includes('--write')) {
  writeFileSync(path, output);
  console.log(`Wrote ${entries.length} routes to ${path}`);
} else if (process.argv.includes('--check')) {
  assert.equal(readFileSync(path, 'utf8'), output, 'Route contract is stale; regenerate with --write');
  console.log(`Verified ${entries.length} versioned contracts`);
} else {
  throw new Error('Usage: node tests/acceptance/contracts.mjs --write|--check');
}
