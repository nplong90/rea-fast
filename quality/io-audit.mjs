#!/usr/bin/env node
// Reviewable direct-input allocation inventory. This is a drift tripwire,
// not a substitute for runtime stress tests or an AST-based security proof.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = join(root, 'src');
const expected = new Map([
  ['analyze.rs', [1, 'file.take(limit + 1)']],
  ['asar.rs', [1, 'file.take(MAX_ASAR_ENTRY_BYTES + 1)']],
  ['evidence.rs', [2, 'MAX_EVIDENCE_BUNDLE_BYTES + 1']],
  ['mcp.rs', [1, 'MAX_LOCAL_ARTIFACT_BYTES + 1']],
  ['mobile.rs', [2, 'MAX_ZIP_ENTRY_BYTES + 1']],
  ['native_binary.rs', [2, 'MAX_RUST_METADATA_BYTES + 1']],
  ['security_io.rs', [1, 'file.take(limit + 1)']],
  ['tauri.rs', [1, '16 * 1024 * 1024 + 1']],
  ['tcp_driver.rs', [1, '.take(limit as u64 + 1)']],
]);

const files = readdirSync(source).filter((file) => file.endsWith('.rs')).sort();
let reviewed = 0;
for (const file of files) {
  const text = readFileSync(join(source, file), 'utf8');
  // Unit-test-only direct file reads are acceptable fixture assertions.
  const production = text.split(/\n#\[cfg\(test\)\]\s*\nmod tests\s*\{/)[0];
  assert.equal((production.match(/(?:std::)?fs::read(?:_to_string)?\s*\(/g) ?? []).length, 0,
    `Unbounded fs::read in production ${file}; add a bounded reader and review`);
  assert.equal((production.match(/\.output\s*\(/g) ?? []).length, 0,
    `Unbounded child .output in production ${file}; drain pipes with limits`);

  const count = (production.match(/\.read_to_(?:end|string)\s*\(/g) ?? []).length;
  const [allowed, marker] = expected.get(file) ?? [0, null];
  assert.equal(count, allowed,
    `Direct Read allocation inventory drift in ${file}: expected ${allowed}, found ${count}`);
  if (marker) assert.ok(production.includes(marker), `Missing resource bound in ${file}: ${marker}`);
  reviewed += count;
}
for (const file of expected.keys()) assert.ok(files.includes(file), `Missing reviewed source: ${file}`);
assert.equal(reviewed, 12);
console.log(`Verified direct I/O inventory in ${files.length} Rust modules (${reviewed} bounded bulk readers)`);
