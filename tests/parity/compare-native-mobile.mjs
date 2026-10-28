#!/usr/bin/env node
// Genuine pinned-upstream comparison of intentionally narrow ELF/APK facts.
// Neither side's deep native semantics, Android components, or runtime state
// can be inferred from these container-level matches.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const expectedUpstream = '6de60993b861266e63a4e70d5c6d9a8073f7cd92';
const opt = (flag) => {
  const index = process.argv.indexOf(flag);
  return index < 0 ? null : process.argv[index + 1];
};
const rustBin = opt('--rust-bin');
const upstream = opt('--upstream');
if (!rustBin || !upstream) throw new Error('--rust-bin and --upstream required');

function invoke(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', timeout: 60_000, maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${command}: ${result.error?.message ?? result.stderr?.slice(-1500) ?? result.status}`);
  }
  return JSON.parse(result.stdout);
}

function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zipStored(entries) {
  const locals = [], central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const filename = Buffer.from(name, 'utf8');
    const bytes = Buffer.from(content);
    const digest = crc32(bytes);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(digest, 14);
    local.writeUInt32LE(bytes.length, 18);
    local.writeUInt32LE(bytes.length, 22);
    local.writeUInt16LE(filename.length, 26);
    locals.push(local, filename, bytes);

    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt32LE(digest, 16);
    record.writeUInt32LE(bytes.length, 20);
    record.writeUInt32LE(bytes.length, 24);
    record.writeUInt16LE(filename.length, 28);
    record.writeUInt32LE(offset, 42);
    central.push(record, filename);
    offset += local.length + filename.length + bytes.length;
  }
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}

function upstreamRoot(artifact) {
  assert.equal(artifact.operation, 'inspect_artifact');
  const result = artifact.normalized_result;
  const inventory = result?.substeps?.find((step) => step.operation === 'inventory_artifact');
  assert.equal(inventory?.status, 'completed');
  const details = inventory.evidence?.normalized_result;
  assert.equal(details?.coverage?.status, 'complete');
  assert.equal(details?.manifest?.root_sha256, result.subject.root_sha256);
  return { result, inventory: details };
}

const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: upstream, encoding: 'utf8' });
if (revision.error || revision.status !== 0 || revision.stdout.trim() !== expectedUpstream) {
  console.log(JSON.stringify({ status: 'not_comparable', reason: 'Upstream checkout not pinned' }));
  process.exitCode = 2;
} else {
  const scratch = mkdtempSync(join(tmpdir(), 'rea-fast-mobile-parity-'));
  try {
    const nativePath = '/usr/bin/true';
    const nativeBytes = readFileSync(nativePath);
    const nativeRust = invoke(rustBin, ['inspect-artifact', nativePath], root);
    const nativeRea = upstreamRoot(invoke(process.execPath, [join(upstream, 'scripts/rea.mjs'),
      'inspect-artifact', nativePath, '--format', 'json'], upstream));
    assert.equal(nativeRust.artifact_kind, 'native_binary');
    assert.equal(nativeRust.format.toLowerCase(), 'elf');
    assert.equal(nativeRea.result.subject.root_format, 'elf');
    assert.equal(nativeRust.file_size, nativeBytes.length);
    assert.equal(nativeRea.inventory.occurrences.find((entry) => entry.logical_path === '.')?.declared_size,
      nativeBytes.length);
    assert.equal(nativeRust.sha256, sha(nativeBytes));
    assert.equal(nativeRea.result.subject.root_sha256, sha(nativeBytes));

    const apkPath = join(scratch, 'fixture.apk');
    const dex = Buffer.from('dex\n035\0minimal deterministic fixture', 'utf8');
    const files = [
      ['AndroidManifest.xml', Buffer.from('<manifest package="dev.rea.fixture"/>')],
      ['classes.dex', dex],
    ];
    const apkBytes = zipStored(files);
    writeFileSync(apkPath, apkBytes);
    const mobileRust = invoke(rustBin, ['inspect-apk', apkPath], root);
    const mobileRootRust = invoke(rustBin, ['inspect-artifact', apkPath], root);
    const mobileRea = upstreamRoot(invoke(process.execPath, [join(upstream, 'scripts/rea.mjs'),
      'inspect-artifact', apkPath, '--format', 'json'], upstream));
    assert.equal(mobileRootRust.artifact_kind, 'android_apk');
    assert.equal(mobileRust.total_files, files.length);
    assert.equal(mobileRust.dex_files.length, 1);
    assert.equal(mobileRust.dex_files[0].name, 'classes.dex');
    assert.equal(mobileRust.dex_files[0].sha256, sha(dex));
    assert.equal(mobileRootRust.sha256, sha(apkBytes));
    assert.equal(mobileRea.result.subject.root_sha256, sha(apkBytes));
    const upstreamPaths = mobileRea.inventory.occurrences
      .filter((entry) => entry.logical_path !== '.')
      .map((entry) => entry.logical_path).sort();
    assert.deepEqual(upstreamPaths, files.map(([name]) => name).sort());
    console.log(JSON.stringify({
      status: 'fixture_match', upstream_commit: expectedUpstream,
      scenarios: [
        { id: 'elf-root', sha256: sha(nativeBytes), bytes: nativeBytes.length,
          matched: ['root sha256', 'root bytes', 'ELF format'] },
        { id: 'android-zip-inventory', sha256: sha(apkBytes),
          entries: upstreamPaths, matched: ['root sha256', 'ZIP member names', 'DEX digest in Rust'] },
      ],
      excluded: ['native deep analysis', 'Android manifest semantics', 'DEX execution',
        'full upstream Evidence graph', 'runtime/device-backed ADB'],
    }, null, 2));
  } catch (error) {
    console.log(JSON.stringify({ status: 'not_comparable', reason: String(error) }));
    process.exitCode = 2;
  } finally {
    rmSync(scratch, { recursive: true });
  }
}
