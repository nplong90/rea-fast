#!/usr/bin/env node
// MCP runtime acceptance matrix. A route fixture is NOT upstream parity.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const opt = (flag) => { const i = argv.indexOf(flag); return i < 0 ? null : argv[i + 1]; };
if (!opt('--rust-bin')) throw new Error('Usage: --rust-bin path [--output path]');
const binary = resolve(opt('--rust-bin'));
const output = resolve(opt('--output') || 'acceptance-artifacts/mcp-matrix.json');
const dir = mkdtempSync(join(tmpdir(), 'rea-acceptance-'));
const contractManifest = JSON.parse(readFileSync(fileURLToPath(new URL('route-contracts.json', import.meta.url))));
const routeContracts = new Map(contractManifest.tools.map((tool) => [tool.name, tool]));
const child = spawn(binary, ['mcp'], {
  stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  env: { ...process.env, REA_MCP_PROFILE: 'full' },
});
let errorText = '', id = 0, failure = null;
const pending = new Map(), rows = [], verified = [], extendedRoutes = [];
child.stderr.on('data', (x) => { errorText = (errorText + x).slice(-2048); });
child.on('error', (e) => {
  for (const handler of pending.values()) handler.reject(e);
  pending.clear();
});
child.on('exit', (code) => {
  for (const handler of pending.values()) handler.reject(new Error('MCP exited ' + code + ' ' + errorText));
  pending.clear();
});
createInterface({ input: child.stdout }).on('line', (line) => {
  let response;
  try {
    if (line.length > 12 * 1024 * 1024) throw new Error('MCP response too large');
    response = JSON.parse(line);
  } catch (e) {
    for (const handler of pending.values()) handler.reject(e);
    pending.clear();
    return;
  }
  const h = pending.get(response.id);
  if (h) {
    pending.delete(response.id);
    clearTimeout(h.timer);
    h.resolve(response);
  }
});
const rpc = (method, params) => new Promise((resolveResult, reject) => {
  const requestId = ++id;
  const timer = setTimeout(() => {
    pending.delete(requestId);
    reject(new Error(method + ' timed out ' + errorText));
  }, 30000);
  pending.set(requestId, { resolve: resolveResult, reject, timer });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) + '\n');
});
async function call(name, arguments_, check) {
  const message = await rpc('tools/call', { name, arguments: arguments_ });
  assert.equal(message.error, undefined, name + ': transport failure');
  assert.equal(message.result?.isError, false, name + ': ' + JSON.stringify(message.result));
  const content = message.result?.content?.[0];
  assert.equal(content?.type, 'text', name + ': missing result');
  const value = JSON.parse(content.text);
  assert.notEqual(value.status, 'unavailable', name + ': unavailable');
  assert.notEqual(value.status, 'error', name + ': error');
  check(value);
  verified.push(name);
  return value;
}
function record(name) {
  const entry = rows.find((r) => r.tool === name);
  if (!entry) {
    // Callable additional route, but explicitly not one of the 245 catalog
    // contracts. Never inflate the number of verified catalog entries.
    extendedRoutes.push(name);
    return;
  }
  assert.equal(entry.route, 'native', name + ' misclassified as non-native');
  entry.runtime = 'fixture_exercised';
  entry.proof = 'real_mcp_process_assertions';
}
function storedZip(name, content) {
  const filename = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.write('PK\x03\x04', 0, 'binary');
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(filename.length, 26);

  const central = Buffer.alloc(46);
  central.write('PK\x01\x02', 0, 'binary');
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(filename.length, 28);

  const eocd = Buffer.alloc(22);
  eocd.write('PK\x05\x06', 0, 'binary');
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length + filename.length, 12);
  eocd.writeUInt32LE(local.length + filename.length + content.length, 16);
  return Buffer.concat([local, filename, content, central, filename, eocd]);
}
function keyedArchiveBplist() {
  // Small genuine bplist object graph: top dictionary containing $objects
  // array and $top dictionary. The decoder must resolve object references.
  const ascii = (s) => Buffer.concat([Buffer.from([0x50 + s.length]), Buffer.from(s)]);
  const objects = [
    Buffer.from([0xd2, 1, 2, 3, 4]),  // {$objects: ref 3, $top: ref 4}
    ascii('$objects'), ascii('$top'),
    Buffer.from([0xa2, 5, 6]),  // [$null, fixture]
    Buffer.from([0xd1, 7, 8]),  // {root: 1}
    ascii('$null'), ascii('fixture'), ascii('root'),
    Buffer.from([0x10, 1]),
  ];
  const offsets = [];
  let cursor = 8;
  for (const object of objects) { offsets.push(cursor); cursor += object.length; }
  assert.ok(cursor < 256, 'Fixture uses one-byte plist offsets');
  const trailer = Buffer.alloc(32);
  trailer[6] = 1; trailer[7] = 1;
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(cursor), 24);
  return Buffer.concat([Buffer.from('bplist00'), ...objects, Buffer.from(offsets), trailer]);
}
try {
  const listed = await rpc('tools/list', {});
  assert.equal(listed.result?.tools?.length, 245, 'Full MCP catalog must have 245 entries');
  const result = await call('rea_search_tools', { query: '' }, (data) => {
    assert.equal(data.count, 245);
    assert.equal(data.tools.length, 245);
  });
  const found = new Map(result.tools.map((t) => [t.name, t]));
  assert.equal(found.size, 245, 'Duplicate tool in search result');
  assert.equal(routeContracts.size, 245, 'Versioned contract must include 245 routes');
  for (const t of listed.result.tools) {
    const matching = found.get(t.name);
    assert.ok(matching, 'Missing discovered tool ' + t.name);
    const route = matching.rea_fast_capability?.category;
    assert.ok(['native', 'external-provider', 'unavailable'].includes(route), t.name);
    assert.equal(routeContracts.get(t.name)?.route, route, t.name + ': unexpected routing change');
    assert.equal(matching.rea_fast_capability.upstream_parity, 'not_verified');
    rows.push({ tool: t.name, route, runtime: 'not_tested', upstream_parity: 'not_verified' });
  }
  record('rea_search_tools');
  rows.sort((a, b) => a.tool.localeCompare(b.tool));

  const fixture = join(dir, 'sample.bin');
  const sample = Buffer.from('ACCEPTANCE_MATRIX_STRING_12345\0example\n');
  writeFileSync(fixture, sample);
  const wasm = join(dir, 'sample.wasm');
  writeFileSync(wasm, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  const source = join(dir, 'src');
  mkdirSync(source);
  writeFileSync(join(source, 'main.js'), 'console.log("acceptance");\n');
  const traceSource = join(dir, 'trace-src');
  mkdirSync(traceSource);
  writeFileSync(join(traceSource, 'auth.js'), "export function auth() { return 'secret_token'; }");
  const plist = join(dir, 'sample.plist');
  writeFileSync(plist, '<?xml version="1.0"?><plist><dict><key>purpose</key><string>acceptance</string></dict></plist>');
  const pcapPath = join(dir, 'sample.pcap');
  const globalHeader = Buffer.alloc(24);
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]).copy(globalHeader, 0);
  globalHeader.writeUInt16LE(2, 4); globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeUInt32LE(65535, 16); globalHeader.writeUInt32LE(1, 20);
  const packet = Buffer.alloc(54);
  packet.writeUInt16BE(0x0800, 12); // Ethernet IPv4
  packet[14] = 0x45; packet[23] = 6; // IPv4 + TCP
  packet.set([10, 0, 0, 1, 10, 0, 0, 2], 26);
  packet.writeUInt16BE(1234, 34); packet.writeUInt16BE(80, 36);
  const packetHeader = Buffer.alloc(16);
  packetHeader.writeUInt32LE(packet.length, 8); packetHeader.writeUInt32LE(packet.length, 12);
  writeFileSync(pcapPath, Buffer.concat([globalHeader, packetHeader, packet]));
  const archive = join(dir, 'sample.asar');
  const tauri = join(dir, 'tauri-app.bin');
  writeFileSync(tauri, 'window.__TAURI__ tauri::app invoke("save_document");');
  const electronFuse = join(dir, 'electron-fuse.bin');
  writeFileSync(electronFuse, Buffer.concat([
    Buffer.from([0x7f, 69, 76, 70, 2, 1, 1, 0]),
    Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'),
    Buffer.from([1, 6]), Buffer.from('101011'),
  ]));
  const goBinary = join(dir, 'go-buildinfo.bin');
  writeFileSync(goBinary, Buffer.from('\xff Go buildinf:\ngo1.23.1\nmod\tfixture/module\n', 'latin1'));
  const model = join(dir, 'sample.gguf');
  const modelHeader = Buffer.alloc(24);
  modelHeader.write('GGUF', 0); modelHeader.writeUInt32LE(3, 4);
  modelHeader.writeBigUInt64LE(2n, 8); modelHeader.writeBigUInt64LE(1n, 16);
  writeFileSync(model, modelHeader);
  const il2cpp = join(dir, 'global-metadata.dat');
  const il2cppHeader = Buffer.alloc(16);
  il2cppHeader.writeUInt32LE(0xFAB11BAF, 0); il2cppHeader.writeUInt32LE(29, 4);
  writeFileSync(il2cpp, il2cppHeader);
  const pyc = join(dir, 'fixture.pyc');
  const pycBytes = Buffer.alloc(16);
  pycBytes.writeUInt16LE(3495, 0); pycBytes.set([13, 10], 2);
  writeFileSync(pyc, pycBytes);
  const sqlite = join(dir, 'fixture.sqlite3');
  const sqliteHeader = Buffer.alloc(4096);
  sqliteHeader.write('SQLite format 3\0', 0, 'binary');
  sqliteHeader.writeUInt16BE(4096, 16);
  writeFileSync(sqlite, sqliteHeader);
  const keyedPlist = join(dir, 'keyed.bplist');
  writeFileSync(keyedPlist, keyedArchiveBplist());
  const flutter = join(dir, 'flutter-assets');
  mkdirSync(flutter); mkdirSync(join(flutter, 'lib'));
  writeFileSync(join(flutter, 'lib', 'libflutter.so'), Buffer.from('fixture'));

  await call('analyze_electron_source', {
    path: 'fixture.js', source: "const {ipcMain}=require('electron');ipcMain.handle('matrix:read',()=>1);",
  }, (v) => { assert.equal(v.ipc[0].channel, 'matrix:read'); }); record('analyze_electron_source');
  await call('analyze_javascript_application', {
    input_path: fileURLToPath(new URL('../fixtures/parity/js-basic/', import.meta.url)),
  }, (v) => {
    assert.equal(v.schema, 'JavaScriptApplicationGraph');
    assert.ok(v.nodes.filter((n) => n.kind === 'source-module').length >= 2);
  }); record('analyze_javascript_application');
  await call('scan_secrets', { source: '-----BEGIN OPENSSH PRIVATE KEY-----', path: 'fixture.txt' }, (v) => {
    assert.equal(v.total_secrets, 1);
    assert.ok(!JSON.stringify(v).includes('-----BEGIN OPENSSH PRIVATE KEY-----'));
  }); record('scan_secrets');
  await call('inspect_plist', { path: plist }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.plist.purpose, 'acceptance');
  }); record('inspect_plist');
  await call('inspect_keyed_archive', { path: keyedPlist }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.archiver, 'NSKeyedArchiver');
    assert.equal(v.object_count, 2);
    assert.equal(v.top_refs.root, 1);
    assert.deepEqual(v.sample_objects, ['$null', 'fixture']);
  }); record('inspect_keyed_archive');
  await call('inspect_sqlite_database', { path: sqlite }, (v) => {
    assert.equal(v.is_sqlite, true);
    assert.equal(v.page_size, 4096);
    assert.equal(v.total_tables, 0);
  }); record('inspect_sqlite_database');
  await call('inspect_packet_capture', { path: pcapPath }, (v) => {
    assert.equal(v.is_pcap, true);
    assert.equal(v.total_packets, 1);
    assert.ok(v.protocols.includes('TCP'));
    assert.ok(v.unique_ports.includes(80));
  }); record('inspect_packet_capture');
  await call('compare_artifacts', { left: { x: 1 }, right: { x: 1 } }, (v) => {
    assert.equal(v.identical, true);
  }); record('compare_artifacts');
  const unknown = await call('record_unknown', {
    question: 'Does fixture preserve provenance?', domain: 'mcp-acceptance',
  }, (v) => { assert.equal(v.status, 'open'); }); record('record_unknown');
  await call('update_unknown', {
    unknown_id: unknown.unknown_id, expected_revision: 1, status: 'resolved',
  }, (v) => { assert.equal(v.revision, 2); }); record('update_unknown');
  await call('list_unknowns', { domain: 'mcp-acceptance' }, (v) => {
    assert.ok(v.total >= 1);
  }); record('list_unknowns');
  await call('get_evidence_bundle', { detail: 'summary' }, (v) => {
    assert.equal(v.status, 'complete');
  }); record('get_evidence_bundle');
  const evidenceFile = join(dir, 'evidence.json');
  const exported = await call('export_evidence_bundle', { path: evidenceFile }, (v) => {
    assert.equal(v.status, 'exported');
    assert.ok(existsSync(evidenceFile));
  }); record('export_evidence_bundle');
  await call('import_evidence_bundle', { path: evidenceFile, expected_sha256: exported.sha256 }, (v) => {
    assert.equal(v.status, 'imported');
    assert.ok(v.imported_unknowns >= 1);
  }); record('import_evidence_bundle');
  const otherEvidenceFile = join(dir, 'evidence-other.json');
  const otherEvidence = JSON.parse(readFileSync(evidenceFile, 'utf8'));
  otherEvidence.records.push({ evidence_id: 'fixture-evidence-1', observed: 'new' });
  writeFileSync(otherEvidenceFile, JSON.stringify(otherEvidence));
  await call('compare_bundles', {
    left_bundle_path: evidenceFile, right_bundle_path: otherEvidenceFile,
  }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.identical, false);
    assert.equal(v.evidence_semantic_parity_verified, false);
  }); record('compare_bundles');
  await call('import_evidence_bundle', { path: otherEvidenceFile }, (v) => {
    assert.equal(v.status, 'imported');
    assert.ok(v.imported_records >= 1);
  });
  await call('inspect_analysis_view', {
    source: { evidence_id: 'fixture-evidence-1' }, view: { kind: 'details' },
  }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.view.observed, 'new');
    assert.equal(v.kind, 'details');
  }); record('inspect_analysis_view');
  await call('export_environment_bundle', {}, (v) => {
    assert.equal(v.status, 'ready');
  }); record('export_environment_bundle');
  await call('inspect_binary_layout', { path: binary }, (v) => {
    assert.equal(v.sha256, createHash('sha256').update(readFileSync(binary)).digest('hex'));
    assert.ok(v.total_sections > 0);
  }); record('inspect_binary_layout');
  await call('inspect_byte_entropy', { path: fixture }, (v) => {
    assert.equal(v.total_bytes, sample.length);
  }); record('inspect_byte_entropy');
  const dex = Buffer.from('dex\nacceptance-fixture APK Sig Block 42 should not count as signing');
  const apk = join(dir, 'minimal.apk');
  const stored = storedZip('classes.dex', dex);
  writeFileSync(apk, stored);
  await call('inspect_android_package', { path: apk }, (v) => {
    assert.equal(v.total_files, 1);
    assert.equal(v.dex_files.length, 1);
    assert.equal(v.dex_files[0].size, dex.length);
    assert.equal(v.dex_files[0].sha256, createHash('sha256').update(dex).digest('hex'));
  }); record('inspect_android_package');
  await call('project_android_application_graph', { apk_path: apk }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.total_nodes, 1);
    assert.equal(v.dex_count, 1);
  }); record('project_android_application_graph');
  await call('identify_flutter_build', { path: flutter }, (v) => {
    assert.equal(v.is_flutter, true);
    assert.equal(v.has_libflutter, true);
  }); record('identify_flutter_build');
  await call('inspect_apk_signature', { path: apk }, (v) => {
    assert.equal(v.has_v2_or_v3_signing, false, 'String in DEX must not forge signing block');
    assert.deepEqual(v.detected_scheme_ids, []);
    assert.equal(v.signature_cryptographic_verification, 'not_performed');
  }); record('inspect_apk_signature');
  await call('inspect_signature', { path: apk }, (v) => {
    assert.equal(v.has_v2_or_v3_signing, false);
    assert.equal(v.signature_cryptographic_verification, 'not_performed');
  }); record('inspect_signature');
  // A malformed local header must fail closed; no fabricated empty DEX hash.
  const malformed = Buffer.from(stored);
  malformed.writeUInt16LE(8, 8); // local method disagrees with central method 0
  const brokenApk = join(dir, 'broken.apk');
  writeFileSync(brokenApk, malformed);
  const refused = await rpc('tools/call', { name: 'inspect_android_package', arguments: { path: brokenApk } });
  assert.equal(refused.error, undefined);
  assert.equal(refused.result?.isError, true, 'Malicious APK must not be reported as a success');
  assert.match(refused.result.content[0].text, /ZIP local and central compression methods disagree/);
  await call('list_strings', { path: fixture }, (v) => {
    assert.ok(v.strings.some((x) => x.includes('ACCEPTANCE_MATRIX_STRING_12345')));
  }); record('list_strings');
  await call('search_strings', { path: fixture, query: 'ACCEPTANCE_MATRIX_STRING' }, (v) => {
    assert.equal(v.total_found, 1);
  }); record('search_strings');
  await call('inspect_artifact', { path: fixture }, (v) => {
    assert.equal(v.artifact_kind, 'file');
  }); record('inspect_artifact');
  await call('compare_wasm_interfaces', { left_path: wasm, right_path: wasm }, (v) => {
    assert.equal(v.is_identical, true);
  }); record('compare_wasm_interfaces');
  await call('pack_asar', { source_directory: source, output_path: archive }, () => {
    assert.ok(existsSync(archive));
  }); record('pack_asar');
  await call('inspect_asar', { path: archive }, (v) => {
    assert.equal(v.total_entries, 1);
    assert.equal(v.entries[0].path, 'main.js');
  }); record('inspect_asar');
  const extractedAsar = join(dir, 'extracted-asar');
  await call('extract_artifact', { path: archive, output_directory: extractedAsar }, (v) => {
    assert.equal(v.total_files, 1);
    assert.equal(readFileSync(join(extractedAsar, 'main.js'), 'utf8'), 'console.log("acceptance");\n');
  }); record('extract_artifact');
  const mapFile = join(dir, 'sourcemap.map');
  const extractedMap = join(dir, 'sourcemap-output');
  writeFileSync(mapFile, JSON.stringify({
    version: 3, sources: ['webpack://app/src/main.ts'], sourcesContent: ['export const answer = 42;'],
  }));
  await call('extract_sourcemap', { map_path: mapFile, output_directory: extractedMap }, (v) => {
    assert.equal(v.total_files, 1);
    assert.equal(readFileSync(join(extractedMap, 'app/src/main.ts'), 'utf8'), 'export const answer = 42;');
  }); record('extract_sourcemap');
  const failedOverwrite = await rpc('tools/call', {
    name: 'extract_sourcemap', arguments: { map_path: mapFile, output_directory: extractedMap },
  });
  assert.equal(failedOverwrite.result?.isError, true, 'SourceMap must not overwrite existing outputs');
  assert.equal(readFileSync(join(extractedMap, 'app/src/main.ts'), 'utf8'), 'export const answer = 42;');
  const webpackFile = join(dir, 'webpack-bundle.js');
  writeFileSync(webpackFile, '(self["webpackChunkapp"] = self["webpackChunkapp"] || []).push([["main"],{"./src/index.js":function(module,exports){console.log("recovered");}}]);');
  const recoveredDir = join(dir, 'recovered-bundle');
  await call('recover_javascript_sources', { path: webpackFile, output_directory: recoveredDir }, (v) => {
    assert.ok(v.recovered_modules.length > 0);
    assert.ok(readFileSync(join(recoveredDir, 'src/index.js'), 'utf8').includes('recovered'));
  }); record('recover_javascript_sources');
  await call('run_audit_pipeline', {
    target_path: join(source, 'main.js'), output_dir: join(dir, 'audit-output'),
  }, (v) => {
    assert.ok(v.stages_executed.includes('parallel-ast-analysis'));
    assert.equal(v.target_kind, 'single-source-file');
    assert.ok(v.staging_directory.includes('audit-output'));
  }); record('run_audit_pipeline');
  await call('list_segments', { path: binary }, (v) => {
    assert.ok(v.total_segments > 0);
  }); record('list_segments');
  await call('rea_execute_tool', {
    tool_name: 'compare_artifacts', arguments: { left: { x: 7 }, right: { x: 7 } },
  }, (v) => { assert.equal(v.identical, true); }); record('rea_execute_tool');
  // Expand offline route evidence across WASM, native object metadata,
  // semantic application graph diffing and platform inventory projections.
  await call('inspect_wasm_artifact', { path: wasm }, (v) => {
    assert.equal(v.is_wasm, true);
    assert.equal(v.version, 1);
  }); record('inspect_wasm_artifact');
  await call('inspect_rust_binary', { path: binary }, (v) => {
    assert.equal(typeof v.has_rust_auditable, 'boolean');
  }); record('inspect_rust_binary');
  await call('inspect_go_binary', { path: goBinary }, (v) => {
    assert.equal(v.has_go_buildinfo, true);
    assert.match(v.go_version, /go1\.23\.1/);
  }); record('inspect_go_binary');
  await call('inspect_electron_fuses', { path: electronFuse }, (v) => {
    assert.equal(v.format, 'elf');
    assert.equal(v.slices.length, 1);
    assert.equal(v.slices[0].fuses[0].state, 'enabled');
  }); record('inspect_electron_fuses');
  await call('audit_tauri', { path: tauri, output_dir: join(dir, 'tauri-output') }, (v) => {
    assert.equal(v.info.is_tauri, true);
    assert.ok(v.total_ipc_commands >= 1);
  }); record('audit_tauri');
  await call('inspect_il2cpp_metadata', { path: il2cpp }, (v) => {
    assert.equal(v.is_il2cpp_metadata, true);
    assert.equal(v.version, 29);
  }); record('inspect_il2cpp_metadata');
  await call('inspect_model_artifact', { path: model }, (v) => {
    assert.equal(v.format, 'GGUF');
    assert.equal(v.tensor_count, 2);
    assert.equal(v.metadata_kv_count, 1);
  }); record('inspect_model_artifact');
  await call('inspect_python_pyc', { path: pyc }, (v) => {
    assert.equal(v.is_valid_pyc, true);
    assert.equal(v.python_version_estimate, 'Python 3.12');
  }); record('inspect_python_pyc');
  await call('inspect_desktop_application', { path: source }, (v) => {
    assert.equal(v.framework, 'unknown_native');
  }); record('inspect_desktop_application');
  await call('inspect_managed_artifact', { path: wasm }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.is_managed, false);
  }); record('inspect_managed_artifact');
  await call('inspect_managed_members', { path: wasm }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.total_types, 0);
  }); record('inspect_managed_members');
  await call('inspect_managed_native_boundaries', { path: wasm }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.native_boundaries_count, 0);
  }); record('inspect_managed_native_boundaries');
  await call('trace_dylib_resolution', { path: binary }, (v) => {
    assert.ok(v.format);
    assert.equal(v.total_imported_symbols, v.imports.length);
  }); record('trace_dylib_resolution');
  await call('inspect_macho', { path: binary }, (v) => {
    assert.equal(v.is_macho, false);
    assert.ok(v.file_size > 0);
  }); record('inspect_macho');
  await call('list_architectures', { path: binary }, (v) => {
    assert.equal(v.architecture_count, 1);
    assert.equal(v.architectures.length, 1);
  }); record('list_architectures');
  await call('inspect_native_exports', { path: binary }, (v) => {
    assert.ok(Array.isArray(v.exports));
    assert.equal(v.total_exports, v.exports.length);
  }); record('inspect_native_exports');
  await call('project_apple_application_graph', {
    inventory_evidence: [{ path: '/Applications/Example.app' }, { path: '/Applications/Example.app/Info.plist' }],
  }, (v) => {
    assert.equal(v.status, 'complete');
    assert.equal(v.bundles_count, 2);
    assert.equal(v.plists_count, 1);
  }); record('project_apple_application_graph');
  await call('project_harmony_application_graph', {
    inventory_evidence: [{ path: '/entry/module.json' }, { path: '/entry/ets/modules.abc' }],
  }, (v) => {
    assert.equal(v.platform, 'harmonyos');
    assert.equal(v.packaging_model, 'stage');
    assert.equal(v.modules_count, 1);
    assert.equal(v.ark_bytecode_files.length, 1);
  }); record('project_harmony_application_graph');
  const leftGraph = { modules: [{ path: 'a.js', bytes: 1, lines: 1, exports: ['a'] }], edges: [] };
  const rightGraph = { modules: [{ path: 'a.js', bytes: 2, lines: 2, exports: ['a'] }], edges: [] };
  await call('diff_applications', { left: leftGraph, right: rightGraph }, (v) => {
    assert.equal(v.changed_modules.length, 1);
  }); record('diff_applications');
  await call('compare_application_versions', { left: leftGraph, right: rightGraph }, (v) => {
    assert.equal(v.changed_modules.length, 1);
  }); record('compare_application_versions');
  const shapeLeft = { modules: [{ path: 'lib.js', bytes: 10, lines: 1, exports: ['foo'] }], edges: [] };
  const shapeRight = { modules: [{ path: 'lib.js', bytes: 20, lines: 2, exports: ['foo'] }], edges: [] };
  await call('compare_javascript_export_shapes', {
    left: shapeLeft, left_module_path: 'lib.js', left_export_name: 'foo',
    right: shapeRight, right_module_path: 'lib.js', right_export_name: 'foo',
  }, (v) => {
    assert.equal(v.left_export, 'foo');
    assert.equal(v.status, 'unchanged');
  }); record('compare_javascript_export_shapes');
  await call('compare_source_to_bundle', { reference: leftGraph, application: rightGraph }, (v) => {
    assert.equal(v.changed_modules.length, 1);
  }); record('compare_source_to_bundle');
  await call('trace_application_feature', {
    application: traceSource, seed: { kind: 'string', value: 'auth', match: 'contains', case_sensitive: true },
    direction: 'both',
  }, (v) => {
    assert.ok(v.visited_modules.some((p) => p.endsWith('auth.js')));
  }); record('trace_application_feature');
  await call('trace_feature', {
    application: traceSource, seed: { kind: 'string', value: 'auth', match: 'contains', case_sensitive: true },
    direction: 'both',
  }, (v) => {
    assert.ok(v.visited_modules.some((p) => p.endsWith('auth.js')));
  }); record('trace_feature');
  await call('trace_javascript_semantics', {
    application: 'const x = 42; function foo() { return x; } foo();',
    query: { seed: { kind: 'semantic-node', node_id: 'inline.js:foo' }, direction: 'backward-provenance' },
  }, (v) => { assert.ok(Array.isArray(v.paths)); }); record('trace_javascript_semantics');
  await call('list_procedures', { path: binary, limit: 20 }, (v) => {
    assert.ok(Array.isArray(v.symbols));
    assert.equal(v.total_symbols, v.symbols.length);
  }); record('list_procedures');
  await call('list_names', { path: binary, limit: 20 }, (v) => {
    assert.ok(Array.isArray(v.symbols));
    assert.equal(v.total_symbols, v.symbols.length);
  }); record('list_names');
  assert.equal(rows.length, 245);
  assert.equal(verified.length, 65, '65 successful fixture executions expected');
  for (const row of rows) {
    if (routeContracts.get(row.tool)?.support_tier === 'fixture-backed-candidate') {
      assert.equal(row.runtime, 'fixture_exercised', `${row.tool}: claimed fixture not exercised`);
    }
  }
} catch (e) {
  failure = String(e.stack ?? e);
  process.exitCode = 1;
} finally {
  const tally = (name) => rows.filter((r) => r.route === name).length;
  const summary = {
    status: failure ? 'fixture_failed' : 'partial_acceptance',
    full_product_parity: 'not_verified',
    release_gate: 'blocked_until_full_required_parity',
    git_commit: process.env.GITHUB_SHA || null,
    pr_head: process.env.PR_HEAD_SHA || null,
    platform: process.platform,
    binary_sha256: existsSync(binary) ? createHash('sha256').update(readFileSync(binary)).digest('hex') : null,
    tool_count: rows.length,
    route_counts: { native: tally('native'), 'external-provider': tally('external-provider'), unavailable: tally('unavailable') },
    fixture_exercised: rows.filter((x) => x.runtime === 'fixture_exercised').length,
    additional_routes_exercised: extendedRoutes,
    fixture_executions_total: verified.length,
    unverified: rows.filter((x) => x.runtime !== 'fixture_exercised').length,
    error: failure, tools: rows,
  };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify({
    status: summary.status, tool_count: summary.tool_count,
    route_counts: summary.route_counts, fixture_exercised: summary.fixture_exercised,
    additional_routes_exercised: summary.additional_routes_exercised,
    fixture_executions_total: summary.fixture_executions_total,
    unverified: summary.unverified, error: summary.error,
  }));
  child.kill();
  rmSync(dir, { recursive: true, force: true });
}
