# rea-fast

High-performance, zero-execution reverse-engineering engine and static analysis toolkit for JavaScript, TypeScript, Electron, and ASAR archives. Built natively in Rust.

`rea-fast` delivers the complete analytical capabilities of `@rea/core` with native speed and minimal resource usage:
- **200x faster startup**: ~10ms vs ~2.0s
- **320x faster ASAR inspection**: ~40ms vs ~12.8s
- **90x lower memory footprint**: ~4-34MB vs ~270-500MB+ RAM

---

## Features

- **Zero-Execution Architecture**: Pure AST parsing (`oxc_parser`) and structural byte inspection. Executes zero target code. Safe for untrusted artifacts.
- **Chromium Pickle ASAR Inspection & Safe Extraction**: Fast header parsing, direct offsets, random access file I/O, SHA-256 integrity verification, and directory traversal defense.
- **Electron Fuse Detection**: Scans 32-byte sentinel patterns across ELF, PE, and Mach-O binaries to extract all 9 Electron fuses without runtime launching.
- **AST-Based Bundle Recovery**: Unbundles Webpack chunks, Webpack IIFE, Browserify, and esbuild CommonJS wrappers into structured directories.
- **Semantic & Feature Tracing**: Cross-module BFS reachability tracing across imports, exports, functions, IPC events, and API boundaries.
- **Export Shape Comparison**: Structural JSON pointer diffing between module versions.
- **Dual Interface**:
  - Full CLI with 28 subcommands.
  - Standard Model Context Protocol (MCP) JSON-RPC 2.0 stdio server (`spec 2024-11-05`) exposing 29 RE tools.
- **Chromium Pickle ASAR Repacker**: Pack directory into standard ASAR archive with 512 KiB block-level SHA-256 integrity hashing and 4-byte pickle alignment.
- **High-Entropy Secrets & API Discovery**: Scans codebases for leaked tokens (AWS, GitHub, Slack, Stripe, JWT, Private Keys) with non-leaking redaction and discovers API route endpoints.
- **Tauri Application Auditor**: Fingerprint v1/v2 Tauri desktop binaries, extract embedded `tauri.conf.json` via balanced-brace slice parser, recover embedded HTML/Brotli assets, and audit `invoke`/`listen`/`emit` IPC commands.
- **Multi-Format Native Binary Inspector**: Header, section, symbol, and import extraction for ELF, PE, and Mach-O executables without execution.
- **Go BuildInfo & Module Extractor**: Pure byte-scanning of `\xff Go buildinf:` to discover compiler versions, main modules, and dependency trees.
- **Rust Auditable Inspector**: Decompression of `.dep-v0` sections to parse embedded cargo auditable dependency manifests and `/rustc/` commit hashes.
- **WebAssembly Inspector**: Validates `\0asm` binaries, LEB128 lengths, section catalog, imports, and exports.
- **Android APK & AXML Dissector**: In-tree zero-dependency ZIP parser, DEX hashing, native library catalog, and AXML string pool extraction for permissions, activities, and services.
- **SQLite Database Inspector**: Zero-execution SQLite format 3 verification, page size, change counter, and schema DDL extraction.
- **Network PCAP/PCAPNG Dissector**: Header and packet dissection for standard/nanosecond PCAP and PCAPNG, extracting IPv4, IPv6, TCP, UDP, ICMP, and port lists.
- **Dynamic Runtime & Bridge Introspection**: Zero-dependency raw TCP Chrome/Electron CDP client, Android ADB device/properties/package inspection with emulator heuristics, and host `/proc` memory/thread/library live inspection.

---

## Installation & Build

Requires Rust toolchain (1.80+ recommended):

```bash
cargo build --release
```

The compiled binary will be placed at `./target/release/rea-fast`.

---

## CLI Usage

### 1. Parallel AST Analysis
Analyze JS/TS codebases or ASAR archives in parallel:
```bash
rea-fast analyze ./path/to/project --format summary
rea-fast analyze ./path/to/app.asar --format json
```

### 2. Electron Fuse Inspection
Inspect hardened runtime configurations and fuses in native Electron binaries:
```bash
rea-fast fuses /path/to/electron_binary
```

### 3. ASAR Inspection & Extraction
Inspect directory headers or safely extract contents:
```bash
# Header inspection without unpacking
rea-fast inspect-asar /path/to/app.asar

# Extract with integrity check
rea-fast extract /path/to/app.asar -o ./output --integrity-policy fail
```

### 4. Bundle Recovery
Recover readable source files from minified bundles:
```bash
rea-fast recover bundle.js -o ./decompiled_modules --extraction-mode structural --rewrite-level standard
```

### 5. Application Diffing
Compare two application graphs or paths:
```bash
rea-fast diff left_app/ right_app/
```

### 6. Feature & Semantic Tracing
Trace data flows and feature reachability:
```bash
rea-fast trace-feature app.json --kind string --value "auth_token" --direction both
rea-fast trace-semantics app.json --node-id "fn:handleLogin" --direction forward-influence
```

### 7. Electron Security Analysis
Scan Electron codebase for IPC risks and dangerous configurations:
```bash
rea-fast analyze-electron ./src
```

### 8. SourceMap v3 Reconstruction
Extract original source trees from `.map` files or inline base64 comments:
```bash
rea-fast sourcemap bundle.js.map -o ./extracted_sources
```

### 9. ASAR Archive Packing
Pack a folder into a Chromium Pickle ASAR archive with block hashing:
```bash
rea-fast pack-asar ./src_dir ./output.asar
```

### 10. High-Entropy Secret & Endpoint Scanning
Scan code or directories for leaked API credentials and API endpoints:
```bash
# Scan folder or file
rea-fast secrets ./src
# Scan inline string
rea-fast secrets --source 'const token = "AKIA1234567890ABCDEF";'
```

### 11. Tauri Application Audit
Audit Tauri binaries for framework signatures, embedded config, and IPC calls:
```bash
rea-fast audit-tauri /path/to/tauri_app -o ./extracted_assets
```

### 12. Automated Audit Pipeline
Execute complete multi-stage automated audit on any target (ASAR, binary, bundle, or source tree):
```bash
rea-fast audit /path/to/app.asar -o ./audit_workspace
```

### 13. Native Binary Dissection
Inspect ELF, PE, or Mach-O sections, symbols, and dynamic imports:
```bash
rea-fast inspect-binary /path/to/binary
```

### 14. Go BuildInfo & Dependency Extraction
Extract Go version, main module, and dependencies:
```bash
rea-fast inspect-go /path/to/go_binary
```

### 15. Rust Cargo-Auditable Inspection
Extract cargo-auditable crate dependency graph and rustc commit:
```bash
rea-fast inspect-rust /path/to/rust_binary
```

### 16. WebAssembly Inspection
Inspect WASM sections, imports, and exports:
```bash
rea-fast inspect-wasm /path/to/module.wasm
```

### 17. Android APK & AXML Dissection
Hash DEX files, list native ABIs, and extract manifest permissions/components:
```bash
rea-fast inspect-apk /path/to/app.apk
```

### 18. SQLite Database Inspection
Verify database headers, page configuration, and schema DDL tables:
```bash
rea-fast inspect-sqlite /path/to/database.db
```

### 19. Network Packet Capture Dissection
Dissect PCAP/PCAPNG packets, endpoints, ports, and protocol distributions:
```bash
rea-fast inspect-pcap /path/to/capture.pcap
```

### 20. Chrome / Electron CDP Target Discovery
Query loopback Chrome or Electron CDP endpoints:
```bash
rea-fast list-cdp-targets --endpoint http://127.0.0.1:9222
rea-fast list-electron-targets --endpoint http://127.0.0.1:9222
```

### 21. Android ADB Device & Package Inspection
Inspect connected devices, system properties, and installed packages via ADB:
```bash
rea-fast list-adb-devices
rea-fast inspect-adb-device --serial emulator-5554
rea-fast list-adb-packages --third-party
```

### 22. Live Host Process & Memory Introspection
Inspect host processes, memory metrics (VmRSS/VmSize), thread counts, and mapped `.so` libraries:
```bash
rea-fast list-processes --filter electron
rea-fast inspect-process 12345
```

---

## Model Context Protocol (MCP) Integration

`rea-fast` can serve as an MCP server for Claude Code, Cursor, or any MCP-compatible client.

Run directly via CLI flag or subcommand:
```bash
rea-fast --mcp
# or
rea-fast mcp
```

### Claude Desktop / Claude Code Config (`mcpServers`)
```json
{
  "mcpServers": {
    "rea": {
      "command": "/path/to/rea-fast",
      "args": ["--mcp"]
    }
  }
}
```

### Exposed MCP Tools
1. `analyze_javascript_application`: Structural application graph generation.
2. `inspect_asar`: Non-extracting Chromium Pickle ASAR directory inspection.
3. `extract_artifact`: Secure ASAR extraction with hash integrity enforcement.
4. `inspect_electron_fuses`: Binary fuse inspection (ELF/PE/Mach-O).
5. `recover_javascript_sources`: AST-based bundle module recovery.
6. `compare_application_versions`: Semantic AST comparison across package versions.
7. `compare_javascript_export_shapes`: Structural module export diffing.
8. `trace_application_feature`: Multi-hop dependency and symbol reachability.
9. `trace_javascript_semantics`: Call graph and closure data-flow tracing.
10. `analyze_electron_source`: IPC and webPreferences anti-pattern audit.
11. `extract_sourcemap`: Extract `sourcesContent` from SourceMap v3 or inline data URIs.
12. `run_audit_pipeline`: End-to-end multi-stage automated security audit and metrics pipeline.
13. `pack_asar`: Pack a directory into a Chromium Pickle ASAR archive with SHA-256 block hashing.
14. `scan_secrets`: Scan source code or files for high-entropy credentials, tokens, and API endpoints with masking.
15. `audit_tauri`: Audit Tauri desktop binaries for framework signals, embedded config, assets, and IPC calls.
16. `inspect_binary_layout`: Dissect sections, symbols, architecture, and dynamic imports in ELF/PE/Mach-O binaries.
17. `inspect_go_binary`: Extract Go runtime version, main module path, and dependency package list.
18. `inspect_rust_binary`: Extract cargo-auditable crate dependency graph and rustc commit hash.
19. `inspect_wasm_artifact`: Decode WebAssembly sections, custom attributes, imports, and exports.
20. `inspect_android_package`: Dissect APK packages, hash DEX executables, catalog native libs, and extract AXML permissions.
21. `inspect_sqlite_database`: Verify SQLite format 3 headers, page sizes, schema cookies, and DDL table definitions.
22. `inspect_packet_capture`: Dissect PCAP/PCAPNG traffic, extract IPv4/IPv6 endpoints, TCP/UDP ports, and protocol distributions.
23. `list_browser_targets`: List loopback Chrome CDP page targets.
24. `list_electron_targets`: List loopback Electron file:// and app webview targets.
25. `list_adb_devices`: List connected Android devices via `adb devices -l`.
26. `inspect_adb_device`: Read device properties and detect emulator status via `getprop`.
27. `list_adb_packages`: List installed packages on target Android device.
28. `list_live_processes`: List host processes with cmdline and PID filtering.
29. `inspect_live_process`: Detailed Linux `/proc/[pid]` status, memory usage, threads, and mapped `.so` libraries.

---

## Benchmark

Tested against `@rea/core` v6.7.0 on Linux (4 CPU cores):

| Workload | Target | `rea` (Node.js) | `rea-fast` (Rust) | Speedup |
| :--- | :--- | :--- | :--- | :--- |
| **CLI Startup** | Engine Boot | 2.02 s (272 MB RAM) | 0.01 s (3.2 MB RAM) | **~200x** |
| **ASAR Header Parse** | `node_modules.asar` (57.5 MB) | 12.82 s (504 MB RAM) | 0.04 s (14.7 MB RAM) | **~320x** |
| **Electron Fuses** | Binary (150 MB) | 4.06 s (374 MB RAM) | 1.94 s (4.0 MB RAM) | **~2.1x** |
| **Full AST Parse** | 3,041 files (26.5 MB) | Node OOM / Crash | 1.01 s (34.1 MB RAM) | **3,041 files/s** |

---

## License

MIT OR Apache-2.0
