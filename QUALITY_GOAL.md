# rea-fast quality goal

## Baselines (2026-10-27)

- Fork: `nplong90/rea-fast`, revision `7e4a6cb59c25d5814535714b0d42ac371c11b15d`.
- Reference: `morluto/rea`, revision `6de60993b861266e63a4e70d5c6d9a8073f7cd92`.
- The Rust executable and upstream TypeScript server are **different implementations**.
  Catalog entry counts, schema byte counts and timing numbers alone are not
  proof of functional parity or task-level speed.
- Upstream has extensive native-provider, MCP and integration tests; this fork
  had 66 Rust tests and no checked-in CI workflow at the comparison baseline.

## Non-negotiable acceptance gates

1. **Truthfulness:** No advertised tool may report `pass`, `verified`, `complete`,
   full coverage or direct reachability without checking the required evidence.
   Unsupported features return explicit `unavailable`, with a reason and no
   fabricated facts. Every result distinguishes observation from inference.
2. **Reliability:** CI passes on Linux and Windows: `cargo test --locked`,
   `cargo check --locked --all-targets`, and the Rust formatting gate.
   MCP malformed and adversarial requests cannot terminate the server.
3. **Compatibility:** Classify each advertised MCP tool as `native`,
   `external-provider`, or `unavailable`. For a feature labeled compatible,
   maintain a fixture proving the same meaningful behavior and evidence
   semantics as pinned upstream. Tool-name overlap is **not** compatibility.
4. **Security:** Enforce input-size and resource bounds on untrusted files,
   debugger children and network responses; avoid target execution in explicitly
   static-only workflows. Audit archive traversal, symlinks, JSON nesting and
   process cleanup. Cover confirmed risks with regression tests.
5. **Performance:** Benchmark only **equivalent completed tasks** on the same
   host and inputs, using cold and warm runs, end-to-end time, CPU, peak memory,
   response bytes/tokens and output correctness. If an operation is missing or
   outputs are not equivalent, mark performance `not comparable`.
6. **Release readiness:** No unresolved P0/P1 correctness/security issue, no
   failing required CI jobs, documented platform/provider limitations and a
   reproducible release artifact with known commit and version.

## Phased work and status

| Phase | Deliverable | Exit condition | Status |
| --- | --- | --- | --- |
| P0 | Fail-closed MCP/evidence behavior | Regression tests cover false successes and meta-tool recursion | In progress |
| P1 | Repeatable CI and Windows smoke | Required test/build jobs green for every PR | In progress |
| P2 | Tool capability inventory | Every advertised tool labeled by verified implementation | In progress — 245 conservative route labels and a verified MCP Electron-source route |
| P3 | Upstream parity fixtures | Real-world scenarios for JS, Electron, ASAR, binary, ADB and CDP | In progress — JS, ASAR and Electron static subsets matched against real upstream |
| P4 | Security and bounded resource fuzzing | No unhandled crash on defined corpus and adversarial inputs | In progress — bounded MCP stdio requests, parser mutation tests |
| P5 | Fair benchmark and release | Reproducible equivalent-task results, signed-off review | Pending |

The quality goal is **not complete** until all gates above are evidenced. A
passing unit suite only establishes P0/P1 coverage, not total REA parity.
Maintain this document as a status ledger; don't convert pending to complete
based on tool counts or synthetic stub responses.

## Verification log

### 2026-10-27 — fail-closed managed workflows and binary plist hardening

- Four unimplemented managed-analysis operations now return `unavailable`
  instead of fabricated `pass`, `complete`, or `verified` outcomes.
- Binary plist parsing validates object offsets, reference spans, extended
  lengths and recursion depth before decoding untrusted data.
- Added regression coverage for managed-analysis false positives and a
  deterministic malformed-bplist mutation corpus.
- Eliminated fabricated Frida session/script lifecycle results, nine CDP
  analysis/comparison success stubs, and a synthetic Interface Builder decode;
  these operations explicitly report `unavailable` pending real implementations.
- Expanded the Rust suite from the original 66 tests to 75 tests; this is
  regression coverage, not proof of feature parity.
- These changes reduce P0/P4 risks but do **not** establish complete parser
  fuzz coverage or managed-analysis parity with upstream.

### 2026-10-27 — P2 MCP capability routing inventory

- Classify every registered MCP catalog entry as `native`, `external-provider`
  or `unavailable` based on source-level dispatch route inspection. Entries
  without an audited route remain `unavailable` by default.
- At this pinned revision: **63 native routes**, **53 provider-dependent
  routes**, **129 unavailable**. These are implementation-route counts, not
  tested compatibility scores.
- Add capability class prefixes to MCP `tools/list` descriptions without
  changing their schema. Add structured routing details and category totals
  to `rea_search_tools` results.
- Assert catalog completeness, unique tool names, explicit unsupported-stub
  classification and search-result totals in Rust regression tests.
- **Unverified:** runtime availability and upstream behavior equivalence.
  Route presence does not establish task success or permission to operate a
  device, browser or executable. P2 remains in progress until fixture-backed
  verification of the classified routes is complete.

### 2026-10-27 — malformed application graph inputs

- `compare_application_versions` and `compare_javascript_export_shapes`
  now reject malformed node arrays, missing/blank module identities, and
  duplicate module paths instead of silently dropping those records and
  potentially returning a misleading empty diff.
- Added negative-input regression coverage for both comparison entry points.

### 2026-10-27 — real upstream JS parity and MCP resource bound

- Built and executed upstream REA `6de60993...` and rea-fast on the same
  self-contained ESM fixture. Both independently returned identical exact
  source paths, SHA-256 content digests, named exports and static import edge,
  also matching the checked-in golden data.
- Added an opt-in Node parity runner (`tests/parity/compare-js.mjs`) with
  explicit `fixture_match`, `fixture_mismatch`, and `not_comparable` states.
  An upstream process-ownership failure initially made the test not comparable;
  running with working `ps` support allowed the actual upstream process to
  complete. No upstream mock or synthetic pass was used.
- MCP stdio line reading now limits individual requests to 64 MiB and drains
  oversized requests before reading the next line, returning a JSON-RPC error
  instead of allocating unbounded input memory. Invalid UTF-8 also produces a
  parse error without terminating the server. Added boundary regression tests
  and a real-process Node smoke harness covering malformed/deep/invalid-UTF-8
  input, notifications, session recovery, and optional streamed >64 MiB input.
  CI runs the protocol smoke on Linux/Windows and streamed limit check on Linux.
- Neither one fixture nor one uncontrolled timing observation establishes
  full parity, resource safety or faster equivalent-task performance.

### 2026-10-27 — second upstream parity fixture: ASAR inventory

- Packed the three-file JS fixture using rea-fast's real Chromium ASAR packer.
  Independently inspected it with rea-fast and upstream REA's artifact-graph
  provider. The complete regular-file inventory, exact path, sizes, declared
  SHA-256 hashes, root digest and archive size matched a checked-in golden.
- Committed the reproducible opt-in runner `tests/parity/compare-asar.mjs`,
  which pins upstream, distinguishes mismatch from `not_comparable`, and
  excludes Evidence provenance, graph semantics and verified extraction from
  its claimed equivalence. P3 and P5 remain open.

### 2026-10-27 — ASAR extraction containment and memory guard

- Reject subdirectory symlinks and non-directory parents below extraction
  destination. Write leaf files with exclusive creation to avoid following a
  symlink or clobbering an existing user file. Existing destinations now fail
  instead of being silently overwritten.
- Bound in-memory ASAR member reads to 64 MiB, check packed data extents for
  overflow/EOF, reject malformed file offsets, and reject symlink/nonregular
  unpacked members before reading. Added regression tests for oversized and
  corrupt offsets, symlink escape attempts, and existing-file preservation.
- This protects against static/pre-existing symlink paths; fully race-free
  extraction to a concurrently mutable destination requires further
  dirfd-relative/openat-style work. P4 remains in progress.

### 2026-10-27 — streamed, non-clobbering ASAR packer

- Avoid loading entire source members or the resulting archive into RAM while
  packing: fixed 64 KiB stream buffers digest input, copy input, and fingerprint
  the output. Compare the copy against the first-pass length/digest before
  publishing the archive, rejecting changed source content.
- Stage the archive in a unique, exclusively created sibling file, then publish
  using a same-filesystem atomic hard link; an existing destination is never
  truncated. Fail closed on overflow and invalid source paths.
- Added tests for destination preservation and packing a sparse 64 MiB+1 member.
  Fully hostile concurrent source modification and filesystem mutation remain
  outside the verified threat model; do not claim race-free packing.

### 2026-10-27 — Electron syntax parity and native MCP route smoke

- Independently executed pinned upstream REA and rea-fast against a small
  Electron main/preload/renderer fixture. Literal IPC direction/channel,
  contextBridge API/methods, and BrowserWindow webPreferences matched the
  checked-in golden. The upstream produced a 25-node, 33-edge graph that the
  Rust structural graph does not yet reproduce. Matching this subset is **not**
  full Electron application-graph or execution parity.
- Added `tests/parity/compare-electron.mjs`; it reports `fixture_match`,
  `fixture_mismatch` and `not_comparable` explicitly.
- The black-box MCP smoke now calls `analyze_electron_source` through actual
  `tools/call` and validates the returned IPC channel/operation. This verifies
  one native route in practice, not all 63 native-labeled routes.


### 2026-10-27 — JSON-RPC request validation and honest MCP error signals

- Valid JSON with an invalid JSON-RPC envelope returns `-32600` rather
  than pretending it is a syntax parse error or dropping an invalid request.
  Malformed JSON still uses `-32700`, and valid notifications stay silent.
- `tools/call` rejects a missing/empty name, non-object arguments and invalid
  params with `-32602` before invoking a tool.
- Tools explicitly returning `status: unavailable` or `status: error` now
  set MCP `isError: true`, rather than marking a non-result as success.
- Added real-process protocol regressions on Windows and Linux. This is a P0
  correctness improvement, not a claim that all providers work.

### 2026-10-27 — bounded and atomic Evidence bundle imports

- Bundle imports now cap reads at 64 MiB, validate required arrays and IDs,
  reject duplicates and conflicting existing records before touching the store.
  Additional provenance sections are imported rather than silently discarded.
- Optional `expected_sha256` verifies the canonical SHA-256 from export. A
  caller-supplied hash is not authenticated provenance; the response explicitly
  reports `authenticity_verified: false`.
- Record/unknown export arrays now sort by ID for reproducible content digests.
  Regression covers failed partial imports, mismatched digests, id conflicts
  and imported supplementary sections. Full Evidence authenticity remains open.

### 2026-10-27 — bounded, no-clobber Evidence export and comparison

- Stage and sync complete Evidence exports in an exclusive sibling file. With
  `overwrite: false`, a hard-link publish refuses existing files and
  symlinks atomically; explicit overwrite uses directory-entry rename rather
  than writing through a destination symlink.
- Bound the serialized export and bundle-comparison inputs to 64 MiB. Reject
  bundles missing records/unknowns arrays rather than returning a misleading
  identical result for empty or malformed data. Comparisons explicitly state
  that Evidence semantic parity is not verified.
- Regression coverage exercises no-clobber, Unix symlink safety, round-trip
  hash agreement, oversized comparison and malformed bundle shape.
- Full chain-of-custody verification and concurrent parent-directory attack
  resistance are still pending.

### 2026-10-27 — portable ASAR path validation and mutation corpus

- Reject Windows device names, alternate-stream colons, separators, control
  characters and trailing dot/space on all platforms when reading or packing
  ASAR. This prevents producing an archive on Linux that can collide with a
  special Windows path upon extraction.
- Add a deterministic 512-case mutated Pickle/header/payload corpus to the
  Rust CI unit suite; accepted archives are also subjected to bounded member
  reads. The test detects crashes and panics, but is not a coverage-guided
  fuzz campaign and cannot certify all filesystem races.

### 2026-10-27 — candidate artifacts, not a parity release

- CI builds a `--release` binary on Ubuntu and Windows, smoke-tests
  `--version`, produces a SHA-256/size/commit manifest, and attaches the
  executable plus manifest as a short-lived Actions artifact.
- The artifact is explicitly marked `candidate_only`; release parity,
  bit-for-bit reproducibility, signing and performance gates are not satisfied.

### 2026-10-27 — second verified MCP native route

- The Linux/Windows real-process MCP smoke now calls native
  `analyze_javascript_application` against the checked-in JS fixture, verifies
  an actual JavaScriptApplicationGraph and at least two source modules, and
  keeps the Electron analyzer smoke. These demonstrate **two** exercised native
  routes, not comprehensive capability readiness or upstream parity.

### 2026-10-27 — unknown resolution lifecycle collision guard

- `record_unknown` is now idempotent: repeating the same question/domain
  cannot reset a resolved unknown to revision 1. Distinct question/domain pairs
  that collide under the legacy concatenated digest are rejected rather than
  silently overwriting evidence. Empty questions are rejected.
- `update_unknown` rejects invalid revision and status types before mutation.
  Two regressions cover revision preservation and legacy hash ambiguity.
- A future versioned ID migration is still needed to allow both colliding
  pairs to coexist without breaking existing imported references.

### 2026-10-27 — opt-in matched-task benchmark harness (P5 partial)

- Added `tests/benchmark/run-js.mjs` with independent real processes,
  a pinned upstream HEAD requirement, interleaved first/subsequent samples
  and a mandatory per-run golden parity check before reporting any metrics.
- On Linux with GNU time, record wall clock, user/system CPU,
  direct-process peak RSS and stdout bytes; report medians. Missing upstream,
  failures, malformed resource reports or output mismatches all yield
  `not_comparable`.
- CI validates the parser, parity gate and script syntax, **not**
  real upstream speed measurements. First-run cache state and full
  process-family memory remain unmeasured; full P5 stays open.

### 2026-10-27 — bounded debugger sessions and truthful results

- Cap active GDB/Rizin sessions at eight, retained output at 512 lines
  per session and retained bytes per line at 8192, draining larger streams.
- Track monotonic record sequence counters so log eviction cannot change the
  meaning of a command's output cursor.
- Only verified GDB MI `^done` yields command `complete`; the
  prompt or elapsed time alone cannot. Rizin's 200 ms capture is returned
  as `unverified`, not `complete` without a terminator.
- Reap explicitly closed debugger child processes. Tests exercise sequence
  eviction, unlimited line draining and completion-evidence semantics.
- Live debugger process/provider verification and full timeout cleanup
  remain open.

### 2026-10-27 — six native MCP routes exercised with real stdio

- Expanded the Linux/Windows MCP child-process smoke to execute
  `scan_secrets`, `compare_artifacts`, `record_unknown` and
  `update_unknown` on synthetic fixture input, in addition to the
  JavaScript and Electron analyzers. Assertions verify structured responses,
  no raw secret disclosure and unknown revision transition.
- This establishes **six native routes exercised end-to-end**, not
  that all 63 labeled native tools have provider readiness or upstream parity.
