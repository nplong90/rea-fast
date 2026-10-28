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
| P2 | Tool capability inventory | Every advertised tool labeled by verified implementation | In progress — 245 conservative route labels; 31 catalog routes now fixture-exercised via MCP (not parity-certified) |
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

### 2026-10-27 — real pinned upstream measurement in PR CI

- Added a separate Ubuntu CI job that checks out the exact pinned
  `morluto/rea` source commit, installs its locked npm dependencies,
  builds both release implementations, asserts JS normalized parity
  and executes the opt-in matched-task benchmark using actual programs.
- Benchmark evidence is uploaded from the runner when available.
  This job **fails** when upstream cannot be built, output diverges or
  resource metrics cannot be obtained; it is not a mocked benchmark.
- The normalized ESM subset and direct-command peak RSS remain narrower
  than full Evidence equivalence and process-family memory acceptance.

### 2026-10-27 — CDP payload bounds and verified outcome semantics

- Reject missing, invalid, duplicate or >2 MiB HTTP Content-Length values
  before allocating target-list buffers. Reject WebSocket frames and outbound
  payloads over 16 MiB (and checked usize conversions) before allocation.
- Only accept CDP result envelopes containing a `result`; do not fabricate
  an empty result for a matching ID with no payload.
- CDP page inspection and script export now return explicit `error` if the
  actual evaluation fails or no verified result is observed. Script/screenshot
  saves use exclusive creation and no longer claim `complete` on write errors.
  Screenshot base64 is decoded and validated even without output path.
- Added bound-validation unit tests. Real browser CDP/WebSocket integration,
  random RFC 6455 masking, handshake authenticity and full content-type
  verification are **not yet validated** and remain open P3/P4 items.

### 2026-10-27 — black-box CDP resource bound socket regressions

- The resource-limit tests now include two actual loopback sockets:
  an oversized HTTP Content-Length response and a huge WebSocket length
  frame with no payload. Both must be refused before any bulk allocation.
- This exercises the protocol parser over real TCP transport, not a live
  browser/Chromium/CDP provider. WebSocket handshake cryptographic
  verification remains an explicitly unclosed P4 gate.

### 2026-10-27 — seventh native MCP fixture: executable binary layout

- Linux/Windows MCP child-process smoke now runs `inspect_binary_layout`
  on the actual compiled rea-fast executable, independently hashes the
  same bytes with Node SHA-256, and asserts parsed nonempty sections and
  architecture. This is a **native route readiness** check for real ELF/PE
  binaries, not a full native-binary Evidence graph upstream comparison.

### 2026-10-27 — common native-binary allocation bound

- Eleven native artifact entrypoints formerly used unbounded `fs::read`.
  They now use one shared 256 MiB maximum checked against file metadata
  and rechecked with `Read::take` while the file is read, preventing growth
  races from expanding allocations indefinitely.
- Added a sparse oversized-file regression asserting both the shared reader
  and real binary-layout inspector refuse over-limit inputs.
- This is a deliberate input limit, not full parser fuzz coverage or
  equivalence for very large binaries; P4 remains open.

### 2026-10-27 — real headless Chromium CDP provider smoke

- Ubuntu CI now launches an actual installed Google Chrome in headless mode
  with a private temporary profile and a random debugging port. A separate
  rea-fast MCP process must discover browser targets, evaluate `1 + 2`
  through runtime CDP, and capture a real PNG screenshot. The test inspects
  PNG magic bytes and compares the declared byte count to the saved file.
- This tests the named read/evaluate/capture routes end to end on the runner,
  not full CDP coverage, complete JS runtime provenance or Windows CDP.
  Unavailable Chrome or any output mismatch fails the job.

### 2026-10-27 — unify bounded CDP discovery paths

- Real Chrome CI exposed a schema mismatch in the integration test:
  MCP `list_browser_targets` returns a target array rather than an
  object with `status`. The harness now validates the actual schema.
- More importantly, its `DynamicBridge::query_cdp_targets` path had a
  second unchecked Content-Length allocation. It now uses the one bounded
  `cdp::fetch_cdp_targets` implementation (2 MiB maximum), retaining the
  typed `CdpTarget` external-tool result.
- Live browser evaluation/screenshot remain pending until the full
  Chrome integration job passes; do not infer success from this patch.

### 2026-10-27 — real CDP JavaScript exception handling

- `evaluate_web_script` now rejects CDP `Runtime.evaluate` responses
  containing `exceptionDetails`, or missing the observed `result`
  object, instead of labeling script errors as `complete`.
- The real headless-Chrome MCP CI harness tests a deliberate thrown
  JavaScript error and asserts `isError: true` and structured status
  `error`, in addition to successful evaluation and a real PNG capture.

### 2026-10-27 — RFC 6455 WebSocket challenge and masking

- The CDP client now derives a fresh 16-byte handshake key from the
  operating system CSPRNG (Unix `/dev/urandom` or Windows BCrypt)
  and validates HTTP 101, Upgrade/Connection and the expected
  `Sec-WebSocket-Accept` value. It refuses forged handshakes.
- Every client-to-server data frame now uses a fresh four-byte mask rather
  than a fixed known mask. RFC SHA-1 is used only to compute the public
  upgrade challenge, not to authenticate a remote host.
- Regression tests use the RFC 6455 known accept value. The real Chrome
  integration job verifies interoperability after this change.
- The transport remains plaintext WebSocket for local loopback CDP and
  still lacks full fragmentation/control-frame/tls support. Full P4 stays
  open until those limitations are addressed.

### 2026-10-28 — bounded entropy results

- Avoid allocating an output JSON entry for every byte when
  `inspect_byte_entropy` receives a 1-byte chunk size. The inspector now
  computes the true `chunk_count` in O(1) and emits at most 64 sampled
  chunk values, with `chunks_truncated: true` when applicable.
- Regression fixture uses 16,384 one-byte chunks and asserts the true count,
  output cap and offsets; resource-allocation pressure no longer follows
  the total number of result chunks.

### 2026-10-28 — fail-closed Android APK ZIP and signature inspection

- Bound file reads for three APK entrypoints to 256 MiB, actual ZIP member
  inflation to 64 MiB, and declared ZIP total uncompressed bytes to 512 MiB.
  Reject malformed central-directory extents/counts, ZIP64 and multi-disk
  containers rather than returning plausible partial inventories.
- Verify DEX/AndroidManifest member decompression succeeds and its byte length
  matches the directory claim. A corrupt DEX no longer receives an invented
  SHA-256 for an empty byte array. Reject inconsistent local/central member
  names and compression methods.
- Detect v2/v3 APK signature *block IDs* only when located immediately before
  the ZIP Central Directory, with matching size fields and valid pair framing.
  Reject a fake `APK Sig Block 42` string embedded inside ordinary member data.
  Report `signature_cryptographic_verification: not_performed`; no signature
  authenticity, signer identity, certificate chain or content digest is
  cryptographically verified by this static inspector.
- Added eight targeted Rust regression fixtures (including 65 MiB expansion
  bomb, 256 MiB+1 sparse APK, malformed ZIP and forged signature marker), plus
  real MCP acceptance calls for `inspect_android_package` and
  `inspect_apk_signature`. Assertions independently check DEX SHA-256,
  reject a forged signing string, and require corrupt APKs to yield
  `isError: true`. The catalog matrix now exercises 31 of 245 routes with
  fixtures, plus one additional callable route. **214 catalog routes remain
  unverified**;
  upstream Android APK task parity is still unverified.
