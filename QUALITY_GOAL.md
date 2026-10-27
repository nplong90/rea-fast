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
| P2 | Tool capability inventory | Every advertised tool labeled by verified implementation | In progress — conservative route labels; fixture verification pending |
| P3 | Upstream parity fixtures | Real-world scenarios for JS, Electron, ASAR, binary, ADB and CDP | In progress — JS module subset matched against real upstream |
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

