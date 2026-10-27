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
| P2 | Tool capability inventory | Every advertised tool labeled by verified implementation | Pending |
| P3 | Upstream parity fixtures | Real-world scenarios for JS, Electron, ASAR, binary, ADB and CDP | Pending |
| P4 | Security and bounded resource fuzzing | No unhandled crash on defined corpus and adversarial inputs | Pending |
| P5 | Fair benchmark and release | Reproducible equivalent-task results, signed-off review | Pending |

The quality goal is **not complete** until all gates above are evidenced. A
passing unit suite only establishes P0/P1 coverage, not total REA parity.
Maintain this document as a status ledger; don't convert pending to complete
based on tool counts or synthetic stub responses.

