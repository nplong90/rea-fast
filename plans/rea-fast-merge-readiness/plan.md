# rea-fast PR #1 — merge-readiness execution plan

## Atomic execution ledger — 2026-10-28

The merger goal is **not complete**. All 15 atomic tasks are versioned in
`quality/task-gates.json` with executable checks, required platforms and
explicit unfinished blockers. Only a same-commit Linux + Windows receipt can
make a cross-platform task DONE. There is no recurring schedule or auto-merge.

Last fully verified PR head: `fcc57842e87232a2f831c838885e047a1d513c95`.
GitHub Actions: https://github.com/nplong90/rea-fast/actions/runs/40645160168
— 6/6 jobs passed, including Windows race/timeout and both platform receipts;
task aggregate artifact `12797103859`.
Pinned upstream: `morluto/rea@6de60993b861266e63a4e70d5c6d9a8073f7cd92`.
Tracking PR: https://github.com/nplong90/rea-fast/pull/1 (Draft).

| Atomic task group | Verified status | Evidence / limitation |
| --- | --- | --- |
| G0 routing | DONE | All 245 catalog contracts checked for drift on Linux and Windows. |
| S1 extraction race | DONE | Handle-relative extraction, concurrent rename/symlink tests on both OS, fresh private outputs. |
| S2a/S2b/S2c/S2 I/O | DONE | Full direct-I/O inventory (`quality/IO_AUDIT.md`), bounded project/file output, ZIP/ASAR/Tauri/procfs/fuses stress regressions and both-OS CI. |
| S3 Unix/Windows | DONE | Child process tree termination in both operating systems, bounded bridge output. |
| C1 and C2 offline | DONE | 63 real-MCP native route fixtures and 51 provider-absent fail-closed probes (2 host-proc exceptions). |
| C2 live | BLOCKED | Still need real ADB/Rizin positive/malformed/timeout matrix or explicit demotion; proprietary integration cannot be declared verified without a provider. |
| E1 upstream | PENDING CI | Four *real* local comparators matched narrow JS, ASAR, Electron, ELF and APK facts; this commit wires them to the Linux atomic gate using pinned upstream, not yet a remote E1 receipt. Full upstream Evidence graph remains excluded. |
| F1 adversarial | BLOCKED | Wider cross-parser/transport deterministic corpus plus CPU/RSS/time ceilings missing. |
| B1 benchmark | BLOCKED | Five comparable workloads with end-to-end process-family metrics missing. |
| R1 merge review | BLOCKED | Independent final-head review and owner's explicit merge decision required. |

Completed task count on last fully verified CI SHA: **10/15**.
Do not upgrade E1 to DONE until the new commit's actual Linux parity job and
same-SHA goal aggregator pass. Do not infer M1/M2 approval from any green CI.

## Decision: merge a bounded hardening milestone, not a drop-in REA replacement

There are two different release conditions:

1. **M1 — safe partial-product merge:** Merge this work into `master` only when
   all currently **claimed/supported** capabilities have reproducible positive
   and negative evidence, all known P0/P1 bugs in reachable paths are fixed or
   routed to `unavailable`, and the product plainly advertises partial parity.
   A permanently `unavailable` tool is not expected to work at M1, but must
   consistently and honestly report unavailability, including through MCP.
2. **M2 — upstream drop-in replacement:** Claim full REA compatibility only
   when every required upstream contract has actual functional/evidence parity,
   provider lifecycle support and representative benchmark coverage. M2 is not
   a precondition for a correctly labeled *partial* M1 product. This distinction
   requires updating the wording of `QUALITY_GOAL.md` and
   `tests/acceptance/README.md` before M1; no silent relaxation of tests.

The owner can choose to require M2 before *any* merge; that is a substantially
larger feature-porting program and must not be conflated with a hardening PR.
Default implementation target here is **M1**. Do not mark the PR ready merely
because CI passes on the current branch.

## Baseline and exact coverage debt

- Catalog: **245** entries = **63 native**, **53 external-provider**, **129 unavailable**.
- Original baseline MCP positive fixtures: **31 catalog entries**, plus one noncatalog route.
- Original baseline: **32 native-labeled routes lacked live fixture assertions**. Provider routes
  need a verified *offline failure* contract and selected real-provider tests.
- 129 `unavailable` routes must have catalog/dispatch/error-code invariants;
  they do not become compatible by appearing in `tools/list`.
- Pinned upstream: normalized subset matches for JS module facts, ASAR inventory
  and Electron IPC syntax; Electron full Evidence graph does not match.
- Performance: one matched JavaScript subset with direct-command RSS; full
  process-family and representative completed-task comparisons are missing.

## Implementation work packages (complete sequentially unless independent)

| ID | Priority / dependency | Implementation | Merge acceptance proof |
| --- | --- | --- | --- |
| G0 | Blocker / first | Freeze supported-vs-experimental-vs-unavailable contract in a versioned JSON manifest. Map each of 245 catalog entries to a real handler, expected evidence claim, platform and required provider. Amend `QUALITY_GOAL.md`, `tests/acceptance/README.md`, `README.md`. | No tool says `verified`/`complete` for an unimplemented operation. CI checks all 245 against the manifest; ambiguity fails the build. |
| S1 | P0 / after G0 | Harden unsafe file output in `src/sourcemap.rs`, `src/bundle.rs` and audit `src/asar.rs`: prevent overwriting existing files and following symlinked parents; use dirfd-relative operations on Unix or isolate output in a fresh private directory with atomic publication. | Unit and real MCP tests using existing file, symlink leaf/parent, adversarial traversal and interrupted extraction; outside sentinel remains untouched. Concurrent filesystem race test is required for any claim of race safety. |
| S2 | P0 / after G0 | Bound direct file readers in `src/pipeline.rs`, `src/storage_pcap.rs`, `src/plist.rs`, `src/tauri.rs`, `src/managed.rs`, `src/sourcemap.rs`; cap decompression in `src/native_binary.rs`; apply size ceilings before and during read. | Sparse over-limit files and compressed expansion bombs are refused without crashes or huge allocation; no caller bypasses shared bounded readers. Limits and unsupported formats documented. |
| S3 | P0 / after G0 | Bound child stdout/stderr in `src/dynamic_bridge.rs`; audit timeout/termination in `src/session_manager.rs`. Propagate truncated-output/timeout as incomplete/error rather than successful evidence. | Fake tools emitting endless output and hanging descendants cannot exhaust memory or survive cleanup; tests run on Windows and Linux. |
| C1 | P1 / after S1–S3 | Convert the **32 remaining native labels** into positive/negative MCP fixtures, or demote implementation gaps from `native` to `unavailable/experimental`. Extend `tests/acceptance/mcp-matrix.mjs` to enforce the chosen M1 contract. | 100% of **supported** native routes have real-process fixture evidence and strict failures; explicit unsupported routes remain distinguishable. Zero `not_tested` in the supported set. |
| C2 | P1 / after G0 | Exercise all **53 provider-dependent routes** with a missing-provider / timeout / malformed-provider matrix. Expand live-provider testing beyond existing GDB/Chrome to ADB and Rizin where CI can safely run them; label environment-dependent ones clearly. | No offline provider returns fabricated success; live-provider claims have trace, process cleanup and repeatable CI. Proprietary integrations without test access remain unavailable/experimental. |
| E1 | P1 / after C1 | Add pinned-upstream comparator fixtures for Electron Evidence semantics, ASAR extract/integrity, native binary, and at least one mobile/ADB scenario. If schemas and graph relations cannot match, narrow the advertised capability rather than labeling parity. | Every M1 compatibility claim names compared fields and verified provenance. Mismatch/unsupported is red or `not_comparable`, never `fixture_match`. |
| F1 | P1 / after S1–E1 | Expand fuzz/regression corpus: ASAR headers/extraction, ZIP/APK, plist, sourcemap, PCAP, MCP JSON and debugger/CDP transport. Fail closed on known resource limits. | CI corpus has 0 crashes/timeouts/panics, deterministic reproduction seeds, and expected error semantics. No unresolved high-severity issue in supported paths. |
| B1 | P2 / after C1 and E1 | Make fair benchmarks on **5 completed workloads** (small/large JS, Electron, ASAR, native artifact) with validated equivalent facts, cold/warm runs, output bytes, CPU, wall, peak process-family RSS, repeatability. | Results published with host/versions, pinned upstream SHA, raw artifacts and `not_comparable` for mismatches. No broad speedup claim from one narrow benchmark. |
| R1 | Final / after all previous | Review all PR changes; audit license/attribution, documentation, Windows+Ubuntu behavior, candidate binary checksum/commit, install + MCP startup smoke; lock merge policy to required CI. | Final head passes all required jobs; 0 known P0/P1; per-tool matrix and parity evidence archived; review findings closed; `master` not modified before explicit merge approval. |

## Native fixture backlog — exact tool names (32)

This was the baseline list; all now have black-box route fixtures. The list is
historical, not a semantic-parity signoff. Real-world positive-format fixtures
and the upstream comparators are still required.

- JS/graph/compare: `compare_application_versions`, `compare_bundles`,
  `compare_javascript_export_shapes`, `inspect_analysis_view`,
  `inspect_desktop_application`, `recover_javascript_sources`,
  `run_audit_pipeline`, `trace_application_feature`, `trace_feature`,
  `trace_javascript_semantics`.
- Evidence/files: `export_evidence_bundle`, `import_evidence_bundle`,
  `extract_artifact`, `extract_sourcemap`.
- Desktop/native/mobile: `audit_tauri`, `identify_flutter_build`,
  `inspect_electron_fuses`, `inspect_go_binary`, `inspect_il2cpp_metadata`,
  `inspect_keyed_archive`, `inspect_macho`, `inspect_managed_artifact`,
  `inspect_managed_members`, `inspect_managed_native_boundaries`,
  `inspect_model_artifact`, `inspect_packet_capture`, `inspect_plist`,
  `inspect_python_pyc`, `inspect_signature`, `inspect_sqlite_database`,
  `project_android_application_graph`, `trace_dylib_resolution`.

## Execution / rollback rules

1. Run G0 first; then security S1–S3, then coverage C1/C2/E1, then fuzz F1,
   fair benchmark B1 and merge review R1. Unrelated independent fixtures can
   proceed while CI is running, but do not skip their acceptance checks.
2. Each package gets a small scoped commit, exact-test evidence in the PR and
   a new Linux/Windows CI run. Keep PR **Draft** until the final gate.
3. If a claimed behavior cannot be verified, demote it clearly, keep the
   feature behind explicit opt-in, or leave M1 blocked. Never add synthetic
   success solely to increase counts.
4. If a change breaks parity or an OS job, revert only the new scoped commit
   after inspecting the cause, without resetting unrelated user work.
5. **Stop condition for M1:** all supported contracts verified, no P0/P1,
   CI green on final head, evidence and docs aligned, independent review
   complete. The user controls the actual merge; no daily recurring schedule.

## M2 backlog, intentionally outside the M1 merge claim

Full 245-tool implementation and upstream Evidence/behavior parity, device
coverage across ADB/Frida/JEB/Ghidra and optional proprietary bridges, complete
MCP lifecycle and auth behavior, and comprehensive cross-platform/performance
comparison. Do not call M1 completion M2 completion.
