# S2 — Direct I/O and decompression budget review

Scope: `src/*.rs` production readers, `cargo test --locked`, `node quality/io-audit.mjs`,
and the atomic Linux/Windows gate. Status is only DONE when CI receipts from
both platforms refer to one commit. The static tripwire is intentionally
conservative: it detects **new direct bulk-reader call sites** but is not a
formal whole-program analysis or a CPU/RSS benchmark.

| Reader family | Max input / expanded output | Failure mode |
| --- | --- | --- |
| Source, bundle, maps, secrets, parser (`security_io`, `analyze`, `sourcemap`) | 64 MiB per source; 256 MiB binary analysis | `metadata` early reject plus `take(limit+1)` EOF sentinel; no partial success |
| Project directory ingestion (`main`, `mcp`, `pipeline`) | 50,000 relevant source files, 512 MiB cumulative *listed* bytes | Reject entire discovery before parallel analysis; sparse over-limit test |
| MCP direct artifact input (`mcp`) | 256 MiB | `take(limit+1)` sentinel and reject |
| Evidence import/compare (`evidence`) | 64 MiB per JSON bundle | `take(limit+1)` sentinel and reject |
| HTTP bridge (`tcp_driver`) | 16 MiB response | Read one extra byte; reject valid-JSON-prefix + extra-byte attacks |
| Provider subprocess (`dynamic_bridge`) | 1 MiB per stdout/stderr and bounded elapsed time | Drain pipes without retaining extra bytes; error on truncation/timeout; Unix/Windows descendant cleanup acceptance |
| Linux `/proc` (`dynamic_bridge`) | 4 MiB each for `comm`, `cmdline`, `status`, `maps` | Read actual content even when procfs `st_size=0`, error on oversize; tolerate process exit/access failure |
| Debugger subprocess (`session_manager`) | 8 KiB per line, 512 retained lines, 8 sessions | Drain output without unbounded per-line allocations |
| Electron fuses (`fuses`) | 1 GiB streamed binary, max 32 fuse sentinels | Reject file growth and excess sentinels, never report incomplete sentinel listing as complete |
| ASAR (`asar`) | 64 MiB in-memory entry, 64 MiB header, 64 MiB listing, 512 MiB cumulative extracted bytes, 50,000 packed files | Validate declared total **and** actual bytes of unpacked siblings before write; bound stream fingerprint growth; reject over-limit packaging |
| APK/ZIP (`mobile`) | 256 MiB APK, 16,384 entries, 512 MiB declared expanded data, 64 MiB inflation per entry | Reject inconsistent ZIP lengths and oversized decompression with `take(limit+1)` |
| Native object/Rust metadata (`native_binary`) | 256 MiB native artifact, 16 MiB Rust metadata inflate | Bound both raw input and zlib expansion |
| Tauri embedded assets (`tauri`) | 16 MiB per Brotli attempt, 64 speculative attempts, 128 MiB total written assets | Reject exhausted heuristic budget (incomplete extraction) and cumulative disk growth |
| CDP/browser (`cdp`) | Framed WebSocket / HTTP limits declared in module | Reject oversized framing instead of growing unbounded buffers |
| SQL/PCAP/binary plist/managed metadata (`storage_pcap`, `plist`, `managed`) | 256 MiB analysis or 64 MiB source input | Shared bounded file reads |

Resource accounting caveats:

- The project aggregate scan uses filesystem metadata, then each file is
  individually read with a limit. A concurrent writer can change the contents
  between listing and analysis; this gate bounds initial listed size and
  each individual allocation, but does **not** claim a transactional snapshot.
- Parsers build semantic results and JSON objects, which can use more memory
  than raw input size. The separate F1 adversarial CPU/RSS corpus and B1
  benchmark must prove end-to-end limits; S2 does not pre-mark them DONE.
- Brotli probing is heuristic, not a complete embedded-asset extractor.
  Exhaustion reports an error, not a fabricated complete asset list.
- External providers may have their own resource characteristics; C2-live
  covers reproducible positive/malformed/timeout runs independently.

Regression acceptance:

1. `node quality/io-audit.mjs` — fails if a new direct `fs::read`, `Command::output`,
   or bulk reader appears without review.
2. Rust tests named in `quality/task-gates.json` verify the actual oversized
   input, forged totals, decompression and procfs failure paths.
3. All checks must pass on Linux and Windows on the same SHA before marking
   `S2-bounded-io` DONE. Linux-specific procfs test runs on Linux only.
