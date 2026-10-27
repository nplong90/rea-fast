# REA-Fast acceptance gate — evidence and functional parity

Target: REA-Fast may be released as **functionally equivalent to upstream REA** only after all required 245-tool contracts have a verified route, a reproducible fixture with observed output, an upstream reference result for matching scope, and passing cross-platform/security tests. A native dispatch entry is *not* proof of readiness; a live fixture is *not* proof of semantic parity.

Run `node tests/acceptance/mcp-matrix.mjs --rust-bin target/debug/rea-fast`. The script starts the real MCP binary in full-profile mode, retrieves all 245 tools through both `tools/list` and `rea_search_tools`, validates uniqueness and routing metadata, executes 20 supported offline fixture contracts and saves a per-tool JSON manifest in `acceptance-artifacts/`. The CI executes this on Ubuntu **and** Windows and archives the manifests even on failures.

Matrix states: `not_tested` means no qualifying runtime fixture; `fixture_exercised` means the stated specific assertions passed. **Every row still has `upstream_parity: not_verified`** until a separate matched upstream comparator proves the same semantic contract. The report is deliberately `partial_acceptance` while substantial functionality remains unverified.

**Release gate:** pass only if the required feature manifest has no `unavailable`, `not_tested`, `not_comparable` or `unverified` entries; full Evidence graph, provider lifecycle, security, and equivalent-output CPU/RSS/time must be verified. The current quality workflow is a regression gate, not a full release certificate. Do not merge PR #1 as complete while this release gate is blocked.
