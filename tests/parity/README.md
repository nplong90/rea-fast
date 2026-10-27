# REA upstream parity fixtures

These opt-in tests compare a **bounded, explicit subset of observable behavior**
against upstream `morluto/rea` pinned at
`6de60993b861266e63a4e70d5c6d9a8073f7cd92`. Upstream and `rea-fast`
are different implementations; matching a fixture is **not** full compatibility.

## JS source-module fixture

The `js-basic` fixture contains two ESM source modules and one package manifest.
The golden facts in `js-basic.expected.json` assert:

- Two exact paths and content SHA-256 digests.
- Named exports `run` and `double`.
- One resolved static import from `src/index.js` to `src/math.js`.

Run with both implementations built and upstream dependencies installed:

```sh
cargo build --locked
node tests/parity/compare-js.mjs \
  --rust-bin "$(pwd)/target/debug/rea-fast" \
  --upstream /absolute/path/to/pinned/rea
```

The upstream execution requires a working process-ownership provider (`ps` on
Linux). The runner uses actual binaries and a 60-second timeout per process.
It **does not** mock upstream responses. Exit codes:

- `0`: the two outputs agree with each other **and** the golden subset.
- `1`: a real semantic mismatch was observed.
- `2`: the run was not comparable (missing build, provider, or output evidence).

Only module path, digest, static imports and export names are compared. Upstream
Evidence provenance, lifecycle, semantic graph, Electron boundaries and
provider capabilities are explicitly excluded. A single uncontrolled elapsed
time observation is logged for diagnosis but **must not be called a benchmark**.
Comparable end-to-end CPU, peak process-family memory, cold/warm runs, output
bytes/tokens and equivalent-task coverage remain P5 work.

## ASAR container fixture


The ASAR runner produces an archive from the same three-file `js-basic`
fixture using the real Rust packer, then independently runs `inspect-asar`
and `inspect-artifact` in Rust and `inspect-artifact` in pinned upstream REA.
It checks against `asar-basic.expected.json`:

- Exact archive SHA-256 and byte size.
- File entry paths, sizes and declared SHA-256 integrity digests.
- Complete archive inventory on both sides; no truncated result allowed.

```sh
node tests/parity/compare-asar.mjs \
  --rust-bin "$(pwd)/target/debug/rea-fast" \
  --upstream /absolute/path/to/pinned/rea
```

The generated archive is placed in a unique temporary directory and cleaned
up after each run. This tests a common **inventory subset**; upstream's
artifact-graph provenance, relationship semantics and verified read/extract
claims exceed Rust's current `inspect-artifact` output and are not certified.
The same 0/1/2 result statuses apply.

## Electron IPC static fixture

The `electron-ipc` fixture contains a main process, an isolated preload bridge,
a renderer script and one HTML entry point. The runnable comparison evaluates:

- The literal `ipcMain.handle` and `ipcRenderer.invoke` channel and direction.
- `contextBridge.exposeInMainWorld` name and exposed method list.
- `BrowserWindow` literal preload, `contextIsolation`, and `nodeIntegration`.

```sh
node tests/parity/compare-electron.mjs \
  --rust-bin "$(pwd)/target/debug/rea-fast" \
  --upstream /absolute/path/to/pinned/rea
```

Rust runs its explicit `analyze-electron` command on main/preload sources;
upstream runs full `analyze-javascript-application`. The checked-in golden is
`electron-ipc.expected.json`. The test also requires upstream to contain
observed `handles` and `exposes` graph edges, but Rust does not currently
reconstruct an equivalent graph. On this fixture, upstream produced 25 nodes
and 33 edges. Matching the normalized syntax facts does **not** prove IPC
reachability, preload ownership, sender security or execution equivalence.

## Matched-task benchmark (opt-in, Linux)

`tests/benchmark/run-js.mjs` invokes **both actual executables** on the
same pinned ESM fixture. Every first/subsequent run must normalize and match
both the checked-in golden and its counterpart before metrics are reported.
It measures process wall time, GNU time direct-command user/sys CPU, direct
child max RSS (KiB), and JSON stdout bytes. The first sample precedes warm
samples; it does **not** purge page caches and is not a true cold-cache test.

```sh
cargo build --locked --release
node tests/benchmark/run-js.mjs \
  --rust-bin "$(pwd)/target/release/rea-fast" \
  --upstream /absolute/path/to/pinned/rea --warm-runs 7
```

Output `measured_equivalent_subset` only verifies the *explicit JS module
facts*, **not** the full upstream Evidence graph. Exit 2 and
`not_comparable` for missing providers, wrong upstream revision, missing
resource metrics, any failed command or any output mismatch. This runner
does **not** claim accurate peak memory of the entire descendant process
family, a page-cache-cleared cold start, or P5 release acceptance.
The CI job runs only parser/gate self-tests; full upstream benchmark is
opt-in and requires a pinned installed checkout.
