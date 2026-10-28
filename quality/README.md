# Goal-driven REA-Fast acceptance gates

This directory tracks the M1 merge-readiness goal as **atomic tasks**, not
calendar-based reminders or an aggregate green/partial-green percentage. An
agent should finish one independently actionable task to its own acceptance
conditions before claiming it is DONE, then select the next unblocked task.

The inventory is `task-gates.json`. Each task declares dependencies, target
platforms, checks, and (where work is still missing) an explicit blocker. Tasks
with no executable checks **cannot** be DONE. A one-platform pass is only
`PASS_PLATFORM`; a global `DONE` requires receipts from every required platform
for the **same git commit**, plus completed dependencies.

Commands from the repository root:

```sh
node quality/task-gate.mjs --validate
node quality/task-gate.test.mjs
node quality/task-gate.mjs --run --strict --output acceptance-artifacts/task-gate-local.json
node quality/task-gate.mjs --run --task G0-routing-contract --strict
node quality/task-gate.mjs --aggregate acceptance-artifacts/task-gate-Linux.json acceptance-artifacts/task-gate-Windows.json --output acceptance-artifacts/task-gate-summary.json
```

- `--run`: executes only the checks with no declared blocker, ordered by
  dependency. Commands have no shell interpolation and each has a 180 s timeout.
  `${REA_FAST_BIN}` resolves to this repository's debug binary.
- `--strict`: returns an unsuccessful exit code if an executable check fails or
  its runner is absent; it does **not** silently treat declared unimplemented
  tasks as DONE, nor does it force an entire pre-merge backlog to be built at
  once.
- `--aggregate`: rejects mismatched commits and incomplete/duplicate per-OS
  reports. It reports `GOAL_IN_PROGRESS` until all 12 atomic tasks meet their
  full acceptance conditions. `next_task` selects the next unfinished task
  whose dependencies are completed, including tasks requiring implementation;
  `next_action` explains whether to **IMPLEMENT** missing proof or **VERIFY**
  missing platform receipts. The `blocked_backlog` shows unfinished work.
- `--task ID`: runs just the target and its prerequisites for local debugging.
  Other tasks explicitly report `NOT_EVALUATED`.

Reports are **CI evidence**, not security attestations against an adversary who
can edit both JSON and checks. The verifier must run from trusted CI on the
reported git revision. A green Quality workflow or an executable that launches
is never, by itself, proof of upstream parity or authorization to merge.

No automatic merge is performed. M1 is an explicitly **partial** REA product;
M2 full upstream compatibility has separate criteria in
`plans/rea-fast-merge-readiness/plan.md`.
