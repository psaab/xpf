# #18560 — the helper advances the userspace_ctrl generation stamp

Replaces the matched-view grace of PR #18572 (kept as a draft) with a
source fix, as decided by the lane coordinator.

- **Timestamp**: 2026-10-31 00:55 PDT
- **Action**: Root cause and design.
  - On loss (r-hitless-i3-seq, fw0 demoting): one failover produced two
    full applies (generations 14 and 17, each driven by a VIP move) and
    3,522 `config_generation_mismatch` drops. The exception ring shows
    packets stamped cfg=11 and cfg=14 after the helper had moved on: the
    shim stamps whatever `userspace_ctrl` holds, and only Go wrote it,
    from the status reply, after the helper finished the apply and Go
    finished its post-reply steps. About 1 ms of line rate per change.
  - The helper now rewrites the two stamp fields right after its
    `RuntimeView` store (`coordinator/ctrl_stamp.rs`,
    `Coordinator::store_runtime_view`). The ctrl row is one value whose
    other fields Go owns, so the write is constrained: only inside a Go
    grant (`ctrl_stamp_deadline_mono_ns`, 250 ms CLOCK_MONOTONIC, stamped
    by `requestDetailedAtSocket` on `apply_snapshot` and
    `bump_fib_generation` only), only on an enabled row with the expected
    metadata version whose stamp is exactly the generation the workers
    left, re-checking the deadline between read and write, and writing
    every other field back as read. Go cannot write ctrl concurrently: it
    holds m.mu across both round trips and writes ctrl only under m.mu,
    and the round trip cannot return before the grant expires unless the
    helper replied (grant < controlShutdownCutover < controlBaseDeadline,
    pinned at compile time).
  - #6592 is unaffected: a stamp ahead of a worker's view and a stamp
    behind it both still drop.
- **File(s)**: `userspace-dp/src/afxdp/coordinator/ctrl_stamp.rs`,
  `userspace-dp/src/afxdp/bpf_map/ctrl_row.rs` (the three map syscalls; the
  #16187 ratchet ceiling for `afxdp/bpf_map` rises 64 -> 67 in
  `protocol/unsafe_ratchet_16187.rs`),
  `userspace-dp/src/afxdp/coordinator/ctrl_stamp_tests.rs`,
  `userspace-dp/src/afxdp/coordinator/mod.rs`, `userspace-dp/src/afxdp/mod.rs`,
  `userspace-dp/src/server/handlers/mod.rs`,
  `userspace-dp/src/server/helpers/status.rs`,
  `userspace-dp/src/server/tests.rs`, `userspace-dp/src/protocol/control.rs`,
  `userspace-dp/src/protocol/status.rs`,
  `userspace-dp/tests/fixtures/protocol_wire_v1.json`,
  `pkg/dataplane/userspace/ctrl_stamp_grant_18560.go`,
  `pkg/dataplane/userspace/ctrl_stamp_grant_18560_test.go`,
  `pkg/dataplane/userspace/process_control.go`,
  `pkg/dataplane/userspace/protocol.go`,
  `pkg/dataplane/userspace/protocol_status.go`,
  `docs/afxdp-packet-processing.md`, `docs/ha-failover-status.md`, and the
  #6592 torn-pair comments in `coordinator/README.md`,
  `coordinator/snapshot_refresh.rs`, `types/runtime_view.rs`,
  `worker/loop_body/reconcile.rs`.
- **Timestamp**: 2026-10-31 01:45 PDT
- **Action**: Go grant keyed on the payload. The grant is stamped on every
  request that carries a Snapshot (exactly apply_snapshot and
  bump_fib_generation today), not on the verb string, so the #9520
  single-send-site census keeps the "apply_snapshot" literal in one place.
  The helper honours it only in those two handlers.
- **Timestamp**: 2026-10-31 02:40 PDT
- **Action**: Folded review seats V and W on #18598 (MINOR from both).
  - W1, the ownership rule rests on timing: the residual (a write that
    completes after the grant can replace a row Go wrote meanwhile) is now
    stated in the module doc and `docs/afxdp-packet-processing.md` instead of
    "never touched", detected as `CtrlStampOutcome::LateWrite` (counted under
    errors, logged), and the structural fix is filed as #18603.
  - W2: cell `ctrl_row_is_written_after_the_view_is_published_18560` (a fake
    row whose update reads the workers' view channel).
  - V3: `CtrlRowFd`, built only by `open_ctrl_row` after the shape check, is
    the only fd `lookup_ctrl_row` / `update_ctrl_row` accept.
  - Nits: a 0 clock never opens a grant; the pin path comes from the
    snapshot's `map_pins.ctrl` (the stored snapshot for a route-only bump),
    no hardcoded path; the grant is a guard object revoked on drop or unwind
    (`CtrlStampGrantGuard`); the rewrite-only cell comment no longer claims to
    see an equivalent mutant; the teardown 0/0 publish is documented.
  - V4 (production-path cell): `ctrl_row_root_18560` creates and pins a real
    array map and drives `PinnedCtrlMap` through open (shape check), lookup
    and a `BPF_EXIST` update, plus a wrong-shape refusal. It needs CAP_BPF and
    bpffs, so it is `#[ignore]` and runs under `make test-root`.
- **Mutants before the fold (8 planned, 6 run)**: S1 advance never called
  (4 cells), S2 enabled check, S3 foreign-stamp check, S4 second deadline
  check, S5 apply-arm revoke, S6 bump-arm grant: all KILLED. S7/S8 were not
  reached before the fold; re-run on the folded head.
- **Timestamp**: 2026-10-31 05:30 PDT
- **Action**: Folded seat V's two gate failures at 9babd8c8a7 (BLOCKING) and
  the nit.
  - `no_banned_lock_poison_shapes_in_production_17201`: the grant guard's
    `Drop`, `open_ctrl_stamp_grant` and `current_ctrl_stamp_grant` used
    `if let Ok(..) = lock()` / `.lock().ok()`. With a poisoned mutex the guard
    left the grant open, which is the case the guard exists for. All three
    (and the test row) now use `sync_util::lock_tolerant`. Cell
    `grant_guard_revokes_through_a_poisoned_mutex_18560` poisons the mutex
    from a panicking thread and asserts the guard still revokes.
  - `scripts/ignored-cell-census.sh`: the privileged cell was `#[ignore]`d with
    a reason that declared neither `MEASUREMENT:` nor `#N:`. Chose the existing
    precedent, the #10868 XFRM lifecycle gate: `ctrl_row_root_18560` is no
    longer ignored; it probes for CAP_BPF and bpffs at runtime, prints SKIP
    and passes without them, and fails when `XPF_REQUIRE_CTRL_ROW_ROOT` is set,
    which `make test-ctrl-row-root` now sets. The decision table is pinned by
    `ctrl_row_root_gate_skips_unprivileged_and_fails_when_required_18560`.
    Census: OK (16 ignored cells, 0 undeclared).
  - Nit: the margin cell's comment no longer claims a red cell for
    `deadline_ns != 0`, which is an equivalent mutant there; the zero grant is
    refused earlier by `open_ctrl_stamp_grant`.
  - Seat W (W4, MINOR): the teardown publish (`stop_inner`, 0/0 with no
    snapshot installed) can run inside an open grant, because a full
    reconcile under `apply_snapshot` tears down first, so "it never writes
    the row" was false. Fixed in code: the advance skips any view whose
    validation has `snapshot_installed == false`. Cell
    `teardown_publish_inside_a_grant_never_writes_the_row_18560`. The
    `LateWrite` comment now says it over-reports (fires at `now >= deadline`)
    on purpose.
- **Timestamp**: 2026-11-01 00:00-01:41 UTC (re-gate after #18638)
- **Action**: Merged origin/master 3f5daa77a7 (`--no-ff`, 9fb6843a19) with
  no conflicts.
  - Full Rust release suite: 75 failures, identical by name to master.
  - pkg/dataplane/userspace: 70 failures, all in the base set.
  - Ignored-cell census: OK.
- **Builds and versions.** The deployed floor was 0.0.26900, so these start
  at +100. Each arm was its own lock cell deploying its own deb, back to back
  per gate, with counters read before and after.
  - master 3f5daa77a7: 0.0.27000 (soak), 0.0.27020 and 0.0.27060
    (failover), 0.0.27040 (ha-crash).
  - PR 9fb6843a19: 0.0.27010 (soak), 0.0.27030 and 0.0.27070 (failover),
    0.0.27050 (ha-crash).
- **A/B on loss.**

  | gate | master 3f5daa77a7 | PR 9fb6843a19 |
  |---|---|---|
  | test-rg-move-soak SOAK_RG=1,2, 40 moves | 40/0/0, max v4 gap 248 ms | 40/0/0, max v4 gap 208 ms |
  | test-failover, run 1 | 67 passed / 2 failed | 66 passed / 3 failed (+ RG1 Group 4) |
  | test-failover, run 2 | 66 passed / 3 failed | 65 passed / 4 failed (+ RG1 Group 4) |
  | test-ha-crash | 44 passed / 0 failed | 44 passed / 0 failed |

  - The failover failures both arms share: whole-run per-stream zero
    intervals, rg1-split planned-move stalls, and (in run 2) a stream that
    did not resume within 3 s.
  - **RG1 Group 4 (policy denied packets) fails on the PR in 2 of 2 runs and
    passes on master in 2 of 2.** Paired delta 60 and 213, all on node0, the
    node that was crashed and rejoined. Those denies are replies to
    established SNAT flows, denied as `wan -> wan` transit right after RG1
    fails back to node0:
    - run 1: `.202:5210 -> .7` (pool SNAT), 59 denies in 27 ms;
    - run 2: `.202:5211 -> .8` (interface SNAT), 194 denies on seven iperf3
      streams, some lasting until 01:38:11 (74 s).
  - Counter deltas per arm. On node0 these span its crash and reboot, so they
    cover the rejoined process only.

    | counter | master soak | PR soak | master failover node0 | PR failover node0 |
    |---|---|---|---|---|
    | config_gen_mismatches (node0 / node1) | +460k / +436k | +244k / +264k | - | - |
    | fib_gen_mismatches (node0 / node1) | +17k / +30k | +50k / +38k | +1 and +0 | +696 and +1754 |
    | ctrl stamp advances / declines / errors | - | 244 / 0 / 0 and 228 / 0 / 0 | - | 0 / 1 / 0 (node1: 10 / 0 / 0) |
    | Sessions stale-config-ignored (both nodes) | flat at 0 (#18646) | flat at 0 | flat at 0 | flat at 0 |

  - Verdict under the re-gate rule ("merge if the PR fails no move class or
    cell that master passes"): **NOT mergeable.** RG1 Group 4 is a cell
    master passes. The deny pattern points at the rejoined node's
    activation; its helper declined its only stamp change, and its FIB
    generation mismatches are elevated.
- **Ledger rows** committed:
  - master: `4946aca7fc092059` (soak PASS), `eb635957bc413f64` (failover
    FAIL), `3097baef25a122b9` (failover FAIL), `f748c8365d7416d7` (ha-crash
    PASS);
  - PR: `6dc6c79d1c3c299b` (soak PASS), `cfbfe9881f2bcdf3` (failover FAIL),
    `3ae3abc74d9aa002` (failover FAIL), `a2ff4ce882f52a3e` (ha-crash PASS).

## Root cause of the Group 4 regression, and the re-gate on top of #18659

- **Timestamp**: 2026-11-01
- **Finding**: the RG1 Group 4 denies were a master defect, #18659 (fixed
  by #18660, merged 1406176ce1), which this PR exposed more often.
  - On RG activation, the HA refresh rewrote each peer-owned reverse row
    onto the unresolved WAN gateway (MissingNeighbor).
  - The copy on the worker that had processed packets since the FIB bump
    carried the current generation stamp, so a WAN reply hashed to that
    worker took the MissingNeighbor arm and was default-denied wan->wan.
  - This PR moves the stamp 1.6 ms after an apply, against 15-20 ms on
    master (1.7 kHz ctrl-row sampler), and showed the denies in 4 of 6
    runs, against 1 of 7 on master.
  - The earlier "0 advances after boot" reading was a reboot-reset mis-diff:
    post-boot the stamp made 9 advances and 1 decline, and the decline was
    the boot apply exceeding its grant.
  - The earlier "persists 74 s" reading was also wrong: each burst lasts
    about 50 ms.
- **Action**: merged origin/master 1406176ce1 into this branch (cee55a0f0e)
  and re-gated in one loss lock cell, arms in order: master 1406176ce1
  (0.0.29517), this PR cee55a0f0e (0.0.29518), and #18675 (0.0.29519).
  Each arm ran test-failover x2, test-ha-crash, and test-rg-move-soak
  SOAK_RG=1,2 x40. Host and VM loadavg were recorded beside each gate.
- **Finding**:

  | arm | test-failover | RG1 Group 4 | wan->wan TCP denies | ha-crash | soak (to node0 / to node1) | worst stall |
  |---|---|---|---|---|---|---|
  | master | 67P/2F, 65P/3F | PASS, PASS | 0 | 44/0 (row VOID: exe_check unavailable) | 20P / 20P | 1.4 s |
  | this PR | 66P/3F, 65P/3F | PASS, PASS | 0 | 44/0 | 20P / 20P | 1.1 s |

  - Group 4 is fixed on this PR.
  - The remaining test-failover FAILs show up on both arms: the rg1-split
    stall (#18656), zero intervals, and interval collapse.
  - One extra FAIL here: "stream 7 did not resume within 3s" at the crash.
    In every run on every arm, all 8 streams go to zero for exactly one 1 s
    interval at the takeover. The failing stream stayed at zero 3 more
    seconds and then recovered. Attribution and further samples are in
    progress.
- **Ledger rows** (this commit):
  - master: `0af88aacd69099f8` (failover FAIL), `ebf494c4c4ad57cc`
    (failover FAIL), `f2a42b08bd7fa17d` (ha-crash VOID, exe_check
    unavailable), `ea979dfa3dff7eae` (soak PASS);
  - PR: `df2c8029e48693ab` (failover FAIL), `3f9c250fecb27622` (failover
    FAIL), `c2b29495db3b3569` (ha-crash PASS), `de00db418ccfdc62` (soak
    PASS);
  - PR earlier (instrumented pr3 run, 0.0.27070): `3d986529ef8457cd`
    (failover VOID).
