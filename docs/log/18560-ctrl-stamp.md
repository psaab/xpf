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
