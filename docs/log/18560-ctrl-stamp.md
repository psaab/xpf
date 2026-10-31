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
