# #18617 follow-up — test-failover transition windows and zero-interval definitions

- **Timestamp**: 2026-10-31 09:10 PDT
- **Action**: (a) Registered the manual RG1 move, which starts the
  split slice (RG1 on node0, RG0/RG2 on node1), as a `[T, T+3]` transition
  window, taken at the request instant (`rg1_move_at_seconds`).
  Previously only the crash and the last-RG-moved failback were registered,
  so zeros at the split move counted as "outside transition windows".
  `iperf-throughput-selftest.sh` asserts the wiring; with the producer line
  removed, the self-test FAILs ("does not pass the RG1 split-move instant").
- **Finding (b)**: In the #18598 gate's master arm (iperf start 13:43:20 UTC),
  2 streams ran at <= 50 Mbit/s from +133 s to +147 s (13:45:33-13:45:47),
  with a single interval at +158 s. The harness's post-crash clock resync was
  at 13:45:01, 32 s earlier, so the window does not start at the resync. It
  is not yet attributed. The node journals of that run were not retained; the
  next test-failover journal capture should be matched against the fw0
  rejoin and bulk-sync timeline.
- **Finding (c)**: My exact-zero count (35) and the harness's 61 reconcile
  by definition. The harness counts per-stream intervals at <= 0.05 Gbit/s
  (58), and `zero_intervals_total` adds the 3 aggregate zero intervals.
  Documented in `docs/userspace-ha-validation.md`.
- **File(s)**: `test/incus/test-failover.sh`,
  `test/incus/iperf-throughput-selftest.sh`, `docs/userspace-ha-validation.md`,
  `docs/log/18617-harness.md`.
