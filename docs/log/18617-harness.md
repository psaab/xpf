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
- **Timestamp**: 2026-10-31 17:36 UTC
- **Action**: Took over #18627 from hitless lane 2. Fresh worktree
  `/var/worktrees/tf-windows-takeover` tracking
  `origin/test/failover-rg1-move-window` (head `ff22a3ec98`), with
  origin/master merged `--no-ff` (cd6f624bd9; brings in #18618). Folded
  seats Y and X (both MINOR).
  - **Seat Y: planned moves are scored, not excused.**
    - The crash keeps its excused `[T, T+3]` (`--event-sec`).
    - The RG1 split move and the RG0/RG2 failback are `--planned-move`s.
      `scripts/iperf-json-metrics.py` scores each one by H11's rules at 1 s
      resolution. PASS: no stalled stream. COST: one stream stalled at most
      10 s and recovered. FAIL: an all-stream zero interval, two or more
      stalled streams, a longer stall, or a dead stream.
    - Planned zeros are not counted in the outside budget twice.
    - test-failover emits one cell per move; COST counts as passed, and the
      summary gains ", <k> cost" (cells_cost on the ledger; the ha-smoke
      adapter now records it).
    - The "whole-run zero-throughput intervals" cell, red by design on every
      crash run, is now recorded as `whole_run_zero_intervals` and judged
      master-relative, not gated. This uses a generic `HARNESS_METRIC:`
      line read by harness-result.sh. `MAX_ZERO_INTERVALS` still gates it
      when set.
    - Dropped the "legitimate split move" wording.
  - **Seat X: behaviour, and anchors at both ends.**
    - Each planned move is anchored at the instant before its request(s)
      AND at its poll-observed landing(s).
    - The RG0/RG2 failback moved into `ha_run_rg02_failback`, which records
      both requests and both landings. Before, only the last landing was
      registered.
    - The argument construction is `ha_build_planned_move_args`, and the
      cells are `ha_planned_move_cells`.
    - iperf-throughput-selftest runs the real `ha_run_rg1_failback_slice`,
      `ha_run_rg02_failback`, the call-site fixture, the builder and the
      cell mapper, with stubbed incus, owner poll and capture helpers.
      SECONDS is aligned to a wall-clock second so the pre-request instant
      is exact.
  - **Docs:** the matrix H1/H9 rows name the registered windows and how each
    cell treats them; `docs/userspace-ha-validation.md` section rewritten.
- **File(s)**: `scripts/iperf-json-metrics.py`, `test/incus/test-failover.sh`,
  `test/incus/iperf-throughput-selftest.sh`, `test/incus/harness-result.sh`,
  `test/incus/harness-result-selftest.sh`, `docs/userspace-ha-validation.md`,
  `docs/regression-test-matrix.md`, `docs/log/18617-harness.md`.
- **Timestamp**: 2026-10-31 17:36 UTC
- **Validation**:
  - iperf-throughput-selftest: 61 passed (14 new cells), 3 runs stable.
  - harness-result-selftest: 267/267.
  - ha-assurance and failover-client selftests pass.
  - Mutation matrix (`/var/tmp/fz/r-18627-mutate.log`, git-free copies,
    every splice checked to have landed): 28/28 KILLED.
    - X1–X11: reset after the slice, local scoping, recording only on the
      failure branch, the instant taken after the request, planned args not
      passed, landing at the request instant, the RG0/RG2 request instant
      after the send, landings not recorded, the builder dropping the
      landing or registering an unlanded move, failback requests dropped.
    - Y1–Y14: a planned move excused as `--event-sec`, planned zeros
      double-counted outside, multi-stream, aggregate, stall-bound or death
      checks removed, first anchor only, the stall measured only inside the
      window, COST as a plain pass, cost dropped from the summary, an
      unscored move not VOIDed, the whole-run cell gated again or not
      recorded, the crash window scored.
    - H1–H3: HARNESS_METRIC ignored, reserved keys accepted, ha-smoke
      without cells_cost.
  - Live: see the next entry.
- **Risk**:
  - **Stricter.** A planned move with two or more streams at zero for a
    second now FAILs. It used to be excused. That is H11's bound, and H10
    (target: at most 3 pings) is stricter still.
  - **Ledger shape.** Rows gain `cells_cost` and `whole_run_zero_intervals`.
    The headline is unchanged (`throughput_gbps`).
  - **Not a gate any more.** The whole-run count no longer gates, so a PR
    that grows it is caught only master-relative, from the recorded metric.
- **Timestamp**: 2026-10-31 17:50 UTC
- **Validation (live #1)**: `make test-failover` on loss under the loss lock
  (17:36–17:47 UTC, `/var/tmp/fz/r-18627-live.log`), no deploy. Both
  nodes ran `xpf 0.0.26642+g443b5e7aa85a` (master 443b5e7aa8), NTP Normal
  (the clock precondition converged in 5.9 s), v4 target `.202`.
  - Result: 64 passed, 5 failed, 0 cost.
  - Planned moves: `rg1-split` (anchors 115 s request, 116 s landing)
    FAILed on "3 streams stalled (11, 19, 9)"; `rg0-rg2-failback` (183,
    184 requests; 184, 185 landings) PASSed.
  - The raw per-stream data shows that FAIL was the threshold, not the
    move. At the RG1 move the aggregate fell from about 9 to 1.2 Gbit/s
    (the split puts every flow on the copy-mode fabric). Streams 11 and
    19 ran at 12 Mbit/s and only stream 9 carried 0 for one second. The
    run's 0.05 Gbit/s "zero" threshold read starved streams as stalled.
  - Fold: a planned-move stall is H11's definition, under 1 Mbit/s
    (`--planned-stall-gbps 0.001`). Streams between that and 0.05 Gbit/s
    are reported as low-share. Rescoring the same live data with the
    final producer gives `rg1-split` COST ("stream 9 stalled 1 s at the
    move and recovered; 2 more stream(s) at or below 0.05 Gbit/s but not
    stalled (11, 19)") and `rg0-rg2-failback` PASS.
  - The other four FAILs are not this PR's:
    - "RG1 Group 4 policy denied packets" (7), seen on master runs before.
    - The crash outage: all 8 streams at zero for 3 intervals (60–62 s),
      past the excused 3 s window. That is "longest outage was 3
      consecutive intervals (budget 2)", "streams ... did not resume
      within 3s", and most of the 20 outside-window zeros (H10/#18561).
    - Split-state low-share intervals past the RG1 window, which also
      count outside.
  - `whole_run_zero_intervals=36` recorded.
- **File(s)**: `scripts/iperf-json-metrics.py`, `test/incus/iperf-throughput-selftest.sh`,
  `docs/userspace-ha-validation.md`, `docs/regression-test-matrix.md`
- **Timestamp**: 2026-10-31 18:00 UTC
- **Validation (live #2, final code)**: `make test-failover` on loss under
  the loss lock (17:52–17:59 UTC, `/var/tmp/fz/r-18627-live2.log`), no
  deploy, scripts sha-checked unchanged. Both nodes ran
  `xpf 0.0.26642+g443b5e7aa85a`, NTP Normal (clock converged in 1.9 s),
  v4 target `.202`.
  - Result: **63 passed, 6 failed, 1 cost**.
  - Planned moves:
    - `rg1-split` (anchors 164 s request, 166 s landing): **COST**, "stream
      19 stalled 0.999 s at the move and recovered; 1 more stream(s) at or
      below 0.05 Gbit/s but not stalled (7)".
    - `rg0-rg2-failback` (234, 234 requests; 235, 235 landings): **PASS**.
  - The real adapter scores the log FAIL with `cells_cost=1`,
    `whole_run_zero_intervals=49`, `clock_converged=1 clock_void=0` and
    `throughput_gbps=10.376`.
  - The six FAILs are not this PR's:
    - two "session sync did not become idle within 30s" (before traffic,
      before the crash);
    - RG1 Group 4 policy denied (7);
    - the crash outage past the excused window, 3 consecutive intervals
      (two oracle cells);
    - the outside-window zeros, 26: the crash tail plus split-state
      low-share intervals past the RG1 window.
  - The ledger row is VOID (exe_check=UNAVAILABLE, no deploy manifest) and
    is not committed.
- **File(s)**: none (validation)
- **Timestamp**: 2026-10-31 18:13 UTC
- **Action**: Seat Y (MINOR at `46ef418a96`): low-share is not covered by
  H9, which is a hand-read row with no cell. The live dip, aggregate 9 to
  1.2 Gbit/s at the move, is below H9's split ceiling, so it is a transition
  cost. The PASS/COST/FAIL boundary is unchanged.
  - Each planned move now records `planned_<move>_low_share_streams`,
    `_min_stream_gbps` and `_window_aggregate_gbps` as `HARNESS_METRIC`
    lines, judged master-relative like `cells_cost`. A selftest cell pins
    their emission.
  - Removed the "split's fabric share" / "judged by H9" attribution from the
    producer comment, the doc, the matrix row and the fixture comment.
  - The doc now says test-failover has no 10 ms ping, so a sub-interval
    stall goes unscored; H11's ping-gap bound lives only in
    `test-rg-move-soak`.
  - Seat X's nits: the aggregate-outage message now says "every stream
    stalled (under 1 Mbit/s)", matching the stall flags it is computed from.
    The doc and matrix say plainly that `whole_run_zero_intervals`,
    `cells_cost` and `planned_<move>_*` are person-read ledger metrics,
    not automated bands.
  - Correction to `46ef418a96`'s message: "the split's fabric share, which
    H9 judges" is withdrawn. Low-share is a recorded transition dip.
  - Rescoring live run #2's data (`iperf3-failover.2002147`) gives
    `rg1-split` low_share=2, min_stream=0.000, window_aggregate=2.773 Gbit/s,
    and `rg0-rg2-failback` low_share=0, min_stream=0.112, window_aggregate
    10.131 Gbit/s.
- **File(s)**: `scripts/iperf-json-metrics.py`, `test/incus/test-failover.sh`,
  `test/incus/iperf-throughput-selftest.sh`, `docs/userspace-ha-validation.md`,
  `docs/regression-test-matrix.md`
