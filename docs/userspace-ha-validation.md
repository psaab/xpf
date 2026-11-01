# Userspace HA Validation

Date: 2026-03-14

This document captures the current repeatable validation path for the isolated
userspace cluster on `loss`:

- `loss:xpf-userspace-fw0`
- `loss:xpf-userspace-fw1`
- `loss:cluster-userspace-host`

Tracked inputs:
- env: [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- config: [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- validator: [userspace-ha-validation.sh](../scripts/userspace-ha-validation.sh)
- failover validator: [userspace-ha-failover-validation.sh](../scripts/userspace-ha-failover-validation.sh)
- phase cycle: [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
- perf compare: [userspace-perf-compare.sh](../scripts/userspace-perf-compare.sh)
- failover parity plan: [userspace-ha-failover-parity-plan.md](../docs/userspace-ha-failover-parity-plan.md)

## Current Model

The isolated userspace cluster is a userspace forwarding development lab. The
validation workflow has to catch two classes of failure:

- hard failures: reachability, RA/default-route, helper/runtime readiness
- soft failures: a run starts fast, then drops to near-zero after the first one or
  two seconds

On `cluster-userspace-host`, the minimum correctness bar remains:
- IPv4 reachability to `172.16.80.200`
- IPv6 reachability to `2001:559:8585:80::200`
- IPv6 default route learned from RA on `eth0`

## Repeatable Validation

Run:

```bash
./scripts/userspace-ha-validation.sh
```

Optional redeploy before test:

```bash
./scripts/userspace-ha-validation.sh --deploy
```

Optional perf capture on the active userspace firewall:

```bash
./scripts/userspace-ha-validation.sh --perf
```

Perf-only compare workflow:

```bash
./scripts/userspace-perf-compare.sh
```

Dedicated RG failover survivability workflow:

```bash
TOTAL_CYCLES=12 CYCLE_INTERVAL=5 \
./scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8
```

Dedicated aged-failover workflow (#16217 never-again gate; streams
age 30 s before one RG1 failover, acceptance is zero zero-intervals —
expect FAIL until the HA-inactive leg in
[ha-failover-status.md](ha-failover-status.md) is closed):

```bash
./scripts/userspace-ha-failover-validation.sh --aged-failover --duration 60 --parallel 4
```

Dedicated steady-state split-RG fabric workflow:

```bash
./scripts/userspace-ha-failover-validation.sh --steady-only --source-node 1 --target-node 0
```

Standard phase workflow:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
```

This is the required sequence after each userspace dataplane phase:

1. commit the phase
2. push the current branch to GitHub
3. deploy to:
   - `loss:xpf-userspace-fw0`
   - `loss:xpf-userspace-fw1`
4. run the isolated userspace HA validation script

For failover-specific HA/session work, also run the dedicated RG failover
validator. The steady-state validator is not enough to prove that an existing
TCP flow survives a manual RG ownership move.

The standard failover stress shape is now:

- a long-lived `iperf3` run, not a short smoke pass
- `-P 8` so all stream lines stay visible during the move
- rapid RG1 movement between `fw0` and `fw1` with `CYCLE_INTERVAL=5`
- enough total cycles and duration to catch late failback wedges, not just the
  first transition

For fabric-path performance and stream-stability work, also run the failover
validator in `--steady-only` mode with RG1 pinned to the peer owner. That
isolates the split-RG fabric path without failover churn and catches
"starts fast, then all streams go to 0" regressions before any RG transition.

Current use of that gate:

- `--steady-only --source-node 1 --target-node 0` is the standard split-RG
  fabric-path repro for the isolated userspace lab
- the acceptance bar is:
  - `0` aggregate zero-throughput intervals
  - `0` per-stream zero-throughput intervals
  - all streams still carrying traffic at the end of the steady-state window

If the validation script is failing and you still need current performance data,
run the perf-compare workflow next. It captures IPv4/IPv6 `iperf3` and `perf`
artifacts without treating current tree instability as a hard blocker.

## What The Validator Enforces

The validator does this in order:

1. uses the tracked env/config in the repo, not `/tmp`
2. waits for CLI availability on both firewalls
3. fails unless the runtime settled into supported userspace forwarding; legacy
   eBPF fallback requires explicit `ALLOW_LEGACY_EBPF_HA_VALIDATION=1`
4. pins the validation RGs to the preferred node, retrying transient failover
   precondition failures while userspace XSK liveness propagates into RG
   readiness
5. forces `cluster-userspace-host` to keep accepting IPv6 RAs (`accept_ra=2`)
6. verifies an IPv6 default route on `cluster-userspace-host`
7. if needed, runs repeated `rdisc6 -1 eth0` to force fresh RA convergence
8. derives the active WAN test interface from the current primary node's route table
9. runs deterministic TTL-expired probes to:
   - IPv4 `1.1.1.1`
   - IPv6 `2607:f8b0:4005:814::200e`
   - the validator treats `ping` exit status `1` as expected for these probes
     when the returned output contains the native time-exceeded response
10. asserts the controlled LAN-to-WAN-target reachability ping received
    replies for both families (the `validate_reachability` gate — this is
    the IPv6 dataplane forwarding-correctness signal, since the LAN host
    reaches the WAN-side target only by transiting the userspace dataplane),
    and asserts the targets do not resolve on-box (`assert_forwarding_route`)
11. records one-cycle `mtr` reports to the public IPv4/IPv6 targets
12. for IPv4 (a reliable responder, `1.1.1.1`), fails if the first hop or the
    final destination hop is unresolved (loss parsed numerically; a
    `(waiting for reply)` / truncated-`%` / `100%` final hop fails closed).
    For IPv6 the public `mtr` is observability-only: an unresolved first hop
    still fails, but any unresolved/silent later or final hop is recorded as
    a warning. External internet IPv6 routing is not gated by the public
    trace — it is gated by the controlled ping/TTL/iperf3 legs to the
    in-control WAN target (see #1303)
13. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
14. runs repeated IPv4 `iperf3` to `172.16.80.200`
15. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
16. pulls `iperf3 -J` JSON back to the repo host, parses it locally, and fails
    if throughput cliffs after startup
17. retries one marginal near-threshold miss once
18. optionally records `perf` data on the active firewall

The dedicated RG failover validator now adds stricter HA gates:

1. a steady-state pre-failover observation window after session sync completes
2. `0.00 bits/sec` enforcement during that window for both:
   - aggregate `[SUM]` output
   - individual `iperf3` streams
3. standby userspace readiness checks after each RG move
4. flat standby WAN TX deltas during stale-owner fabric redirect checks

For standard HA failover stress on `loss`, use:

- `TOTAL_CYCLES=12`
- `CYCLE_INTERVAL=5`
- `--duration 600`
- `--parallel 8`
- one forward run and one reverse `iperf3 -R` run

That is the preferred repro shape for the remaining "first failover degrades,
failback wedges one stream" class because it exercises:

- longer-lived inherited flows
- repeated ownership changes in both directions
- per-stream survival, not just aggregate throughput
- both traffic ownership directions, not only the host-sending path

This matters because a split-RG fabric-path bug can kill streams before the
first failover. That must fail as a fabric regression, not be misclassified as
a failover-survivability regression.

### RG1 Group 7: former-owner readiness (#18686)

Group 7 judges the former RG1 owner (node1) at `phase=mid`, after the RG has
moved off it. It must be ready to take the RG back: helper `Enabled: true`,
`Forwarding armed: true`, `rg1 active=false`, and `Ready bindings` above
zero. Any one of these false is FAIL. A missing, duplicated or malformed
field is VOID.

These fields come from the userspace status summary in the
`show chassis cluster data-plane statistics` capture (`RG1_STATS`). The
`show chassis cluster status` capture (`RG1_STATUS`) has none of them. The RG's
flag is not a line of its own: the summary joins every group on one line,
`HA groups: rg0 active=true watchdog=N; rg1 active=false watchdog=N; ...`
(`pkg/dataplane/userspace/format/status_sections.go`).
`ha_standby_status_verdict` therefore takes the `rg<N>` entry out of that line.
It needs exactly one `HA groups:` line and exactly one entry whose id is that
whole token, so `rg10` is not `rg1`.

Until #18686, Group 7 was handed `RG1_STATUS`. The parser also expected
`rg1 active=` on its own line, and the selftest fixtures (hand-written in the
parser's shape) agreed with it. So Group 7 was VOID on every live run, and an
offline replay confirmed it: VOID on 117 of 117 preserved runs. It is now
handed `RG1_STATS`. The verdict judges all 117 captures PASS. With the RG1
slice's owner preconditions applied, the harness would score 116 PASS, and
1 VOID by precondition (in that run node0 owned RG1 at phase-pre, so
`can_measure` is false). The selftest rows are
the real captured file
(`test/fixtures/ha-assurance/rg1-failback-mid-node1-18686.stats`), each row
changing one line of it, plus the production renderer golden. A pin checks
that the call site passes `RG1_STATS[mid:node1]` and that `RG1_STATS` is the
data-plane statistics capture.

### Session-sync idle precondition

Both `make test-failover` (`ha_wait_for_session_sync_idle`, before traffic,
before the fw0 crash and before the RG1 failback) and this validator
(`wait_for_session_sync_idle`) wait for session sync to be idle before they
move an RG. They share one sample predicate, `ha_session_sync_idle_sample` in
`test/incus/ha-assurance-lib.sh`.

**The property.** Idle = N samples at an unchanged floor, the latest of them
included, with no create outstanding beyond that floor and nothing pending at
those reads. N is `SESSION_SYNC_IDLE_STABLE_SAMPLES` (3).

- "Pending" covers both the target's helper delta queue
  (`Session delta pending`) and the source's helper delta buffer.
- The source must also have dropped no delta since the wait began.

A sample reads D = the source's `Session create` Sent minus the target's
`Session create` Received (`show chassis cluster data-plane statistics`).
The floor is the lowest D the wait has seen. "Outstanding beyond the floor" is
D minus the floor.

The N samples need not be consecutive:
- A sample above the floor, or with something pending, neither counts nor
  resets the count.
- A new floor or a counter rewind restarts it. A source drop does not: that
  sample is not idle, and because the drop baseline is kept, no later sample
  can count either, so the wait FAILs.
- The wait PASSes only on a sample at the floor.

Each counted sample is an exact reading: nothing was outstanding beyond the
floor at that read. Requiring consecutive samples false-FAILed a healthy pair
on `loss` (#18632 live run 2, build 0.0.26680). During the "before fw0 crash"
wait, the mirror sweep sent about 4 creates per second. One landed between
the two reads in pairs about every 4 samples, so readings at the floor came in
pairs and never 3 in a row.

**What a timeout costs.** The wait gives up after `SESSION_SYNC_IDLE_TIMEOUT`
(30) **attempts**, not seconds. Each attempt is two CLI captures and a 1 s
sleep, about 1.7 to 2.1 s on `loss` (measured), so a full wait takes about a
minute. The FAIL message reports the attempts, the measured seconds and how
many samples it counted at the floor.

The limit leaves a wide margin for the count:
- **Measured.** In run 2, 15 of the 29 samples after the baseline read the
  floor, and the count reached 3 at sample 8. Treating the samples as
  independent, the chance of fewer than 3 floor samples in 29 is below 1 in a
  million. Floor readings came in pairs, though. Taking the 14 or so pairs as
  the independent units, it is about 6 × 10⁻⁴, roughly 1 in 1,700.
- **Pessimistic.** If creates arrived as a Poisson stream at 4 per second,
  with about 0.5 s between the two reads, about 14 % of samples would read the
  floor. The chance of a timeout would then be about 23 %. That figure depends
  on the read gap: about 5 % at 0.4 s and about 36 % at 0.55 s.
- **Reading a timeout.** A timeout means fewer than N samples proved idle.
  The D sequence in the log tells the causes apart. With dense, varying
  creates, D fluctuates and rarely returns to its minimum. With a backlog or a lost
  create, D stays above the floor at every sample and is flat or rising.

 A timeout is a FAIL cell. Before the RG1
failback it also sets the RG1 slice's `sync_ok=false`, and
`ha_rg1_mark_groups_void` then VOIDs RG1 Groups 1 to 8 for that run
(`test-failover.sh`, `ha_run_rg1_failback_slice`). It is a precondition
result, not a takeover verdict.

How the predicate gets there:

- **Floor, not equality.** The two counters do not share an epoch. Bulk-sync
  frames are counted by the receiver only, and a restart zeroes one side. On
  `loss`, Sent was 22047 against Received 129487 while caught up (#16289).
- **Target first, then source.** A create the target has counted was
  enqueued on the source before the target's read, and the source counts it
  as sent right after the enqueue (`queueMessage`: the channel send, then
  `sentCounter.Add`). So a source read taken after the target read includes
  it, and D reads high (a create in flight or one sent between the reads),
  not low. The one exception: if the source stalls between the send and the
  count for longer than the gap between the reads (about 0.4 s), D reads one
  low. That sets a floor below the real one and FAILs the wait; it can never
  PASS one falsely.
  - With the source read first, a create sent between the two reads and
    delivered before the target read counted as received but not as sent.
    A baseline taken on that sample sat one below the floor, and every later
    quiet sample read as one create outstanding for the whole wait.
  - On the #18627 `loss` run, Sent − Received was −107440 at the baseline of
    both waits and −107439 on all 49 later samples. Pending was 0 throughout,
    so nothing was backed up (#18632).
  - The first sample of a wait often catches a burst of creates, because the
    waits start right after an RG reset or an iperf3 start.
- **The floor only moves down.** What a baseline can absorb is its D minus
  the true floor, i.e. the creates in flight at it. Moving to a lower D
  shrinks that amount and never grows it. It also discards an inflated first
  sample. This verdict ("new floor") resets the streak, so a backlog that is
  still draining never reads idle. The floor never moves up, so a create lost
  **after** the wait has seen a sample at the true floor (nothing in flight)
  keeps D above it, and the wait FAILs.
- **No `sent == received` escape.** The old #16500 escape only helped when both
  counters shared an epoch, which is why the #18632 failure recurred. With the
  target read first it could only mask a create that really is outstanding.
- **Source-side deltas.** A session delta the source's helper still holds, or
  has dropped, never becomes a "sent" create. So neither D nor the target's
  pending count can see it. The predicate therefore also reads the source's
  `Session delta pending` (must be 0 at an idle sample) and
  `Session delta dropped` (any increase since the wait's first sample keeps
  every later sample not idle, so the wait FAILs).
- **Unknown verdicts.** An unknown helper verdict VOIDs the wait in both
  loops.

**What it cannot see.** Counters alone have these blind spots. The
pre-#18632 predicate has them too, and closing them needs a per-create epoch
or sequence number, not counts.

- **Drain plus loss.** Creates in flight at every sample so far can mask a
  create lost before they land. Example: two creates are in flight at the
  first sample, and a third is sent and never received. When the two land, D
  falls to one above the true floor. That becomes the new floor, and the wait
  PASSes. A selftest cell pins this, so any change to it is deliberate.
- **Constant lag.** If at least one create is in flight at every sample, the
  lag is the floor and the wait PASSes. A *growing* lag is caught.
- **Varying background creates.** A create in *every* read window at a
  steady rate is a constant offset that the floor absorbs, so the wait PASSes.
  A healthy pair FAILs only when the number of creates per window varies and
  the minimum is rarely seen again. On `loss` the mirror sweep left about half
  the samples at the floor (run 2).
- **Stale stability evidence.** Samples above the floor neither count nor
  reset the count. A lag that clears for one sample can therefore PASS on
  earlier counted samples as old as the wait itself, up to about 28
  attempts. The PASS sample is still an exact reading, so this is not a lost
  create.
- **A rewind wipes a drop.** A counter rewind (a daemon or helper restart)
  re-baselines everything, including the source's dropped count, so a drop
  seen before it is forgotten.
- **After the last sample.** A create sent after the last idle sample is not
  covered.
- **The event-stream delta path.** The source checks read the helper's
  per-binding RPC-fallback delta buffer. In event-stream mode, session deltas
  reach the daemon over the event stream instead. A loss there latches an
  owner-RG resync. The CLI's `Event stream producer: dropped=` counter mixes
  rate-limited log events with HA deltas, so it cannot be gated without false
  FAILs. #18635 tracks exposing an HA-delta loss counter.

`test/incus/ha-assurance-selftest.sh` covers this with fixed counter pairs and
with timeline cells. In a timeline cell the counters depend on when each
capture reads them:

- a create sent between the first two reads must still PASS;
- a lost create must FAIL, including one lost after the streak began and one
  lost after the true floor was seen;
- the drain-plus-loss case is pinned as a PASS (the known limit above).

### `make test-failover` RG1 Group 1: session-miss drops and a raw floor (#18670)

RG1 Group 1 exists for one HA failure: an established flow whose session is
missing after the RG1 failback. It is two judged checks over the failback
window, both nodes summed. Each check is VOID on its own failure modes, and
the group fails if either check fails.

- **1a, session-miss drops.**
  - The lab configs carry no `no-syn-check`. Under the SYN-first default,
    an established TCP flow's packet that misses its session in transit is
    dropped by the transit gate and counted as a screen drop
    (`strict_syn_check_drops_new_flow_tunnel_with_payload`, recorded as
    "strict-syn-check"). Closing (FIN/RST) misses and unknown-flags
    fragments are counted the same way.
  - The helper exposes those only in the aggregate `Screen drops`. 1a
    judges its delta against `MAX_FAILOVER_SESSION_MISS_DROP_DELTA`
    (default 4).
  - `Screen drops` bounds `strict-syn-check` drops, not lost sessions as
    such; other screen reasons add to it.
  - Recorded windows read 0 on every node. 0 in 12 windows bounds the
    per-window false-red rate only at about 22% (the exact binomial 95%
    bound, 1 − 0.05^(1/12)), while a lost established flow drops on every
    retransmitted packet; hence 4.
- **1b, a coarse raw `Session misses` floor.**
  - 1a is blind to a lost session whose miss resolves to LocalDelivery.
  - The labs use catch-all `source-nat interface`. The WAN→LAN reply half
    of a lost SNAT session is therefore addressed to the firewall's own
    WAN address, and its miss resolves to LocalDelivery.
  - LocalDelivery is exempt from the SYN-first gate, so the packet is
    denied host-inbound (`host_inbound_denied_packets`) and never counted
    as a screen drop. This is #18531's third mechanism, the one matrix row
    H1 names.
  - The miss counter runs before disposition, so 1b judges the raw delta
    against `MAX_FAILOVER_RAW_SESSION_MISS_FLOOR` (default 256). Recorded
    raw deltas are 18–61 on master and up to 71 on #18656.
  - A flow that loses its reply path stalls within about one RTT: roughly
    a window of ACK misses per stream, then one per RTO backoff. 1b
    therefore detects a broad reply-half loss (most streams, the #18531
    failback shape), with about 185 misses of headroom over the largest
    recorded delta.
  - A single-stream loss can stay under the floor. It is left to the
    iperf3 stream-continuity cells.
- **Why not misses net of creates.** A new flow is one miss and one or two
  creates, depending on whether a local reverse companion is installed. The
  #18676 review found that the create delta matched the RT_FLOW
  `session_create` count on node1 in the recorded windows. Reverse repair, local delivery,
  missing-neighbour seeding and hit-path materialization also create with
  no miss. Misses minus creates is therefore only a lower bound on real
  misses.
  - Raw misses and creates per node are printed on a report-only line.
- **Host-inbound denies, report-only.** test-failover also captures `show
  security flow statistics` per node and phase, and prints the `Host-inbound
  denies` delta as a report-only line (`ha_host_inbound_denies_report`).
  - That value is xpfd's `GlobalCtrHostInboundDeny` mirror. It is
    refreshed at xpfd's 1 s status poll, and `safeDelta` absorbs helper
    resets (`pkg/dataplane/userspace/manager_counters.go`), so it trails
    the helper by up to a second and does not rewind on a helper restart.
  - The helper `PID:` line appended to the capture comes from the
    data-plane capture taken just before it. The helper-PID guard it
    feeds is therefore stricter than this counter needs, and it is not a
    guard on xpfd.
  - That is the direct counter for the LocalDelivery reply half. The WAN
    segment carries foreign lab devices (the #18558 ARP conflicts), so
    its noise needs a master population before it is judged (#18681).
  - The judged check also needs an xpfd-side identity guard and must
    allow for the poll lag.
  - Until then the LocalDelivery reply half is covered only by the 1b
    floor.
- **Helper identity.** Every Group 1–4 delta (`ha_snapshot_counter_delta`)
  is VOID when the two captures' `PID:` lines differ, or when only one has
  one. A helper restart inside the window zeroes the counters, which then
  regrow past the baseline as an ordinary-looking delta.
- **Retired knob.** `MAX_FAILOVER_SESSION_MISS_DELTA` (the old raw budget
  of 64) is refused at start.
- **What it cannot see.** A lost UDP or ICMP session is recreated by its
  next packet (one miss, one or two creates, no drop).
  - Neither check reports it unless the misses reach the 1b floor.
  - The stream cells (iperf3 per-stream continuity and zero intervals)
    cover TCP only. A UDP/ICMP continuity observable is open (#18679).
  - A moved session whose local row is lost but whose peer-synced copy
    survives is rebuilt on the hit path. That is the designed recovery,
    not a miss.
- **Selftest.** `make test-ha-assurance-lib` has rows for:
  - master-like and PR-like runs (both checks PASS; the old raw-64 cell
    FAILs the PR-like files);
  - established-flow drops (1a FAIL, the 1b floor PASS);
  - drops on node0 only;
  - the 1a boundary (3 and 4 PASS, 5 FAIL);
  - a lost reply half (1a PASS, 1b FAIL at 2000);
  - missing, malformed and rewound counters (VOID);
  - a helper restart and a one-sided `PID:` line (VOID).

  A mutant of the lib's own function text must flip each defence, and a
  pin keeps `test-failover.sh` emitting both judged checks with their own
  budgets.
- **Not changed.** `scripts/userspace-ha-failover-validation.sh` has its
  own per-cycle raw `MAX_FAILOVER_SESSION_MISS_DELTA` check. That script
  is manual-only (`test/incus/HARNESSES.unreached`). It carries the same
  new-flow bias and is left for its own follow-up (#18680) rather than
  changed here unmeasured.

### `make test-failover` per-stream crash and failback cells (#18692)

`iperf3_sum_parse.py --failover-check --straggler-cost` (test-failover
passes it) prints one cell per event, judged in real seconds on iperf3's own
interval clock. Every stream that carried data in the 5 s before the crash
(or the failback) is judged by its resume instant:

- **FAIL**: it has not resumed within **10 s** (dead or stuck), or the
  telemetry is missing.
- **COST**: it resumed, but **after 3 s** (a straggler). The cell names it
  with its latency. A COST counts as passed and is recorded as `cells_cost`,
  judged master-relative like H11's COST. `cells_cost` also counts the
  planned-move COSTs, so the ledger's `crash_resume_straggler_streams` is
  what tells a straggler COST from a planned-move one.
- **PASS**: every stream resumed within 3 s.

**Why the 3 s line is a COST, not a FAIL** (the coordinator's decision on
#18703). Over 192 streams in 24 preserved loss runs, resumes fall at
0.97–2.91 s, then nothing, then six stragglers at 3.75–4.59 s. The 3 s line
sits in that gap, inside TCP's RTO backoff. As a FAIL line it red-flagged
about a quarter of crash runs, master's included, on which side of a
retransmission a stream landed. Under the green-on-master rule that blocks
PRs at random. The 10 s line still catches a stream that never comes back.
The straggler latencies stay visible: ledger metrics
`crash_resume_data_max_s`/`_median_s`, `crash_resume_straggler_streams` and
the rest, judged against master's band.

**The defect it replaced.** The old window took the event instant from
`$((SECONDS - iperf_start_seconds))`: two integer truncations plus the
iperf3 launch delay, so it could sit a second either side of the real crash
on iperf3's clock. It then asked for data in an interval STARTING in
`[T+1, T+3]`, so the 1 s interval grid decided a stream that resumed 3–4 s
after the crash. Both directions are in the preserved loss runs:

- an in-phase anchor (T = floor of the crash) FAILs a stream that resumed
  2.91 s after the crash (`r-18598/failover-dbg2-025351`, stream 11);
- an anchor one second late PASSes a stream that resumed 4.05 s after it
  (`r-18598/failover-master2-012401`, stream 11);
- an anchor one second early counts the interval holding the crash, so its
  pre-crash bytes pass as a resume.

**The anchor** (`EventAnchor`: an instant plus its error bound).

1. **The crash window.** test-failover reads, from the orchestrator:
   - the LAN host's clock minus its own, from the minimum-RTT
     `incus exec date` reading (`_failover_clock_offset`, error ±rtt/2). The
     iperf3 client stamps its start (`start.timestamp.timemillisecs`) with
     the LAN host's clock;
   - `failover_epoch`, just before the sysrq exec;
   - `failover_epoch_after`, just after the exec returns. The exec never
     returns cleanly, because the VM dies under it, so this is `timeout`
     reaping it about 10–15 s later.

   Only that pair bounds when the sysrq ran. An exec round trip measured
   beforehand is a minimum, not a limit. No firewall node's clock enters, so
   node clock skew cannot move the window.
2. **The crash instant: the stop on iperf3's own clock** inside that window.
   A crash kills every stream's path at once, so the interval holding it
   carries the pre-crash rate for the part of it before the crash. Two reads:
   - **The aggregate's stop**, when the next interval is empty (under 5 %
     of the pre-crash rate).
   - **The streams that stopped together**, when it is not. In a fast
     takeover some streams resume inside the next interval: the #18703 live
     run on 0.0.29546 kept 8 % there. The streams that stayed down for that
     whole interval still carry the crash. At least a quarter of them (and
     at least three) must stop in the same interval. The stop is the median
     of their own fractions, and in that run 5 streams agreed at 0.24 s into
     the interval.

   Either way the crash lies inside the stop interval, so the next interval
   is wholly after it. Its ±0.05 s is a DESIGN BUDGET, not a measured bound:
   rate noise of about 2 % per interval, plus socket buffers filling, which
   only reads late. Live runs record `crash_stop_after_epoch_s`, the stop's
   distance from the mapped `failover_epoch`, to build the evidence; the
   live run read 0.117 s.
3. **The failback**: `failback_epoch`, taken just after the poll that saw
   the last RG land, on the same clock mapping. As before, the anchor is
   that observation, not the move itself.
4. **No clock window that holds the stop** (a reading missing, or no
   `timemillisecs`): the same stop, searched within ±1 s of the integer
   anchor. It is on iperf3's own clock and needs no clock reading. A stop
   before the clock window's start, when there is one, is not the crash.
5. **No stop at all**: the integer verdict under the same COST/FAIL policy,
   evaluated at the integer anchor and one second either side of it. No
   interval starting before anchor+1 counts as resume evidence for any of
   the three. With the old `[T+1, T+deadline]` window, the anchor-1
   candidate's window starts at the anchor, so when the crash lies in the
   second after the anchor, the interval holding it starts just after the
   anchor and its PRE-crash bytes read as a resume for every stream, a dead
   one included. The #18703 review reproduced exactly that: "52s PASS" for a
   stream that never resumes. The cell keeps the verdict when all three
   agree and is VOID when they do not, because the integer clock cannot say
   which side of a line a stream fell on. Callers without `--straggler-cost`
   (`ha-smoke-iperf-lib.sh`) get the old integer verdict unchanged.

**The zero-interval cell agrees with the policy.** test-failover passes the
crash cell's own anchor (`--print-crash-anchor`, else the integer one) to
`iperf-json-metrics.py --resume-event-sec`. A stream's zero seconds inside
`[T, T+10]` are then not "outside" zeros when that stream carries data
again later: they are the crash cell's COST. A stream that never resumes
keeps them. The count is recorded as
`crash_resume_excused_zero_intervals`. This does not make that cell green
on the preserved runs: it was red on all 24 of them, master included, and
almost all of its zeros sit in the RG1 split window (about 111–151 s), not
at the crash. A straggler added at most one zero per run.

**The resume instant.** Only intervals that start at or after the anchor's
latest edge are used, so no pre-event byte is counted. In a stream's first
such interval with data, `[s, e)`, the stream's next interval gives its
post-resume rate. So the data took `duration × bps / bps_next` of the
interval, and the resume instant is `e` minus that. The read has an error
band: a stream still ramping inside the interval reads late, and a burst
followed by a smaller share in the next interval reads early. The true
instant is somewhere in `[s, e)`. So when a 3 s or 10 s line, widened by
the anchor's uncertainty, falls inside a stream's resume interval, the cell
names the stream: the in-interval read decided its side of that line. The
2s91 fixture's stream 11 is one such case at 3 s.

**What the cell reports.** Beside the status, each stream's data latency and
its rate latency. The rate latency is the first interval at or above 50 % of
the lower of the stream's own pre-crash mean (`[T-6, T-1)`) and its own
median over `[T+5, T+15)`. After a takeover the streams re-share the link:
one loss run (`r-18598b/failover-dbg18672-122007`, stream 13) kept a stream
at 15–43 % of its pre-crash rate for 66 s while the aggregate ran at or
above its pre-crash rate. The post window ends before the rejoin, split and
failback, so none of them sets the reference. The cell also gives max and
median of both latencies. The ledger row records `HARNESS_METRIC` lines for:

- `crash_resume_data_max_s`, `_median_s` and `_never`, and their `rate`
  twins;
- `crash_resume_straggler_streams`;
- `crash_at_s`, `crash_anchor_uncertainty_s`, `crash_anchor_precise` and
  `crash_stop_after_epoch_s`;
- the same `failback_*`.

So arms are compared on the distribution (#18561).

**Preserved runs re-judged.** This was done offline, with the data stop as
the anchor, since those runs recorded no epoch (method and table in
`docs/log/18692.md`). Of 29 preserved loss runs, 24 have an empty aggregate
interval at the crash. Two more anchor on the streams that stopped together
(both PASS, data max 2.61 s and 2.26 s). The last three (all recorded PASS)
take the integer fallback, which gives PASS for each of them at every
integer anchor from 2 s before their dip to 1 s after it. On the 3 s line alone, the real-seconds verdict matches the
recorded verdict on all 24, and none flips within ±0.05 s of its anchor.
Under the COST policy, the six recorded FAILs are COSTs (stragglers at
3.75–4.59 s) and no run FAILs. On four runs no in-phase integer anchor
reproduces the recorded verdict, so the anchor was a second off. On the two
rows above, the recorded verdict is right only because of which way it was
off.

**Selftest.** `iperf3_sum_parse_test.PreciseCrashAnchorTests` (run by
`make test-incus-lib`) judges two real loss logs
(`test/incus/failover-crash-straggler-{2s91,4s05}.jsonl`), the #18703 live
run (`test/incus/failover-crash-fast-takeover.jsonl`), and three logs
derived from the 4s05 one by holding its stream 11 down longer (every other
byte is the run's own). The rows:

| row | stream 11 resumes | status |
|---|---|---|
| 2s91 | 2.91 s | PASS (3 s line inside its resume interval: named) |
| 4s05 | 4.05 s | COST |
| 4s05 held to 9 s | 9.06 s | COST (10 s line inside its resume interval: named) |
| 4s05 held to 10 s | 10.14 s | FAIL |
| 4s05 held forever | never | FAIL |
| fast takeover (the #18703 live run, aggregate never empty) | 2.39 s max | PASS, anchored on 5 streams' stop |
| 4s05, integer anchor 54 s, no clock | stop found within ±1 s | COST |
| dead, integer anchor 53 s, no clock | stop found within ±1 s | FAIL |
| 4s05, three-anchor cell at 54 s | 53 s COST, 54 s COST, 55 s PASS | VOID |
| dead, three-anchor cell at 53 s | FAIL at all three (no evidence before 54 s) | FAIL |

It also pins the integer anchors that mis-score the two real logs. Eleven
executable mutants each flip a named row. Each mutant is one exact textual
replacement of the parser source, executed in a fresh namespace, with a
no-op control through the same path. The mutants:

- an integer anchor;
- counting the interval that holds the crash;
- the resume at the interval start;
- the resume at the interval end;
- no stop refinement;
- no 3 s COST line;
- no 10 s FAIL line;
- a fallback that trusts one integer anchor;
- the anchor-1 candidate counting the interval that holds the crash (the
  review's "52s PASS");
- a fallback without the ±1 s stop search;
- the aggregate stop only, with no stop of streams together.

`make test-iperf-throughput-lib` adds the producer rows. A straggler that
resumes at T+5 is excused to the 10 s line (0 outside, 2 excused). The same
bytes without `--resume-event-sec` count 2 outside. A dead stream is not
excused (17 outside).

### `make test-failover` zero-interval cells: windows and definitions

`scripts/iperf-json-metrics.py` scores the whole-run iperf3 stream. A
per-stream interval counts as "zero" at or below `--zero-gbps` (default
0.05 Gbit/s), not only at 0 bytes. At iperf3's 1 s resolution one zero
interval means a stream carried almost nothing for about a second.

**Registered windows.** Each is `[T, T+3]` around an anchor `T`, in seconds
since the iperf launch on the harness's integer `SECONDS` clock. That clock
can be up to about 1 s off iperf's own clock.

| Event | Anchors | Kind | How its zero intervals are scored |
|---|---|---|---|
| the crash (`failover_at_seconds`) | the crash instant | **excused** (`--event-sec`) | not counted: peer-loss detection is by design (in the lab about 1.0–1.05 s after the last heartbeat, 0.8–1.05 s after the crash, when the #18570 probe goes unanswered; about 1.2 s more under the sync-recency rule for a peer without ack support, whose last sync frame is about one interval younger than its last heartbeat) |
| the crash, for a stream that resumes (`--resume-event-sec`, #18692) | the crash stream cell's own anchor (sub-second when it has one), to its 10 s FAIL line | **excused for that stream only** | not counted outside: a resuming straggler is the crash cell's COST. A stream that never carries data again keeps its zeros. Counted as `crash_resume_excused_zero_intervals` |
| the RG1 move that starts the split slice (RG1 on node0, RG0/RG2 on node1) | the instant before the request, and the poll-observed landing | **planned** (`--planned-move rg1-split=...`) | scored as a move, below |
| the RG0/RG2 failback that ends the split | the instant before each of the two requests, and each RG's poll-observed landing | **planned** (`--planned-move rg0-rg2-failback=...`) | scored as a move, below |

A planned move is anchored at the request AND the landing, because a landing
takes 1.3–3 s. With the request alone, a stall at the landing falls outside
the window. A move that did not land is not registered; its own cells have
already failed.

**Planned moves are scored, not excused** (#18617). Sessions are on both nodes
before a planned move, so every lost packet is a transition cost (matrix H10).
Each move is one cell, judged by H11's rules at 1 s resolution. A stream is
**stalled** in an interval when it carried under 1 Mbit/s (H11's stall,
`--planned-stall-gbps 0.001`). A stream between that and the 0.05 Gbit/s
zero threshold is **low-share**: a transition dip, not a stall. It does not
change the move's verdict. On the live run on 2026-10-31 the aggregate fell
from about 9 to 1.2 Gbit/s at the RG1 move, below H9's 2.0–3.5 Gbit/s split
ceiling on loss. Two streams ran at 12 Mbit/s and one stopped. That dip is a
transition cost (H10), so each planned move records it on the ledger as
`HARNESS_METRIC` lines, judged master-relative like `cells_cost`:

- `planned_<move>_low_share_streams`: the number of low-share streams;
- `planned_<move>_min_stream_gbps`: the lowest per-stream rate in the
  move's windows;
- `planned_<move>_window_aggregate_gbps`: the mean aggregate rate over the
  move's windows.

`<move>` is `rg1_split` or `rg0_rg2_failback`. The low-share streams are also
named in the cell's text.

- **PASS:** no stream stalled in the move's windows.
- **COST:** exactly one stream stalled. Its stall is the whole run of
  consecutive zero intervals that touches the window, inside it or past it.
  The stall lasted at most 10 s (H11's `SOAK_MAX_COST_STALL_MS`), and the
  stream carried data again afterwards. A COST counts as passed and is
  recorded as `cells_cost` (the summary's `, <k> cost`), judged
  master-relative as H11 judges its COST.
- **FAIL:** any of:
  - every stream stalled (under 1 Mbit/s) in one interval: an aggregate
    outage over H11's 1 s;
  - more than one stream stalled;
  - a stall was longer than 10 s;
  - a stream never carried data again.

**The cells.**

- **Outside the windows:** `stream_zero_intervals_outside_events_total`, the
  "per-stream zero intervals outside the crash and planned-move windows" cell
  (`MAX_STREAM_ZERO_INTERVALS`, default 0). It counts every zero interval that
  is not wholly inside a registered window. Planned-move zeros are scored by
  their move cell instead, so they are never counted twice. A stall that
  outlasts its window counts here too.
- **Whole run:** `zero_intervals_total` is aggregate zero intervals PLUS
  per-stream zero intervals, with no window excluded. The crash alone zeroes
  every stream for 1–3 intervals (8 streams give 8–24), so a fixed limit of 2
  was red on every crash run. Its fate is decided: it is **recorded**, not
  gated, as `whole_run_zero_intervals` on the ledger row (a `HARNESS_METRIC:`
  line), and judged master-relative. `MAX_ZERO_INTERVALS=<n>` gates it
  absolutely again for a one-off run.
- **Who reads these.** `whole_run_zero_intervals`, the `planned_<move>_*`
  metrics and `cells_cost` are ledger metrics that a person reads against
  master's rows. Nothing compares them automatically: `ledger_compare` bands
  only the headline (`throughput_gbps`).
- **What this cannot see.** test-failover has no 10 ms ping, so a stall
  shorter than one 1 s interval goes unscored here. H11's ping-gap bound lives
  only in `test-rg-move-soak`.
- **Counting.** Count a run by the same definition before comparing numbers:
  an exact-zero count of the #18598 gate's master arm gives 35, while the
  harness definition gives 3 + 58 = 61.

## Target And Interpretation

Validation target for the active userspace forwarding path:

- IPv4 `iperf3 -P 6 -t 5`: `22-23 Gbps`
- IPv6 `iperf3 -P 6 -t 5`: `22-23 Gbps`
- Retransmits: `0`
- Sustained transfer: no “fast first second, then collapse to 0 bps” interval pattern

The default `PARALLEL=6` is intentional for the six-worker AF_XDP lab shape:
the smoke test should cover the worker/RSS set. Use an explicit lower
`PARALLEL` value when studying low-flow RSS behavior; do not treat a
worker-underdriven run as the dataplane ceiling.

That is the target, not a guarantee of the current tree state.

Current `master` reality:

- the isolated HA lab is used for both active userspace-forwarding work and
  explicit legacy regression coverage, depending on the active config and
  runtime gate
- the userspace validator fails by default if the node settled into legacy eBPF
  fallback; set `ALLOW_LEGACY_EBPF_HA_VALIDATION=1` only for a deliberately
  scoped legacy regression run
- the tree is still under active forwarding-correctness and performance work on
  the AF_XDP fast path
- it is normal for the validator to fail while a phase is in progress
- a failing validation run is signal; do not “fix” it by lowering the threshold

Use [userspace-perf-compare.md](../docs/userspace-perf-compare.md)
for the current measured numbers and current hot-path deltas. This document defines
the required workflow and the target, not the current performance claim for every
tree state.

The validator now treats interval collapse as a separate failure mode from average
Gbps. A run that peaks high and then drops near zero is a failure even if the short
overall average still looks superficially acceptable.

For the dedicated failover workflow, the operator should watch all eight stream
lines, not only the `[SUM]` line, for both:

- forward `iperf3 -c ...`
- reverse `iperf3 -c ... -R`

A run is still a failure if aggregate traffic recovers but one stream remains
pinned at `0.00 bits/sec` after failback, or if only one direction recovers.

The validator treats forwarding correctness and traceroute visibility as
distinct concerns. It does not require every internet hop to answer. It does
require:

- the controlled LAN-to-WAN-target ping (`172.16.80.200` /
  `2001:559:8585:80::200`) to receive replies for both families. The LAN
  host reaches these WAN-side targets only by transiting the userspace
  dataplane, so this is the controlled IPv6/IPv4 forwarding-correctness gate
  (`validate_reachability`). It also asserts the targets do not resolve
  on-box, so the transit premise cannot silently drift
  (`assert_forwarding_route`)
- the firewall hop to answer TTL-expired probes
- the final destination hop in IPv4 `mtr` to resolve for `1.1.1.1`. Loss is
  parsed numerically, so a final hop printed as `(waiting for reply)`, with
  a column-truncated loss (`100.0` without `%`), with integer `100%` loss,
  or with an unparseable loss column fails closed
- IPv6 `mtr` to have a resolved first hop. The public IPv6 trace to
  `2607:f8b0:4005:814::200e` is **observability-only**: any unresolved or
  silent later/final hop is recorded as a warning, never a hard failure,
  because the external endpoint and intermediate ICMPv6 rate-limiting are
  outside our control (#1303). IPv6 dataplane forwarding is gated by the
  controlled ping/TTL/iperf3 legs above, not by this external trace

For the TTL / hop-limit probes, a non-zero `ping` exit code is not itself a
failure. The validator accepts the probe when the returned output contains the
expected native time-exceeded text from the userspace firewall.

Artifacts kept on `cluster-userspace-host`:

- `/tmp/userspace-ping-v4.out`
- `/tmp/userspace-ping-v6.out`
- `/tmp/userspace-ttl-v4.txt`
- `/tmp/userspace-ttl-v6.txt`
- `/tmp/userspace-mtr-v4.txt`
- `/tmp/userspace-mtr-v6.txt`
- `/tmp/ipv4-*.json`
- `/tmp/ipv6-*.json`

The `cluster-userspace-host` only needs the runtime tools used to generate the
artifacts:

- `ping`
- `mtr`
- `iperf3`

The interval-collapse analysis runs on the repo host using
[iperf-json-metrics.py](../scripts/iperf-json-metrics.py),
so the cluster test host does not need `python3`.

Short-lived outliers can still happen immediately after rolling deploy while HA
ownership and RA converge. That is why the validator explicitly waits for IPv6
route state before throughput checks.

## Operational Rule

For the isolated userspace cluster, do not use `/tmp` cluster env/config files
as the source of truth.

Use:

- [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
