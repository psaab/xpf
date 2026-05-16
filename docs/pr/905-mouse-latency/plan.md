# Plan: #905 — mouse-latency tail measurement (v4)

Issue: #905
Predecessor: #900 (`docs/pr/900-100e100m-harness/findings.md` —
elephant-side answered; mouse-side not measured).
Source of recommendation: `docs/pr/838-afd-lite/findings.md`.

Plan revisions:
- v1 → v2: incorporated Codex R1 (17 findings; PLAN-NEEDS-MAJOR).
- v2 → v3: incorporated Codex R2 (3 HIGH + 2 MED + 2 LOW;
  PLAN-NEEDS-MAJOR).
- v3 → v3 (mid-rev): incorporated Codex R3 (2 HIGH-partial +
  3 MED + 1 LOW; PLAN-NEEDS-MAJOR).
- v3 → v4: incorporated Codex R4 (3 HIGH + 3 MED + 2 LOW;
  PLAN-NEEDS-MAJOR).
- v4 (revision): incorporated Codex R5 (4 MED + 1 LOW;
  PLAN-NEEDS-MINOR).
- v4 (revision): incorporated Codex R6 (2 MED + 1 LOW;
  PLAN-NEEDS-MINOR).
- v4 (revision): incorporated Codex R7 (2 MED;
  PLAN-NEEDS-MINOR).

Disposition tables at §11. Each round produced concrete
file/line-grounded findings; each fix is anchored in §11.

## 1. Goal

Produce per-cell JSON RTT data for short TCP request/response
"mice" running concurrently with a varying number of long-lived
"elephant" iperf3 streams across the xpf-userspace HA cluster.
Report:

- p50, p95, p99 RTT per cell (p999 omitted: too few tail samples
  even at the matrix-scaled run length to be robust — see §6.1).
- Achieved per-coroutine RPS distribution (closed-loop semantics
  hides degradation in absolute counts; achieved-RPS is the
  co-metric — see §4.4).
- IQR of p99 across reps as a noise-floor proxy.

Concrete deliverable: a verdict against the **decision threshold**
from #905:

> Mouse p99 RTT at (N=128 elephants, M=10 mice, mouse_class =
> best-effort) is ≤ 2 × the idle baseline (N=0, M=10, same class).

This threshold is a **decision aid for whether to pursue further
algorithm work**, not a product SLO. Product mouse-latency
tolerance is a separate decision; #900 explicitly rejected uncited
SLO numbers in its plan and this PR follows the same discipline
(see §7.2).

## 2. What this is NOT

- Not an algorithm change. The deliverable is data + a verdict.
- Not the 100E100M harness from #900 (which hit raw-socket and
  iperf3-single-tenant walls). Smaller, scoped harness.
- Not a HA failover test. RG state and journalctl VRRP events
  are sampled across each rep; any rep with an in-window
  state change is invalidated.
- Not multi-mouse-class. Best-effort only; `iperf-a-shared`
  dropped with the explicit caveat that this PR's verdict
  cannot distinguish "cross-class isolation works" from "same
  class doesn't HOL" — see §3.4.
- Not v6. v4-only with the explicit caveat that the verdict
  does not generalize to dual-stack — see §3.5.
- Not a mechanism-attribution study. The plan's v1 claimed the
  histogram could identify HOL/cross-class/SFQ as the failure
  mechanism on FAIL; that requires daemon counters and CoS
  deltas which this harness does not capture (R1 #12). On FAIL,
  the deliverable is the latency tail + the follow-up file
  `docs/pr/905-mouse-latency/findings.md` proposing a separate
  mechanism issue.

## 3. Test environment

### 3.1 Cluster

- `loss:xpf-userspace-fw0` (primary, weight 200) +
  `loss:xpf-userspace-fw1` (secondary, weight 100).
- **Source container** for mice + elephants:
  `loss:cluster-userspace-host`. (R1 #8: this is the LAN-side
  client container, not the firewall — `apply-cos-config.sh`
  targets the firewall VM, not this host.)
- Target: `172.16.80.200` (operator-managed):
  - port 5201 → iperf3 server; CoS class `iperf-a`, 1 Gb/s
    shaped (matches existing classifier term 0).
  - port 7 (TCP) → echo; CoS class `best-effort` (no classifier
    term matches, falls through to default queue, 100 Mb/s
    shaped).

### 3.2 CoS preconditions

Before any run, apply the standard fixture on the primary using
the qualified incus name (R1 #7):

```
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

(The script's default and usage line both use the `loss:` prefix;
v1 dropped it and would have applied to a local instance.)

### 3.3 Port-7 best-effort path verification (R1 #9, R2 F2)

R1 asked for an active counter-delta assertion that port-7 traffic
hits the best-effort queue. R2 (F2) correctly noted the daemon
command shape this plan invented (`xpf-ctl status --json`) does
not exist — the operational CLI is `cli`, the JSON status path
doesn't expose per-queue tx counters keyed by class name, and the
filter-term counters only fire when a classifier term matches
(port 7 has no matching term, so it's an explicit fallthrough).

v3 drops the daemon-counter-delta preflight. Two static facts and
one dynamic check carry the assertion instead:

1. **Static**: port 7 has no term in
   `test/incus/cos-iperf-config.set` (terms 0-3 cover 5201-5204
   only; verified by Codex R1 #9). Userspace dataplane default
   queue selection for unmatched filter is the best-effort
   queue per `userspace-dp/src/afxdp/forwarding_build.rs:653`
   and `userspace-dp/src/afxdp/tx.rs:4937` (R4 LOW 7: v2 cited
   `filter.rs:342-344` which is unmatched-filter accept
   semantics, not queue selection).
2. **Static**: best-effort scheduler is shaped at 100 Mb/s
   (`cos-iperf-config.set:13-14`).
3. **Dynamic preflight (§4.6)**: the echo-server preflight
   issues real port-7 probes from the source through the
   firewall. Reachability + echo-correctness is asserted
   end-to-end.

(R3 F2 corrected: v3's prior wording suggested the >100 Mb/s
shaper would visibly engage and act as a sanity. That is
wrong. Closed-loop probe traffic at M=50 is in the
order-of-magnitude single-digit-megabit-per-second range —
well below the 100 Mb/s shaper. (R4 L8 + R5 L8 residual: prior
attempts at a precise byte-count derivation contradicted
themselves; we drop the precise math and stick to the
order-of-magnitude argument, which is what the conclusion
actually requires.) The shaper-engages sanity is dead code;
v3 drops it.)

We do **not** dynamically assert "port-7 traffic landed in the
best-effort queue" from outside the daemon. The static
configuration above carries the assertion. If a future analysis
finds port-7 traffic is NOT taking the best-effort path, that
itself becomes a finding worth filing as a separate bug — but
we don't synthesize a CLI command that doesn't exist to gate
this PR's matrix on it.

This is a real measurement-gap acknowledgement: we are
assuming the dataplane behaves as the config implies. Adding
a real per-queue tx-counter CLI is out of scope; tracked as
follow-up if needed.

### 3.4 Why best-effort only (rationale, R1 #15)

#905 lists `mouse_class ∈ {best-effort, iperf-a-shared}`.
`iperf-a-shared` requires reclassifying port 7 into iperf-a, which
needs per-cell CoS-config edits.

Best-effort is the **PASS gate cell**, so a best-effort verdict is
sufficient to pursue the recommendation in `docs/pr/838-afd-lite/findings.md`
(stop algorithm work if PASS).

**Caveat (must appear in findings.md):** A best-effort PASS does
NOT imply the dataplane has cross-class isolation; it only implies
mice-on-best-effort survive elephant-on-iperf-a. The
`iperf-a-shared` cell would be required to distinguish "cross-
class isolation works" from "same-class HOL/SFQ doesn't degrade".
A FAIL on best-effort already motivates further work without
needing the shared cell.

### 3.5 Why v4-only (rationale, R1 #14)

#905 text says "v4 + v6"; #838 findings cites both echo addresses.
The dataplane has separate v4/v6 TX selection paths
(`userspace-dp/src/afxdp/tx.rs:4793-4797`), so a v4 PASS does
not generalize.

This PR is v4-only because:
- The PASS-gate decision (stop further algorithm work?) is the
  same on either family if v4 PASSes — v6 unfairness is its own
  follow-up at most.
- Doubling the matrix doubles wall time + harness surface.
- A v6-only follow-up issue is small if v4 produces actionable
  data.

**Caveat (must appear in findings.md):** A v4 PASS does NOT
generalize to v6.

### 3.6 SYN-cookie state recorded, not assumed (R1 #10)

The `screen syn-cookie` engagement threshold is referenced in
`CLAUDE.md` and `docs/syn-cookie-flood-protection.md`, but the
test cluster's HA config (`docs/ha-cluster-userspace.conf`) does
not assign any screen profile to a security zone. Plan does not
assume screen-cookie is active.

Preflight step in §4.5: before each matrix, capture
`show security screen statistics zone wan` (R4 MED 6:
`docs/ha-cluster-userspace.conf:154` places the WAN-side
zone as `wan`, not `untrust`; the v2 plan had the wrong
zone name). Record the syn-flood counters at start + end.
If they advance during the matrix, flag the cell as
"screen-engaged" in manifest.json — analyst decides whether to
invalidate.

## 4. Harness design

### 4.1 Probe driver — `test/incus/mouse_latency_probe.py`

Python 3 script (no third-party deps; aggregator in §4.5 uses
the stdlib `statistics` module — no `numpy`, R1 #13).

Per-cell invocation contract:
```
python3 test/incus/mouse_latency_probe.py \
    --target 172.16.80.200 --port 7 \
    --concurrency 10 \
    --duration 60 --payload-bytes 64 \
    --out /tmp/probe.json
```

**Closed-loop semantics, no per-iteration sleep** (R1 #1, #2):

The v1 plan tried to mix closed-loop coroutines with a
`pace-ms / concurrency` inter-iteration sleep. That was wrong:
M coroutines burst at startup and the sleep formula doesn't
produce a bounded global rate. v2 drops the sleep entirely:

1. Spawn `--concurrency` (= M) asyncio coroutines.
2. Each coroutine, in a loop until `--duration` seconds elapse:
   a. `t0 = time.monotonic_ns()`.
   b. Open TCP socket to `(target, port)` with a 5 s connect
      timeout.
   c. Send `--payload-bytes` random bytes; flush with a
      deadline-bounded `drain()`.
   d. Read back exactly `--payload-bytes`; on drain timeout,
      short-read, or
      timeout, count as error.
   e. Close socket.
   f. `t1 = time.monotonic_ns()`.
   g. Append `t1 - t0` to its own RTT list. Increment its own
      attempt counter.
3. Each coroutine immediately starts its next probe — no sleep.

This is canonical closed-loop "M concurrent mice". Achieved RPS
falls if RTT rises; that drop IS data, not a bug.

Implementation note: later 100E100M work added a `persistent`
connection mode and optional `--min-interval-ms` closed-loop
start-to-start spacing. Both modes keep connect, write-drain, and
echo-read phases bounded by the probe deadline so TCP backpressure
cannot stall a rep beyond `--duration`.

### 4.2 Achieved-RPS as co-metric (R1 #2, #3)

Closed-loop semantics implies achieved RPS is workload-dependent.
The harness reports it explicitly:

- Per-coroutine: `attempts_per_coroutine[i]`.
- Aggregate: `sum / duration`.
- Median + IQR of `attempts_per_coroutine`.

**Degenerate-coroutine guard (R1 #3):** if
`min(attempts_per_coroutine) < 0.5 × median(attempts_per_coroutine)`,
the cell is INVALIDATED — a coroutine has stalled (e.g. socket
hang, server-side per-IP cap), so the histogram excludes its
slow region and `error_rate` alone would not catch it.

**Per-rep validity:** in addition to the existing
`error_rate < 0.01`:
- `min(attempts_per_coroutine) >= 0.5 × median(attempts)`.
- Total `attempts` minimum (R5 fresh #4: v3's
  `100 × concurrency` floor was too loose for p99 robustness):
  - **For M ≥ 10**: `attempts >= 5000` per rep
    (yields ≥ 50 tail samples for p99 within the rep, the
    minimum for the §6.1 robustness argument to hold).
  - **For M = 1**: `attempts >= 500` per rep (single coroutine
    can't reach 5000 in 60 s under typical RTT; the M=1 cells
    tolerate looser p99 — which is also why M=1 cells are
    excluded from the PASS-gate ratio in §7.2).

### 4.3 JSON output schema

```json
{
  "config": {
    "target": "172.16.80.200", "port": 7,
    "concurrency": 10,
    "duration_s": 60, "payload_bytes": 64
  },
  "totals": {
    "attempted": 12000, "completed": 11982, "errors": 18,
    "error_rate": 0.0015,
    "attempts_per_coroutine": [1198, 1199, 1201, 1198, 1200, 1199, 1202, 1198, 1203, 1184],
    "achieved_rps_total": 199.7
  },
  "rtt_us": {
    "p50": 250, "p95": 800, "p99": 1500,
    "min": 80, "max": 18000, "mean": 320, "iqr": 92
  },
  "histogram_us": {
    "buckets": [10, 20, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 100000],
    "counts": [0, 12, 480, 8011, 2102, 587, 187, 14, 1, 0, 0, 0]
  },
  "validity": {
    "ok": true, "reasons": []
  }
}
```

`p999` deliberately omitted (R1 #4).

### 4.4 Elephant driver with cwnd-settle gate (R1 #5)

v1 used `iperf3 -J` + a 2 s sleep. R1 #5 correctly flagged that
this doesn't prove steady-state. v2 mirrors #900's approach:

```
iperf3 -c 172.16.80.200 -p 5201 -P <N> -t <iperf3_duration> -i 1 --forceflush
```

(R4 HIGH 3: `--forceflush` is required when stdout is
redirected/tailed, otherwise iperf3 buffers and the live
`[SUM]` parser sees nothing until the run ends, falsely
tripping `INVALID-cwnd-not-settled`. Existing harnesses use
the same flag, e.g. `test/incus/test-stress-failover.sh:159`.)

`iperf3_duration` is computed by the orchestrator (R2 F3):
`SETTLE_BUDGET (20s) + probe_duration (60s) + SLACK (10s) = 90s`
for the 60s probe window. If `probe_duration` changes via flag,
the orchestrator recomputes. The original v2 expression
`duration+10` was structurally too short (60s + 10s = 70s
versus 80s required) — iperf3 would exit during the probe
window.

Text mode (no `-J`), with `-i 1` for live per-second aggregate.
The orchestrator (§4.5):

1. Launches iperf3, redirects stdout to `<out_dir>/iperf3.txt`.
2. Tails the output, parses each `[SUM]` row's Gbps.
3. Waits for a "settled" condition: 3 consecutive `[SUM]` rows
   each within ±15 % of each other AND ≥ 0.7 × class-shaper
   (0.7 Gb/s for iperf-a). Timeout: `SETTLE_BUDGET = 20 s`. On
   timeout, abort the rep as INVALID-cwnd-not-settled.
4. Once settled, launches the probe driver with
   `--duration 60`.
5. Continues monitoring `[SUM]` during probe window. If any
   `[SUM]` row drops below 0.5 × shaper for ≥ 3 consecutive
   seconds, mark rep as INVALID-elephant-collapsed.
6. After probe driver exits, waits for iperf3 to exit (or
   kills with the remaining `SLACK = 10 s` timeout).
7. Parses the final `[SUM]` totals into iperf3.json (a derived
   file; the raw text is also kept).

**`[SUM]` line format pin (R2 F5):** iperf3 in text mode emits
per-interval lines of the shape
`[SUM]   3.00-4.00   sec  118 MBytes  990 Mbits/sec  ...`. The
parser (in the orchestrator + a small Python helper) anchors
on `^\[SUM\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+\S+\s+\S+\s+(\S+)\s+(\S+)/sec`
and extracts (rate, unit). Unit is normalized to bits/sec via a
unit table (Kbits, Mbits, Gbits). The same parser is used for
the per-second monitoring in step 5 and the final-summary
aggregation in step 7.

The parser ships as `test/incus/iperf3_sum_parse.py` with unit
tests in `iperf3_sum_parse_test.py` covering: per-second rows
across all unit prefixes, the final summary line shape, and
malformed input (empty, non-SUM, partial). Listed in §9.1.

For N=0 (idle baseline), no iperf3 is launched.

### 4.5 Run orchestrator — `test/incus/test-mouse-latency.sh`

```
./test/incus/test-mouse-latency.sh <N> <M> <duration> <out_dir>
```

Steps per rep:

1. **CoS preflight** (§3.2): apply
   `cos-iperf-config.set` to the primary. (R4 MED 4: do NOT
   re-attempt a port-7→best-effort dynamic assertion here —
   §3.3 v3 explicitly removed that check; the static config
   carries the assertion. Step 1 is fixture-apply only.)
2. **Source-CPU sampling** (R1 #11, Copilot R1 #3): launch
   `mpstat 1 <duration>` on `cluster-userspace-host` JUST BEFORE
   the probe (not at top-of-rep), so its count completes naturally
   when the probe ends and the `Average:` summary row is emitted.
   If `Average:` busy > 80 %, mark rep as INVALID-client-saturated;
   if mpstat output is missing or unparseable, INVALIDATE rather
   than silently passing.
3. **RG state polling** — query the primary at 1 Hz (Copilot R1
   #7: a single `cli -c "show chassis cluster status"` query
   from the local node returns BOTH nodes' RG-state rows because
   `Manager.FormatStatus` includes peer state in the same
   output, so polling one node is sufficient to detect any
   transition). Initial sample at t=0, plus continuous poll
   throughout the rep (R3 fresh #2 + R4 HIGH 1).

   **CLI command pinned (R4 HIGH 1):**
   ```
   incus exec loss:xpf-userspace-fw0 -- cli -c "show chassis cluster status"
   ```
   The output is text from
   `pkg/cluster/cluster.go:1767-1830` (`Manager.FormatStatus`).
   Relevant identity for "did the RG state change?" is the
   FULL set of `(rg_id, node_id, state)` triples (R5 fresh
   #3: capturing only `(rg_id, primary_node_id)` would miss a
   secondary's drift through `hold`/`disabled`/`lost` states
   that can also indicate cluster instability without a
   primary change). Parser anchors:
   - `^Redundancy group: (\d+)` introduces an RG block.
   - `^node[01]\s+\d+\s+(primary|secondary|hold|disabled|lost)`
     gives the per-node state row inside the block.
   The orchestrator extracts, per sample, a sorted list of
   `(rg_id, node_id, state)` triples and writes them to
   `<out_dir>/rg-state-poll.txt` as
   `<unix_ms>\trg=<id>\tnode=<id>\tstate=<state>` lines (one
   line per (rg, node) tuple per sample).

   Parser ships as `test/incus/cluster_status_parse.py` with
   unit tests in `cluster_status_parse_test.py` (added to §8
   and §9.1).

   Continuous polling catches a complete failover+failback
   cycle (same start and end state, but transient master
   change in between) that start/end-only sampling would miss.
4. **journalctl cursor capture on BOTH nodes** (R7 MED 2):
   ```
   for FW in xpf-userspace-fw0 xpf-userspace-fw1; do
       incus exec loss:$FW -- journalctl --show-cursor -n 0 \
           > <out_dir>/jc-cursor-$FW.txt
   done
   ```
   Both fw0 and fw1 are captured because either node may be
   the primary at the start of a rep, and a transition could
   originate from either side.
4a. **SYN-cookie counter snapshot on the current primary**
    (R5 fresh #1, R7 MED 2: explicit incus invocation):
    ```
    incus exec loss:xpf-userspace-fw0 -- \
        cli -c "show security screen statistics zone wan" \
        > <out_dir>/screen-pre.txt
    ```
    fw0 is the standing primary in the test cluster; if a
    transition happens during the rep, the post-snapshot at
    step 9a is taken from whichever node is primary at that
    point (orchestrator queries
    `cli -c "show chassis cluster status"` first to find it).
    Captured into the manifest. Delta written into
    manifest.json under `screen_engaged: <bool>`.
5. **Elephant launch + cwnd-settle gate** (§4.4) if N>0.
6. **Probe driver** (§4.1) for `<duration>` seconds.
7. **Source-CPU stop**, parse mpstat result.
8. **Elephant stop** (R1 #5: invalidate if collapsed during
   window).
9a. **SYN-cookie counter post-snapshot** (R5 fresh #1):
    ```
    cli -c "show security screen statistics zone wan" \
        > <out_dir>/screen-post.txt
    ```
    Diff with `screen-pre.txt` (step 4a); if any syn-flood
    counter advanced, set `screen_engaged: true` in manifest.
    Not auto-invalidating; analyst flag.
9. **journalctl diff on BOTH nodes** (R1 #6, R2 F1, R7 MED 2):
   ```
   for FW in xpf-userspace-fw0 xpf-userspace-fw1; do
       incus exec loss:$FW -- journalctl \
           --after-cursor="$(cat <out_dir>/jc-cursor-$FW.txt)" \
           -u xpfd | grep -iE '<HA_TRANSITION_REGEX>'
   done
   ```
   The userspace cluster has `PrivateRGElection=true`
   (`pkg/config/compiler_system.go:810`), which suppresses
   RETH VRRP entirely — the dominant state-change log is
   `cluster: primary transition` from `pkg/cluster/cluster.go:1671`.
   For the remaining VRRP-on-non-RETH paths, the log shape is
   `vrrp: transitioning to (MASTER|BACKUP|INIT)` from
   `pkg/vrrp/instance.go:779,796`.

   `HA_TRANSITION_REGEX` =
   `cluster: primary transition|vrrp: transitioning to (MASTER|BACKUP)`

   (R3 F1: dropped the `INIT` arm — `pkg/vrrp/instance.go` only
   emits `transitioning to MASTER` and `transitioning to BACKUP`;
   no `INIT` log string exists.)

   **grep + journalctl exit-status handling (R3 fresh #1, R4
   MED 5):** `grep` exits 1 when no lines match, which is the
   *expected* clean case. `journalctl` exit code is captured
   separately so an upstream journalctl failure (e.g. cursor
   invalid, daemon log unavailable) is NOT silently treated as
   "no matches".

   ```
   set +e; set -o pipefail
   matches=$(journalctl --after-cursor="$cursor" -u xpfd \
                 2> /tmp/jc-stderr; echo "JC_RC=$?")
   jc_rc=$(echo "$matches" | sed -n 's/.*JC_RC=//p' | tail -1)
   matches=$(echo "$matches" | sed '/JC_RC=/d' | grep -E "$RE")
   gr_rc=$?; set -e
   ```
   - `jc_rc != 0` → harness failure, fail the rep with
     "INVALID-jc-error" + capture stderr.
   - `gr_rc == 1 && empty matches` → success (no transitions).
   - `gr_rc == 0 && nonempty matches` → INVALID-ha-transition.
   - `gr_rc > 1` → harness failure.

   If any state-transition event appears in the rep window,
   INVALIDATE the rep with
   `<out_dir>/INVALID-ha-transition`.
10. **RG state poll review**: stop the background poller from
    step 3, scan `rg-state-poll.txt` for any state value that
    differs from the t=0 sample. ANY mismatch — even one that
    later returns to the original state — INVALIDATES the rep
    with `<out_dir>/INVALID-rg-state-flap`. This catches the
    full failover+failback cycle that journalctl grep can miss
    if the daemon log rotates or the regex has a gap.
11. **Manifest write**: `<out_dir>/manifest.json` with cell
    parameters, RG samples, journalctl excerpt, mpstat
    summary.

If any step fails or marks INVALID, the rep counts toward the
INVALID quota; matrix orchestrator schedules a replacement
under the cell's overall rep cap (R6 NEW-LOW: clarifying the
two limits' interaction).

The cell's hard rep ceiling is **15** (matching §4.7's
auto-extension), of which up to 5 may be retries. So a cell
that hits 10 valid reps without retries is done at 10; a cell
with retry-eligible failures gets up to 5 replacement reps,
not exceeding 15 total. Gate-grade cells require all 10 valid
reps; cells with fewer than 10 valid reps after the 15-rep
ceiling are INSUFFICIENT-DATA.

### 4.6 Echo-server preflight (R1 #17)

Before the matrix starts, a one-shot preflight:

```
python3 test/incus/mouse_latency_probe.py \
    --target 172.16.80.200 --port 7 \
    --concurrency 1 --duration 5 \
    --out /tmp/preflight.json
```

Required for matrix to proceed:
- TCP connect succeeds.
- Echo readback exactly matches sent payload bit-for-bit (the
  probe driver's per-probe verification).
- p99 RTT < 5 ms (sanity — idle path through firewall should
  be <1 ms but we allow margin).
- error_rate < 0.001.

If preflight fails, matrix aborts with the preflight JSON +
operator-actionable diagnosis. No partial data is collected.

### 4.7 Matrix orchestrator — `test/incus/test-mouse-latency-matrix.sh`

Iterates 12 cells (N ∈ {0, 8, 32, 128} × M ∈ {1, 10, 50}).

**Per-cell rep accounting (R7 MED 1, reconciles §4.5 retries
with §4.7 auto-extension):**

- Baseline: 10 reps scheduled.
- Replacement reps (per §4.5: any rep that lands INVALID
  triggers a replacement) and auto-extension reps (per §4.7:
  triggered when INVALID rate > 30 % in the first 10) BOTH
  count against the same 15-rep hard ceiling.
- Order: any in-baseline INVALID schedules an immediate
  replacement; if total reps reaches 10 with INVALID rate
  > 30 %, additional reps are scheduled up to 15. Both
  mechanisms are subordinate to the 15-rep ceiling.
- Cell stops once 10 valid reps are collected, or 15 total
  reps have run, whichever is first.
- Cell is reported INSUFFICIENT-DATA if fewer than 10 valid
  reps after the ceiling.

**Wall-budget math (R2 F4):** per-rep total is iperf3
lifetime + setup ≈ 90 s + ~15 s setup/teardown ≈ 105 s. Base
matrix at 10 reps: 12 × 10 × 105 s ≈ 210 min (3.5 h). With
auto-extension to 15 reps in the worst case (every cell hits
the extension trigger): 12 × 15 × 105 s ≈ 315 min (5.25 h).

Wall-budget cap: **6 hours**. v2's "4 h" was incorrect for the
extension worst case; v3 raises the cap. If exceeded, the
matrix runs as far as it can and the partial results are
written; findings.md flags incomplete cells as
INSUFFICIENT-DATA. Cells are run in order N=0 first (idle
baseline = the gate's reference cell, must be present), then
M=10 cells (the gate's measurement cells), then the rest —
so the gate-relevant data lands first and a wall-budget
truncation degrades gracefully.

## 5. Aggregator — `test/incus/mouse_latency_aggregate.py`

Reads `<out_dir>/cell_N{n}_M{m}/`, picks median rep per cell
(by p99), produces:

- `<out_dir>/summary.json` — per cell, the median rep's
  **p50, p95, and p99 RTT** (R5 fresh #2: §1 promises all
  three; v3's narrower "median p99 + IQR" was an output
  contract gap), plus IQR of p99 across reps and the
  achieved-RPS distribution.
- Markdown table to stdout, suitable for findings.md.
- The decision-threshold verdict (§7.2): PASS / FAIL /
  INSUFFICIENT-DATA, naming the two reference cells.

## 6. Statistical notes

### 6.1 Why p999 is omitted (R1 #4)

At M=10, achieved RPS is bounded by the probe path. From #900's
data, idle p99 across the firewall is sub-millisecond, so closed-
loop achieved RPS ≈ 200 RPS at M=10. Per-rep samples ≈ 200 × 60
= 12000.

The aggregator picks the **median rep by p99** (§5), not a pooled
sample set across all 10 reps (R2 F6). So the reported p99 is
estimated from a single rep's ~12000 samples — that's its
sample count, ~120 tail samples for p99 within that one rep.

p999 within a single rep ≈ 12 tail samples — too narrow for a
robust point estimate. We deliberately omit p999 from the report.

p99 with 120 tail samples per rep is the primary metric; p95
(600 tail samples) is the secondary. Across-rep variance is
captured by IQR of p99 over the 10 reps and reported alongside
the median.

### 6.2 Decision-threshold defense (R1 #16)

The 2× threshold is from the #905 issue body. It is a
**decision-aid heuristic**, not a product SLO. Specifically:

- If p99 at (N=128, M=10) is ≤ 2× idle, the elephants are not
  inflicting catastrophic mouse latency under best-effort
  isolation — sufficient to defer further algorithm work and
  pursue measurement-driven follow-ups.
- If > 2×, the harness produced concrete data motivating a next
  algorithm investigation; product can then decide what its
  actual tolerance threshold is.
- Either verdict is mergeable. The merge gate is "we collected
  data and reported it honestly" (per §7.1).

## 7. Acceptance / gates

### 7.1 Merge gates (block merge if not met)

- `python3 -m unittest discover -s test/incus/ -p '*_test.py'`
  passes for the new test files (R4 HIGH 2: default discover
  pattern is `test*.py`; our file-naming convention puts
  `_test` as a suffix, so the explicit pattern is required for
  discovery to find anything).
- Echo-server preflight succeeds (§4.6).
- Smoke cell `N=0 M=1` runs end-to-end with valid output.
- Codex hostile plan + code review: PLAN-READY YES + MERGE YES,
  every finding disposed.
- Copilot inline review: addressed.

The harness PR ships first; the matrix is run separately on the
loss cluster and `findings.md` lands in a follow-up commit (or a
follow-up PR) once the data is collected. Copilot R1 #2 correctly
flagged that v4 had `findings.md exists` as a merge gate while
the PR contained no findings file — the gate is dropped here in
favor of "harness PR merges; findings PR adds the data".

### 7.2 Decision threshold (per #905; reported, not gating)

Mouse p99 at (N=128, M=10, best-effort) ≤ 2 × idle baseline
(N=0, M=10, best-effort).

## 8. Files touched

This is a plan; the files below are **deliverables**, not
asserted-existing. The plan ships first (this commit), then
the implementation commits add the rest. R3 reviewer briefly
read this section as "v3 claims iperf3_sum_parse_test.py
ships and it doesn't" — clarifying that plan.md is the
specification and these files are written in the
implementation phase.

New files (planned deliverables):
- `docs/pr/905-mouse-latency/plan.md` (this file)
- `docs/pr/905-mouse-latency/findings.md` (post-data)
- `docs/pr/905-mouse-latency/results/cell_N{n}_M{m}/...` (raw)
- `test/incus/mouse_latency_probe.py`
- `test/incus/mouse_latency_aggregate.py`
- `test/incus/test-mouse-latency.sh`
- `test/incus/test-mouse-latency-matrix.sh`
- `test/incus/mouse_latency_probe_test.py`
- `test/incus/mouse_latency_aggregate_test.py`
- `test/incus/iperf3_sum_parse.py`
- `test/incus/iperf3_sum_parse_test.py`
- `test/incus/cluster_status_parse.py`
- `test/incus/cluster_status_parse_test.py`

Modified files: none.

## 9. Test strategy

### 9.1 Unit tests (R1 #13)

`mouse_latency_probe_test.py`:
- Histogram bucket assignment correct at boundaries.
- p99/p95/p50 from synthetic input matches `statistics.quantiles`
  output (no `numpy` dependency).
- Error-rate >1 % marks rep INVALID.
- Degenerate-coroutine guard (R1 #3): rep INVALID when one
  coroutine completes < 0.5 × median.
- Min-attempts gate (per §4.2 thresholds, R5 F4):
  rep INVALID when M≥10 and total attempts < 5000, or M=1
  and total attempts < 500. Test cases at the boundary
  (4999 vs 5000 for M=10; 499 vs 500 for M=1).
- Achieved-RPS computation correct for synthetic input.
- Duration-elapsed loop exit — no off-by-one.

`mouse_latency_aggregate_test.py`:
- Median-of-10 by p99 picks the 5th-or-6th rep, not the mean.
- Decision-threshold computes correctly for synthetic inputs at
  PASS, FAIL, exactly-2.0× boundary.
- INSUFFICIENT-DATA verdict when valid reps < 10.
- INVALID cells excluded from median.

`cluster_status_parse_test.py` (R4 HIGH 1, schema updated by
R5 F3):
- Single-RG canonical output → correct list of
  `(rg_id, node_id, state)` triples (one triple per
  (RG, node) pair).
- Multi-RG output → list extraction with ordering stable
  (sort by `(rg_id, node_id)` for deterministic comparison
  across samples).
- Output with peer-down state (no `node1` row) → triples
  list contains only the local node's row; missing peer
  is implicit, not an error.
- Output with hold/disabled/lost states for either node
  surfaces correctly in the `state` field.
- Empty / malformed input returns empty list, no crash.

`iperf3_sum_parse_test.py` (R2 F5):
- `[SUM]` per-second rows parsed correctly across Kbits, Mbits,
  Gbits unit prefixes; rate normalized to bits/sec.
- Final summary line shape parsed correctly.
- Malformed input (empty, non-SUM, partial line, line with
  trailing per-stream rows like `[SUM-PER-STREAM]`) returns
  None / no-match instead of garbage.
- Anchored regex does not match per-stream `[N]` rows.

`test-mouse-latency.sh`:
- Smoke test only — argument parsing + invocation contract.
  Full integration is the harness run itself.

### 9.2 Smoke run

Before the full matrix (R6 NEW-MED 2: smoke duration must
satisfy the §4.2 M=1 min-attempts floor of 500):
```
./test/incus/test-mouse-latency.sh 0 1 60 /tmp/smoke
```
Verify ≥ 500 completed probes (matches the M=1 floor),
error_rate < 0.01, validity OK, no journalctl HA transitions
in the rep window. Wall time: ~75 s (60 s probe + ~15 s
setup/teardown).

### 9.3 Full matrix

12 cells × 10 reps. Outputs land in
`docs/pr/905-mouse-latency/results/`, committed alongside
findings.md.

### 9.4 Validation lane (per `docs/engineering-style.md` §8)

- Standalone deploy + ping: N/A — this PR is harness-only,
  no daemon code.
- iperf3 -P 16 baseline: implicit in the elephant runs.
- HA failover: not exercised; harness is read-only on the
  dataplane. Per-rep journalctl + RG-state samples protect
  against in-flight failover.

## 10. Risks

- **Echo-server capacity unknown.** §4.6 preflight catches
  obvious failure, but at M=50 sustained for 60 s = up to
  ~12 000 connection attempts; if the echo server has lower
  per-IP concurrency caps that show up only at M=50, the
  M=50 cells INVALIDATE via degenerate-coroutine guard.
  Mitigation: drop to M=25 if M=50 fails consistently;
  document in findings.md.

- **Source-host TCP-stack contention.** Closed-loop M=50 may
  exceed `cluster-userspace-host`'s socket-recv buffer. The
  mpstat gate (§4.5 step 2) catches client saturation; data
  from a saturated source is invalidated.

- **64-byte payload tests connect path, not in-stream
  queueing.** This is a known scope choice; the connect path
  is the canonical mouse workload. If the verdict is FAIL, a
  follow-up could test in-stream RTT at 8 KB.

- **Cluster steady-state drift over 6-hour wall budget.**
  Mitigated by per-rep validity gates + median-of-10. A
  systemic drift (e.g. RSS table mutation between cells)
  shows as monotonic trend in `summary.json`, surfaced in
  findings.md analysis.

- **journalctl cursor on busy daemon.** If xpfd produces
  state-transition logs at high frequency (it shouldn't —
  CLAUDE.md says HA transitions are state-changes only,
  not per-tick), the journalctl-diff grep could miss
  events. Mitigation: also check the RG-state-sample diff
  in step 10.

## 11. R1 disposition

| #  | Sev  | Topic                                | v2 status |
|----|------|--------------------------------------|-----------|
| 1  | HIGH | Pacing math wrong                    | RESOLVED — §4.1: dropped per-iteration sleep, closed-loop only |
| 2  | HIGH | Closed-loop hides overload           | RESOLVED — §4.2: achieved-RPS reported, IQR + per-coroutine distribution |
| 3  | HIGH | Error-rate gate passes degenerate cell | RESOLVED — §4.2: degenerate-coroutine guard (min < 0.5×median), min-attempts gate |
| 4  | HIGH | Three reps statistically weak        | RESOLVED — §4.7: 10 reps baseline, auto-extend to 15. §6.1: p999 dropped, p99/p95 retained |
| 5  | HIGH | Elephant load not proved steady      | RESOLVED — §4.4: text-mode iperf3, cwnd-settle gate ≥0.7× shaper, in-window collapse check at <0.5× |
| 6  | HIGH | HA contamination via in-cell failover | RESOLVED — §4.5 step 4 + 9: journalctl cursor + diff for VRRP transitions |
| 7  | HIGH | CoS apply command wrong namespace    | RESOLVED — §3.2: `loss:xpf-userspace-fw0` qualified |
| 8  | MED  | Source-host claim wrong              | RESOLVED — §3.1: clarified that `cluster-userspace-host` is LAN client, `apply-cos-config.sh` targets the firewall |
| 9  | MED  | Port-7 best-effort live assertion    | SUPERSEDED by R2 F2 — see §3.3 v3: synthetic counter check dropped (no real CLI), replaced with static config + dynamic echo-preflight |
| 10 | MED  | SYN-cookie unverified                | RESOLVED — §3.6: assumption dropped, screen counters recorded as analyst signal |
| 11 | MED  | Client CPU bottleneck                | RESOLVED — §4.5 step 2: mpstat 1 with > 80 % invalidation |
| 12 | MED  | Mechanism attribution overclaimed    | RESOLVED — §1, §2: scope reduced to data + verdict; mechanism is follow-up |
| 13 | MED  | Unit tests miss risky behavior       | RESOLVED — §9.1: added pacing absence, achieved-RPS, degenerate-guard, min-attempts coverage; dropped numpy |
| 14 | MED  | v6 omission rationale weak           | RESOLVED — §3.5: explicit caveat, narrowed PASS-gate scope, v6 = follow-up |
| 15 | MED  | Dropping iperf-a-shared              | RESOLVED — §3.4: explicit caveat about cross-class diagnosis |
| 16 | MED  | PASS threshold not defended as SLO   | RESOLVED — §6.2: 2× is a decision-aid, NOT a product SLO. Findings.md must repeat the caveat |
| 17 | MED  | Echo-server preflight underspecified | RESOLVED — §4.6: explicit preflight (connect, echo readback, p99 < 5 ms, error_rate < 0.001) |

### R2 disposition (after v2 → v3 fixes)

| ID | Sev  | Topic                                | v3 status |
|----|------|--------------------------------------|-----------|
| F1 | HIGH | HA regex doesn't match real log      | RESOLVED — §4.5 step 9: regex now `cluster: primary transition\|vrrp: transitioning to (MASTER\|BACKUP\|INIT)` grounded in `pkg/cluster/cluster.go:1671` + `pkg/vrrp/instance.go:779,796` |
| F2 | HIGH | `xpf-ctl status --json` does not exist | RESOLVED — §3.3 v3: synthetic-counter preflight dropped; static config + dynamic echo-preflight carry the assertion |
| F3 | HIGH | Elephant iperf3 lifetime too short   | RESOLVED — §4.4: `iperf3_duration = SETTLE_BUDGET (20s) + probe_duration (60s) + SLACK (10s) = 90s` |
| F4 | MED  | Wall-budget math ignores extension   | RESOLVED — §4.7 v3: cap raised to 6 h; cells run gate-relevant first so truncation degrades gracefully |
| F5 | MED  | `[SUM]` parsing untested             | RESOLVED — §4.4: parser pinned with a regex; `iperf3_sum_parse_test.py` added; §9.1 lists tests |
| F6 | LOW  | p99 sample-count claim overstated    | RESOLVED — §6.1: clarified that median-rep selection means p99 is from a single rep's samples, not pooled |
| F7 | LOW  | bucket edges fine                    | NO-OP — concern was theoretical, not material |

### R3 disposition (after v2 → v3 fixes)

| ID | Sev  | Topic                                  | v3 status |
|----|------|----------------------------------------|-----------|
| F1 | HIGH (partial) | INIT regex arm ungrounded     | RESOLVED — §4.5 step 9: `INIT` removed; only `MASTER`/`BACKUP` arms remain, grounded in `pkg/vrrp/instance.go:781,798` |
| F2 | HIGH (partial) | 100 Mb/s sanity is dead code  | RESOLVED — §3.3 v3: dead-code claim removed; explicit "we do not dynamically assert this; static config carries it; daemon-CLI follow-up if needed" |
| F5 | MED (still-broken) | parser test file doesn't exist | CLARIFIED — §8: explicit "files below are deliverables, not asserted-existing"; Codex misread plan as implementation. No code change |
| Fresh-1 | MED  | grep no-match exits 1                | RESOLVED — §4.5 step 9: explicit `set +e; rc==1 && empty` handling for clean case |
| Fresh-2 | MED  | failover+failback returns same state | RESOLVED — §4.5 step 3 + 10: continuous 1 Hz RG-state polling during rep, ANY mismatch INVALIDATES |
| Fresh-3 | LOW  | invocation path ambiguous            | RESOLVED — all `python3 test/incus/...` invocations qualified |

### R4 disposition

| ID | Sev  | Topic                                | v4 status |
|----|------|--------------------------------------|-----------|
| H1 | HIGH | RG state polling unspecified         | RESOLVED — §4.5 step 3: `cli -c "show chassis cluster status"` pinned, parser regex pinned, new `cluster_status_parse.py` + `_test.py` files |
| H2 | HIGH | unittest discover discovers nothing  | RESOLVED — §7.1 + §10 acceptance: `discover -p '*_test.py'` flag added |
| H3 | HIGH | iperf3 stdout buffering              | RESOLVED — §4.4: `--forceflush` added to iperf3 invocation |
| M4 | MED  | §4.5 step 1 contradicted §3.3        | RESOLVED — §4.5 step 1 reduced to fixture-apply only |
| M5 | MED  | journalctl exit code unchecked       | RESOLVED — §4.5 step 9: explicit `jc_rc` capture + branch |
| M6 | MED  | SYN-cookie zone wrong (`untrust` → `wan`) | RESOLVED — §3.6: zone corrected per `docs/ha-cluster-userspace.conf:154` |
| L7 | LOW  | filter.rs citation off               | RESOLVED — §3.3: cite `forwarding_build.rs:653` + `tx.rs:4937` |
| L8 | LOW  | byte math off                        | RESOLVED — §3.3: derivation corrected to ~1.7 Mbps |

### R5 disposition

| ID | Sev  | Topic                                | v4 status |
|----|------|--------------------------------------|-----------|
| F1 | MED  | §3.6 SYN counter not wired into rep flow | RESOLVED — §4.5 step 4a + 9a: explicit pre/post snapshot, manifest delta |
| F2 | MED  | §1 promises p50/p95/p99 but §5 only median p99 | RESOLVED — §5: aggregator outputs all three quantiles per cell |
| F3 | MED  | RG poll schema too narrow            | RESOLVED — §4.5 step 3: `(rg_id, node_id, state)` triple, not `(rg_id, primary_node_id)` |
| F4 | MED  | min-attempts floor too loose for p99 | RESOLVED — §4.2: ≥5000 for M≥10, ≥500 for M=1; M=1 excluded from PASS gate per §7.2 |
| L8r| LOW  | byte math residual                   | RESOLVED — §3.3: dropped precise derivation, kept order-of-magnitude argument |

### R6 disposition

| ID  | Sev | Topic                                              | v4 status |
|-----|-----|----------------------------------------------------|-----------|
| NM1 | MED | §9.1 cluster_status_parse_test still primary-only  | RESOLVED — §9.1: triple-schema test contract |
| NM2 | MED | §9.2 smoke probe count (~200) contradicts M=1 floor (500) | RESOLVED — §9.2: smoke duration bumped from 10 s to 60 s; expectation set to ≥ 500 probes |
| NL1 | LOW | retry-cap (3) vs extension-cap (15) interaction unspecified | RESOLVED — §4.5: hard ceiling 15 reps total, up to 5 of which may be retries |

### R7 disposition

| ID | Sev | Topic                                              | v4 status |
|----|-----|----------------------------------------------------|-----------|
| M1 | MED | §4.5 retries vs §4.7 extension reconciliation      | RESOLVED — §4.7: explicit "both mechanisms subordinate to 15-rep ceiling; cell stops at 10 valid OR 15 total" |
| M2 | MED | journalctl/SYN-counter both-node coverage ambiguous | RESOLVED — §4.5 step 4 + 4a + 9: explicit `incus exec loss:xpf-userspace-fw{0,1}` invocations; SYN snapshot tracks primary across in-rep transitions |

## 12. Acceptance checklist

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Probe + aggregate Python implemented; unit tests green.
- [ ] Orchestrator + matrix shell scripts implemented.
- [ ] Smoke cell (N=0, M=1) runs on the loss cluster with
      validity OK.
- [ ] Echo-server preflight succeeds.
- [ ] Full 12-cell matrix runs (10 reps each, auto-extend
      to 15); results committed under
      `docs/pr/905-mouse-latency/results/`.
- [ ] `findings.md` written with the summary table, decision
      verdict, AND the §3.4 / §3.5 / §6.2 caveats.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Copilot inline review: addressed.
- [ ] PR opened, CI green, both reviewers clean.
