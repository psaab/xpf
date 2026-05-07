---
status: REVISED v3 — addressing Codex round-2 (2 NEW blockers; task-mov1mk84). Gemini PLAN-READY at v2 (task-mov1moka).
issue: #1219
phase: implementation plan; minimum-viable PR scope
prerequisites:
  - PR #1217 (fairness-regimes contract) MERGED as e1ec6b90 ✓
  - PR #1216 (CoSQueueRuntime split) MERGED as a1688792 ✓
---

## Round-2 verdict resolution (v3)

Gemini round-2 (task-mov1moka): **PLAN-READY** — all v1 fatals
resolved; "well-scoped, the implementation path is clear". ✓

Codex round-2 (task-mov1mk84): **PLAN-NEEDS-MAJOR** — 2 new
blockers v2 missed:

1. **`flow_cache` does NOT have `last_used_ns`** as v2 assumed.
   `FlowCacheEntry` has no timestamp field; `lookup()` only
   validates/promotes/hits — it does NOT update recency. The 100ms
   scan as v2 specified is unimplementable.
2. **Per-queue + ≥1% throughput qualification still uncomputable**.
   v2 deferred this to harness time, but `iperf3 -P N` uses the
   same destination port for all N streams; RSS decides binding;
   there's no identity join between "stream X had ≥1% throughput"
   and "stream X landed on binding Y".

v3 addresses both:

- **Fix #v3-1**: add a `last_used_epoch: u16` field to
  `FlowCacheEntry`. Owner-only writes the current epoch in
  `lookup()` on hit. Worker tick increments the per-binding
  epoch counter every 100ms. To check "active in last 1s",
  count entries with `(current_epoch - entry.last_used_epoch) <= 10`.
  Cost: ~1-2 ns/lookup (single u16 store on a struct already
  loaded in the hot path).

- **Fix #v3-2**: harness uses **distinct source ports per
  iperf3 stream** (`iperf3 --cport <base+i>` per-stream).
  Harness computes the kernel RSS hash + indirection table
  (read via `ethtool -x <iface>`) to deterministically map
  each stream's 5-tuple to an RX queue, then maps RX queue →
  xpf binding via the existing per-binding status surface.
  Per-stream throughput from iperf3 JSON is then known per
  binding; ≥1% threshold is applied at the harness layer.

## Round-1 verdict resolution — fundamental rescope

Both reviewers PLAN-NEEDS-MAJOR with convergent fatal findings:

**Codex blockers**:
1. `DistinctFlowTracker` in shared `BindingLiveState` (Arc) requires
   `&mut self` — wrong locality.
2. `record()` on every flow-cache lookup at 2 Mpps × 30 ns/HashMap-insert
   = **60 ms/sec/core = 6% CPU on tracking alone**. Not acceptable.
3. Signal semantically wrong: contract wants active flows **per queue
   with ≥1% throughput qualification**, not "any key on binding in last
   1s". Pollutes Cstruct with other queues / background flows.
4. Go collector cannot compute `observed_CoV`/`starved_flows` from
   current status surface — current status has aggregate queue
   counters, not per-flow rolling throughput. Plus Prometheus
   `Collect` is scrape-driven, not a 1 Hz sampler.

**Gemini fatals**:
B. HashMap on hot path = 6% CPU. Suggestion: embed `last_seen_ns`
   in existing flow_cache entries; aggregate at 100ms tick.
C. `MAX_TRACKED_FLOWS=1024` silent saturation → false-pass on
   high-fan-in skewed.
D. Rust↔Go formula drift. Suggestion: CGo / single source of truth.

**v2 response**: massively reduce scope. The contract needs
measurement at **test-harness time**, not continuous production
observability. Two goals:

1. **Test harness**: answer "is today's 47% iperf3 CoV at structural
   ceiling or scheduler bug?" — needs Cstruct compute + per-binding
   distinct-flow-count *sampled* once, not maintained at line-rate.
2. **Production observability** (Prometheus): rolling `xpf_fairness_*`
   metrics. Adds significant data-plane complexity.

**v2 ships only goal 1.** Production observability is deferred to a
follow-up issue (#1220, to be filed). This addresses every round-1
fatal:
- No new HashMap on the hot path (Codex #2, Gemini B)
- No production-side per-flow rolling throughput (Codex #4)
- No Rust↔Go drift (only Rust does the math; Go absent in v2)
  (Gemini D)
- Per-queue throughput qualification computed from iperf3 output at
  harness time, not from xpf (Codex #3)

## 1. Issue framing

Implement the test-harness side of the fairness-regimes contract
(PR #1217 e1ec6b90). Goal: answer **"is today's 47% iperf-c P=12 -R
CoV at the structural ceiling for the observed RSS distribution, or
is it Δ above ceiling indicating a scheduler bug?"**

Production Prometheus observability is a separate follow-up
(#1220, file after this lands).

## 2. Honest scope/value framing

**Small implementation PR.** Touches:
- New Rust `pure-fn` module (`userspace-dp/src/fairness/mod.rs`,
  ~150 LOC + tests). Purely computational; identical to v1's
  pure-fn module which Codex independently verified is correct.
- New per-binding **active flow count** read from EXISTING flow_cache
  state at the worker's existing 100 ms tick. NO new HashMap. NO new
  per-packet writes. Just an atomic gauge + reader. ~30 LOC.
- New gRPC field on per-binding status: `active_flow_count: u32`.
  ~20 LOC of plumbing.
- Test harness `test/incus/fairness-harness.sh` (~80 LOC bash) that:
  - runs iperf3 with `-J --forceflush` for per-second JSON buckets
  - polls gRPC once per second for per-binding `active_flow_count`
  - feeds buckets into a thin Rust binary `bin/fairness-eval` that
    calls the pure-fns and outputs {Cstruct, observed_CoV, regime,
    PASS/FAIL}

**Out of scope for v2** (deferred to #1220):
- Prometheus exports `xpf_fairness_*` (4 metrics)
- Production rolling 30s windows
- Cross-language formula sharing (CGo / RPC)
- Continuous starved-flow counter

**Value**: today, after merge, run the harness against the existing
iperf-c P=12 -R workload and **immediately know** whether the 47%
gap is at structural ceiling (no scheduler bug; gate passes once
the contract harness is in place) or scheduler-actionable.

**If reviewers conclude the harness is still too complex for v2 or
the active-flow read from flow_cache is unreliable, PLAN-KILL is
acceptable. The contract gate can be hand-computed for a one-off
measurement if the harness PR doesn't ship.**

## 3. Concrete design

### 3.1 Rust pure-fn module (unchanged from v1; Codex verified correct)

`userspace-dp/src/fairness/mod.rs` — `compute_cstruct`,
`compute_observed_cov`, `starved_flow_count`, `is_saturated`. Pure
functions. Unit-tested against the contract's 5-row worked-example
table. See v1 plan §3.1 for the full code; v2 keeps it byte-identical.

### 3.2 Per-binding active flow count — epoch counter + tick scan

Per Codex round-2 finding: `FlowCacheEntry` doesn't currently have
a recency timestamp. v3 adds the cheapest possible recency signal:

```rust
// userspace-dp/src/afxdp/flow_cache.rs — extend FlowCacheEntry
pub(in crate::afxdp) struct FlowCacheEntry {
    // ... existing fields
    /// #1219: last_used_epoch — u16 set on every successful
    /// lookup() hit. Compared to the per-binding `current_epoch`
    /// that the worker tick increments at 100 ms cadence to count
    /// active flows in the last N epochs (N=10 → 1 s window).
    /// u16 wraps every 256 × 100 ms = 25.6 s — plenty of headroom
    /// vs the 1 s window. Single-writer (the owner worker is the
    /// only code path that mutates this entry), Relaxed-equivalent
    /// (the snapshot reader reads via the gRPC status surface
    /// which already copies the cache for sharding).
    last_used_epoch: u16,
}

impl FlowCache {
    /// Owner-only call from `lookup()` on hit. Single u16 store;
    /// no atomic; same single-writer discipline as the rest of the
    /// flow_cache mutation path.
    #[inline]
    pub(in crate::afxdp) fn note_hit(entry: &mut FlowCacheEntry, current_epoch: u16) {
        entry.last_used_epoch = current_epoch;
    }
}
```

Cost on the hot path: **single u16 store** on a struct already
loaded into a register from the lookup. Estimated ~1-2 ns/lookup,
or ~2-4 ms/sec/core at 2 Mpps. Order-of-magnitude smaller than v1's
HashMap-insert proposal (60 ms/sec/core) and acceptable at the
hot-path budget.

The `current_epoch: AtomicU16` per-binding counter:

```rust
// extend BindingLiveState (Arc-shared status state)
pub(in crate::afxdp) flow_cache_epoch: AtomicU16,
pub(in crate::afxdp) active_flow_count: AtomicU32,
```

Worker's existing 100 ms tick:

```rust
// at the worker's existing 100ms periodic tick
let new_epoch = state.flow_cache_epoch
    .load(Ordering::Relaxed)
    .wrapping_add(1);
state.flow_cache_epoch.store(new_epoch, Ordering::Relaxed);

// Count entries within the last 10 epochs (1 second window)
const ACTIVE_WINDOW_EPOCHS: u16 = 10;
let count = flow_cache.entries.iter()
    .filter(|e| {
        // Wrap-safe: difference within the wraparound window.
        let age = new_epoch.wrapping_sub(e.last_used_epoch);
        age < ACTIVE_WINDOW_EPOCHS && e.last_used_epoch != 0
    })
    .count() as u32;
state.active_flow_count.store(count, Ordering::Relaxed);
```

Tick-side scan: O(N) over flow_cache cap (8192 entries) every
100 ms = 80K loads/sec/worker = ~10 µs of work per second on the
periodic-maintenance path. Not on the hot path.

`last_used_epoch == 0` is treated as "uninitialized" so freshly
added entries on a brand-new binding don't count as active until
they actually receive a hit.

### 3.3 Atomic gauge published to gRPC

```rust
// extend BindingLiveState (which is an Arc; this is a simple
// AtomicU32 read by the gRPC status path, written by the owner
// worker on its tick)
pub(in crate::afxdp) active_flow_count: AtomicU32,
```

Owner writes via `Ordering::Relaxed`; gRPC status reader reads
`Ordering::Relaxed`. No cross-worker coordination needed.

Per-binding gRPC status response gets one new field:

```proto
// proto/xpf/v1/dataplane.proto
message UserspaceBindingStatus {
    // ... existing fields
    uint32 active_flow_count = N;  // last 1s distinct-flow count from flow_cache
}
```

### 3.4 Per-queue + ≥1% throughput qualification — distinct source ports + RSS join

Per Codex round-2 blocker #2: with `iperf3 -P N` and a single
destination port, RSS decides binding and there is no identity
join between an iperf3 stream and its landing binding.

v3 fixes this with **distinct source ports per stream + harness-
side RSS join**:

1. **Harness launches iperf3 streams with explicit source ports**:
   ```bash
   for i in $(seq 0 $((N-1))); do
       iperf3 -c $TARGET -p $PORT --cport $((CPORT_BASE+i)) -t $T -J ... &
   done
   ```
   Each stream now has a unique 5-tuple
   `(client_ip, CPORT_BASE+i, target_ip, PORT, TCP)`.

2. **Harness reads kernel RSS configuration** via
   `ethtool -x <iface>` (indirection table) and
   `ethtool -u <iface>` (n-tuple rules, if any) and the RSS hash
   key (also from `ethtool`). Standard Linux Toeplitz hash; key
   typically 40 bytes.

3. **Harness computes the destination RX queue** for each iperf3
   stream's 5-tuple by running the same Toeplitz hash + lookup
   in the indirection table that the kernel does. This is a
   well-known algorithm:
   ```rust
   // bin/fairness-eval.rs — uses standard Toeplitz hash impl
   fn compute_rx_queue(
       five_tuple: FiveTuple,
       rss_key: &[u8; 40],
       indirection_table: &[u8],
   ) -> u32 {
       let hash = toeplitz_hash(rss_key, &five_tuple.bytes());
       indirection_table[hash as usize % indirection_table.len()] as u32
   }
   ```
   This is read-only and identical to what the kernel does at
   packet receive time. No kernel changes needed.

4. **Harness maps RX queue → xpf binding** via the existing per-
   binding status surface, which exposes `bound_rx_queue: u32`
   per binding (already there in `BindingStatus`; verify in
   `pkg/dataplane/userspace/protocol.go`).

5. **Apply ≥1% throughput qualification at harness layer**:
   for each binding, sum the per-stream throughputs of streams
   that mapped to that binding via RSS. A stream is "active" iff
   its measured throughput is ≥ 1% of the across-flow mean.
   `aᵢ` for binding i = count of active streams that landed on
   binding i.

6. **Data-plane `active_flow_count` is now a sanity check**, not
   the source of truth for `{aᵢ}`. The harness reports both
   numbers and flags disagreement > ±2 (allowing for cache churn
   + non-iperf3 background flows).

This works **only** because the harness controls the source ports
of iperf3 streams. If the workload were not test-controlled, the
harness couldn't compute the RSS mapping. v3 documents this
limitation; production observability (#1220) will need a different
approach.

**Risk**: the kernel's RSS hash + indirection table is
configurable per-NIC, and some NICs apply additional steering
(flow director, ATR, etc). The harness must read the actual NIC
state, not assume defaults. Implementation must include a self-
test: launch a single iperf3 stream, observe which binding it
lands on (via per-binding TX bytes), verify it matches the
harness's RSS prediction. If mismatch, the harness fail-fasts
with a diagnostic.

### 3.5 Test harness `test/incus/fairness-harness.sh` (~80 LOC bash)

```bash
#!/usr/bin/env bash
# v2: runs iperf3, polls gRPC active_flow_count, feeds both into
# bin/fairness-eval which calls Rust pure-fns. PASS/FAIL output.

set -euo pipefail
PORT=${1:-5203}
N=${2:-12}
T=${3:-120}
TARGET=${4:-172.16.80.200}

# 1. Background poll of per-binding active_flow_count via gRPC
#    (1 Hz) into /tmp/binding-flows.jsonl
gflows_poll &
GFLOWS_PID=$!

# 2. Run iperf3 with --forceflush JSON output
iperf3 -c $TARGET -P $N -t $T -p $PORT -J --forceflush > /tmp/iperf-out.json

# 3. Stop poll
kill $GFLOWS_PID

# 4. Run the Rust eval binary
fairness-eval \
    --iperf-json /tmp/iperf-out.json \
    --binding-flows /tmp/binding-flows.jsonl \
    --warmup-secs 5 \
    --final-burst-secs 1
```

The eval binary outputs JSON like:

```json
{
  "regime": "saturated_skewed",
  "distribution_a_i": [3, 3, 2, 2, 1, 1],
  "n_active": 6,
  "cstruct": 0.47,
  "observed_cov": 0.48,
  "gap": 0.01,
  "saturated": true,
  "starved_flow_count": 0,
  "aggregate_mbps": 21500,
  "verdict": "PASS"
}
```

### 3.6 `bin/fairness-eval` Rust binary

A small (~120 LOC) Rust binary in `userspace-dp/bin/fairness-eval.rs`
that:
- Parses iperf3 JSON intervals
- Aligns to wall-clock 1-second buckets
- Excludes warmup (first 5s) and final-burst (last 1s)
- Calls the pure-fns from §3.1 with the appropriate inputs
- Emits the JSON above

This is the **single source of truth** for the fairness math —
no Go side at all in v2. Production observability (when it
ships in #1220) will either reuse this binary or thread the
pure-fns through the existing Go collector via CGo / a JSON-RPC
local socket. Not in scope here.

## 4. Public API preservation

- gRPC: 1 new field on per-binding status (`active_flow_count: u32`).
  Backward-compatible (proto field number reserved).
- HTTP REST: unchanged.
- Prometheus: **unchanged** in v2. (Production observability deferred
  to #1220.)
- CLI: unchanged.

## 5. Hidden invariants the change must preserve

- Worker 100 ms tick already runs periodic maintenance; adding the
  flow_cache scan must not regress per-tick budget (verify: 80K
  loads/sec is a small fraction of one worker's idle time at 100 Hz).
- `active_flow_count` is `Relaxed` atomic; no cross-worker coherence
  required (single writer, many readers).
- HA failover: `BindingLiveState` is fresh on role flip; counter
  starts at 0 and ramps to steady-state in < 1 s.
- Pure-fn formulas tested against the contract's worked-example
  table to ≤ 0.005 absolute.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression on FIFO/owner-local | NONE | Code path unchanged |
| Behavioral regression on shared_exact | NONE | Hot path unchanged; only periodic 100ms scan added |
| Hot-path perf cost | NONE | No per-packet write; periodic scan only |
| Per-tick perf cost | LOW | ~10 µs/sec/worker on a path that has spare time |
| Rust↔Go drift | NONE in v2 | Only Rust does the math |
| HA failover | LOW | Fresh state on role flip; ramp <1s |
| Memory pressure | NONE | No new map; reuse flow_cache |

## 7. Test plan

- `cargo build --release` clean (production binary + new
  `fairness-eval` binary)
- `cargo test --release`: 977/977 + new fairness pure-fn tests pass
- New named test: `fairness::tests::cstruct_worked_examples` — all 5
  rows from the contract's table within 0.005
- 5×flake on `fairness::tests::*`
- `go test ./...`: clean (no Go changes in v2)
- `make test-deploy` to standalone test VM — verify gRPC field is
  populated
- Smoke matrix on loss userspace cluster:
  - Pass A (CoS off) — connectivity + 12-stream `-R` line rate
  - Pass B (CoS on) — 24 cells per-class + harness output for each
- **Most important test**: run `fairness-harness.sh` against the
  existing iperf-c P=12 -R workload. Expected output: `cstruct`,
  `observed_cov`, `gap`, `verdict`. **This is the deliverable.**
- `make test-failover` clean — counter recovers on role flip

## 8. Out of scope (explicitly)

- Prometheus exports `xpf_fairness_*` — **deferred to #1220**
- Production rolling-window observed_CoV — deferred
- Rust + Go formula sharing strategy — deferred (only Rust in v2)
- Deterministic RSS-skew test fixture (Codex Path 0) — separate issue
- Active flow detection with throughput threshold inside the data
  plane — deferred; v2 does this at the harness layer

## 9. Open questions for adversarial review

1. **Flow_cache scan cost validation**. 80K loads/sec/worker on the
   100 ms tick — is the cache layout cache-friendly enough that this
   stays in L1/L2? If not, the scan could be more expensive than
   estimated.

2. **flow_cache cap**. Cache cap is 8192 entries (verify exact).
   At extremely high fan-in the cache itself becomes the bottleneck
   for distinctness measurement, but the cap exposed to the harness
   is documented and predictable (unlike the v1 1024 cap which was
   hidden).

3. **Per-stream port-to-binding mapping at the harness**. The
   harness assumes iperf3 destination port maps cleanly to a
   binding/queue. With `iperf3 -P N` all streams hit the same
   destination port; binding selection happens at the kernel RSS
   layer. The harness gets `{aᵢ}` from xpf, not from iperf3 port
   mapping — so this is fine. Confirmed in §3.4.

4. **gRPC poll cadence**. Harness polls 1 Hz; on a 60s steady-state
   window that's 60 samples per binding. Sufficient for `{aᵢ}`?

5. **fairness-eval as a separate binary vs library**. A binary is
   more useful for the harness; a library is more useful for #1220
   (Prometheus integration). v2 ships the binary; #1220 will
   either link the library or shell out.

6. **Active flow count vs distinct flows seen**. flow_cache evicts
   entries on capacity pressure (cache is bounded). At very high
   fan-in we'd see fewer than the actual distinct count. Document
   the cap; harness flags if `active_flow_count == cache_cap`.

7. **HA failover during harness run**. If a role flip happens
   mid-run, the secondary's `active_flow_count` rebuilds from 0.
   The harness should detect this (gRPC reports `role_change_at`
   timestamp) and fail-fast rather than report bogus Cstruct.

## 10. Verdict request

PLAN-READY → execute (Rust pure-fns + flow_cache scan + gRPC field
+ fairness-eval binary + harness script, all in one PR).
PLAN-NEEDS-MINOR → tighten cache scan strategy / harness input
formats / failover handling.
PLAN-NEEDS-MAJOR → restructure (e.g., move active-flow detection
deeper into the data plane than flow_cache scan; ship Prometheus
together with harness; add CGo).
PLAN-KILL → harness logic still too complex; defer the entire
contract enforcement to manual measurement until #1220 forces
the issue.
