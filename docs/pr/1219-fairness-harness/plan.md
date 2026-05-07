---
status: REVISED v7 — addressing Codex round-6 (6 stale gRPC refs; task-mov2qck7): purged all remaining gRPC mentions in scope-bullets, snapshot-doc-comments, test plan, open questions, verdict request. Path consistently named "helper-process control-socket JSON" / "status JSON" / "Manager.Status()" throughout.
issue: #1219
phase: implementation plan; minimum-viable PR scope
prerequisites:
  - PR #1217 (fairness-regimes contract) MERGED as e1ec6b90 ✓
  - PR #1216 (CoSQueueRuntime split) MERGED as a1688792 ✓
---

## Round-3 verdict resolution (v4)

Codex round-3 (task-mov1wpqo): **PLAN-NEEDS-MAJOR**. 4 findings:

1. v3 harness sketch ran single `iperf3 -P N` without `--cport`,
   contradicting the per-stream `--cport` claim earlier in the doc.
2. RSS tuple wrong for `-R` workload: data direction is reversed,
   tuple must be the on-wire RX tuple at the measured-direction
   ingress interface, NOT the control-direction client tuple.
3. `bound_rx_queue` field doesn't exist in `BindingStatus`. Real
   fields are `QueueID`/`WorkerID`/`Interface`/`Ifindex`. Plus no
   public proto for binding status — needs to specify whether
   harness reads control-socket JSON, `Manager.Status()`, or new
   gRPC.
4. Stale impl details on `last_used_epoch`.

### v4 architectural insight: drop the RSS-join entirely

After reading the actual codebase (`pkg/dataplane/userspace/protocol.go:615`
shows real `BindingStatus`), the RSS-join from harness is unnecessary
complexity. The simpler path:

- Data plane has flow_cache + epoch counter (Fix #v3-1).
- Per-binding active flow count `aᵢ` is computed in the data plane
  via the ~65 ms umem debug-publish tick scan (every 0xFFFF poll
  ticks ≈ 65 ms in steady state) and exposed as a Prometheus metric.
- Harness scrapes `/metrics` every 1 second during the iperf3 run.
- Harness reads per-binding `active_flow_count` directly — that IS
  `{aᵢ}` already, no kernel RSS hash + indirection table read
  needed at all.
- iperf3 per-stream throughput from `iperf3 -P N -J` (single
  invocation; per-stream join via `start.connected[].socket` ↔
  `intervals[].streams[].socket`).

This addresses ALL 4 Codex findings:
- **#1**: drop the per-stream `--cport` requirement; single `iperf3
  -P N -J` with socket-id join.
- **#2**: irrelevant — we don't compute RSS hashes anymore.
- **#3**: harness reads via existing Prometheus `/metrics` endpoint,
  not via a new gRPC RPC. We add ONE new Prometheus metric
  `xpf_userspace_binding_active_flow_count{binding_slot=...}` (a
  scrape-time snapshot, not a rolling window — much narrower than
  the v1 production Prometheus exports that were deferred to #1220).
- **#4**: `last_used_epoch` impl details cleaned up.

### Trade-off acknowledged

Per-binding active_flow_count includes ALL flows on the binding,
not just iperf-c flows. For iperf3-only test workloads this is
fine (background flows are negligible). Document this limitation;
production observability with per-queue qualification stays in
#1220.

The ≥1% throughput qualification from the contract is **not
applied** in v4 because we don't have per-flow throughput in the
data plane. v4 documents this gap; if a flow is starved (< 1%
throughput) the **starved_flow_count** gate (Gate 1) catches it
at the harness layer using iperf3 per-stream throughputs. Cstruct
is computed from the data-plane `{aᵢ}` which counts all active
flows — slight over-count compared to the contract's "≥1%"
qualified count, but bounded and conservative.

## Round-2 verdict resolution (v3)

Gemini round-2 (task-mov1moka): **PLAN-READY** — all v1 fatals
resolved; "well-scoped, the implementation path is clear". ✓

Codex round-2 (task-mov1mk84): **PLAN-NEEDS-MAJOR** — 2 new
blockers v2 missed:

1. **`flow_cache` does NOT have `last_used_ns`** as v2 assumed.
   `FlowCacheEntry` has no timestamp field; `lookup()` only
   validates/promotes/hits — it does NOT update recency. The ~65ms
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
  epoch counter every ~65ms. To check "active in last ~650 ms",
  count entries with `(current_epoch - entry.last_used_epoch) < ACTIVE_WINDOW_EPOCHS` (= 10).
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
   in existing flow_cache entries; aggregate at ~65ms gate (call-rate dependent).
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
  state at the worker's existing ~65 ms umem debug-publish tick. NO new HashMap. NO new
  per-packet writes. Just an atomic gauge + reader. ~30 LOC.
- New `active_flow_count: u32` field through the
  Rust→Go→Prometheus pipeline (per Codex round-4 finding #2):
  - **Rust live state**: `BindingLiveState.active_flow_count:
    AtomicU32` (per §3.3); written from owner-only ~65ms gate (call-rate dependent).
  - **Rust snapshot**: `BindingStatus.active_flow_count` field
    in the snapshot struct copied to the helper-process status JSON.
  - **Status JSON**: serialized field `active_flow_count` in
    the helper-process control-socket JSON consumed by the Go
    `Manager.Status()` path.
  - **Go BindingStatus**: new field
    `ActiveFlowCount uint32 \`json:"active_flow_count,omitempty"\``
    on the existing `pkg/dataplane/userspace/protocol.go:615`
    `BindingStatus` struct.
  - **Prometheus**: new metric descriptor + emitter in
    `pkg/api/metrics.go` (per the existing `/metrics` Go-side
    machinery at `pkg/api/metrics.go:424`).
  - **Test**: a new `metrics_test.go` case verifies the metric
    emits with the expected label and value path from a
    synthetic `ProcessStatus`.
- Test harness `test/incus/fairness-harness.sh` (~80 LOC bash) that:
  - runs iperf3 with `-J --forceflush` for per-second JSON buckets
  - scrapes `/metrics` once per second for per-binding
    `xpf_userspace_binding_active_flow_count{binding_slot=N}`
  - feeds buckets into a thin Rust binary
    `userspace-dp/src/bin/fairness-eval.rs` that calls the
    pure-fns and outputs {Cstruct, observed_CoV, regime,
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
    /// that the worker tick increments at ~65 ms cadence (umem
    /// debug-publish gate, every 0xFFFF poll ticks) to count
    /// active flows in the last N epochs (N=10 → ~650 ms window).
    /// u16 wraps every 65536 × ~65 ms ≈ 71 minutes — plenty of headroom
    /// vs the ~650 ms window. Single-writer (the owner worker is the
    /// only code path that mutates this entry), Relaxed-equivalent
    /// (the snapshot reader reads via the helper-process status JSON surface
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

Worker's existing ~65 ms umem debug-publish tick:

```rust
// at the worker's existing ~65ms periodic tick
let new_epoch = state.flow_cache_epoch
    .load(Ordering::Relaxed)
    .wrapping_add(1);
state.flow_cache_epoch.store(new_epoch, Ordering::Relaxed);

// Count entries within the last 10 epochs (~650 ms window at ~65 ms tick)
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

Tick-side scan: O(N) over flow_cache cap (4096 entries) every
~65 ms (the umem debug-publish gate fires every 0xFFFF poll
ticks, which is approximately 65 ms in steady state) ≈ ~63K
loads/sec/worker = ~8 µs of work per second on the periodic-
maintenance path. Not on the hot path.

`last_used_epoch == 0` is treated as "uninitialized" so freshly
added entries on a brand-new binding don't count as active until
they actually receive a hit.

### 3.3 Atomic gauge published via existing JSON status path

```rust
// extend BindingLiveState (which is an Arc; this is a simple
// AtomicU32 read by the snapshot/status path, written by the
// owner worker on its tick)
pub(in crate::afxdp) active_flow_count: AtomicU32,
```

Owner writes via `Ordering::Relaxed`; status snapshot reader
reads `Ordering::Relaxed`. No cross-worker coordination needed.

The Rust `BindingStatus` snapshot struct (the in-memory shape
that the helper process serializes into the status-JSON the Go
manager reads via control socket) gets one new field:

```rust
// userspace-dp/src/.../snapshot.rs (extend existing BindingStatus
// snapshot struct used by the helper-process status JSON encoder)
pub(in crate::afxdp) struct BindingStatus {
    // ... existing fields
    pub(in crate::afxdp) active_flow_count: u32,
}
```

The status JSON serializer adds `"active_flow_count": N` to each
binding entry. The Go side
(`pkg/dataplane/userspace/protocol.go:615`) decodes it into the
new `ActiveFlowCount uint32 \`json:"active_flow_count,omitempty"\``
field on `BindingStatus`.

**No public gRPC / proto change.** The status surface this PR
extends is the helper-process control-socket JSON, which is
internal to xpfd's own daemon ↔ helper communication and not
part of the public gRPC API.

### 3.4 Per-queue + ≥1% throughput qualification — DROPPED in v4 (RSS-join unnecessary)

**v4 architectural change**: don't compute RSS at the harness;
read `{aᵢ}` directly from the data plane.

The reasoning (per round-3 verdict resolution above): the data
plane already has the flow_cache, the epoch counter (Fix #v3-1),
and the ~65ms-tick scan that publishes per-binding active flow
count. Adding ONE Prometheus metric exposes that count to the
harness. The harness scrapes `/metrics` every 1s during the iperf3
run and reads `xpf_userspace_binding_active_flow_count{binding_slot=N}`
for each binding to get the snapshot `{aᵢ}` distribution.

No RSS-hash computation. No indirection-table read. No kernel-
side hash key extraction. No direction-reversal complications for
`-R` workloads. The data plane *knows* which packets land on
which binding because that's literally what AF_XDP zero-copy does
— it puts the packet into the binding's UMEM. The flow_cache hits
on each binding give us the count for free.

**Limitations explicitly acknowledged** (deferred to #1220):
- All-binding count, not per-CoS-queue count: a binding may serve
  multiple queues. For iperf3-only workloads, background traffic
  is negligible and the count is dominated by iperf3 flows. In
  production with mixed traffic, per-queue qualification matters
  and #1220 must address it.
- No ≥1% throughput qualification: the data plane counts any
  flow that hit flow_cache in the last ~650 ms, regardless of
  byte rate. This may over-count — a starved flow that's barely
  doing anything still counts as 1 in `aᵢ`. The starved-flow
  gate (Gate 1) catches this case at the harness layer using
  iperf3 per-stream throughputs, which are exact. Cstruct from
  unqualified `aᵢ` is a slightly **conservative** measure (it
  may report a higher Cstruct than the qualified version, which
  means the gate `observed ≤ Cstruct + 0.05` is slightly more
  forgiving — ie. preserves more "fairness budget" — than strict
  contract reading).

  v5 additionally requires a **harness fail-fast guard** (Codex
  round-4 finding #3): during the steady-state window, compute
  `sum(per_binding_active_flow_count)` from the data plane and
  the count of non-starved iperf3 streams from the iperf3 JSON
  output. If they disagree by more than `max(2, 0.10 × N)` the
  harness exits with diagnostic. This prevents background-flow
  pollution from silently moving `Cstruct` either direction.

### 3.4.1 (DELETED) v3 RSS-join steps removed

v3 contained a 6-step RSS-hash + indirection-table + harness
self-test design. v4 dropped that approach. v5 explicitly
deletes the stale text per Codex round-4 finding #1.

### 3.5 Test harness `test/incus/fairness-harness.sh` (~80 LOC bash)

```bash
#!/usr/bin/env bash
# v4: single iperf3 -P N invocation; concurrent /metrics polling;
# fairness-eval consumes both. No --cport; no RSS hashing.

set -euo pipefail
PORT=${1:-5203}
N=${2:-12}
T=${3:-120}
TARGET=${4:-172.16.80.200}
REVERSE=${5:-}  # set to "-R" for reverse-mode

# 1. Background poll: scrape /metrics every 1s, extract
#    xpf_userspace_binding_active_flow_count{binding_slot=...}
#    -> /tmp/binding-flows.tsv (timestamp, slot, count)
poll_metrics &
POLL_PID=$!

# 2. Run iperf3 once with -P N -J --forceflush
iperf3 -c "$TARGET" -P "$N" -t "$T" -p "$PORT" $REVERSE -J --forceflush \
    > /tmp/iperf-out.json

# 3. Stop poll
kill "$POLL_PID" 2>/dev/null || true
wait "$POLL_PID" 2>/dev/null || true

# 4. Run the Rust eval binary
fairness-eval \
    --iperf-json /tmp/iperf-out.json \
    --binding-flows /tmp/binding-flows.tsv \
    --warmup-secs 5 \
    --final-burst-secs 1 \
    --epsilon 0.05
```

`fairness-eval` parses iperf3 JSON, extracts per-stream throughput
from `intervals[].streams[]` joined by `socket` field to
`start.connected[].socket` (the per-stream local-port mapping
that Codex round-3 pointed at as the canonical join). Aligns to
1-second wall-clock buckets, applies warmup/final-burst exclusion.
For `{aᵢ}` it reads `binding-flows.tsv` (one row per
binding-slot per second), takes the median over the steady-state
window per binding to get the steady-state `aᵢ` for each binding,
and computes `Cstruct` from the resulting distribution.

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

### 3.6 `fairness-eval` Rust binary

A small (~120 LOC) Rust binary at
`userspace-dp/src/bin/fairness-eval.rs` (Cargo's auto-discovered
`src/bin/` subdirectory; no `[[bin]]` entry needed in
`Cargo.toml`). Codex round-4 finding #4: `userspace-dp/bin/`
doesn't exist; the crate has only `src/main.rs` today, so the
binary lives under `src/bin/` per Cargo conventions.
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

- gRPC / public proto: **no change**. The status surface this PR
  extends is the internal helper-process control-socket JSON
  (xpfd ↔ Rust helper) consumed by Go `Manager.Status()` — not
  the public gRPC API.
- Helper-process status JSON: 1 new field on per-binding status
  (`active_flow_count: u32`). Backward-compatible (older Go
  consumers ignore unknown fields per `json:"...,omitempty"` etc).
- HTTP REST: unchanged.
- Prometheus: **1 new metric**
  `xpf_userspace_binding_active_flow_count{binding_slot=N}` —
  scrape-time snapshot, not a rolling window. Emitted from the
  existing `pkg/api/metrics.go:424` machinery via the new
  `BindingStatus.ActiveFlowCount` Go field. Production rolling-
  window observability remains deferred to #1220; v5's metric is
  the minimum needed for the harness to scrape.
- CLI: unchanged.

## 5. Hidden invariants the change must preserve

- Worker ~65 ms umem debug-publish tick already runs periodic
  maintenance; adding the flow_cache scan must not regress per-tick
  budget (verify: ~63K loads/sec/worker is a small fraction of one
  worker's idle time at ~15 Hz publish rate).
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
| Behavioral regression on shared_exact | NONE | Hot path unchanged; only periodic ~65ms scan added |
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
- `make test-deploy` to standalone test VM — verify the new
  `active_flow_count` field is populated in the helper-process
  status JSON (and surfaced through `Manager.Status()`)
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

1. **Flow_cache scan cost validation**. ~63K loads/sec/worker on the
   ~65 ms umem debug-publish tick — is the cache layout cache-friendly
   enough that this stays in L1/L2? If not, the scan could be more
   expensive than estimated.

2. **flow_cache cap**. Cache cap is 4096 entries (verify exact).
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

4. **Prometheus scrape cadence**. Harness scrapes `/metrics` 1 Hz;
   on a 60s steady-state
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
   The harness should detect this (status JSON reports `role_change_at`
   timestamp) and fail-fast rather than report bogus Cstruct.

## 10. Verdict request

PLAN-READY → execute (Rust pure-fns + flow_cache scan + helper-process status JSON field
+ fairness-eval binary + harness script, all in one PR).
PLAN-NEEDS-MINOR → tighten cache scan strategy / harness input
formats / failover handling.
PLAN-NEEDS-MAJOR → restructure (e.g., move active-flow detection
deeper into the data plane than flow_cache scan; ship Prometheus
together with harness; add CGo).
PLAN-KILL → harness logic still too complex; defer the entire
contract enforcement to manual measurement until #1220 forces
the issue.
