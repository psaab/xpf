---
status: REVISED v2 — addresses Codex PLAN-NEEDS-MAJOR (task-moupsqds: settle-time accounting, window-delta publish, batch-hoisted ArcSwap+ECN); Gemini PLAN-KILL (task-mouptde4: cache-line/QSBR/ECN-deployment-reality concerns) acknowledged. Gemini said 'PR #1217 should be the steady-state product' — v2 keeps that path open by treating #1211 as research, not a blocker.
issue: #1211
phase: research-only — no implementation in this plan; goal is reviewer convergence on whether ANY race-safe design is feasible on AF_XDP ZC architecture
prerequisites:
  - #1206 (CoSQueueRuntime split) merged as a1688792 ✓
  - PR #1217 (fairness-regimes contract) — independent; this plan does NOT block #1217 shipping
  - Convergent finding (Codex task-mounv6zx + task-mouozcic; Gemini task-mounvopl + task-mouozuvq): cross-worker re-routing is structurally unreachable on AF_XDP ZC; AFD ECN backpressure is the only remaining algorithmic lever, IF it can be made race-safe
---

## 1. Issue framing

Saturated-RSS-skewed regime per `docs/fairness-regimes.md`: per-flow
CoV currently 25-30% on iperf-c P=12 -R; this plan's goal is to
explore whether AFD/CSFQ-style **per-flow ECN/drop overlay** can
reduce that to ≤25% (matching saturated-balanced) by pushing TCP
senders to slow flows that exceed their global fair share.

Per the killed-approaches list:
- #836 shared HOL-finish-time → non-commutative
- #838 AFD-lite per-flow bytes-served → 4 race surfaces
- #1215 cross-worker shared per-bucket signal + stall → permanent
  deadlock + HoL + can't transfer hardware capacity
- #937 ingress XDP_REDIRECT → AF_XDP ZC queue-binding permanent
  per kernel `xsk_rcv_check()`

This plan must NOT replicate any of those patterns.

## 2. Honest scope/value framing

**Research plan, not an implementation plan.** Goal: reviewer
convergence on whether ANY race-safe AFD design is feasible on this
codebase's AF_XDP ZC architecture, given:

- Codex's strict constraints (per-worker writes only; epoch
  snapshots; no rollback coupling; no global hot-path period reset)
- Gemini's hostile critique (cross-worker shared state for AQM =
  cache-line bouncing nightmare; Path 2 is "as unviable as Option B")

If reviewers converge PLAN-KILL, the user has clear evidence to
accept Path 4 (the fairness-regimes contract at #1217) as the
steady-state product.

If reviewers converge PLAN-READY-with-constraints, multi-week
implementation plan follows.

**Value cap**: improve saturated-RSS-skewed CoV from 25-30% toward
≤25% on TCP-with-ECN traffic. Does NOT help on UDP, non-ECN-capable
TCP, or workloads where senders ignore congestion signals.

## 3. Mechanism — race-safe AFD with sharded estimators

### 3.1 Shape

Each shared_exact queue gets:

```rust
// userspace-dp/src/afxdp/cos/afd.rs (new module, plan-only)
pub(in crate::afxdp) struct AfdEstimatorShard {
    /// Single-writer per worker. Each worker increments only its
    /// own shard. Cross-worker reads are atomic + Relaxed; readers
    /// accept eventual consistency.
    served_bytes: [AtomicU64; AFD_BUCKETS],
}

#[repr(C, align(64))]
pub(in crate::afxdp) struct AfdShardCacheLine {
    shard: AfdEstimatorShard,
    _pad: [u8; PAD_TO_64],
}

pub(in crate::afxdp) struct AfdQueueState {
    /// One shard per worker servicing this queue. Each worker's
    /// shard is on its own cache line — no cross-worker writes
    /// to the same cache line ever.
    shards: Box<[AfdShardCacheLine]>,

    /// Epoch number incremented by the snapshot owner only.
    /// Workers read this to know which window summary is current.
    epoch: AtomicU64,

    /// Read-mostly published window summary. Single writer
    /// (snapshot owner / coordinator); many cross-worker readers.
    /// Updated via ArcSwap (RCU-style). Never written from hot
    /// path.
    published_summary: ArcSwap<AfdWindowSummary>,
}

pub(in crate::afxdp) struct AfdWindowSummary {
    /// Per-bucket fair share computed from prior window.
    fair_share_bytes_per_bucket: [u64; AFD_BUCKETS],

    /// Per-bucket aggregate served-bytes from prior window
    /// (sum across all worker shards).
    aggregate_served: [u64; AFD_BUCKETS],

    /// Window duration in ns (for rate computations).
    window_duration_ns: u64,

    /// Active flow-bucket count from prior window.
    active_buckets: u16,
}
```

## User directive (v4)

User explicitly accepted complexity tradeoff 2026-05-07: "Complexity
is ok". Gemini's round-2 + round-3 PLAN-KILL on
complexity-vs-value grounds is therefore overridden by user
direction. Technical fixes (Codex's PLAN-NEEDS-MAJOR findings)
are still required and v4 addresses them.

PR #1217 (fairness-regimes contract) ships in parallel and is
NOT gated on this plan. If implementation work on this plan
hits a wall, #1217 is still the steady-state product.

## v2 — round-1 reviewer fixes (must read before §3 design)

### Fix #1: AFD accounting moves from pop-time to settle-time

Codex round-1 finding #1: pop-time `fetch_add` over-states served
work because TX-failure restoration pushes items back without a
matching `fetch_sub`. This is the same pitfall that killed #1215
v1 — see queue_service/service.rs:298 (restore-on-failure) and
v_min.rs:32 (existing V_min publishes only post-settle for
exactly this reason).

v2 moves AFD `fetch_add` into the settle-side helpers
(`settle_exact_*_scratch_submission_flow_fair` family in
`userspace-dp/src/afxdp/cos/queue_service/mod.rs` around lines
740 + 795 — see Fix #9). The
settle path receives the **inserted prefix** of the scratch slice
— exactly the items that hit the TX ring. The accounting walks
that prefix and increments per-bucket `served_bytes` for inserted
items only. The flow_bucket for each item is recomputed at
settle (cheap; same hash function used at enqueue, batch-amortized
to ~3 ns per item).

Restored items (uninserted prefix or partial-insert tail) skip
the AFD accounting entirely. **No fetch_sub anywhere.**

### Fix #2: published summary carries window DELTA, not cumulative

Codex round-1 finding #2: comparing cumulative `aggregate_served`
to a one-window `fair_share` eventually marks/drops every active
bucket forever (since cumulative grows without bound).

v2 changes the published summary to carry **per-window delta**:

```rust
pub(in crate::afxdp) struct AfdWindowSummary {
    /// Per-bucket served-bytes DELTA over the most recent window.
    /// Zero for buckets that had no activity. The hot path
    /// compares this to the per-window fair_share, which has
    /// matching units.
    pub(in crate::afxdp) window_served_delta: [u64; AFD_BUCKETS],

    /// Per-window fair-share threshold (bytes). Computed as
    /// `(window_total_bytes / active_bucket_count)` by the
    /// snapshot owner; published atomically with the delta array.
    pub(in crate::afxdp) fair_share_window_bytes: u64,

    /// Window duration in ns (for diagnostic only — not used by
    /// the hot path).
    pub(in crate::afxdp) window_duration_ns: u64,

    /// Snapshot owner's window-end monotonic timestamp (ns).
    pub(in crate::afxdp) window_end_ns: u64,
}
```

The snapshot owner computes delta by storing the prior window's
cumulative aggregate (in its own state, not in the published
summary) and subtracting on every snapshot:

```rust
fn snapshot_publish(state: &mut SnapshotState, afd: &AfdQueueState) {
    let now_ns = clock_monotonic_ns();
    let window_duration_ns = now_ns - state.last_window_end_ns;
    let mut current_aggregate = [0u64; AFD_BUCKETS];
    for shard in afd.shards.iter() {
        for b in 0..AFD_BUCKETS {
            current_aggregate[b] += shard.shard.served_bytes[b].load(Ordering::Relaxed);
        }
    }
    let mut window_delta = [0u64; AFD_BUCKETS];
    let mut active_count = 0u32;
    let mut window_total = 0u64;
    for b in 0..AFD_BUCKETS {
        let delta = current_aggregate[b].saturating_sub(state.prior_aggregate[b]);
        window_delta[b] = delta;
        if delta > 0 {
            active_count += 1;
            window_total += delta;
        }
    }
    let fair_share = if active_count > 0 {
        window_total / active_count as u64
    } else {
        u64::MAX
    };
    afd.published_summary.store(Arc::new(AfdWindowSummary {
        window_served_delta: window_delta,
        fair_share_window_bytes: fair_share,
        window_duration_ns,
        window_end_ns: now_ns,
    }));
    state.prior_aggregate = current_aggregate;
    state.last_window_end_ns = now_ns;
}
```

Hot path reads `summary.window_served_delta[bucket]` vs
`summary.fair_share_window_bytes` — both have matching units
(per-window bytes). A bucket whose recent-window served exceeded
fair share gets ECN-marked / probabilistically dropped. A bucket
that's been idle this window has `delta = 0` and is never marked.

### Fix #3: batch-hoist ArcSwap.load and ECN-write costs

Codex round-1 finding #3: the v1 budget claim of `~3-5 ns` for
ArcSwap.load was wrong; the real cost is `~30 ns` per load (per
`arc-swap` v1.8.2 docs/source). Same for ECN-write — v1 said
`~5 ns`, but `userspace-dp/src/afxdp/cos/ecn.rs:98` parses IPv4
and updates checksum, materially more.

v2 fixes the hot path by **batch-hoisting both at the drain
entry**, not per-pop:

```rust
// In drain_shaped_tx_for_queue (called once per drain batch):
let afd_summary = ff.afd.as_ref().map(|afd| afd.published_summary.load());
//                                          ^ ArcSwap.load happens ONCE per batch (~30ns)
//                                            then we hold the Guard for all packets in batch.

for packet_idx in 0..batch_size {
    // ... existing pop logic ...
    if let Some(summary) = afd_summary.as_ref() {
        let bucket = bucket_u16 as usize;
        let delta = summary.window_served_delta[bucket];  // ~2ns L1 read
        let fair = summary.fair_share_window_bytes;       // ~2ns L1 read (cached after first)
        if delta > fair && cos_item_is_ect_fast(&item) {
            cos_item_mark_ce_fast(&mut item);             // tx_completion ECN cost
        }
        // ... probabilistic drop for non-ECT (see Fix #5 below) ...
    }
}
// At drain end, the Guard is dropped — settle-time accounting handles
// fetch_add (Fix #1).
```

Per-pop cost reduces to **2 array reads + 1 conditional write**
on the hot path: ~10 ns per pop in the marked case, ~4 ns in
the unmarked case. Per-batch ArcSwap cost amortizes:
`30 ns / TX_BATCH_SIZE` — at TX_BATCH_SIZE=64 that's `0.47 ns
per pop`.

Total per-pop cost: ~10 ns marked, ~4 ns unmarked, ~0.5 ns
ArcSwap-amortized. Within budget at 1500B/2Mpps; still tight
at 64B/35Mpps but acceptable since AFD is shared_exact-only and
small-packet workloads typically hit best-effort or owner-local
queues.

### Fix #4: ECN write cost — batched fast-path helper

`cos_item_mark_ce_fast` is a new helper that uses the cached
parsed offsets from the existing `ParsedPacket` metadata
(populated by xdp_main / forward.rs) rather than re-parsing.
Cost reduces from ~50 ns (full IPv4 parse + checksum) to ~10 ns
(direct byte write + 16-bit checksum delta — incremental, not
full).

If the parsed metadata is not available at the AFD decision site,
fall back to the existing slower path. The fast-path helper is an
optimization, not a correctness requirement.

### Fix #6 (v3 round-2): RFC 3168-compliant ECN marking

Gemini round-2 PLAN-KILL finding #1: v2 used a binary 100% mark
rate for ECT packets:

```rust
if delta > fair && cos_item_is_ect_fast(&item) {
    cos_item_mark_ce_fast(&mut item);  // 100% mark on ECT, regardless of magnitude
}
```

This violates **RFC 3168**, which mandates that CE marks be
applied with the **same probability as the equivalent drop**.
Otherwise ECN-capable flows get pegged at full congestion-response
while non-ECN flows see only ~`p_drop` × loss, starving ECN flows.

v3 unifies the marking probability with the drop probability:

```rust
let p = afd_drop_probability(delta, fair);   // 0..255
if p > 0 {
    let r = (afd_per_worker_random_byte()) as u8;  // see Fix #7
    if r < p {
        if cos_item_is_ect_fast(&item) {
            cos_item_mark_ce_fast(&mut item);
        } else {
            return Drop;
        }
    }
}
```

Both ECN-mark and drop now fire at the same probability `p`,
satisfying RFC 3168. ECT packets get marked instead of dropped;
non-ECT packets get dropped at the same rate.

### Fix #7 (v3 round-2): per-worker non-atomic PRNG state

Codex round-2 finding #2: `bpf_random_u32()` is not a Rust
userspace primitive. The userspace dataplane runs in pure Rust
without BPF helpers in scope.

v3 uses a per-worker non-atomic PRNG state seeded once at queue
construction from the existing `cos_flow_hash_seed_from_os()` call
(which uses `getrandom(2)`):

```rust
// In FlowFairState (per-worker; single-writer):
pub(in crate::afxdp) afd_prng_state: u64,

#[inline]
fn afd_per_worker_random_byte(ff: &mut FlowFairState) -> u8 {
    // splitmix64 — fast, statistically adequate for AFD drop probability
    ff.afd_prng_state = ff.afd_prng_state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = ff.afd_prng_state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    (z ^ (z >> 31)) as u8
}
```

splitmix64 has acceptable statistical properties for AQM drop
probability decisions (we're not doing crypto, just need
uncorrelated bits across packets). No `rand` crate dependency
needed.

### Fix #8 (v3 round-2): ECN fast-path metadata sourcing

Codex round-2 finding #3: `TxRequest`/`PreparedTxRequest` do NOT
carry cached L3 offsets. The "fast-path" claim was wrong.

v3 acknowledges that the AFD ECN-mark site lives in the
**settle-time accounting path** (per Fix #1, in
`settle_exact_*_scratch_submission_flow_fair` family in
queue_service/mod.rs:740+795 — see Fix #9), AFTER the packet has been popped
from the queue and submitted. At settle time, the packet has
already been transmitted — too late to ECN-mark.

This means **Fix #6's RFC 3168 unified marking moves to the
TX-side encapsulation point, BEFORE submit**, not at settle. The
correct hook is the **shared-exact pre-submit path** in
`userspace-dp/src/afxdp/cos/queue_service/service.rs:186-260`
(local variant) and `:517-617` (prepared variant), immediately
before the TX-ring submit. These call sites have access to the
binding/UMEM context AND see the post-rewrite frame layout (per
Codex round-4 finding: the offsets are stable here, after any
VLAN/tunnel/L3 rewrite has been applied by the TX dispatch
pipeline). `tx/dispatch.rs` is too early — it builds/enqueues
the `TxRequest`/`PreparedTxRequest` but does not own the
shared-exact submit decision.

v3 design reorganization:
- **Per-pop**: read summary's `delta` and `fair` for this bucket
  (batch-hoisted Arc Guard, ~0.5 ns amortized per pop).
- **Pre-submit** (in `cos/queue_service/service.rs:186-260`
  local variant or `:517-617` prepared variant — see Fix #8 for
  the canonical hook location): compute drop probability, draw
  random byte, decide ECN-mark vs drop vs pass.
- **At settle (post-TX)**: increment per-bucket served_bytes for
  inserted prefix only (Fix #1).

This keeps the ECN-mark on the post-rewrite frame while
preserving Fix #1's submit-failure correctness. Whether the
mark site uses 0a (reparse) or 0b (cached post-rewrite metadata)
is the implementation-PR decision — see Phase 0 in Fix #10.

### Fix #10 (v4 round-3): TxRequest metadata prerequisite

Codex round-3 verified that `TxRequest` and `PreparedTxRequest`
do not currently carry cached L3 offsets, and the existing ECN
path in `enqueue_cos_item` re-parses bytes/UMEM. So Fix #8's
"cached metadata" claim required a prerequisite that v3 did not
explicitly call out.

v4 makes the prerequisite explicit. **Implementation work is
phased**:

- **Phase 0 (prerequisite)**: ECN-marking happens at the
  shared-exact pre-submit hook in
  `cos/queue_service/service.rs:186-260` (local variant) and
  `:517-617` (prepared variant), where the TX-frame **after
  rewrite** is what we actually mark. Ingress-side L3 offsets
  cannot be reused directly because egress VLAN add/remove,
  tunnel encapsulation, and L3 rewrite paths all change the
  offset (the existing `cos/ecn.rs:179` ECN code re-parses the
  outgoing wire bytes precisely because sideband metadata
  drifts; `frame/mod.rs:245` computes output `eth_len` from
  `tx_vlan_id` so the offset is rewrite-time-known).

  Phase 0 has two viable sub-options:
  - **0a (lower invasive)**: do not pipe metadata through
    TxRequest at all. Re-parse the post-rewrite TX-frame at
    the AFD ECN-mark site (same as the existing
    `cos/ecn.rs:179` path). Per-mark cost: ~50 ns (existing
    measurement). Acceptable for the saturated-RSS-skewed
    target workload (large-packet TCP at 2 Mpps where 50 ns
    is ~10% of budget).
  - **0b (lower runtime cost)**: extend `TxRequest` and
    `PreparedTxRequest` (`userspace-dp/src/afxdp/types/tx.rs:12`
    + `:54`) to carry post-rewrite L3 + L4 offsets and IP
    version, computed at the rewrite site itself
    (`frame/mod.rs:245` is the natural producer). Per-mark
    cost: ~10 ns. Touches every TX construction site and the
    rewrite path. Larger diff.

  Recommendation: ship 0a first (zero metadata diff; reuses
  existing parse), then evaluate 0b if budget pressure shows
  up empirically. Either choice is structurally compatible
  with the AFD design; the implementation PR picks one.

- **Phase 1**: add the AFD module (`userspace-dp/src/afxdp/cos/afd.rs`)
  with `AfdQueueState`, `SharedFlowSlot` types, and the snapshot
  owner logic.

- **Phase 2**: wire the pre-submit AFD decision in
  the shared-exact pre-submit path
  (`cos/queue_service/service.rs:186-260` local variant +
  `:517-617` prepared variant). The mark site reads the
  post-rewrite frame either by re-parsing it on the spot
  (Phase 0a; reuses `cos/ecn.rs:179`-style parse) or by
  consuming cached offsets that Phase 0b would have threaded
  through `TxRequest`/`PreparedTxRequest`. RFC 3168-compliant
  unified mark/drop probability per Fix #6.

- **Phase 3**: wire settle-time `served_bytes` accounting in
  `settle_exact_*_scratch_submission_flow_fair`
  (queue_service/mod.rs:740 + :795) per Fix #1 + #9.

If Phase 0's TxRequest extension is judged too invasive on its
own, the ECN-mark falls back to the existing reparse path in
enqueue_cos_item (with worse per-pop budget — ~50 ns instead of
~10 ns). This fallback may push 64B/35Mpps workloads out of
spec; document the trade-off explicitly in the implementation
PR.

### Fix #9 (v3 round-2): settle hook location

Codex round-2 finding #4: settle hook is in
`settle_exact_*_scratch_submission_flow_fair`, not
`apply_cos_send_result`. v3+v4 reference the correct symbol path
in the queue_service module (line ~740 in `mod.rs`).

### Fix #5: probabilistic drop curve (vs Gemini's "drop cliff" critique)

Gemini round-1 finding H: a binary `if delta > 2*fair { drop } else
{ keep }` creates a drop-cliff that hammers TCP harder than a
smoothed AQM curve.

v2 uses a smoothed CSFQ-style drop probability for non-ECT
packets:

```rust
// p_drop = max(0, (delta - fair) / delta) when delta > fair, else 0
fn afd_drop_probability(delta: u64, fair: u64) -> u8 {
    if delta <= fair {
        return 0;
    }
    let excess = delta - fair;
    // Probability scaled to 0-255 for cheap random-byte comparison.
    let p = ((excess as u128 * 255) / (delta as u128)).min(255) as u8;
    p
}

// Hot path:
let p_drop = afd_drop_probability(delta, fair);
if p_drop > 0 && !cos_item_is_ect_fast(&item) {
    let r = afd_per_worker_random_byte(ff);  // splitmix64 per-worker; see Fix #7
    if r < p_drop {
        return Drop;
    }
}
```

This matches the CSFQ paper's per-flow drop probability formula
and avoids the bursty-drop pathology Gemini flagged.

---

### 3.2 Hot path — read-only published summary, batch-hoisted

> **NOTE (v3)**: Sections 3.2 / 3.3 / 3.4 below are SUPERSEDED
> by the v2 fixes section above (Fixes #1-5). The text below is
> retained for traceability of the design evolution but the
> implementation MUST follow the v2 fixes. See "v2 — round-1
> reviewer fixes" above. Specifically:
>
> - §3.2's "fetch_add at pop time" is REPLACED by Fix #1
>   (settle-time accounting in queue_service/mod.rs:740+795).
> - §3.2's "ArcSwap.load() per pop" is REPLACED by Fix #3
>   (batch-hoist at drain entry, ~30 ns per batch amortized).
> - §3.3 / §3.4's "cumulative aggregate_served" is REPLACED by
>   Fix #2 (window_served_delta in published summary).
> - §3.2's binary "drop if 2*fair" is REPLACED by Fix #5
>   (smoothed CSFQ probability + RFC 3168 same-probability ECN
>   marking; see v3 reconciliation in §3.8 below).

On every shaped-pop on a shared_exact queue:

```rust
// In cos/queue_ops/pop.rs, after the existing served_finish/vtime advance.
if let Some(afd) = ff.afd.as_ref() {
    let bucket = bucket_u16 as usize;
    let my_shard = &afd.shards[queue.v_min.worker_id as usize];
    // Single-writer — fetch_add on own shard only. No false sharing
    // because own shard is on its own cache line.
    my_shard.shard.served_bytes[bucket].fetch_add(item_len_u64, Ordering::Relaxed);

    // Read the published summary (Relaxed via ArcSwap load).
    // ArcSwap.load() is an atomic pointer load + refcount inc —
    // ~5 ns amortized. Re-using the loaded Arc across multiple
    // packets in a batch via Box-deref hoisting (see #1206
    // pattern) amortizes further.
    let summary = afd.published_summary.load();
    let fair_share = summary.fair_share_bytes_per_bucket[bucket];

    // Decide ECN-mark based on prior-window aggregate vs fair share.
    // No live cross-worker read; only the published summary.
    let aggregate_for_bucket = summary.aggregate_served[bucket];
    if aggregate_for_bucket > fair_share && cos_item_is_ect(&item) {
        cos_item_mark_ce(&mut item);
    }
    // Probabilistic drop for non-ECT only when severely over-share.
    if aggregate_for_bucket > fair_share.saturating_mul(2) && !cos_item_is_ect(&item) {
        // Drop; let TCP retransmit slower.
        return Drop;
    }
}
```

**Key properties:**
- **No cross-worker writes to the same cache line.** Each worker's
  shard is `#[repr(C, align(64))]` with padding; fetch_add on own
  shard never bounces.
- **No live cross-worker reads.** The hot path reads only
  `published_summary` (RCU-style; Arc pointer load + dereference).
  This is a **read-mostly** access; the published Arc is updated
  rarely (once per window, ~10ms) by a single writer.
- **No rollback.** The fetch_add is monotonic per-worker. Submit-
  failure restoration of items does NOT decrement the counter
  because the bytes were genuinely served by the time we got to
  the pop site (per #1215's failed analysis — actually, this is
  the same pitfall #1215 had; need to reconsider). **Open**: see
  §6 Q1.
- **No global period reset.** Each worker's shard accumulates
  monotonically. The snapshot-owner reads them, computes window
  delta, publishes summary, then RESETS the snapshot baseline (not
  the shard — workers don't see resets).

### 3.3 Cold path — snapshot owner

A single dedicated thread (or piggybacked on existing 1Hz
coordinator status poll):

```rust
fn afd_snapshot_window(afd: &AfdQueueState, prior: &AfdWindowSummary) -> AfdWindowSummary {
    let now_ns = clock_monotonic_ns();
    let window_duration_ns = now_ns - prior.window_end_ns;
    let mut aggregate = [0u64; AFD_BUCKETS];
    for shard in afd.shards.iter() {
        // Cross-cache-line read here. Slow path; happens at window
        // boundary (~10ms cadence). Not a hot-path concern.
        for b in 0..AFD_BUCKETS {
            aggregate[b] += shard.shard.served_bytes[b].load(Ordering::Relaxed);
        }
    }
    // Compute fair share from active-bucket count, deltas vs prior.
    let active_buckets = aggregate.iter().filter(|&&b| b > prior.aggregate_served[b]).count();
    let total_window_bytes = aggregate.iter().zip(prior.aggregate_served.iter())
        .map(|(a, p)| a.saturating_sub(*p)).sum::<u64>();
    let fair_share_per_bucket = if active_buckets > 0 {
        total_window_bytes / active_buckets as u64
    } else {
        u64::MAX  // no marking when idle
    };
    AfdWindowSummary {
        fair_share_bytes_per_bucket: [fair_share_per_bucket; AFD_BUCKETS],
        aggregate_served: aggregate,
        window_duration_ns,
        active_buckets: active_buckets as u16,
    }
}
```

Then `afd.published_summary.store(Arc::new(new_summary))`. ArcSwap
ensures the old Arc is dropped after no readers hold it (epoch GC).

### 3.4 Race surfaces (vs #838's 4 known)

| #838 surface | This plan's answer |
|---|---|
| **Period reset coherence** | NO PERIOD RESET on workers. Only the snapshot owner sees window boundaries; it just publishes a new summary (RCU). Workers never see resets — they accumulate monotonically. |
| **Fair-share denominator staleness** | Denominator (`active_buckets`) is computed by snapshot owner ONCE per window and baked into the published summary. Workers never compute it. Window-to-window staleness = window duration (~10ms); acceptable as we're targeting TCP-cwnd-scale fairness. |
| **Rollback semantics** | Not applicable — workers don't do AFD-related rollback. The submit-failure restoration of pending items is orthogonal: those bytes were served (counted) but didn't go on the wire. **OPEN**: this same pitfall killed #1215 (see §6 Q1). |
| **Batch-latency mismatch** | Both selector (per-pop ECN-mark decision) and accumulator (per-pop fetch_add) are per-pop. No batch-vs-packet mismatch. |

### 3.5 Cache-line analysis (vs Gemini's "concurrency nightmare" critique)

- `shards` array is `Box<[AfdShardCacheLine]>` — each shard is
  exactly 64 bytes aligned. Worker N writes only to `shards[N]`.
  No cross-worker write contention.
- `published_summary` is an `ArcSwap<AfdWindowSummary>`. Workers
  only call `.load()` on it (Arc refcount + pointer read). The
  refcount is on its own cache line (Arc internal layout).
- Refcount inc/dec on `.load()` IS a cross-cache-line write. **This
  is the residual cache-line bouncing concern.** Mitigations:
  - ArcSwap uses a hazard-pointer-style mechanism that avoids
    incrementing the refcount in the common case (refcount-free
    fast path).
  - If even the hazard-pointer cost is too high, the published
    summary can be a `Box<AfdWindowSummary>` swapped via raw
    `AtomicPtr` with epoch-based reclamation (crossbeam-epoch).
    More complex but zero refcount traffic.
- `epoch: AtomicU64` is a snapshot-owner-write, worker-read field.
  Could be the same cache line as ArcSwap's internal pointer (false
  sharing across snapshot vs hot path). Place on its own cache line
  via `#[repr(C, align(64))]`.

**Estimated cost per pop on shared_exact queue:**
- 1 atomic fetch_add on own cache line: ~5 ns (no contention)
- 1 ArcSwap.load() (hazard-pointer fast path): ~3-5 ns
- 1 array index read on the published summary: ~2 ns (likely L1
  cache hit for the working bucket)
- 1 conditional ECN-mark write on packet: ~5 ns
- **Total: ~15-20 ns added to the per-pop hot path**

**This is the budget question.** At 64-byte packets / 35 Mpps line
rate, the per-packet budget is ~28 ns — adding 15-20 ns is 50-70%
of budget consumed, which is too much for line-rate-PPS workloads.
At 1500-byte packets / ~2 Mpps line rate, the budget is ~480 ns and
15-20 ns is 3-4% — acceptable.

**xpf's actual workload is mostly large-packet TCP** (iperf-style),
NOT 64-byte-PPS small-packet flooding. Small-packet performance is
not in the saturated-RSS-skewed regime; it's in high-fan-in
(separate gate). So the budget analysis at 1500B/2Mpps is the
relevant one.

### 3.6 HA failover

- On role flip, the `AfdQueueState` is dropped with the queue and
  rebuilt fresh. New shards start at zero served_bytes; new
  published summary starts with `fair_share = u64::MAX` (no
  marking until first window completes).
- **No saturating_sub underflow risk** because we never compute
  byte-rate diffs from old vs new values — only the snapshot owner
  computes deltas, and on a fresh queue the prior summary is the
  zero-init one.

### 3.7 Out-of-scope clarifications

- **Owner-local-exact queues**: NOT covered. AFD applies only to
  shared_exact queues where cross-worker fairness matters.
- **Best-effort queues**: NOT covered. Best-effort fairness is
  driven by single-FIFO drain order; AFD adds nothing.
- **UDP / non-ECN-capable**: AFD's ECN-mark path is a no-op; the
  probabilistic drop path applies but TCP's ECN response is the
  primary mechanism, so UDP gets only the drop side. Document this
  limitation.

## 4. Concrete prototype scope (if reviewers PLAN-READY)

A separate plan-and-PR after this plan is approved would deliver
the phased Fix #10 implementation:

1. New module `userspace-dp/src/afxdp/cos/afd.rs` (~400 LOC).
2. **Pre-submit ECN-mark hook** in the shared-exact pre-submit
   path: `cos/queue_service/service.rs:186-260` (prepared
   variant) and `:517-617` (prepared variant), immediately before
   the TX-ring submit. These call sites have:
   - binding/UMEM context (needed to access the wire frame),
   - the post-rewrite frame layout (any VLAN/tunnel/L3 rewrite
     done by the TX dispatch pipeline has already happened),
   - the AFD `AfdQueueState` Arc on the queue runtime.

   NOT in `cos/queue_ops/pop.rs` — pop runs at the queue-
   abstraction level with no binding/UMEM/submit context. NOT
   in `tx/dispatch.rs` — that's where `TxRequest` /
   `PreparedTxRequest` are first BUILT, before the shared-exact
   submit decision and before any post-rewrite parse is
   meaningful.

   At the shared-exact pre-submit hook, the AFD code uses
   either:
   - 0a: re-parse path inside `cos/ecn.rs`-style helper called
     on the wire frame (~50 ns/mark; reuses `cos/ecn.rs:179`
     existing logic; recommended initial path)
   - 0b: cached-offset path consuming post-rewrite metadata
     produced at `frame/mod.rs:245` rewrite time (~10 ns/mark;
     larger diff to thread offsets through; defer until
     measured budget pressure justifies)
3. **Settle-time `served_bytes` accounting** (per Fix #1) in
   `settle_exact_*_scratch_submission_flow_fair`
   (queue_service/mod.rs:740 + :795) — counts only the inserted
   prefix.
4. **Snapshot owner thread** piggybacked on existing coordinator
   1Hz status poll, OR as a new dedicated 100Hz thread (window
   boundary cadence TBD by §6 Q3).
5. **`AfdQueueState`** allocated alongside `vtime_floor` and
   `flow_fair_state` at queue promotion time.
6. **Feature flag** (off by default) to enable AFD per
   shared_exact queue.
7. **Telemetry**: per-bucket marks, drops, fair-share-window —
   pin to #1209 telemetry double-buffer.

## 5. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression on FIFO/owner-local | NONE | Code path unchanged |
| Behavioral regression on shared_exact aggregate | LOW-MED | ECN marks should not reduce TCP throughput on ECN-capable senders if marks are accurate; UDP probabilistic drops will reduce throughput in over-share regime by design |
| Hot-path perf cost | MED | ~15-20 ns added per shaped-pop; acceptable at 1500B/2Mpps but not at 64B/35Mpps |
| Race-safety on shared atomics | LOW | Single-writer shards on own cache lines; published summary via RCU; no rollback |
| Cache-line bouncing | LOW-MED | ArcSwap hazard-pointer fast path mitigates; if measured high, fall back to crossbeam-epoch |
| HA failover | LOW | Fresh AfdQueueState on role flip; no underflow arithmetic |
| TCP receiver ECN response in production | UNKNOWN | Depends on receiver kernel + ECN-deployment status. Modern Linux honors ECN; some legacy stacks ignore it |

## 6. Open questions for adversarial review

1. **Submit-failure pitfall (same as #1215)**: when a worker pops a
   packet, fetch_adds served_bytes, then submit fails and the
   packet is restored to the queue, does the served_bytes counter
   over-state served work? §3.4 claims "not applicable" but Codex
   round-2 on #1215 specifically called this out as wrong reasoning.
   How does this plan actually avoid the same pitfall?

2. **Cache-line bouncing on ArcSwap**: Gemini's #937 review called
   cross-worker shared state for AQM a "concurrency nightmare." Is
   ArcSwap's hazard-pointer fast path actually low-overhead enough,
   or does crossbeam-epoch need to be the baseline?

3. **Window cadence**: 10ms (~100Hz) snapshot owner publishes —
   is this fast enough to react to TCP-burst dynamics, or too fast
   (causing window-boundary noise)? At ~100ms (~10Hz) we react
   slowly; at ~1ms (~1000Hz) the snapshot read itself becomes a
   per-cache-line cost on every shard. Where's the sweet spot?

4. **TCP-with-ECN deployment reality**: in 2026, what fraction of
   TCP senders honor CE marks? If <50%, the ECN side is ineffective
   and only the probabilistic drop side fires, hurting TCP via
   actual loss instead of the cwnd response.

5. **Bucket aggregation across shards**: §3.4 says
   `aggregate[b] = sum_over_shards(shard.served_bytes[b])`. With
   8 workers × AFD_BUCKETS buckets, that's 8 × N atomic loads per
   window. At AFD_BUCKETS = 4096 (matching COS_FLOW_FAIR_BUCKETS),
   that's 32K loads per window. At 10ms cadence, that's 3.2M
   loads/sec — uses ~16MB/s memory bandwidth. Acceptable?

6. **What if measurement shows ≤25% saturated-RSS-skewed gate is
   STILL not closed by AFD**? The fairness-regimes contract
   already accepts saturated-RSS-skewed at ≤30%. If AFD only
   moves it from 28% to 27%, was the multi-week effort worth it?
   At what improvement threshold should we ship vs decline?

7. **Should this plan include an explicit measurement-first
   gate** like #900 / Codex Path 0? "Build the deterministic
   RSS-skew fixture first, measure CoV at every stage, only ship
   AFD if it provably closes the gap"?

## 7. Verdict request

PLAN-READY → plan a separate prototype implementation PR.
PLAN-NEEDS-MINOR → tighten cache-line analysis or window cadence.
PLAN-NEEDS-MAJOR → restructure (e.g., make epoch-based reclamation
the baseline, not a fallback; or pivot to a different snapshot
mechanism).
PLAN-KILL → §6 Q2 is fundamentally unsolvable on this codebase
(cache-line bouncing dominates regardless of design); OR §6 Q4 is
'<50% ECN' so the TCP side is too weak to matter; OR §6 Q1 (submit-
failure pitfall) cannot be cleanly avoided. Acceptable verdict; in
that case the fairness-regimes contract (PR #1217) is the
steady-state product.
