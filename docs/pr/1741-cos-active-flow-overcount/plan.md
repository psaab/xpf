# #1741 — CoS active-flow count over-counts (reverse-direction entries)

Status: PLAN-KILLED (v2) — approach wrong-targeted; symptom not reproducible

## PLAN-KILL summary (2026-06-01)

Both the v1 (forward-only filter) and v2 (per-FlowCache canonical-pair
dedup) designs are killed. Verdicts:

- **Codex round 1 (v1): PLAN-NEEDS-MAJOR** — a blanket `!is_reverse`
  filter undercounts the reverse-data (`-R`) direction, which the
  fairness harness defaults to (`fairness-harness.sh:88`,
  `fairness-cos-throughput-headroom.sh:17`).
- **Codex round 2 (v2): PLAN-NEEDS-MAJOR**, two findings CONFIRMED
  against the live loss cluster:
  1. **Dedup domain mismatch.** `active_flow_debug_entries` runs
     per-`FlowCache`, but each `BindingWorker` owns multiple bindings
     (one per interface) each with its own flow cache, and the public
     metric is summed at the COORDINATOR by `(ifindex, queue_id,
     worker_id)` (`coordinator/status.rs:190-198`) AFTER per-binding
     canonical ids are discarded. Per-FlowCache dedup cannot collapse
     duplicate counts that arise across bindings on the same worker that
     map to the same public cell. To dedup at the right layer the
     canonical ids would have to be carried up to the coordinator — a
     wire/protocol change far beyond this telemetry fix.
  2. **NAT breaks the canonical-pair identity on the acceptance path.**
     The loss cluster applies `lan -> wan` interface SNAT
     (`test/incus/xpf-cluster-fw0.conf:146`); the WAN egress (ifindex 14
     = reth0.80) is the SNAT interface (`nat_src_ip 172.16.80.8`,
     confirmed live: `cos_active_flow_count{ifindex="14",...}`). The
     forward half's wire key `{client, server}` and the reverse half's
     wire key `{server, 172.16.80.8}` do NOT form the same unordered
     pair, so the canonical-pair dedup is a no-op exactly where the v4
     acceptance proof runs. The plan's "reth0.80 is non-NAT" premise is
     false.
- **AGY rounds 1 and 2: PLAN-READY** — NOT credible. AGY reviewed v1 in
  round 1 (missing the `-R` undercount Codex caught) and in round 2
  argued forward/reverse always land in different `(ifindex,queue_id)`
  cells so "the count stays 1" — which, taken to its conclusion, says
  the over-count does not exist. AGY never explained the actual 49/75
  mechanism and its NAT analysis is wrong for this path. Per
  `feedback_gemini_low_signal_on_refactor` / AGY-never-blesses-alone,
  AGY's PLAN-READY does not override Codex's quoted, live-confirmed
  MAJOR findings.

### Symptom not reproducible on master

Deployed master on `loss:xpf-userspace-fw0`, applied the documented
`--symmetric` CoS fixture (`apply-cos-config.sh --symmetric`), and ran
the pinned-`--cport` repro (`iperf3 -R`) at N=24 and N=48 to shaped port
5202. The summed `cos_active_flow_count` was a stable, severe
**UNDER-count** (2 active flows for 48 pinned `-R` streams), never the
reported 49/75 over-count. The shaped 1g queue throttles most flows out
of the 650ms active window. The issue's repro context ("Codex
fresh-review session rss-evenness-fresh-view", a specific RSS-key +
sequential-`--cport` arrangement) is not captured in a runnable form, so
no fix can be validated against the actual symptom.

### Recommendation

Re-open with a CAPTURED, runnable reproduction (exact RSS key config,
ports, stream count, scrape timing, and the raw per-(ifindex,queue,worker)
rows showing the over-count) BEFORE attempting a fix. The correct fix
layer is almost certainly the coordinator aggregation
(`coordinator/status.rs:cos_active_flow_counts`) or the fairness-eval
`--iface`/`--cos-ifindex` selection (`fairness_eval/`), not the
per-worker flow cache — and any session-identity dedup must be
NAT-aware (use the post-NAT wire key / `forward_wire_key` +
`reverse_canonical_key` consistently, not the raw observed tuple). The
650ms active-window aging is a separate, second-order contributor to the
MS-key 62 outlier.

---

(Historical) Status: DRAFT v2 — revised after Codex PLAN-NEEDS-MAJOR (round 1)

## Round-1 review outcome (why v2 changes the fix)

Codex round 1 = PLAN-NEEDS-MAJOR. Key correct objection: the fairness
harness defaults to **reverse iperf (`-R`)**
(`test/incus/fairness-harness.sh:88`) and the CoS-headroom harness
explicitly drives reverse data
(`test/incus/fairness-cos-throughput-headroom.sh:17`). The fairness
contract counts the **data-direction** flows on the selected CoS queue,
not "canonical forward half"
(`fairness_eval/mod.rs:33,59`, `verdict.rs:62`). A blanket
`!entry.metadata.is_reverse` filter (v1) would EXCLUDE the real
data-direction queue when the data flows reverse, undercounting `-R`
tests. Codex confirmed v1's other claims: not correct-by-design (don't
move to the gauge derivation), `is_reverse` is dead state on the
flow-cache datapath/TX/HA path, and no two-forward-install counterexample
exists.

Also relevant (found while revising): `verdict.rs` already carries a
`direction_multiplier` (1 for iface-filtered, 2 for bidirectional) and a
`GUARD_OVERCOUNT_DIVISOR`/#1281 "stale entry" overcount tolerance — these
are downstream *compensation* for exactly this double-count. They do NOT
save the symmetric-key case: under symmetric hashing BOTH directions land
on the SAME interface AND the SAME worker, so iface filtering (which
keeps `dir_mult=1`) still sees two entries per session → 49/75. The fix
must make the snapshot itself report one count per session.

### v2 fix: per-session dedup (direction-independent), NOT forward-only

The real bug is **both halves of one session counted twice when they
share a worker+queue**, not "reverse is bad." Dedup the CoS count by a
direction-independent canonical session identity so each distinct session
on a queue counts exactly once — regardless of whether the data direction
is forward or reverse, and regardless of whether one or both halves
landed on this worker.

Original v1 status line preserved below for history.

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

`xpf_userspace_cos_active_flow_count{queue_id,worker_id}` (and the
`xpf_fairness_cstruct` / per-flow-CoV / `max_worker_flow_share` gauges
derived from it, #1247) intermittently report MORE active flows than
exist. With exactly 48 pinned iperf streams on one CoS queue, summed
per-worker counts came out 48 on most runs but 62/49/49/75 on others.
`cos_active_flow_counts_truncated` was 0 throughout — this is NOT the
#1247 truncation path. Over-counting is worse under a symmetric RSS key.

## Root cause (read end-to-end, confirmed in code)

The per-worker flow cache (`afxdp/flow_cache.rs`) is keyed on the **wire
5-tuple as parsed from the packet on ingress** — `FlowCacheEntry.key =
flow.forward_key`, where `flow` comes from
`parse_session_flow_from_bytes(packet_frame, meta)` in
`stage_parse_flow_and_learn` (poll_stages.rs:179). The "forward_key"
name is a misnomer for the cache: it is simply *this packet's* source→dst
tuple, not the session's canonical forward tuple.

A bidirectional session (e.g. an iperf3 TCP stream: data client→server,
ACKs server→client) is **forwarded in both directions** by the worker.
Each direction parses to a *different* wire tuple, so each direction
produces its **own** `FlowCacheEntry` via
`FlowCacheEntry::from_forward_decision` (poll_descriptor/mod.rs:1925) →
`binding.flow.flow_cache.insert(entry)` (:1945). Both entries are stored
with `metadata.is_reverse: false` hardcoded
(`from_forward_decision`, flow_cache.rs:360) and both carry a CoS
`tx_selection.queue_id`.

`active_flow_debug_entries` (flow_cache.rs:465) scans every active cache
entry and increments `cos_counts[(egress_ifindex, queue_id)]` for **every**
entry that has a `queue_id`, with no direction filter and no session-level
dedup. So a single bidirectional flow that traverses one worker in both
directions is counted **twice**.

This precisely explains the issue evidence:

- **Symmetric RSS key**: forward and reverse wire tuples hash to the
  **same** RX queue → both directions handled by the **same** worker →
  both cache entries live in the same `flow_cache` → counted twice on the
  same worker. Sum overshoots (49, 75). Matches "worse under symmetric
  key."
- **Asymmetric MS key**: forward and reverse tuples hash to **different**
  queues/workers → each worker holds only one direction's entry → sum
  stays ≈ N (clean 48). Matches the clean MS rows.
- **MS-key 62 outlier**: with random ports, some flows' fwd/rev tuples
  collide onto the same worker by chance; additionally the ~650ms active
  window (`ACTIVE_WINDOW_EPOCHS = 10`) can briefly retain a just-closed
  flow's entry. Both effects are second-order and consistent with an
  occasional MS overshoot that the symmetric-key double-count makes
  systematic.

So the dominant, systematic bug is **reverse-direction cache entries being
counted as additional active flows**, not stale aging or a scrape race.
Aging is a real but second-order contributor.

The active-flow signal is meant (per #1217/#1247 fairness contract) to be
the count of **distinct flows assigned to each worker/queue**. For a
bidirectional flow, the canonical flow is ONE flow; counting its reverse
half as a second flow is wrong by definition. The fix is to count only
the forward-direction entry per session.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (Here the "gain" is correctness of an
operator-facing + automated-fairness-gate metric, not throughput; a
KILL would instead argue the count is correct-by-design as bidirectional
— see Open Questions.)

## What's already shipped / related

- #1219: `last_used_epoch` recency + `count_active_flows` 650ms active
  window. `tick_advance_epoch` on the ~65ms worker tick.
- #1247: derived fairness gauges (`fairness_cstruct`, per-flow CoV,
  `max_worker_flow_share`) consume `cos_active_flow_count`.
- #1249: `active_flow_debug_entries` bounded debug map + CoS counts.
- `cos_active_flow_counts_truncated` (#1247) — the FLOW_WORKER_MAP cap
  path, confirmed 0 in the issue, so out of scope here.

## Concrete design (v2 — per-session canonical dedup)

The fix is contained entirely in `active_flow_debug_entries`
(flow_cache.rs:465). No change to `from_forward_decision`, no new
parameter, no call-site threading — the v1 direction-threading is
DROPPED. We do not need to know the session direction at all; we need a
direction-independent identity so the two halves of one session collapse
to one count.

### Canonical per-session dedup key

Each flow cache entry's `key` is the wire 5-tuple as observed on ingress.
For a non-NAT bidirectional flow the forward half is
`(cIP:cPort, sIP:sPort)` and the reverse half is `(sIP:sPort, cIP:cPort)`
— the same *unordered* endpoint pair. Define a canonical, order-independent
session identity by sorting the two `(ip, port)` endpoints:

```rust
#[inline]
fn canonical_session_id(key: &SessionKey) -> (u8, (IpAddr, u16), (IpAddr, u16)) {
    let a = (key.src_ip, key.src_port);
    let b = (key.dst_ip, key.dst_port);
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    (key.protocol, lo, hi)   // addr_family is implied by IpAddr variant
}
```

Both halves of a non-NAT session map to the **same** `canonical_session_id`.
(`IpAddr` and `u16` derive `Ord`, so the tuple comparison is total and
stable.)

### Dedup the CoS count per (egress_ifindex, queue_id)

Replace the `cos_counts: BTreeMap<(i32,u8),u32>` running counter with a
per-queue *set* of canonical session ids during the scan, then collapse
each set's cardinality to the published count:

```rust
let mut cos_sessions =
    BTreeMap::<(i32, u8), std::collections::BTreeSet<CanonId>>::new();
...
for slot in self.entries.iter() {
    // ... existing active_entry_age gate ...
    active = active.saturating_add(1);
    if let Some(queue_id) = entry.descriptor.tx_selection.queue_id {
        let qkey = (entry.descriptor.egress_ifindex, queue_id);
        cos_sessions
            .entry(qkey)
            .or_default()
            .insert(canonical_session_id(&entry.key));
    }
    // ... existing rows.push (unchanged) ...
}
let cos_counts = cos_sessions
    .into_iter()
    .map(|((ifindex, queue_id), ids)| CoSActiveFlowCount {
        ifindex,
        queue_id,
        active_flow_count: ids.len() as u32,
    })
    .collect();
```

This counts **distinct sessions per (egress_ifindex, queue_id) cell**,
which is exactly the fairness-contract definition of `{a_i}` for the
data-direction interface, and is correct for BOTH forward (`push`) and
reverse (`-R`) data directions: a single session contributes 1 whether
the worker holds its forward half, its reverse half, or both.

**Why dedup is per-cell and therefore safe across RSS regimes.** The
dedup happens *inside* each `(egress_ifindex, queue_id)` bucket. Two
cache entries collapse to one count only if they share both the same
egress+queue cell AND the same canonical session id — i.e. they are the
two halves of one session that were both classified onto the SAME queue
on the SAME worker. That is precisely the symmetric-key double-count bug
(the harness applies reverse source-port CoS filters via `--symmetric`
so both the data direction and its ACK/return direction can match the
same shaped queue when they hash to the same worker). Under the MS key
the two halves hash to different workers, so no single cell ever holds
both halves → dedup is a no-op there and the existing clean `sum == N`
(48) is preserved. Dedup never crosses worker, interface, or queue
boundaries, so it cannot turn the MS `N` into `2N` or undercount a
flow that legitimately occupies two distinct cells.

The total `active` count and the bounded `rows` debug map are UNCHANGED —
they still enumerate every active cache entry (the flow-worker map
intentionally shows both halves with `forward_wire_key` +
`reverse_canonical_key` per row for operator inspection). Only the
CoS-count series that feeds the fairness gauges is deduped.

### NAT caveat (explicit, bounded)

With NAT the two halves' wire tuples may not form the same unordered pair
(forward ingress sees the pre-SNAT internal tuple; reverse ingress sees
the post-SNAT public tuple), so a NAT'd session whose both halves land on
one worker could still count as 2. This is acceptable and a strict
improvement: (a) the regression target is the iperf smoke path
(reth0.80, no NAT on the data path), where dedup fully resolves to N;
(b) for NAT'd flows the two halves are *distinct observed wire flows on
the queue* and counting each is defensible; (c) v1's forward-only filter
would have MIS-counted NAT'd reverse-data flows worse. Documented as a
known bound, not silently ignored.

### Memory / cost

The per-queue `BTreeSet<CanonId>` lives only for the duration of one
periodic owner-only scan (already cold, ~once per ~65ms tick, off the
packet path). Bounded by active-flow count (≤ 4096 cache entries). One
`CanonId` is `(u8, (IpAddr,u16), (IpAddr,u16))` — at most ~40 bytes; the
set is dropped at end of scan. No hot-path allocation, no per-packet cost,
no struct size change.

### Invariant

For N distinct pinned iperf streams (forward OR reverse data) on one CoS
queue, summed per-worker `cos_active_flow_count == N` once steady-state
(within the 650ms active window). More generally, on the non-NAT data
path: `sum(cos_active_flow_count for queue q) ==
distinct_live_sessions_on_queue_q`, never `2×`.

## Public API preservation

- `from_forward_decision`: UNCHANGED (v1's new param dropped).
- `CoSActiveFlowCountStatus` wire/JSON shape unchanged.
- `active_flow_debug_entries` signature unchanged; only the internal
  cos-count accumulation changes from a counter to a per-queue set whose
  cardinality is published.
- `count_active_flows` (test-only total): UNCHANGED.
- No call-site changes in poll_descriptor/mod.rs.

## Hidden invariants preserved

- **Side-effect ordering**: no change — dedup is read-only over the same
  owner-only scan; only the local accumulator type changes.
- **Allocation rules**: the per-queue `BTreeSet` is a short-lived
  scan-local allocation in an already-cold periodic scan (off the packet
  path). No hot-path allocation, no struct size change.
- **HA sync portability**: untouched. Flow cache is worker-local; HA sync
  uses the session table, not the flow cache.
- **Scheduling / datapath behavior**: UNCHANGED. v2 touches ONLY the
  periodic debug/CoS scan accumulation. No `from_forward_decision` change,
  no poll-path change, no field read on the TX/cache-hit path. Pure
  telemetry; no failover/datapath behavior change → `make test-failover`
  not required.
- **Stale-handle hazards**: none.
- **Borrow shape**: `entry.key` read under the same `&FlowCacheEntry`
  borrow already held in the scan loop.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Telemetry-only; datapath and poll path entirely untouched in v2. |
| Lifetime / borrow-checker | LOW | Scan-local `BTreeSet`; one extra read of `entry.key`. No new borrows escape the loop. |
| Performance regression | LOW | A per-queue set in a cold ~65ms periodic scan; bounded by ≤4096 entries; dropped at scan end. |
| Architectural mismatch | LOW | Reuses the existing wire-key on cache entries; canonical-id is a pure function. No new architecture. |

## Test plan

- `cargo build` clean.
- New unit test in `flow_cache_tests.rs`: insert one forward + one reverse
  entry for the same logical session (same queue_id, swapped src/dst
  tuples), both freshly hit; assert `active_flow_debug_entries` returns a
  CoS count of **1** for the queue (deduped), while `active` (total) is 2
  and the debug `rows` show both. Add: N distinct sessions (each as its
  fwd+rev pair) on one queue → CoS count **N** (not 2N). Add: a
  reverse-only session (only the reverse half cached) still counts 1
  (proves `-R` data direction is not undercounted). Add: two genuinely
  distinct sessions sharing no endpoints → count 2 (no false dedup).
- 5/5 flake check on the new named test.
- Full cargo `--release` suite.
- Go suite (30 packages) — no Go change expected, run for safety.
- Deploy to loss userspace cluster; apply CoS config; confirm classifier
  bound.
- **Definitive repro/fix proof**: run N pinned iperf streams via
  sequential `--cport` on a CoS port under BOTH a symmetric and the MS
  RSS key; scrape `xpf_userspace_cos_active_flow_count`; assert summed
  per-worker count == N (was 49/75 under symmetric). Do v4 + v6.
- Standard smoke matrix (Pass A CoS-disabled, Pass B per-class) for
  regression coverage, since the change touches the flow-cache populate
  call site.

## Out of scope

- The ~650ms aging-window second-order transient (the MS-key 62). Dedup
  removes the systematic 2× term; any residual brief overshoot under rapid
  flow churn is bounded by the active window and not the N-pinned-stream
  (long-lived) invariant this PR proves.
- `cos_active_flow_counts_truncated` path (#1247) — confirmed 0, unrelated.
- Any change to the fairness verdict math itself (#1217 contract). The
  `direction_multiplier` in `verdict.rs` becomes a no-op-ish 1× under
  iface filtering after dedup; we leave it (harmless) rather than churn
  the contract evaluator in a telemetry-source fix.

## Open questions for adversarial review (v2)

1. **Canonical-id correctness across NAT.** v2 documents that NAT'd
   sessions whose halves land on one worker may still count 2 because the
   wire tuples don't unordered-match. Is that acceptable for the
   contract, or does any production CoS-shaped path apply NAT such that
   this re-introduces a systematic 2× on a queue the fairness gate reads?
   (Claim: smoke data path reth0.80 is non-NAT.)
2. **False-dedup hazard.** Could two genuinely distinct sessions ever
   produce the same `canonical_session_id` on one queue (e.g. a flow and
   its own mirror, or A→B and B→A as separate real sessions), causing an
   UNDER-count? Enumerate when `(proto, {endpointA, endpointB})` collides
   for non-partner flows.
3. **Reverse-data (`-R`) direction.** Confirm v2 counts a reverse-only
   data flow as 1 (the v1 defect Codex caught). Does any path cache ONLY
   the reverse half with a queue_id and never the forward half, such that
   dedup-by-set still yields 1 (correct) rather than 0?
4. **Aging residual.** Does dedup alone satisfy `sum == N` for N
   long-lived pinned streams within the 650ms window, or is a churn
   transient still observable at scrape time?
5. **MS-key semantics.** Under the MS key the two halves are on different
   workers; each worker's set has 1 element for that flow, so the
   cross-worker SUM is 2 for one logical flow. Wait — is that an
   over-count under MS? (Analysis: the contract sums per-worker counts;
   under MS the flow legitimately occupies two workers' queues with one
   wire-flow each, so 2 is the correct per-queue-occupancy sum. Under
   symmetric, both wire-flows are on ONE worker and dedup to 1. Confirm
   this is the intended `{a_i}` semantics and not a new MS over-count.)
6. **`active` vs CoS divergence.** v2 keeps `active` (total) counting both
   halves while CoS counts deduped. Any consumer that assumes
   `sum(cos_counts) == active`? (Claim: none; they are separate series.)
3. **Miss-path direction**: on the session-miss new-flow path, is
   defaulting `flow_cache_is_reverse = false` always correct, or are there
   reverse-seeding miss arms (NAT64 reverse, cluster-return ReverseFlow)
   that would now be miscounted as forward? Enumerate them.
4. **Aging residual**: will forward-only counting alone satisfy
   `sum == N` for N long-lived pinned streams, or does the 650ms window
   still admit transient overshoot that breaks the invariant at scrape
   time?
5. **Asymmetry under MS key**: under the MS key, forward and reverse land
   on different workers. After the fix, the reverse-only worker contributes
   0 to the CoS count for that flow. Is that the desired semantics (count
   the flow once, on its forward worker) or does it under-count when the
   forward half is on a different egress interface/queue?
6. **Does anything else read `FlowCacheEntry.metadata.is_reverse`?**
   Confirm setting it true for reverse cache entries has no datapath
   side effect (TX, NAT, fabric).
