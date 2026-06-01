# #1741 — CoS active-flow count over-counts (reverse-direction entries)

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

## Concrete design

### 1. Record the session direction on the cache entry

`FlowCacheEntry` already carries `metadata: SessionMetadata` whose
`is_reverse` field exists but is hardcoded `false` for cache entries.
Thread the real direction in.

`from_forward_decision` gains a parameter `flow_is_reverse: bool` and
stores it into `metadata.is_reverse` instead of the hardcoded `false`:

```rust
pub(super) fn from_forward_decision(
    ...,
    flow_is_reverse: bool,      // NEW
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
) -> Option<Self> {
    ...
    metadata: SessionMetadata {
        ...
        is_reverse: flow_is_reverse,   // was: false
        ...
    },
}
```

### 2. Thread direction from the session-hit at the call site

In `poll_descriptor/mod.rs`, a new mutable flag mirrors the existing
`flow_cache_owner_rg_id` / `apply_nat_on_fabric` flags:

```rust
let mut flow_cache_is_reverse = false;   // NEW, alongside :230-231
```

Set on the session-hit arm (where `resolved` is in scope, ~:293):

```rust
flow_cache_is_reverse = resolved.metadata.is_reverse;
```

The session-MISS arm creates the session from the first (forward) packet
and installs `ForwardFlow` (or `ReverseFlow` on specific cluster-return /
NAT64-reply seeds). For the miss path, default `false` is correct for the
normal new-forward-flow case. The explicit-reverse-install cases
(`is_reverse: true` at :1373, the `ReverseFlow` fabric-return at :465)
already set their own metadata; we mirror that into
`flow_cache_is_reverse` at each such arm so the cached entry reflects the
true direction.

Pass `flow_cache_is_reverse` to `from_forward_decision` at :1925.

### 3. Count forward-direction entries only in the CoS snapshot

In `active_flow_debug_entries` (flow_cache.rs), gate the `cos_counts`
increment on forward direction:

```rust
if !entry.metadata.is_reverse {
    if let Some(queue_id) = entry.descriptor.tx_selection.queue_id {
        let key = (entry.descriptor.egress_ifindex, queue_id);
        *cos_counts.entry(key).or_insert(0) += 1;
    }
}
```

`active` (the total active-flow count) and the bounded `rows` debug map
KEEP counting both directions — those are diagnostics and the flow-worker
map intentionally shows both halves (it exposes `forward_wire_key` AND
`reverse_canonical_key` per row for operator inspection). Only the
**CoS active-flow-count series that feeds the fairness gauges** is
restricted to forward-direction flows, because that series is defined as
"distinct flows per queue."

### Invariant

For N pinned forward iperf streams on one CoS queue, summed per-worker
`cos_active_flow_count == N` (was: up to 2N under symmetric hashing).
More generally: `sum(cos_active_flow_count for queue q) <=
live_forward_session_count_for_queue_q`.

## Public API preservation

- `from_forward_decision` gains one `bool` param (internal `pub(super)`;
  the only call site is poll_descriptor/mod.rs:1925). No protocol/gRPC
  schema change.
- `CoSActiveFlowCountStatus` wire/JSON shape unchanged.
- `active_flow_debug_entries` signature unchanged; only the internal
  cos_counts filter changes.
- No change to `count_active_flows` (test-only total) semantics.

## Hidden invariants preserved

- **Side-effect ordering**: no change — the filter is read-only over the
  same owner-only scan.
- **Allocation rules**: no new hot-path allocation; the change is a
  branch in an already-cold periodic scan and a stored bool in an
  existing struct field (zero size change — `is_reverse` already exists).
- **HA sync portability**: untouched. Flow cache is worker-local; HA sync
  uses the session table, not the flow cache.
- **Scheduling / datapath behavior**: UNCHANGED. `is_reverse` on a flow
  cache entry is consumed nowhere on the forward/TX path (verified: grep
  shows `metadata.is_reverse` on cache entries is currently dead — only
  the debug/CoS scan reads metadata). So this is telemetry-only; no
  failover/datapath behavior change → `make test-failover` not required.
- **Stale-handle hazards**: none; no handles added.
- **Borrow shape**: `entry.metadata.is_reverse` is read under the same
  `&FlowCacheEntry` borrow already held in the scan loop.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Telemetry-only; datapath untouched. `is_reverse` on cache entries is currently dead state. |
| Lifetime / borrow-checker | LOW | One extra bool param + one field read; no new borrows. |
| Performance regression | LOW | One bool branch in a cold periodic scan; param is register-passed at a single non-hot call site. |
| Architectural mismatch | LOW | Uses the existing `SessionMetadata.is_reverse` already on the struct; no new architecture. |

## Test plan

- `cargo build` clean.
- New unit test in `flow_cache_tests.rs`: insert one forward + one reverse
  entry for the same logical session (same queue_id, opposite tuples),
  both freshly hit; assert `active_flow_debug_entries` returns
  `cos_counts` summing to 1 for the queue (forward-only), while `active`
  (total) is 2 and the debug `rows` show both. Also assert N forward
  entries → cos count N.
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

- The ~650ms aging window second-order overshoot (the MS-key 62). If the
  forward-only filter does not fully eliminate transient overshoot under
  rapid flow churn, a follow-up could tie aging to session close; not
  needed for the N-pinned-stream invariant which uses long-lived flows.
- `cos_active_flow_counts_truncated` path (#1247) — confirmed 0, unrelated.
- Any change to the fairness verdict math itself (#1217 contract).

## Open questions for adversarial review

1. **Is the over-count correct-by-design?** Could the fairness contract
   intend to count bidirectional half-flows separately (i.e. is the
   "distinct flows per queue" definition actually "distinct cache entries
   per queue")? If so the FIX should instead be in the #1247 gauge
   derivation (divide by 2 / forward-only there), not the snapshot. Check
   `fairness_eval/verdict.rs` and `inputs.rs` semantics.
2. **Is `resolved.metadata.is_reverse` the right signal?** On a session
   hit, does `is_reverse` reliably mean "this packet is the reply
   direction of a session whose forward half is also (or could be) on
   this worker"? Are there sessions where BOTH installed entries are
   `is_reverse: false` (e.g. two forward installs), which would defeat the
   filter?
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
