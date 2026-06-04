# #1763 — Residual addressable CPU levers (post-#1753/#1755/#1760)

Research-only plan. Stops at PLAN-READY or PLAN-KILL. No production code is
touched here. Sub-path of #1752.

## 1. Problem statement

After #1753 (session in-place), #1755 (CoS probestack removal) and #1760
(collision counter) merged, a fresh profile on the loss userspace cluster shows
throughput 16.0 → 16.6 Gb/s with **all 6 cores 99-100% busy** — the 6/6
no-headroom ceiling (#1757). Mutex contention is already ruled out (workers
`futex_wait` 2×/10s; the only contended kernel lock is `rtnl_mutex`, off the
forwarding path). This research evaluates the two residual *addressable*
software levers the issue names, and is explicit up front that **PLAN-KILL on
both — documenting why the residual is the floor — is a valid and expected
outcome.**

- **Path 1 (primary):** `cos_queue_pop_front_inner_with_cap` → the O(N)
  `cos_queue_min_finish_bucket` linear scan over active flow buckets per
  dequeue (MQFQ head-finish selection). Reported ~3.84%, now the largest CoS
  sub-cost.
- **Path 2 (secondary):** neighbor-dispatch / `rtnl_mutex` netlink churn —
  `learn_dynamic_neighbor_from_packet` (0.36%) + `retry_pending_neigh` (0.19%),
  reportedly driving ~45 netlink/rtnl ops/s at steady state.

## 2. Code under study (master @ 4feab15ef)

### 2.1 Path 1 — the min-finish scan

`userspace-dp/src/afxdp/cos/queue_ops/mod.rs:101` `cos_queue_min_finish_bucket`:

```rust
for bucket in ff.flow_rr_buckets.iter() {
    let b = usize::from(bucket);
    let finish = ff.flow_bucket_head_finish_bytes[b];   // strided u64 load
    if finish < fallback_finish { fallback_finish = finish; fallback = Some(bucket); }
    let observed = ff.flow_bucket_observed_bps[b];       // 2nd strided u64 load
    if observed <= target_bps && finish < eligible_finish { ... }
}
eligible.or(fallback)
```

Called from `cos_queue_pop_front_inner_with_cap` (pop.rs:81), `cos_queue_front`
(mod.rs:136) and `cos_queue_front_with_cap` (mod.rs:158). The scan iterates the
active ring `flow_rr_buckets` (a `FlowRrRing`, `types/cos.rs:171`: fixed `[u16;
4096]` ring, O(1) push/pop, **O(len) `remove`**). Per dequeue the cost is the
scan (O(len)) PLUS, when a bucket drains to empty, `FlowRrRing::remove`
(types/cos.rs:286, another O(len) shift). Two strided loads per bucket from two
4096-entry `[u64; …]` arrays (`flow_bucket_head_finish_bytes`,
`flow_bucket_observed_bps`) — different cache lines, so each active bucket can
cost up to two L1/L2 misses on a cold working set.

This is the deferred candidate #4 from the #1755 plan (§2.3 / §3): "real,
~1.5-2%, touches the MQFQ **selection key**, fairness-sensitive, needs
property-differential + CoV-neutrality gate, do **not** bundle." It is the
#1207/#1545 trap one level up: any structure that changes *which* bucket wins
ties or perturbs the head-finish ordering is a fairness correctness regression.

### 2.2 Path 2 — neighbor netlink writes

`userspace-dp/src/afxdp/poll_stages.rs:72` `stage_link_layer_classify` calls
`add_kernel_neighbor` (neighbor.rs:214) on **every transiting ARP-Reply / NDP-NA
frame**, with NO per-key dedup or rate-limit (unlike the warmer's
`WARM_PER_KEY_RATE_LIMIT_NS = 5 s`). `add_kernel_neighbor` does
`socket(AF_NETLINK) + sendto(RTM_NEWNEIGH) + close()` (3 syscalls + a `vec!`
alloc) per call; `RTM_NEWNEIGH` is the `rtnl_mutex` acquisition.
`learn_dynamic_neighbor_from_packet` (neighbor_dispatch.rs:288) and
`learn_dynamic_neighbor` (:336) only mutate the **in-process** `ShardedNeighborMap`
(`with_all_shards`) — no syscalls. `retry_pending_neigh`
(neighbor_dispatch.rs:47) walks `binding.pending_neigh` post-poll; it is a no-op
early-return when the queue is empty (`:60`).

## 3. Live measurements (loss:xpf-userspace-fw0, primary, master @ 4feab15ef)

Environment: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env`. fw0 is
RG primary (forwarding-active). CoS loaded (`show class-of-service interface`
→ reth0.80, 12 exact iperf-* queues + best-effort). iperf3 from
`cluster-userspace-host` → 172.16.80.200.

### 3.1 Path 1 — active flow bucket count N (the decisive number)

`active_flow_buckets_peak` is a per-queue, owner-only, MAX-only,
lifetime-monotonic counter (`types/cos.rs:781`, only ever `peak = max(peak,
active)`; aggregated MAX across workers in coordinator/mod.rs:1143; reset only on
`FlowFairState` (re)alloc). Exact queues promote eagerly and stay promoted, so
their peak is a true lifetime maximum. Read live from
`/run/xpf/userspace-dp.json`.

| Run | Offered flows | Realized SUM | Peak `active_flow_buckets` (max over all exact queues) |
|-----|---------------|--------------|--------------------------------------------------------|
| iperf3 `-P48 -p5210` | 48 TCP | ~9.4 Gb/s | **14** |
| iperf3 `-P12 -p5210` | 12 TCP | ~6.2 Gb/s | **14** (lifetime max unchanged; ≤14 at -P12) |

**N peaks at 14 active flow buckets even under -P48.** The 48 offered TCP flows
never produce >14 concurrently-backlogged buckets: the per-class exact queue
drains faster than flows accumulate, so the instantaneous active set is small.
This is well below the per-flow-spread expectation in the counter's own contract
doc (`active_flow_buckets_peak >= N` for `-P N`); under a single exact class the
backlog set is the bottleneck, not the hash spread.

### 3.2 Path 1 — self-time

`perf report -i perf_p48.data --no-children` (worker threads 2000-2005, -F999,
20 s during -P48): `cos_queue_pop_front_inner_with_cap` = **4.28% self-time**
(matches the issue's ~3.84%; the inlined `cos_queue_min_finish_bucket` is the
dominant inner cost per #1755 §2.3 annotate). For reference,
`poll_binding_process_descriptor` = 8.93% (NOT addressable, our per-packet
dispatch). The `mlx5_crypto_dek_pool_remove_bulk` / `mlx5_crypto_modify_dek_key`
caller edges in the callgraph are the **known symbolization artifact** (broken
frame unwind under the BPF prog), not a real caller — self-times are the
trustworthy figures.

### 3.3 Path 2 — netlink / rtnl ops rate

bpftrace kprobes on `neigh_add` (the RTM_NEWNEIGH netlink handler — the
`rtnl_mutex` path) and `__neigh_update` (all neighbor-state updates):

| Window (under load) | `neigh_add` (RTM_NEWNEIGH netlink) | `__neigh_update` (all) |
|---------------------|------------------------------------|------------------------|
| 30 s steady -P12 | **0** | 56 (≈1.9/s, kernel-internal) |
| 20 s, 8× short reconnect churn | **0** | 49 (≈2.4/s) |

`add_kernel_neighbor`'s netlink write fires **0 times/s** at steady state and
even under connection churn — once a neighbor is resolved in the kernel table,
no further ARP-Reply/NDP-NA frames transit, so `stage_link_layer_classify` never
re-fires the netlink write. The `~45 ops/s` in the issue body was a **transient**
(cold-start ARP/NDP resolution burst), not a steady-state forwarding cost. The
`rtnl_mutex` contention `perf lock` saw (227 acq/5 s, 16.9 ms wait) is real but
is control-plane / cold-start, off the forwarding hot path, and does not recur
during the saturated transfer.

## 4. Disposition

### Path 1 — PLAN-READY (fused select+pop, NOT a heap)

**The data-structure framing is a KILL; the redundant-work framing is a
PLAN-READY win.** Round-1 hostile review (Codex + AGY + Claude SMR) converged:
replacing the scan with a heap/incremental-pointer/SoA structure is correctly
killed at N=14, but the scan **runs twice per successful dequeue** on both hot
paths and that redundancy is a safe, fairness-neutral lever.

**Why the heap idea is dead (KILL retained for that sub-option):** N peaks at 14
(§3.1). At N=14 a min-heap is no faster — the head-finish key mutates on every
pop (pop.rs:163), forcing a re-heapify per dequeue, and the `eligible`/`fallback`
two-pass (over-cap skip, mod.rs:114) cannot be a single-key heap. The
`FlowRrRing` is a flat `[u16; …]`; 14 contiguous u16s are one cache line. An
incremental min-pointer is invalidated on every pop (winning bucket's key
advances). Structure replacement: KILL.

**The actual lever — fuse the double scan (Codex/AGY/SMR-verified):** both hot
drain paths peek then pop with NO queue mutation between, so the second scan
re-derives the identical bucket:

- Cap-aware drain: `cos_queue_front_with_cap` (drain.rs:209, and Prepared :461)
  → inspect len/type/mirror_clone → `cos_queue_pop_front_with_cap` (drain.rs:234,
  :472) re-scans. `target_bps` is sampled once and constant for the batch
  (drain.rs:206-208) → same winner both times.
- No-cap best-effort builder: `cos_queue_front` (mod.rs:1605/1646) →
  `cos_queue_pop_front` (mod.rs:1617/1658) re-scans.

Each `front*`/`pop*` calls `cos_queue_min_finish_bucket` (mod.rs:81/136/158), so
the 4.28% pop self-time pays the scan **once for the peek and once for the pop**.

Two complementary, composable sub-levers, both **fairness-neutral by
construction** (they reuse the exact same scan result / skip provably-dead work;
they do not touch selection order, the head-key advance, the cap arithmetic, or
the eligible/fallback semantics):

- **Lever A — fused `peek_min_bucket` + `pop_known_bucket(bucket)`.** Peek
  returns the *bucket id*; the caller inspects `flow_bucket_items[bucket].front()`
  for len/type/budget/mirror gating; if it commits, `pop_known_bucket` pops that
  exact bucket with NO re-scan. Removes one full scan per committed pop. The
  abandon paths (drain.rs:217 budget break, :221 mirror reserve) stay at exactly
  1 scan (same as today) → strictly non-regressing. A `debug_assert` that the
  known bucket is still the active-front guards the no-mutation invariant.
- **Lever B — `target_bps == u64::MAX` no-cap fast path.** For every
  `cos_queue_front`/`cos_queue_pop_front` caller (the whole best-effort builder,
  mod.rs:1597-1658), `observed <= u64::MAX` is always true so `eligible ==
  fallback` always — the `flow_bucket_observed_bps` load (mod.rs:113) and the
  two-pass are dead. A no-cap branch that scans only
  `flow_bucket_head_finish_bytes` removes the second strided big-array load per
  bucket (the two arrays are on different cache lines), halving the per-bucket
  cache-miss exposure with zero ordering change.

Combined, a fused no-cap pop does ~1 single-array O(14) scan instead of 2
double-array O(14) scans on the best-effort path (up to ~3-4× less scan work);
the cap-aware path gets Lever A's ~2× on the scan. Realistic upside on the 4.28%
is meaningful and the change is fairness-neutral by construction.

**Risk gate (mandatory before merge):** property-differential test (fused vs
current produce byte-identical dequeue order on randomized backlogs incl.
over-cap mixes and equal-depth flows), CoV-neutrality on the full
v4/v6 × push/-R × CoS-on matrix, `make test-failover` (exact-queue HA sync), and
a live re-measure of pop self-time to confirm the win. This is a separate,
narrow PR — do NOT bundle with anything else.

### Path 2 — PLAN-KILL

`neigh_add` (the netlink/`rtnl_mutex` write) fires **0/s** at steady state and
under churn. `learn_*` (0.31%) and `retry_pending_neigh` (0.18%) are in-process
map / empty-queue-early-return work, not netlink. There is no steady-state
netlink churn to batch, cache, or rate-limit; the issue's 45 ops/s was a
cold-start transient. A latent hardening opportunity exists (the
`stage_link_layer_classify` netlink write at poll_stages.rs:92/113 has no
per-key dedup, unlike the warmer's 5 s rate-limit, so a pathological ARP-Reply
flood *could* storm `rtnl_mutex`), but it does not fire on the forwarding hot
path at steady state and is a robustness item, not a throughput lever. KILL for
throughput; note the dedup gap for a possible separate robustness issue.

## 5. Why the rest of the residual is the floor

After the Path 1 fused-scan win, the remaining worker time is: driver RX
(`mlx5e_xsk_skb_from_cqe_linear` + `xp_raw_get_dma` + irq/poll_rx_cq ≈ inherent
~16% at 1.39 Mpps — not addressable), the per-packet poll dispatch
(`poll_binding_process_descriptor` 8.93% — our own per-packet work, not a clean
lever), and the irreducible single min-finish scan (an O(14) selection that no
structure beats). Removing the *redundant* second scan is the one clean software
lever; the single scan itself, the RX path, and the poll dispatch are the floor
on this 6/6 box.

## 6. Alternatives considered (Path 1) — all structure-replacement options rejected; the chosen lever (§4) is redundant-scan removal, not any of these

- **Min-heap keyed by head-finish:** rejected — key mutates every pop →
  re-heapify per dequeue; cannot express the eligible/fallback two-pass; pointer
  chasing worse than a 14-entry contiguous scan.
- **Incremental min-pointer:** rejected — invalidated on every pop; degenerates
  to re-scan.
- **≤1-active-bucket short-circuit:** marginal — only helps when N≤1, but the
  hot regime is N≈14, and a `len()==1` branch adds a per-pop compare to the
  N≥2 common case for zero benefit there. Not worth a fairness-gated PR.
- **Two strided arrays → struct-of-arrays packing (one cache line per bucket):**
  the only *structurally* plausible micro-win (co-locate head_finish +
  observed_bps so one line serves both loads). Still touches the selection data
  layout, still fairness-gated, ≤~1% best case, and risks the 4096-entry array
  sizing / `CoSQueueRuntime` ~232 KB box. Not worth it on a 6/6 box. Recorded,
  not proposed.

## 7. Risks of acting anyway

Perturbing MQFQ selection ordering regresses the per-class exact guarantees and
the equal-flow / surplus-sharing equalizers (#911/#915/#1743/#1745) that took
many cycles to stabilize. The blast radius (every CoS dequeue, every HA-synced
exact queue) is large; the measured win is zero-to-negative at N=14.

## 8. Test / validation plan (if a lever had survived — it did not)

For the record, any Path 1 change would have required: property-differential
test (old vs new selection produces identical dequeue order on randomized
backlogs), a CoV-neutrality gate (per-flow CoV unchanged within noise on the
full v4/v6 × push/-R × CoS-on matrix), and `make test-failover` (touches HA
exact-queue sync). None run because both paths KILL.

## 9. Measurements appendix (raw)

- `active_flow_buckets_peak` peak = 14 (qid with iperf-* exact class) under -P48
  and -P12, read from `/run/xpf/userspace-dp.json` (monotonic lifetime max).
- `perf report` worker self-time: pop 4.28%, poll_descriptor 8.93%,
  account_enqueue 0.68%, push_back 0.55%, learn_dynamic_neighbor 0.31%,
  retry_pending_neigh 0.18%.
- `neigh_add` kprobe = 0 over 30 s steady + 20 s churn; `__neigh_update` ≈ 2/s
  (kernel-internal).
- Callgraph `mlx5_crypto_*` edges = symbolization artifact (validated against
  self-time + the #1755 cautionary note); not a real caller.

## 10. Recommendation

**Path 1: PLAN-READY. Path 2: PLAN-KILL.**

Path 1 — the *heap* idea is dead (N=14 measured under -P48; a heap is no faster
and the selection key is the #1207/#1545 fairness trap), but the min-finish scan
**runs twice per dequeue** on both hot paths (peek then pop, no mutation
between). Fusing them (Lever A: `peek_min_bucket` + `pop_known_bucket`) plus a
`target_bps == u64::MAX` no-cap fast path (Lever B: skip the dead
`observed_bps` load + fallback pass) removes the redundant scan / dead load,
fairness-neutral by construction, up to ~3-4× less scan work on the best-effort
path against the 4.28% pop self-time. **`/engineer 1763` is warranted for this
narrow, gated refactor.** Do NOT replace the data structure with a heap.

Path 2 — KILL. The netlink/rtnl `neigh_add` write fires **0/s** at steady state
and under churn (measured); the issue's 45 ops/s was a cold-start ARP/NDP
transient. No steady-state churn to batch. Separately, file a low-priority
robustness issue for the missing per-key dedup on the `stage_link_layer_classify`
netlink write (poll_stages.rs:92/113, ARP-flood hardening) — unrelated to
throughput.

Measured active-bucket N (Path 1): **14** (peak under iperf3 -P48, exact queue).

## 11. Reviewer verdicts

### Round 1 (against v1, which had killed both paths)

All three reviewers KILLED the v1 Path-1 KILL and confirmed Path-2 KILL.

- **Codex (foreground, task this session):** "PLAN-KILL-THE-KILL. Path 2 KILL
  stands, but Path 1 KILL is defective. The plan argues heap vs linear scan, but
  misses a safer lever: the hot drain paths do the same min-finish selection
  twice, back-to-back, before one pop." Quoted the front+pop pairs at
  drain.rs:209/234, drain.rs:461/472, mod.rs:1605/1617. "A fused
  select/check/pop helper can preserve the exact MQFQ key and tie behavior while
  removing one full scan per successful pop. No heap, no new ordering, no
  eligible/fallback semantic change." Confirmed N=14 not undercut by #1735
  (exact queues return before demotion at mod.rs:223). Confirmed `neigh_add` is
  the correct RTM_NEWNEIGH kprobe (neighbour.c:3916 registration, RTNL assert).

- **AGY (background adversarial-review-mpz0f3xy-diho0y):** PLAN-KILL-THE-KILL.
  Confirmed Path 2 KILL and the `neigh_add` kprobe. For Path 1 proposed a
  complementary lever: split a `target_bps == u64::MAX` no-cap fast path that
  loads only `flow_bucket_head_finish_bytes` and skips `flow_bucket_observed_bps`
  + the eligible/fallback pass — "reducing memory loads and cache-line misses by
  50% per active bucket… does not alter selection priority or equal-share
  ordering… no data-structure layout changes." Confirmed exact queues never
  demote/reset peak.

- **Claude SMR (claude-smr-plan-r1.md):** PLAN-NEEDS-WORK. v1 evaluated only
  data-structure replacement and never asked how many times the scan runs per
  pop — it runs twice on both hot paths. Endorsed both Lever A (fuse) and Lever
  B (no-cap fast path) as complementary and composable, fairness-neutral by
  construction; required property-differential + CoV-neutrality + test-failover
  gates and a non-regression contract for the peek-then-abandon paths.

**Convergence:** 3/3 → Path 1 PLAN-READY (fused select+pop + no-cap fast path,
NOT a heap), Path 2 PLAN-KILL. v2 incorporates both levers and the gates.
