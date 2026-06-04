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

### Path 1 — PLAN-KILL

1. **N is tiny (measured peak = 14).** The scan is 14 × (one `& 0xfff` mask +
   two strided u64 loads + two compares). At N=14, a min-heap or incremental
   min-pointer is *slower or equal*: a binary heap pays pointer-chasing /
   non-contiguous loads and a sift-up/sift-down per push AND per pop (the
   head-finish key changes on every pop at pop.rs:163, so the heap key is
   mutated every dequeue → a decrease/increase-key + re-heapify every single
   pop, not amortized). The `FlowRrRing` is a flat `[u16; …]` — 14 contiguous
   u16s are one cache line; the strided u64 loads into the two big arrays are
   the only misses and a heap does not remove them (it still must read
   `flow_bucket_head_finish_bytes[b]` for the key). An incremental min-pointer
   is invalidated on every pop (the winning bucket's key advances, possibly
   making another bucket the new min) → it degenerates to a re-scan. At N=14
   the linear scan over a hot contiguous ring is at or near optimal.

2. **It touches the MQFQ selection key — the #1207/#1545/#915/#911 fairness
   trap.** `cos_queue_min_finish_bucket` *is* the exact-guarantee / vtime
   head-finish ordering. The #1755 plan already classified candidate #4 as
   fairness-sensitive and DEFER-not-bundle. Any structure that changes tie-break
   order, the `eligible`-vs-`fallback` (over-cap skip) two-pass semantics
   (mod.rs:114), or the head-key advance interaction (pop.rs:153-164) is a
   correctness regression on the equalizers shipped in #911/#915/#1743/#1745.
   The `fallback` second pass means a heap would need TWO keys (finish, and
   finish-among-eligible) — a single-key heap cannot reproduce the work-
   conserving over-cap fallback without a full second structure.

3. **4.28% self-time on a 6/6-saturated box, with N=14, gates behind a
   property-differential + CoV-neutrality smoke** for a structure that is
   provably not faster at the measured N. Cost/benefit and risk both say KILL.

Documented floor: at realistic load the min-finish scan is an O(14) hot
contiguous-ring scan whose only cache cost (two strided big-array loads per
bucket) is intrinsic to MQFQ selection and not removed by any alternative
structure. This is the floor on this hardware.

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

## 5. Why the residual is the floor

The remaining worker time is: driver RX (`mlx5e_xsk_skb_from_cqe_linear` +
`xp_raw_get_dma` + irq/poll_rx_cq ≈ inherent ~16% at 1.39 Mpps — not
addressable), the per-packet poll dispatch (`poll_binding_process_descriptor`
8.93% — our own per-packet work, not a clean lever), and the MQFQ
enqueue/dequeue (pop 4.28% over an O(14) scan that no structure beats). None of
these is a clean software lever on a 6/6 box. **16.6 Gb/s is the floor on this
hardware with this feature set.**

## 6. Alternatives considered (Path 1)

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

**PLAN-KILL on both paths.** Path 1: the O(N) min-finish scan runs at N≈14 (peak
14 measured under -P48), a regime where the contiguous-ring linear scan equals
or beats any heap/incremental structure, and the scan is the fairness-critical
MQFQ selection key (the #1207/#1545 trap). Path 2: the netlink/rtnl write fires
0/s at steady state — the 45 ops/s was a cold-start transient. 16.6 Gb/s on a
6/6-saturated box is the floor on this hardware. Do **not** `/engineer 1763`.
Optionally file a separate low-priority robustness issue for the missing per-key
dedup on the `stage_link_layer_classify` netlink write (ARP-flood hardening),
unrelated to throughput.

## 11. Reviewer verdicts

(Filled per round below.)
