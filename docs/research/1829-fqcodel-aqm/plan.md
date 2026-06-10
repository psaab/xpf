# #1829 — CoS FQ-CoDel dequeue-time AQM for shaped queues (+ #1828 engine boundary)

## 1. Status

DRAFT v1 — pending adversarial plan review (Claude SMR + Codex + AGY, /research mode).

Research-only. No production code on this branch. Base: master `d30cfab84`.

## 2. Issue framing

**#1829** is deferred item (f) from the #1731 CoS fresh-look review: `codel_target_ns`
is plumbed end-to-end on the wire but enforced nowhere — there is no sojourn
computation and no dequeue-time AQM in `userspace-dp/src`. Its stated blocker
(#1735, generalize MQFQ per-flow buckets to all shaped queues) merged via PR #1740,
so the per-flow queueing substrate FQ-CoDel needs now exists. The ask: dequeue-time
sojourn AQM (CoDel control law) on the per-flow MQFQ buckets.

**#1828** asks where WAN "smart queueing" (fq_codel/CAKE-style egress AQM on
uplinks) should live: kernel qdisc via tc/networkd on the uplink, or the userspace
CoS path. Section 4 answers this decisively from AF_XDP TX semantics; the verdict
constrains #1828 to build on this issue's engine.

### Verified current state (all against `d30cfab84`)

`codel_target_ns` wire plumbing, end to end, **write-only**:

| Stage | Location |
|---|---|
| Junos config `set class-of-service schedulers <s> codel-target <ms>` | `pkg/config/compiler_class_of_service.go:254-261` (ms → ns) |
| Typed config | `pkg/config/types_cos.go:90-96` (`CodelTargetNS`, "0 disables") |
| Go→helper wire | `pkg/dataplane/userspace/protocol.go:236-242`, `cos.go:140` |
| Rust wire | `userspace-dp/src/protocol/cos.rs:118-119` |
| Build into runtime | `userspace-dp/src/afxdp/forwarding_build/cos.rs:317-318` |
| Runtime structs | `userspace-dp/src/afxdp/types/cos.rs:108` (build config), `:696` (queue runtime config) |

`grep -rn codel userspace-dp/src --include='*.rs'` shows **zero reads** of the
runtime field outside construction. There is no `codel-interval` knob; only target.

No per-packet enqueue timestamp exists anywhere in the TX path: `TxRequest` /
`PreparedTxRequest` (`afxdp/types/tx.rs:12,79`) and `CoSPendingTxItem`
(`afxdp/types/cos.rs:1276`, a 2-variant enum wrapping those structs) carry none.
Any sojourn AQM must add one — that is the main structural cost of this issue.

## 3. Honest scope/value framing

**What already exists is more AQM than the issue title implies.** The admission
path is not a dumb tail-drop FIFO:

1. **Per-flow share caps** (`cos_queue_flow_share_limit`, admission.rs:124) —
   BDP-aware on shared_exact (#914): `max(fair_share×2, bdp_floor).clamp(24KB,
   buffer_limit)`.
2. **Aggregate delay clamp** (`cos_flow_aware_buffer_limit`, admission.rs:218) —
   flow-fair queues are capped at `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS = 5 ms` of
   queueing **at the configured rate** (admission.rs:44).
3. **ECN CE marking at admission** (`apply_cos_admission_ecn_policy`,
   admission.rs:276) — depth-threshold (1/3 of share cap or buffer limit,
   per-flow arm on owner-local-exact, aggregate arm on shared_exact/FIFO),
   live-tuned across #728/#754.
4. **MQFQ per-flow dequeue ordering** on all shaped queues post-#1735 — the
   "FQ" half of FQ-CoDel is already shipped. Mice do not wait behind elephants
   *in scheduling order*.

So the honest question is: **what does the CoDel half add on top?** Three things,
all real but narrow:

- **Time-domain correctness when actual drain rate < configured rate.** The 5 ms
  clamp and the BDP floors are denominated in *bytes at configured rate*. In the
  surplus/residual regime, under V_min throttling, or when several queues contend
  for the same physical line, a queue's *actual* service rate is below configured —
  the byte-denominated bound then under-bounds real delay. Sojourn measured at
  dequeue is actual-rate-aware by construction. This is not hypothetical:
  **#1359** (OPEN) shows the 100E100M matrix passing the p99.9 mouse-latency gate
  under strict-exact but **failing under surplus-sharing** — exactly the regime
  where byte-denominated admission bounds decouple from time. p99.9 even in the
  passing exact run is ~7 ms loaded (~6.9 ms idle); the failing surplus runs blow
  the 2× ratio gate. **#1365** (OPEN) shows high-rate classes can't even settle.
  These are the motivating measurements.
- **Burst-tolerant standing-queue discrimination.** Admission ECN fires on
  instantaneous depth; CoDel's interval logic (only act when the *minimum*
  sojourn over a 100 ms window exceeds target) ignores transient bursts and
  targets only the standing queue. The #754 history (1/5 threshold over-marked a
  single low-rate flow into bimodal stalls, retuned to 1/3) is precisely the
  failure mode CoDel's interval filter is designed to avoid.
- **Head signaling.** Admission marks the *arriving* (tail) packet; the receiver
  sees the signal one full queue-sojourn later. CoDel marks/drops at the *head*,
  so the congestion signal reaches the receiver one sojourn earlier — at 5 ms
  standing delay that is a 5 ms faster control loop per signal.

**What it does NOT add:** the smoke lab's shaped classes already hit their shapes
cleanly with ECN marks and zero buffer drops in the strict-exact regime
(`docs/cos-validation-notes.md` — e.g. 16.5 M ECN marks, drops attributable to
known causes). CoDel will not move strict-exact single-class throughput or
fairness numbers; if it does, that is a regression. The win is bounded to
p99.x latency in the surplus/contended regimes and to operator-visible delay
telemetry.

**Cycle cost at absolute scale:** Phase 1 (telemetry) is ~3-5 ns per dequeued
packet (one u64 subtract + EWMA shift-add + max, on data already in cache) and
8 B per queued item. Phase 2 (control law) adds ~2-4 ns on the common
below-target path (one compare + one rarely-taken branch). No allocation, no
atomics, no new syscalls (clock is the existing per-poll-tick `loop_now_ns`).

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* Additionally, this plan is **structured
to invite a partial kill**: Phase 2 is gated on Phase 1 sojourn evidence — if
live telemetry shows shaped queues never sustain standing sojourn above target
in any regime we care about (including surplus-sharing under #1359's workload),
Phase 2 dies and Phase 1 remains as operator delay-visibility telemetry.

## 4. #1828 engine boundary — kernel qdisc is a NO-OP for forwarded traffic (decisive)

**Claim:** attaching fq_codel or CAKE to the WAN uplink via tc/networkd would
shape essentially none of the traffic #1828 cares about, because the dataplane's
TX path bypasses the kernel qdisc layer entirely in both AF_XDP modes.

**Evidence:**

1. **How this project transmits.** All forwarded traffic leaves via the AF_XDP
   socket TX ring: descriptors are written to the XSK TX ring and the kernel is
   kicked with `sendto(fd, NULL, 0, MSG_DONTWAIT)` when `needs_wakeup` is set
   (`userspace-dp/src/afxdp/tx/rings.rs:143-260`, `worker/xsk_rings.rs:14`).
   Bind mode is zero-copy with copy fallback (`XskBindMode::{Copy,ZeroCopy}`,
   `worker/mod.rs:196-216`; `umem/snapshot.rs:34`). The mlx5 VFs on the loss
   userspace cluster run zero-copy (the smoke target's "AF_XDP zero-copy fast
   path" per the cluster docs).
2. **Zero-copy TX semantics (kernel).** In ZC mode the driver consumes
   descriptors directly from the XSK TX ring (`ndo_xsk_wakeup` →
   driver ZC TX poll). No skb is built; `dev_queue_xmit()` — the only entry
   point into the qdisc layer (`__dev_xmit_skb`) — is never invoked. There is
   structurally no hook where a root qdisc could see these frames.
3. **Copy-mode TX semantics (kernel).** `xsk_generic_xmit()` (net/xdp/xsk.c)
   builds skbs and transmits them via `__dev_direct_xmit()` (net/core/dev.c),
   which is the *explicitly qdisc-bypassing* transmit path — it calls the
   driver's `ndo_start_xmit` on the selected TX queue directly. So even the
   copy-mode fallback never traverses fq_codel/CAKE.
4. **What WOULD traverse a kernel qdisc on the uplink:** only kernel-stack-
   originated traffic — VRRP adverts (Go control plane, AF_PACKET), FRR/BGP,
   DHCP, host ICMP, the Rust helper's kernel neighbor probes
   (`afxdp/neighbor.rs`). Control-plane kilobits; shaping them is pointless and
   risks delaying VRRP (30 ms advert interval, ~97 ms master-down — a
   badly-tuned shaper on the uplink could plausibly *cause* failovers).

**Verdict for #1828:** kernel fq_codel/CAKE on uplinks is a no-op for forwarded
traffic and a hazard for control traffic. WAN smart queueing MUST be built on
the userspace CoS path — i.e., on this issue's engine: the existing token-bucket
shaper (set to uplink rate minus headroom, the standard SQM pattern) + MQFQ
per-flow scheduling (already shipped, #1735) + the FQ-CoDel sojourn AQM proposed
here. That combination is functionally the fq_codel side of SQM; CAKE's extras
(per-host isolation, DiffServ tiers, ack-filter) map respectively to: possible
future flow_hash keying option, already-existing forwarding-classes/schedulers,
and out of scope. The only alternative placement is shaping at a different hop
(upstream CPE), which is outside xpf.

Recommended disposition for #1828 after this research: keep it open as the
**config-surface/UX issue** ("one-liner WAN smart-queue convenience on top of
CoS"), dependent on #1829; or fold it into #1829's Phase 3 if the maintainer
prefers one tracking surface. It must not proceed as a tc/networkd feature.

## 5. What's already shipped / partially batched (composition constraints)

- **#1735 / PR #1740** — flow-fair MQFQ on ALL shaped queues: eager promotion on
  exact, lazy promotion on non-exact via the hash-free front-key probe
  (`queue_ops/push.rs:43`), demotion with hysteresis
  (`maybe_demote_drained_best_effort`, `queue_ops/mod.rs:310`). CoDel state must
  survive (or be correctly reset by) promote/demote cycles.
- **#1763 / PR #1764** — fused select+pop: ALL production dequeues go through
  `cos_queue_peek_min_bucket` + `cos_queue_pop_known_bucket` with a
  **no-mutation-between-peek-and-pop invariant** (debug_assert re-scan in dev).
  4 fused peek+pop pairs: `queue_service/mod.rs:1610/1622, 1653/1665` (non-exact
  Local/Prepared), `queue_service/drain.rs:217/241, 472/483` (exact Local/
  Prepared flow-fair — also reached via `queue_service/service.rs:226,573`);
  plus the FIFO index-walk drains
  (`drain_exact_*_fifo_items_to_scratch`) which build scratch without popping
  and settle later. The AQM check must not reintroduce the double-scan #1763
  removed and must not mutate the queue between peek and pop.
- **#913/#1355 pop-snapshot rollback** — popped items can be `push_front`ed back
  on TX-ring-full (LIFO snapshots, `pop_snapshot_stack`). Existing drop sites
  (frame-capacity, slice-range) already handle "pop then drop" via
  `cos_queue_clear_orphan_snapshot_after_drop` — the exact machinery a CoDel
  head-drop needs; precedent is in `queue_service/drain.rs:236,266,505`.
- **Admission ECN + caps** (section 3) — CoDel must compose, not double-signal.
  Note admission ECN on owner-local-exact uses the per-flow arm; shared_exact
  uses the aggregate arm specifically because MQFQ already penalizes hot flows
  and double-signaling collapsed cwnd twice (admission.rs:335-353). The same
  argument constrains how aggressively CoDel may mark on top.
- **#1734 PLAN-KILL** — the per-poll-tick frozen `now_ns` is settled as fine at
  batch timescales (µs); ms-scale sojourn measurement is comfortably inside that
  resolution. CoDel must use the existing `loop_now_ns`/`ctx.now_ns` plumbing
  (`worker/loop_body/mod.rs:158`, `tx/drain/mod.rs:24,87`) — **no new
  `clock_gettime` on the hot path**, and no mid-pass clock advance (that was the
  #1734 kill: mid-pass advance peer-skews v8 epoch rotation).
- **ECN markers exist and are dequeue-compatible** — `mark_ecn_ce_ipv4/_ipv6` +
  `maybe_mark_ecn_ce{,_prepared}` (`cos/ecn.rs:98,152,179,216`) mutate Local
  bytes or UMEM frames in place (incremental checksum). The Prepared variant
  needs `&MmapArea`, which every drain call site already holds.
- **#1614 A3** — introduced the wire field with the explicit note "userspace
  enforcement deferred to a focused follow-up" (protocol.go:236). This is that
  follow-up.

## 6. Concrete design

### Phase 1 — sojourn instrumentation (measurement-first; ships alone)

**1a. Per-item enqueue timestamp.** Two carrier options (Open Question Q1):

- **Option A (preferred): `enqueue_ns: u64` field on `TxRequest` AND
  `PreparedTxRequest`.** Set in `enqueue_cos_item` (tx/cos_classify.rs:809)
  from a threaded `now_ns`; zero for non-CoS uses. +8 B on structs of ~96/64 B
  where the dominant cost (Local) is already the heap `Vec<u8>`. Compiler
  enforces initialization at every construction site (mechanical churn,
  ~15-25 sites). Preserved automatically across `into_prepared_request` /
  `to_local_request` conversions and across pop→push_front rollback (re-queued
  retry items keep their ORIGINAL enqueue time — correct for sojourn).
- **Option B: wrap the deque element** (`struct CoSQueuedItem { item:
  CoSPendingTxItem, enqueue_ns: u64 }`). Cleaner layering (CoS-only cost) but
  churns every `flow_bucket_items`/`hot.items` touch point — push/pop/peek/
  drain/migrate/snapshot, dozens of sites including the #1735 promote
  migration. Higher regression surface for the same 8 B.

**1b. `now_ns` threading.** Enqueue: callers of `enqueue_local_into_cos` /
`enqueue_prepared_into_cos` already have `ctx.now_ns` (tx/drain/mod.rs) or the
poll-path `now_ns` (poll_descriptor/mod.rs threads it through the RX path).
Dequeue: thread `now_ns` from `drain_shaped_tx(binding, now_ns, ..)` down into
the drain/service helpers (2-3 signature levels; mechanical). No new clock
reads; same tick value for the whole pass per #1734.

**1c. Telemetry.** Per-queue, in `CoSQueueTelemetry` alongside
`drop_counters` (types/cos.rs:1080): `sojourn_ewma_ns` (shift-add EWMA, α=1/8,
updated per pop), `sojourn_peak_ns` (lifetime max, same contract as
`active_flow_buckets_peak`). Computed at the dequeue commit (the fused-pop
sites). Surfaced through the existing CoS status snapshot →
`protocol/cos.rs` → `show class-of-service interface` + Prometheus, exactly
like `admission_ecn_marked` (protocol/cos.rs:253). Update is owner-only,
non-atomic, allocation-free.

**1d. Gate evidence.** Re-run the #1359 100E100M surplus-sharing matrix and the
standard per-class sweep with Phase 1 deployed; capture per-queue sojourn EWMA/
peak per regime. **Kill criterion for Phase 2:** if no shaped queue sustains
sojourn above `codel-target` (default candidate 5 ms) for ≥ one interval
(100 ms) in any regime including surplus-sharing, Phase 2 is PLAN-KILLED and
#1829 closes with Phase 1 as the deliverable.

### Phase 2 — CoDel control law at dequeue (gated on 1d)

**2a. State placement (hybrid, mirrors the #1735 promote/demote split):**

- **FIFO (unpromoted) queues**: one `CodelState` inline in `CoSQueueHotState` —
  a FIFO queue is single-flow by the #1735 probe invariant, so per-queue state
  IS per-flow state. ~32 B.
- **Flow-fair (promoted) queues**: per-bucket parallel arrays in
  `FlowFairState`, sized `COS_FLOW_FAIR_BUCKETS = 4096`, allocated only when
  `codel_target_ns > 0` (an `Option<Box<CodelBucketState>>` so queues without
  the knob pay nothing):
  `first_above_ns: [u64; 4096]`, `drop_next_ns: [u64; 4096]`,
  `count: [u16; 4096]`, `lastcount: [u16; 4096]`, `dropping: [bit; 4096]`
  ≈ 84 KB. Initialized via the #1755 `new_boxed`-style heap construction
  (never on the stack); zeroed (POD) so `MaybeUninit` init is trivial. State
  resets on demote (whole box dropped) — correct, since the queue is fully
  drained at demote by definition.

Per-queue-only state (rejected): with mixed flows, one elephant's standing
delay would put the shared state into dropping mode and the control law would
hit whichever bucket happens to be at the min-finish head — including mice.
FQ-CoDel's whole point is per-flow CoDel state; we have the bucket structure,
use it. Collisions at 4096 buckets are the same risk MQFQ already accepts
(#1731 finding 6, telemetry tracked under #1830).

**2b. The check (O(1), allocation-free, at the fused-pop boundary).** A single
helper, called at each of the 4 fused peek+pop pairs and the FIFO drains, AFTER
peek and BEFORE the commit decision:

```rust
enum CodelVerdict { Transmit, MarkAndTransmit, DropHead }

#[inline]
fn cos_codel_check(
    target_ns: u64,        // queue.config.codel_target_ns (0 = disabled)
    interval_ns: u64,      // hardcoded 100ms const, Phase 3 knob if needed
    st: &mut CodelState,   // per-bucket slot or FIFO per-queue state
    sojourn_ns: u64,       // now_ns - item.enqueue_ns (saturating)
    now_ns: u64,
) -> CodelVerdict
```

Standard CoDel (RFC 8289) with the standard `count` reuse on re-entry and
`interval/sqrt(count)` spacing via the incremental Newton step (no f64 sqrt on
the hot path — use the classic `rec_inv_sqrt` u32 fixed-point recurrence from
the reference implementation). Disabled (`target_ns == 0`, today's only
shipped value) short-circuits to `Transmit` on the first compare — one
predictable branch, preserving current behavior exactly.

**2c. Verdict handling per call site:**

- `Transmit` — unchanged path.
- `MarkAndTransmit` — for ECT packets: pop via the already-peeked bucket
  (`cos_queue_pop_known_bucket`, no re-scan), apply
  `maybe_mark_ecn_ce{,_prepared}` to the popped item (Local bytes / UMEM frame —
  both available at every site), bump `codel_ce_marked`, transmit. **ECN-mark is
  the preferred signal** — the lab smoke's shaped-class pass criteria are built
  on ECN with zero buffer drops, and Junos-parity AQM (RED) on this project has
  always preferred marking. Per RFC 8289 §4.1 we still fall through to DropHead
  while in dropping mode if marking shows no effect — Phase 2 keeps it simple:
  mark ECT, drop non-ECT, identical control law.
- `DropHead` — for non-ECT packets: pop the peeked bucket, recycle (Prepared:
  `recycle_cancelled_prepared_offset_with_shared`; Local: drop the Vec),
  `cos_queue_clear_orphan_snapshot_after_drop`, bump `codel_dropped` +
  `dropped_bytes` accounting like the existing capacity-drop sites, then
  **continue the drain loop** (re-peek is the next loop iteration's normal
  work — NOT a reintroduced double-scan; CoDel drops are rare by design,
  ~once per interval/sqrt(count)). MQFQ "drops consume virtual service"
  semantics already hold on this path (pop advanced vtime).

This placement keeps the #1763 invariant intact: peek → (codel decision, no
queue mutation) → pop-known-bucket → mutate. The debug_assert re-scan still
validates every pop.

**2d. Head-drop vs the drop-newest style rule.** `docs/engineering-style.md`
("Drop policy on full: drop-newest") targets queue-FULL eviction, where
head-drop wastes near-service work. CoDel head-drop is the opposite case: a
deliberate congestion signal whose value is precisely that the head is the
oldest (largest-sojourn) packet and its loss is detected soonest. The rule
itself says "unless there's a specific reason otherwise, and document the
rationale at the drop site" — this is that documented exception, and ECN-mark
(no drop at all) is the dominant path in this ECT-heavy lab.

**2e. Defaults and the RTT question.** Cluster RTT is 5-7 ms post-shaper
(admission.rs:94, project memory). Standard CoDel defaults (target 5 ms,
interval 100 ms) fit: target matches the existing
`COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS` envelope, interval ≥ worst RTT with margin.
`codel-target` stays operator-set per scheduler (existing knob, 0 = off —
**default remains off**; no behavior change without explicit config).
Interval: hardcoded 100 ms const with a compile-time assert `interval >
target`; a config knob only if live evidence demands it (Phase 3).

### Phase 3 (follow-up issues, not this plan)

- #1828 config-surface: WAN smart-queue convenience (shaper at uplink-rate
  minus headroom + codel-target on the WAN schedulers) — pure pkg/config sugar.
- `codel-interval` knob, per-host (CAKE-style) keying — only on evidence.

## 7. Public API preservation

- All `cos_queue_*` queue-ops signatures preserved except mechanical `now_ns`
  threading additions on drain/service helpers (internal `pub(in crate::afxdp)`
  surface, not a public API).
- Wire protocol: `codel_target_ns` field already exists both sides (no wire
  change for Phase 2). Phase 1 adds **new optional status fields** (sojourn
  EWMA/peak; later codel_ce_marked/codel_dropped) — additive, `#[serde(default)]`
  both sides, old/new mixed-version safe (same pattern as every prior counter
  addition; both-sides grep per `feedback_wire_protocol_both_sides` mandatory).
- Junos config grammar: unchanged (knob exists). `show class-of-service
  interface` gains lines; no existing output removed.
- Go control plane: no RPC changes; Prometheus adds gauges/counters.

## 8. Hidden invariants the change must preserve

1. **#1763 fused-pop no-mutation invariant** — codel check sits strictly between
   peek and pop and must not mutate bucket structures (CoDel state arrays are
   disjoint from MQFQ ordering state; the debug_assert re-scan keeps honest).
2. **Snapshot-stack contract** (#913/#1355) — every CoDel head-drop must run
   `cos_queue_clear_orphan_snapshot_after_drop` (existing helper handles vtime
   clamping for survivor restores). A missed cleanup = release-mode panic on the
   next push_front (pop.rs:307 `assert!(false)`).
3. **Rollback timestamp semantics** — pushed-back retry items keep original
   `enqueue_ns` (option A gives this for free); re-evaluation on re-pop may
   re-mark — idempotent (CE is sticky) and semantically correct.
4. **#1735 promote/demote** — promotion migration re-enqueues resident items
   through `cos_queue_push_back`; items carry their timestamp, nothing to do.
   Demote drops CoDel state with the FlowFairState box; by the demote
   quiescence predicate the queue is empty, so state reset is sound.
5. **Hot-path allocation rule** — zero allocations per packet: CoDel state is
   pre-allocated at promote/build; telemetry is plain u64 fields; the check is
   arithmetic only.
6. **No mid-pass clock advance** (#1734 kill rationale) — all sojourn math uses
   the pass's single `now_ns`; never call `monotonic_nanos()` inside drain loops.
7. **v8 lease / V_min coordination** — CoDel drops go through the normal pop
   path, so per-worker active-flow mirrors and vtime publication are untouched.
8. **HA session sync** — unaffected (CoS queues are per-worker TX-side state,
   never synced).
9. **Admission ECN composition** — Phase 2 must not stack a second *depth*
   signal: CoDel's is time-domain and interval-filtered, but the smoke gate
   (sec. 10) must verify no cwnd double-collapse on shared_exact classes
   (the #784 bimodal regression signature: winners/losers split + retrans
   spike).
10. **`enqueue_ns = 0` legacy/non-CoS items** — sojourn `saturating_sub` on a
    zero timestamp yields a huge value; the check must treat `enqueue_ns == 0`
    as "no data → Transmit" (one extra predictable compare), so non-CoS or
    pre-upgrade items can never be spuriously dropped.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Phase 1: LOW (telemetry only, +8 B/item). Phase 2: default-off knob; risk concentrated in drop-path accounting (snapshot cleanup, recycle) — all reusing existing tested drop machinery; and in mis-tuned target collapsing cwnd (mitigated: ECN-first, default off, #754-style live tuning loop). |
| Lifetime / borrow-checker | **LOW-MED** | The codel-state borrow must coexist with the `&CoSPendingTxItem` peek borrow (immutable) before the `&mut` pop — same pattern #1763 already navigates; per-bucket arrays are disjoint fields of FlowFairState. Option B (wrapper struct) would raise this to MED-HIGH; Option A keeps it low. |
| Performance regression | **LOW** | ~3-5 ns/pop Phase 1, +2-4 ns Phase 2 common path; no alloc/atomic/syscall. Gate: per-class sweep throughput unchanged ±noise, pop self-time via the #1763 measurement harness. +8 B per TxRequest/PreparedTxRequest (cache-line layout check at review). +84 KB per promoted queue ONLY when codel-target configured. |
| Architectural mismatch | **LOW** | Intra-queue, within-worker — explicitly the side of the line #1731 cleared (no cross-worker AF_XDP physics). The FQ substrate exists (#1735); CoDel is the textbook companion. The one mismatch risk is *value* (already-sufficient admission AQM) — addressed by the Phase 1 evidence gate, not by argument. |

## 10. Test plan

- **Unit (Rust):** CoDel control-law vector tests (sojourn sequences →
  verdict sequences, RFC 8289 reference traces incl. count-reuse on re-entry);
  `enqueue_ns == 0` guard; per-bucket state independence (elephant in dropping
  state, mouse bucket unaffected); drop-path differential test in the
  `fused_diff_tests.rs` style proving queue bookkeeping (vtime, active set,
  queued_bytes, local_item_count, snapshot stack) after a CoDel drop is
  byte-identical to the existing capacity-drop path; promote/demote state
  lifecycle; rollback (pop→mark→push_front→re-pop) idempotence.
- **Build/test suites:** `cargo build` clean, full cargo test (1000+),
  `cargo +nightly miri` for the new boxed-state constructor, 30 Go packages,
  `make audit-check`.
- **Smoke (loss userspace cluster, serialized per smoke-runner rules):**
  v4+v6 line-rate; per-class CoS sweep 5201-5211 with codel-target UNSET
  (verifies default-off no-op — counters all zero, throughput/CoV unchanged);
  then codel-target 5 on one 1 Gbps class: shape held, `codel_ce_marked > 0`
  under -P 12, `codel_dropped == 0` for ECT iperf3, no #784 bimodal signature.
- **The decisive measurement:** #1359 100E100M surplus-sharing mouse-latency
  matrix, before/after Phase 2 on the same build — the gate is the p99.9
  loaded/idle ratio moving toward the ≤2.0 pass line without throughput loss.
  (Phase 1's sojourn telemetry is itself the instrument for attributing any
  residual failure.)
- **Failover:** not cluster/VRRP-touching, but the standard 13-stream failover
  smoke runs anyway per deploy gate.

## 11. Out of scope (explicitly)

- #1828 config-surface work (one-liner WAN SQM convenience) — follow-up on
  this engine; recommendation in §4.
- `codel-interval` config knob; per-host/CAKE-style isolation keying;
  ack-filtering; DiffServ remapping (exists already as forwarding-classes).
- Admission-path changes — the existing caps/ECN thresholds are untouched.
- #1830 (bucket-vs-flow collision telemetry, >32-worker scratch) — sibling.
- Kernel qdisc integration of any kind (ruled out in §4).
- Cross-worker anything (#1211/#937/#1693 wall).

## 12. Open questions for adversarial review

1. **Q1 (carrier):** Option A (+8 B on TxRequest/PreparedTxRequest, set only on
   CoS enqueue) vs Option B (CoS-local wrapper). Is there a construction site
   where `now_ns` is genuinely unavailable for Option A, or a cache-line layout
   regression (PreparedTxRequest packing) that flips the answer? PLAN-KILL the
   phase if neither carrier is acceptably cheap.
2. **Q2 (value):** Given admission already bounds flow-fair queues to ~5 ms at
   configured rate and ECN-marks at 1/3 cap, is the surplus-regime
   time-vs-bytes decoupling argument (§3, #1359) strong enough to justify a
   second AQM? If reviewers believe #1359's surplus failure is attributable to
   scheduling (phase-2 surplus admission, #1743 lineage) rather than standing
   queues, Phase 2 should be killed and only Phase 1 (instrumentation that
   would settle exactly this question) survives. **Invited kill.**
3. **Q3 (state):** per-bucket CoDel arrays (84 KB per configured promoted
   queue) vs a smaller open-addressed table over the ACTIVE bucket set
   (typically 2-16). Is the 84 KB straight-line array worth the simplicity, or
   does it blow the FlowFairState footprint budget post-#1755?
4. **Q4 (signal policy):** mark-ECT/drop-nonECT with one shared control law —
   or should dropping mode escalate to drops even for ECT (RFC 8289 §4.1
   "unresponsive flow" clause)? Phase 2 proposes the simple form; is that
   defensible against an unresponsive-ECT-flow adversary, given the per-flow
   share caps already bound such a flow's buffer?
5. **Q5 (placement):** is the fused-peek boundary the right single choke point,
   or should the check live inside `cos_queue_pop_known_bucket_inner` (one site,
   but verdict-before-pop becomes verdict-after-pop, forcing un-pop or
   drop-after-pop semantics)? The per-call-site helper form is proposed;
   challenge it.
6. **Q6 (FIFO drains):** the exact-FIFO index-walk drains
   (`drain_exact_*_fifo_items_to_scratch`) select items without popping and
   settle later — measuring sojourn at scratch-build vs at settle differs by
   one TX commit. Is scratch-build-time measurement (proposed) correct, and is
   the FIFO path even worth CoDel given #1735 promotes any 2-flow queue?
7. **Q7 (#1828):** is the §4 qdisc-bypass verdict airtight — is there ANY
   forwarded-traffic path in this codebase that reaches `dev_queue_xmit` (e.g.
   fabric IPVLAN xdpgeneric path, coordinator packet inject), and if yes does
   it matter for WAN egress specifically?

## 13. Reviewer ledger

Task IDs + verdicts per round in `reviewer-ids.md` (same directory); per-round
docs `codex-plan-r<N>.md` / `agy-plan-r<N>.md` / `claude-smr-plan-r<N>.md`.
