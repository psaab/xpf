# Claude SMR hostile plan review — #1829 FQ-CoDel AQM — round 1

Reviewer: Claude (domain SMR: AQM/CoDel, AF_XDP dataplane, Rust hot paths).
Artifact: `docs/research/1829-fqcodel-aqm/plan.md` v1 @ `70fb61dd6`.
Posture: hostile; every plan claim re-derived against the worktree.

## Verdict

**PLAN-READY-WITH-FINDINGS** — the architectural premise is sound (intra-queue,
within-worker; the FQ substrate exists; the engine-boundary verdict for #1828 is
airtight), but five findings must fold into r2. None is fatal; F1 and F3 would
each become NEEDS-MAJOR if ignored at /engineer time.

## Verified claims (spot checks, no findings)

- `codel_target_ns` is genuinely write-only: constructed at
  `forwarding_build/cos.rs:317-318`, stored at `types/cos.rs:108,696`, zero
  reads elsewhere (`grep -rn codel userspace-dp/src --include='*.rs'`).
- No enqueue timestamp exists on `TxRequest`/`PreparedTxRequest`
  (`types/tx.rs:12-25,79-94`) or `CoSPendingTxItem` (`types/cos.rs:1276`).
- All production flow-fair dequeues funnel through
  `cos_queue_peek_min_bucket`/`cos_queue_pop_known_bucket`
  (`queue_service/mod.rs:1610/1622,1653/1665`; `queue_service/drain.rs:217/241,
  472/483` via `service.rs:226,573`). The #1763 no-mutation invariant and the
  per-call-site helper placement are compatible: the CoDel check is
  read-mostly between peek and pop; its state arrays are disjoint from MQFQ
  ordering state.
- Drop-after-pop machinery exists and is precedented:
  `cos_queue_clear_orphan_snapshot_after_drop` usage at
  `queue_service/drain.rs:236,266,285,505,537`.
- `now_ns` availability: enqueue callers hold `ctx.now_ns`
  (`tx/drain/mod.rs:87-100`) or the poll-path `now_ns`
  (`poll_descriptor/mod.rs:68` onward); dequeue-side
  `service_exact_local_queue_direct` **already takes `now_ns`**
  (`service.rs:12-19`) — threading into the two drain.rs helpers is one level,
  not 2-3 as the plan estimates (plan is conservative; fine).
- **#1828 §4 verdict — CONFIRMED AIRTIGHT for this codebase.** All forwarded
  traffic exits via the XSK TX ring + `sendto` wake (`tx/rings.rs:143-260`),
  bind modes Copy/ZeroCopy only (`worker/mod.rs:196-216`). ZC TX never builds
  an skb (driver consumes the ring); copy-mode TX goes
  `xsk_generic_xmit → __dev_direct_xmit`, which bypasses the root qdisc by
  construction. The only kernel-qdisc-traversing TX from this system is
  control-plane (Go VRRP AF_PACKET, FRR, DHCP, `afxdp/neighbor.rs` probes) —
  exactly as §4.4 states, including the real hazard that an uplink shaper
  could delay VRRP adverts. The #1828 recommendation (build on the CoS engine,
  never tc/networkd) follows necessarily.

## Findings

**F1 (MED-HIGH — evidence honesty / #1359 attribution).** §3 claims the
surplus-sharing mouse-latency failure is "exactly the regime where
byte-denominated admission bounds decouple from time." Plausible — but the
failure is equally attributable to queue-level surplus *service scheduling*
(the #1743 phase-2 surplus lineage; residual budgets are queue-level, #1731
finding 7 folded into #1735) rather than per-flow standing sojourn. Under MQFQ
a mouse's bucket head is served within ~active_buckets quanta; at 1 Gbps /
100 elephants that is ~1.2 ms of HOL, not 7 ms. If the mouse delay is
service-gap-induced, CoDel marks elephants to no effect on the gate. Remedy:
§6.1d's kill criterion must require **attribution**, not existence — capture
per-queue sojourn DURING the failing #1359 surplus cells and require the
sojourn excursions to correlate with the p99.9 probe failures before Phase 2
proceeds. Soften the §3 wording from "exactly" to "candidate mechanism".

**F2 (MED — target vs admission BDP interplay).** Admission sizes per-flow
buffering for cwnd at `RTT_TARGET_NS = 10 ms` (`admission.rs:94,118-121`); a
5 ms CoDel target will signal before a flow reaches the occupancy admission
was designed to allow. For ECT flows that is intended SQM behavior (mark, cwnd
adapts, throughput holds — DCTCP-like). For **non-ECT** flows it is a drop
regime, and the #704/#707/#754 history shows low-rate classes oscillate badly
when loss-signaled near the fast-retransmit floor. Remedy: r2 must (a) note
the interplay explicitly and recommend target ≥ 5 ms with the 10 ms admission
envelope in mind, (b) add a **non-ECT smoke leg** (iperf3 without ECN
negotiation) on a codel-enabled low-rate class to §10 — the current smoke plan
only exercises the ECT/mark path.

**F3 (MED — drop-and-continue accounting ownership unspecified).** Existing
capacity-drop sites RETURN `ExactCoSScratchBuild::Drop { dropped_bytes }` and
the *caller* settles `queued_bytes` / runnable / nonempty bookkeeping. §6.2c's
"continue the drain loop" means the inline path must own every side effect:
`queued_bytes` decrement, `nonempty_queues`/`runnable_queues` transitions if
the queue empties mid-batch, Prepared recycle, snapshot cleanup, counters. The
plan says "like the existing capacity-drop sites" — not a specification. A
missed `queued_bytes` decrement leaks → queue permanently appears backlogged.
Remedy: r2 (or the /engineer plan) must enumerate the side-effect owner per
field, and the §10 differential test must diff `queued_bytes`,
`nonempty_queues`, `runnable` against the reference drop path — not just the
FlowFairState fields.

**F4 (LOW-MED — Phase 1 unconditional cost).** The sojourn EWMA+peak update
runs on every CoS pop for all traffic even when no scheduler configures
codel-target. Two u64 RMWs + a compare is almost certainly noise, but the
plan asserts 3-5 ns without measurement while #1763 spent a whole PR removing
~1.5% of pop self-time. Remedy: §10 must run the #1763 pop self-time
measurement for **Phase 1 standalone**, not only Phase 2; alternatively gate
the EWMA on `codel_target_ns != 0` and keep only `sojourn_peak_ns`
unconditional (one cmp+cmov).

**F5 (LOW — Q6 is moot; simplify).** The FIFO index-walk drains
(`drain_exact_*_fifo_items_to_scratch`, `queue_service/drain.rs:37,301`) are
**production-unreachable post-#1735**: exact queues always promote eagerly
(`admission.rs:525-532`), and `service_exact_local_queue_direct` dispatches to
the flow-fair variant whenever `flow_fair()` (`service.rs:21-27`); unpromoted
single-flow non-exact queues are served by `build_cos_batch_from_queue`, which
already uses the fused peek+pop with the FIFO sentinel
(`queue_service/mod.rs:1610,1653`). Remedy: r2 drops the "and the FIFO drains"
clause — CoDel scopes to the fused peek+pop pairs ONLY, and the per-queue
`CodelState` in `CoSQueueHotState` covers the sentinel (unpromoted) path at
the same choke points. This removes the weakest part of the design (§6 Q6's
scratch-build-vs-settle timing question evaporates).

**F6 (note, no action required for r2).** `interval = 100 ms` hardcoded is
right for the lab (RTT 5-7 ms), but #1828's WAN use case is precisely where
operator paths can approach or exceed 100 ms RTT. When #1828's config-surface
work lands on this engine, `codel-interval` likely needs to be a knob at that
point, not "only on evidence". Keep the Phase-3 placement; record the
dependency.

## Answers to §12 open questions

- Q1: Option A. No construction site lacks `now_ns` reach (enqueue_cos_item's
  callers all hold it); Option B's churn through the #1735 promote migration
  and the snapshot paths is strictly worse for the same 8 B.
- Q2: Not redundant *as instrumentation*; redundancy of the control law is an
  empirical question that F1's tightened attribution gate answers. Killing
  Phase 2 now would be premature; shipping it ungated would be unjustified.
  The plan's structure (Phase 1 ships alone, Phase 2 gated) is the correct
  resolution.
- Q3: Straight arrays. 84 KB appears only on queues with codel-target set;
  an open-addressed table over the active set adds probe branches to the
  common path to save memory nobody configured away.
- Q4: mark-ECT/drop-nonECT is defensible: an unresponsive ECT flow is already
  bounded by the per-flow share cap (`cos_queue_flow_share_limit`) — it cannot
  buy more buffer by ignoring marks; it just loses at admission. Document this
  as the answer to RFC 8289 §4.1 rather than adding escalation complexity.
- Q5: per-call-site helper, yes — the verdict must precede the pop because
  DropHead and MarkAndTransmit diverge on caller-owned resources (recycle vs
  scratch). In-pop placement would force drop-after-pop semantics into a fn
  that cannot recycle Prepared offsets.
- Q6: moot per F5.
- Q7: verified, no qdisc-traversing forwarded path exists (see above).

## Required for r2

Fold F1-F5 (F1, F3 mandatory; F2 mandatory in §6.2e+§10; F4 as a §10 gate;
F5 as a simplification). F6 recorded as a note in §11/Phase 3.
