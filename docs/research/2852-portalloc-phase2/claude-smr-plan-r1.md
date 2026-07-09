# Claude-SMR hostile plan review — #2852 Phase-2 evaluation — r1

Reviewer: Claude SMR (in-conversation, hostile per `feedback_triple_review_includes_claude_smr`).
Target: `docs/research/2852-portalloc-phase2/plan.md` r1 (recommends CLOSE + PLAN-KILL Phase 2).
Method: try hard to BREAK the CLOSE recommendation (argue FOR Phase 2). If the
recommendation survives a genuine attack, land there; otherwise flip.

---

## Attack 1 — "Other locks exist" is not a reason to leave THIS lock unfixed

**Adversarial claim:** The whack-a-mole argument (§2.2/§3.0) is a fallacy.
`publish_shared_session` and `replicate_session_upsert` being locks too does not
mean the NAT allocator mutex shouldn't be sharded. Fixing one bottleneck is
progress; you fix the next one next. By this logic you'd never optimize anything.

**Hostile test against the code.** The question is not "does another lock exist"
but "would sharding THIS lock produce a measurable end-to-end new-flow-scaling
win, which is what #2852 promises." I checked the relative lock cost per new flow
(`poll_descriptor/mod.rs:3123–3160`):

- NAT `live` mutex: ONE shared lock, 1 `get` + 1 `insert`. Taken by SNAT-matched
  flows only.
- `publish_shared_session` (`:3136`): locks THREE distinct `Arc<Mutex<FastMap>>`
  (synced/nat/forward_wire) + an owner-RG index in sequence — a bigger serialized
  section than the NAT CS, taken by EVERY new flow.
- `replicate_session_upsert` (`:3157`, `session_glue/mod.rs:736–741`): a loop over
  N−1 peer-worker queues, `lock_recover` + `push_back` each — **O(N) contended
  lock acquisitions per new flow**, taken by EVERY new flow, each queue contended
  by ~N threads.

So the NAT mutex is neither the only, the biggest, nor the worst-scaling
per-new-flow lock; replication is O(N) and unconditional. Making the NAT claim
lock-free while leaving a 3-lock publish + O(N) replication in place cannot move
the aggregate new-flow ceiling meaningfully. **Attack 1 fails: the whack-a-mole
argument is not a fallacy here — it is a quantified statement that this specific
lock is not the binding constraint on the metric the issue names.** A "shard all
new-flow cross-worker state" effort is a different, far larger scope than #2852
(and would live outside `nat/`).

**Verdict on Attack 1:** recommendation survives. Kill-argument #1 is sound.

## Attack 2 — the F4 exact-cap regression is avoidable

**Adversarial claim:** §3.3 overstates the regression. A sharded design can keep
an exact cap: give each shard a sub-cap of `max_tracked_flows / N` and reject
locally; the sum is exact. Or fall back to a serialized exact path only for tiny
pools.

**Hostile test.** Per-shard static sub-caps are NOT equivalent to a global cap:
with skewed flow-key hashing (the §8.1 skew-80/20 profile), one shard fills to its
sub-cap and rejects while the pool has free ports in other shards — that is
*premature exhaustion*, the exact failure mode that killed the striping option
(Option C). A dynamic global counter is back to `AtomicUsize` reserve/rollback,
which overshoots by up to M (`microbench-results.md:141–154`: 71–79%
false-exhaustion on a narrow pool at M=6/8). The "serialized fallback for small
pools" works but adds a mode split and a size threshold to tune — added
complexity, and it concedes that the exact-cap property is genuinely at risk. So
the regression is real; it is *mitigable* but only by trading it for either
premature exhaustion or a fallback mode. **Attack 2 partially lands: the
regression is not strictly unavoidable, but every avoidance path adds cost or a
different failure mode.** Net: this is a genuine con of Phase 2, not disqualifying
alone, but it removes the "Phase 2 is free" framing. Downgrade §3.3 from "REGRESSES
(hard)" to "puts at risk (mitigable only with added complexity or a new failure
mode)" — still a con.

**Verdict on Attack 2:** recommendation survives, with a wording softening.

## Attack 3 — CLOSE is wrong; keep #2852 OPEN as a Phase-2 tracker

**Adversarial claim:** Even if Phase 2 isn't built now, the residual mutex is a
real (if secondary) bottleneck. Closing loses the tracking. Keep it open,
labeled deferred.

**Hostile test.** "Deferred, left open" is exactly the state the campaign flags
as a non-terminal work queue — the thing this task exists to end. The residual is
genuinely captured two ways: (a) the design is preserved verbatim in §5 of this
doc on the research branch, reopenable with one command; (b) the honest blocker
is not "we forgot" but "the win is architecturally bounded by co-resident locks
and unmeasured" — which is a CLOSE-with-reason, not a defer. If a future high-CPS
appliance makes new-flow scaling a real target, the correct response is a NEW
issue scoped to "shard ALL per-new-flow cross-worker state (publish + replication
+ NAT), gated on a conn-rate measurement" — not this narrow NAT-only issue whose
headline defect is already fixed. **Attack 3 fails**, BUT it correctly flags that
CLOSE must be accompanied by a narrow follow-up issue for the conn-rate generator
+ measurement so the residual is not silently dropped (the plan already says
this, §0/§10 — good).

**Verdict on Attack 3:** recommendation survives; follow-up issue is mandatory.

## Attack 4 — is there a workload where the NAT mutex IS dominant?

**Adversarial claim:** A pure CGNAT box (every flow SNAT'd, HA off) — maybe there
the NAT mutex dominates.

**Hostile test.** Even with HA off, `replicate_session_upsert` is unconditional
for N>1 workers (it is the reverse-direction-correctness mechanism, not an HA
feature — `session_glue/mod.rs:731`, called at `:3157` with no cluster gate). And
the NAT mutex only contends when N>1. So any config that contends the NAT mutex
also pays O(N) replication per flow. `publish_shared_session` is also
unconditional at `:3136`. There is no realistic N>1 config where the NAT mutex is
contended but replication is not. SYN-flood (the other high-CPS scenario) is
short-circuited by screen syn-flood + SYN-cookie before session/NAT creation
(plan §3.2) — I did not re-verify the exact cookie path here, so I treat §3.2 as
*supporting, not load-bearing*; the argument stands without it. **Attack 4
fails.**

**Verdict on Attack 4:** recommendation survives.

## Attack 5 — Option A design soundness (if Phase 2 ships anyway)

If reviewers overrule the kill, §5 Option A must be correct. Checks:
- Deadlock: hot path takes ONE flow shard; persistent/deterministic path takes
  `leases` then a flow shard, fixed order — no ABBA. `release_flow` computes the
  flow shard from the 5-tuple (no need to read the map to learn the persistent
  key first — `release` already has the 5-tuple; the `persistent_key` is read from
  the record AFTER taking the flow shard, then `leases` taken second). Wait —
  that is flow-shard → leases on release, but leases → flow-shard on allocate:
  **an ABBA inversion.** §5.3 says "compute the flow shard from the 5-tuple; if the
  record carries a persistent_key, also take leases (same fixed order)" — but you
  cannot know whether the record has a persistent_key until you have read the
  record, which requires the flow-shard lock. This is the prior plan's F5
  resurfacing in Option A. FIX: release must take `leases` UNCONDITIONALLY first
  (a non-persistent release takes+noops it) to preserve the global `leases →
  flow_shard` order, OR store enough in the flow-shard record to avoid touching
  `leases` for non-persistent releases and accept that persistent releases take
  leases first by re-deriving the persistent key from the 5-tuple WITHOUT the
  record (possible only if the persistent key is a pure function of the 5-tuple +
  permit mode, which it is — `PersistentSourceKey` = proto/src_ip/src_port/remote,
  all in the flow key + rule). This must be nailed before Option A is PLAN-READY.
  **This is a real finding: Option A as written in §5.3 has the F5 hazard.**

**Verdict on Attack 5:** Option A is NOT PLAN-READY as written (F5 lock-order
inversion on the release path). This strengthens the CLOSE recommendation: even
the "simpler" Phase 2 has the same deadlock surface the prior reviewers flagged.

---

## Convergence

Four of five attacks on the CLOSE recommendation failed; Attack 2 landed only a
wording softening; Attack 5 found a real defect in the *alternative* (Option A),
which reinforces rather than undermines the kill. The recommendation is robust.

**VERDICT: PLAN-KILL / CLOSE (agree with the recommendation).**

- CLOSE #2852: its headline defect (global mutex serializes ALL fast-path SNAT,
  destroys multi-core scaling) is substantially fixed by Phase 1 (`6cbb10615`) +
  #4676 (`c7194b2af`); scaling went negative→positive, the port claim + GC are
  off the lock, and the residual is one hashmap insert/remove.
- PLAN-KILL the Phase-2 map-sharding: the win is (i) architecturally bounded — the
  new-flow path has co-resident all-workers locks (`publish_shared_session` 3×,
  `replicate_session_upsert` O(N)) taken by MORE flows than the NAT mutex, so
  sharding it alone cannot restore linear new-flow scaling (proven in code, not
  hypothesized); (ii) unmeasured on real hardware (no conn-rate generator; the
  reviewer-mandated cluster measurement never run); (iii) correctness-risking (F4
  exact-cap; and even the simpler Option A carries an F5-style release-path
  lock-order inversion, Attack 5).
- REQUIRED with the close: a narrow follow-up issue for a connection-rate
  generator + loss-cluster new-flow-ceiling measurement, so Phase 2 is reopenable
  with data if a high-CPS workload ever makes new-flow scaling a real target
  (which would then be scoped to shard ALL per-new-flow cross-worker state, not
  NAT alone).

## Required plan edits before final

1. §3.3 / §6.4: soften "REGRESSES" to "puts at risk (mitigable only via premature
   exhaustion or a fallback mode)" per Attack 2.
2. §5.3: note the F5 release-path lock-order inversion (Attack 5) — Option A is NOT
   PLAN-READY as written; if it were ever pursued, release must take `leases`
   unconditionally first or re-derive the persistent key from the 5-tuple.
3. §10: make the narrow follow-up issue an explicit deliverable of the CLOSE.
