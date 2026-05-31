# #1693 — Path C: rate-aware, transaction-safe queue→worker placement

Revision: v1 (DRAFT — pending hostile 3-way plan review: Codex + AGY +
Claude-SMR)
Branch: refactor/1693-rate-aware-placement
Base: origin/master @ b0bd988fa (#1691 Path B merged; #1692 Path A
PLAN-KILLED; master GREEN, canary fixed #1723)
Status: **PLAN-KILL CANDIDATE.** This plan argues the issue should be
PLAN-KILLED on an ARCHITECTURAL-MISMATCH leg that needs no cluster run,
hardened by the unmet-prerequisite leg (#1692) and the #761 transaction-
safety leg. An active perturbative experiment is specified (§5) as the
mandated confirmer, but §3 shows it would not rescue Path C even on its
most favorable outcome.

> If reviewers conclude the perf gain is too small to justify the churn,
> PLAN-KILL is an acceptable verdict. In THIS plan PLAN-KILL is the
> RECOMMENDED verdict; the burden is on any reviewer who wants to keep
> #1693 alive to produce a counter-example to §3.A.

This is a `/engineer` (triple-review) deliverable driven via the
`engineer` skill. No production source is modified by this plan. The
issue (#1693) is explicitly DEFERRED behind #1692 (instrument-first),
which was PLAN-KILLED.

---

## 1. Issue framing (in my words)

#1693 (#1614 "Path C") proposes a **rate-aware, transaction-safe
queue→worker placement mechanism** to address the #1614 §3.B finding:
under 11-class simultaneous load with `guarantee-rate 0.7`,
`shaping-rate 25g`, the mid-rate exact classes **3g/6g are delivered at
~51-54% of shape while ~6 G of the ~24 G push ceiling sits unused**, and
3g/6g equalize with the unguaranteed priority-low 24g instead of being
honored small-first.

The Path C hypothesis (from #1614 §4 Path C): queue→worker assignment is
round-robin by queue index (`coordinator/mod.rs:1216-1219`); worker 5 got
9g+uncapped (6.94 G) while worker 0 got best-effort+12g. Spreading large
classes to distinct workers / clustering small classes would even the
per-class-achievement spread, and since one worker CAN push 14 G (#1614
§2.4, 18g solo), placement "DOES matter."

The #1693 body itself states the gate: *"DEFERRED — do not start until
Path A (instrument-first) determines whether the §3.B guarantee-rate gap
is a placement problem at all."* Path A (#1692) was PLAN-KILLED without
isolating any layer. The issue comment (psaab, 2026-05-30) narrows the
charter: *"any future attempt must use ACTIVE/perturbative experiments …
to first establish whether the §3.B 3g/6g gap is even a placement
problem. Do not start #1693 until such an active experiment confirms
placement is the cause; otherwise it risks the #1211 'fix for a
non-existent problem' failure mode."*

## 2. Honest scope/value framing

If Path C worked, the win would be: under the `small4+24g` falsifier,
lift 3g/6g from ~52% toward ~90% of shape by re-homing their drain to
under-loaded workers, at the documented cost of regressing 24g (the
`guarantee-rate` contract intent). Absolute scale: ~6 G of currently-
idle ceiling redistributed toward two mid classes on a 6-worker mlx5 VF
binding. That is a real operator-facing win **if and only if** placement
is the gating layer.

**The thesis of this plan is that it is not** — and worse, that Path C's
specific lever (`owner_worker_by_queue`) is structurally incapable of
moving the under-protected tier, independent of whether placement
"matters" in the abstract. PLAN-KILL is the recommended verdict.

## 3. The decisive architectural-mismatch leg (no cluster run required)

This is the #961 / #946-Phase-2 dead-end pattern: the proposed mechanism
operates on a data structure that does not control the targeted
behavior. It is verifiable from production source alone.

### 3.A — `owner_worker_by_queue` does NOT place the under-protected tier

The #1614 §2.2 "queue X owned by worker Y" table OBSCURES the
shared-exact threshold (`worker/cos/mod.rs:31`):

```
COS_SHARED_EXACT_MIN_RATE_BYTES = 2_500_000_000 / 8   // 2.5 Gbps
```

- **< 2.5 G (100m, 1g): SINGLE-OWNER tier.** The TX request funnels to
  `owner_worker_id` — the map Path C wants to make rate-aware. These two
  classes are ALREADY protected (94% in `small4+24g`, #1692 §1).
- **≥ 2.5 G (3g, 6g, 9g … 24g): SHARED-EXACT tier.** Each worker drains
  its OWN RSS-placed flows locally; `owner_worker_id` is NEVER consulted.

The code paths, verbatim:

1. `cos/cross_binding.rs:69` —
   `step1_bail = (queue_fast.shared_exact && iface_fast.tx_owner_live.is_some()) || queue_fast.owner_worker_id == current_worker_id;`
   For a shared-exact queue with a live TX owner, Step-1 redirect-to-owner
   ALWAYS bails. The owner map is not consulted.
2. `cos/cross_binding.rs:123` and `:187` (the Local and Prepared
   redirect helpers) both open with
   `if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() { return Err(req); }`
   — shared-exact never routes by owner.
3. `tx/dispatch/cos.rs:91-99` `enqueue_local_request_to_target_or_owner`:
   if `request_runs_under_shared_exact_policy(...)` (i.e.
   `queue_fast.shared_exact`), the request is
   `pending_tx_local.push_back(req)` — **kept on the current
   (RSS-placed) worker.** Only the non-shared-exact branch
   (`:100-108`) funnels to `owner_live` / `owner_worker_id`.

So the 3g/6g shards land on whatever worker the 5-tuple RSS-hashed to,
and are gated there by the v8 per-worker fair-share lease (L1) —
**`owner_worker_by_queue` has zero effect on them.** Re-homing the owner
of a 3g queue moves nothing, because the drain of a shared-exact queue
is RSS-placed, not owner-placed.

### 3.B — the project DELIBERATELY removed owner-routing for this tier

This is not an accident Path C could fix. The #1598 fix
(`tx/dispatch/cos.rs:39-90` doc comment, verbatim) records that
consulting `owner_worker_id` for shared-exact queues **recreated a
production regression** (the cross-binding funnel): *"the lease-only gate
here was funneling them to a single owner_worker_id (rebuilding the
cross-binding funnel the worker/cos/mod.rs:126-131 primary fix was
supposed to break (#1598 primary smoke regression))."* The shared-exact
tier is RSS-spread BY DESIGN, for throughput. Path C proposes to re-
introduce owner-driven placement for exactly the tier #1598 spread —
which would re-fund the funnel #1598 killed.

### 3.C — even #1614 §2.4's own data refutes the placement premise

#1614 §2.4: **18g reached 14.25 Gbps from a SINGLE owner worker**
(q8/worker 2), and **3g degrades monotonically with COMPETITOR COUNT**
(94% solo → 69% +1 → 54% +4). The deficit is set by HOW MANY classes are
simultaneously backlogged sharing the ~24 G ceiling and the v8 per-worker
share split — NOT by which worker owns a queue. A placement re-home
cannot change competitor count or the v8 active-flow-proportional share.
The §1614 Path C note "placement DOES matter (18g hit 14 G on one
worker)" is a NON-SEQUITUR: it shows one worker is not CPU-capped, which
makes the deficit a SHARING/LEASE problem (L1), not a placement problem.

**Conclusion of §3:** Path C's lever does not touch the under-protected
tier; the tier is RSS-placed and L1-gated by design (#1598); and #1614's
own decisive sweep attributes the deficit to competitor-count / share-
split, not ownership. This is a structural PLAN-KILL requiring no cluster
time.

## 4. The unmet-prerequisite leg (#1692, already 3-of-3 PLAN-KILLED)

#1693 was DEFERRED behind #1692 (Path A, instrument-first). #1692 was
PLAN-KILLED (Codex r2 + AGY r2 + Claude-SMR r3 converged): passive
per-(class,worker) counters CANNOT disambiguate the three serially-coupled
gating layers (L1 v8-lease → `queue.hot.tokens` → L3 selector → drain) —
they measure the composition L1∘L3 — and the only independent demand
signal (`backlog_i`) is collapsed by TCP closed-loop pacing
(`tx/cos_classify.rs:887,915` / `cos/tx_completion.rs:511`). #1692 §12
concluded the most-probable real cause is **(0) demand-bound (#1630
cause-2 transport floor)** or **(L1) v8 share-cap BY-DESIGN**
(#1304/Cstruct/#1220 strict-per-flow-fairness trade) — **both are
PLAN-KILL outcomes** — and the only fixable layer is **(L3) the per-worker
Phase-1 selector budget, which lives in the selector, NOT in placement.**

So the prerequisite #1693 demands (placement confirmed as the gating
layer) is not merely unmet — #1692 produced positive evidence that the
gating layer is L1/demand/L3, **none of which is placement.**

## 5. The mandated active/perturbative experiment (specified, but §3
makes it non-rescuing)

Per the issue comment and the task charter, the FIRST deliverable of any
#1693 attempt must be an ACTIVE experiment (not passive counters, not a
mechanism) to break the #1692 closed-loop collapse and establish whether
placement is the cause. The decisive A/B is already specified in #1692
§12 "What a future revisit needs," option (A):

**Experiment E1 — pin ONE 3g flow to ONE worker.** A single 3g flow ⇒
`active_flow_buckets` has one nonzero entry ⇒ `my_share = full class cap`
on that worker ⇒ the v8 per-worker share split (L1) CANNOT starve it.
Measure whether the single pinned 3g flow reaches ~3 G shape.
- **Reaches shape ⇒** the multi-worker under-delivery IS the v8
  active-flow-proportional share split (L1 by-design — #1304/Cstruct/
  #1220 trade). PLAN-KILL.
- **Does NOT reach shape ⇒** L3 selector or demand-bound. Either way
  NOT placement (L3 is the selector; demand is transport).

**Experiment E2 — open-loop UDP demand** (breaks the TCP-pacing collapse
#1692 hit): drive 3g/6g with `iperf3 -u -b <rate>` so offered load is
exogenous, then read per-class delivered + `park_queue` deltas. If
3g/6g deliver to shape under open-loop UDP while TCP under-delivers, the
deficit is transport/closed-loop (demand-bound, #1630 cause-2) ⇒
PLAN-KILL. If they still under-deliver under open-loop UDP with backlog,
the gate is L1/L3 (still not placement).

**Why E1/E2 cannot rescue Path C (the key point):** NONE of the
experiment outcomes points to placement, because (§3.A) the owner map
does not place the shared-exact tier at all. The experiment's role here
is CONFIRMATORY of the kill, not exploratory: it can only land on L1,
L3, or demand — all already-killed or non-placement. There is no E1/E2
outcome that reads "placement is the gating layer," because placement
(owner_worker_by_queue) is not in the shared-exact drain path. Running
E1/E2 strengthens the kill record; it cannot revive Path C. **A reviewer
who wants to keep #1693 alive must first refute §3.A — show a code path
where `owner_worker_by_queue` routes a shared-exact (≥2.5 G) queue's
drain — not merely demand the experiment be run.**

If reviewers nonetheless require the run before kill, it executes on the
loss userspace cluster (`loss:xpf-userspace-fw0`, node 0 primary), per-
class ports 5201-5211, v4 172.16.80.200 + v6 2001:559:8585:80::200 (NOT
172.16.100.x), deploy WIPES CoS → `apply-cos-config.sh` first,
`<!-- AWAITING-DIAG -->` to serialize on the shared cluster.

## 6. The transaction-safety leg (#761, only reached if §3 is wrong)

Even granting (contrary to §3) that placement mattered, the current
builder `build_cos_owner_worker_by_queue_with_fallback_ifindexes`
(`coordinator/mod.rs:1177-1223`) is the EXACT mechanism #761
PLAN-KILLED: round-robin `eligible_workers[*next_slot % len]` over
`iface.queues` in queue_id order (`:1216-1219`). Adding or removing a
class shifts `*next_slot` and **reassigns the owner of EXISTING queues
mid-flight** — the #761 fatal: a slot shift misroutes traffic, and on an
HA peer with a different transient queue set the owner maps diverge →
synced sessions misroute across chassis. A rate-aware variant that
re-sorts by rate makes this WORSE (every rate-set change reshuffles).
#1693's own body acknowledges this: *"any placement change needs a
transaction-safe slot ledger with tombstones."* That is substantial new
HA-portable machinery (stable slot IDs, tombstones for removed classes,
deterministic cross-node derivation, `make test-failover` coverage) —
justified ONLY if §3 is refuted. It is not.

## 7. Risk assessment (for the mechanism, IF §3 were refuted)

| Class | Level | Note |
|------|------|------|
| Behavioral regression | HIGH | Re-introduces owner-routing for shared-exact ⇒ re-funds the #1598 funnel regression (§3.B). |
| Architectural mismatch (#961/#946-P2) | **FATAL** | Lever (owner map) doesn't control target tier (§3.A). This alone kills the plan. |
| HA portability / mid-flight slot shift (#761) | HIGH | Current builder is the #761-killed round-robin; needs tombstoned ledger (§6). |
| Performance regression | HIGH | Owner-funnel for ≥2.5 G tier caps reverse throughput (the #1598 smoke regression). |

## 8. Decision matrix

| If reviewers find … | Verdict |
|---|---|
| §3.A holds (owner map ≠ shared-exact drain path) | **PLAN-KILL** (recommended) |
| §3.A refuted (a code path routes shared-exact by owner) | re-open design; run E1/E2; revisit #761 ledger |
| §3 holds but reviewer wants E1/E2 run anyway | run E1/E2 as confirmer, then PLAN-KILL on its result (§5) |

## 9. Out of scope

- Any selector (L3) fix — that is #1614 Path A candidate 4 (re-derive
  Phase-1 boundary from configured RATES), a SEPARATE issue if #1692's
  successor active-A/B fingers L3. Not placement, not #1693.
- Any v8 surplus/work-conserving policy change — a separate design issue
  (#1211 warns this space is hard).
- Per-flow CoV (PLAN-KILL by #1220/#1244, #1614 §3.2).
- Default proportional mode (bit-for-bit preserved regardless).

## 10. Open questions for hostile plan review (each invitable to KILL or
to refute the kill)

1. **§3.A is the load-bearing claim. Refute it or ratify it:** is there
   ANY code path where `owner_worker_by_queue` / `queue_fast.owner_worker_id`
   routes the DRAIN of a shared-exact (≥2.5 G) queue? I claim no
   (`cross_binding.rs:69,123,187`; `tx/dispatch/cos.rs:91-99`). If yes,
   the kill collapses — cite the line.
2. **Is the shared-exact threshold (2.5 G) actually the line for the
   #1614 fixture's 3g/6g?** 3g = 3e9/8 = 375 MB/s ≥ 312.5 MB/s; 6g
   likewise. Confirm both are shared-exact (so owner map doesn't place
   them).
3. **Does #1614 §2.4 (18g=14 G one worker; 3g monotonic in competitor
   count) actually attribute the deficit to share-split not placement?**
   Or is there a placement reading of that data I'm missing?
4. **Is the #1598-funnel-revival risk (§3.B) real** — would owner-routing
   the ≥2.5 G tier re-cap reverse throughput, or has the TX path changed
   since #1598 such that it wouldn't?
5. **Is the active experiment (§5) genuinely non-rescuing?** Is there an
   E1/E2 outcome that would legitimately point at placement (owner map)
   rather than L1/L3/demand? If so, the kill should be downgraded to
   "run the experiment first."
6. **Does the #761 transaction-safety leg (§6) stand** — is the current
   builder the round-robin-over-queue-order #761 killed, with the
   mid-flight slot-shift + HA-divergence hazard?

## 11. References

- #1614 converged research: `docs/research/1614-simul-load-diagnosis/plan.md`
  v3 @ `e672bb821` (§2.4 sweep, §3.B signal, Path C note in §4).
- #1692 PLAN-KILL: `docs/research/1692-3g6g-guarantee-instr/plan.md`
  v3 @ `4a14aeac7` (§2 three layers, §12 KILL SUMMARY + revisit options).
- shared-exact threshold: `userspace-dp/src/afxdp/worker/cos/mod.rs:31`.
- shared-exact bail / RSS-local drain: `cos/cross_binding.rs:69,123,187`;
  `tx/dispatch/cos.rs:39-109` (#1598 funnel-removal comment).
- owner builder (round-robin, #761 hazard):
  `coordinator/mod.rs:1177-1223`.
- v8 lease share split: `types/shared_cos_lease/rotate_epoch_v8.rs:308`
  (`my_share`), `mod.rs:1152` (`acquire_v8`).
- KILL lineage: #1211 #761 #836 #840 #1203 #937 #1215 #1692 #1236 #1237
  #1239 #936 #1220 #1244.
