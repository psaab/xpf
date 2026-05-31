# #1693 — Path C: rate-aware, transaction-safe queue→worker placement

Revision: v2 (Codex r1 + AGY r1 folded — §3.A narrowed from an absolute
to a topology-conditional claim; both reviewers found the foreign-egress
owner path and both ratify PLAN-KILL for the loss-cluster symmetric
topology, which IS #1614's environment)
Branch: refactor/1693-rate-aware-placement
Base: origin/master @ b0bd988fa (#1691 Path B merged; #1692 Path A
PLAN-KILLED; master GREEN, canary fixed #1723)
Status: **PLAN-KILLED (3-of-3 converged: Codex r2 + AGY r2 + Claude-SMR
r2 all PLAN-READY = ratify the KILL for #1614's loss-cluster topology).**
The issue is PLAN-KILLED on a TOPOLOGY-CONDITIONAL architectural-mismatch
leg (verified for #1614's loss-cluster single-egress-NIC symmetric
topology), hardened by the unmet-prerequisite leg (#1692) and the #761
transaction-safety leg. An active perturbative experiment is specified
(§5) as the empirical confirmer of the symmetric-binding invariant, but
§3 shows it cannot point at placement as the §3.B gating layer — both
reviewers independently confirmed it can only land on L1/L3/demand, none
of which is placement.

> KILL SUMMARY (see §3 + §12): The Path C lever, `owner_worker_by_queue`,
> does not place #1614's under-protected shared-exact tier (3g/6g, ≥2.5
> G). On the loss cluster (`worker_id = queue_id % workers`,
> `server/helpers.rs:618-636`; 6 queues → 6 workers) every worker binds
> reth0, so `tx_owner_live` is `Some` on every worker for reth0.80, the
> shared-exact owner-redirect bail (`cross_binding.rs:69,123,187`) always
> fires, and 3g/6g drain RSS-local gated by the v8 per-worker share lease
> (L1) — not by the owner map (`tx/dispatch/cos.rs:91-99`). #1598
> deliberately REMOVED owner-routing for this tier (funnel regression).
> The only path that consults the owner map (foreign-egress,
> `tx_owner_live==None`) is unreachable for #1614's single-egress
> workload and is a cross-binding HANDOFF target that does not change the
> v8 share split (`total_flows`/`my_count`/`new_cap` unaffected,
> `rotate_epoch_v8.rs:308`). #1692 already established 3-of-3 that the
> §3.B gating layer is L1 (by-design, #1304/#1220) / L3 (selector — a
> separate #1614 Path A issue) / demand (#1630 cause-2) — none placement.
> The current owner builder is the #761-killed round-robin (mid-flight
> slot shift → HA misroute), so even granting placement mattered, the
> mechanism needs a tombstoned ledger #761 already killed. PLAN-KILL.

> v2 CHANGE LOG: v1's §3.A claimed `owner_worker_by_queue` has an
> ABSOLUTE "zero effect on shared-exact drain." Codex r1
> (PLAN-NEEDS-MAJOR) and AGY r1 (PLAN-KILL-IS-WRONG) BOTH found the same
> counter-example, verified: the shared-exact bail
> (`cross_binding.rs:69,123,187`) is conditional on
> `iface_fast.tx_owner_live.is_some()`. When the processing worker has NO
> local binding to the egress TX ifindex (`tx_owner_live == None`), Step 1
> does NOT bail and the request DOES route via `owner_worker_id`
> (`cross_binding.rs:74,126,190`; `tx/drain/mod.rs:517-534`). v1's
> absolute invariant is false for asymmetric / multi-egress topologies.
> v2 narrows §3.A to the loss-cluster topology (single egress NIC reth0,
> 6 RX queues → 6 workers → every worker binds reth0's tx_ifindex →
> `tx_owner_live` is `Some` on every worker for reth0.80 → bail ALWAYS
> fires → owner map never consulted for 3g/6g). BOTH reviewers'
> decision matrices independently land on PLAN-KILL for that topology
> (AGY r1 §4: "symmetric worker bindings (loss cluster) ⇒ PLAN-KILL";
> Codex r1: ratify once §3.A is narrowed to "shared-exact with live
> per-worker TX binding"). The asymmetric/multi-egress case is a
> DIFFERENT, unfiled question outside #1614's chartered scope (§3.D).

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

## 3. The decisive architectural-mismatch leg (topology-conditional;
verified for #1614's loss-cluster environment)

This is the #961 / #946-Phase-2 dead-end pattern: the proposed mechanism
operates on a data structure that does not control the targeted behavior
**in the deployment #1614 measures**. It is verifiable from production
source plus one binding-topology fact the active experiment (§5)
confirms on the cluster.

### 3.A — on #1614's topology, `owner_worker_by_queue` does NOT place the under-protected tier

The #1614 §2.2 "queue X owned by worker Y" table OBSCURES the
shared-exact threshold (`worker/cos/mod.rs:31`, inclusive `>=` at `:168`):

```
COS_SHARED_EXACT_MIN_RATE_BYTES = 2_500_000_000 / 8   // 2.5 Gbps
```

3g = 375,000,000 B/s and 6g = 750,000,000 B/s are both ≥ 312,500,000 B/s
(confirmed: `parseBandwidthLimit` bits→bytes at
`pkg/config/compiler_protocols.go:840-843`; fixture rates at
`test/incus/cos_port_grid_test.py:24-25`). So:

- **< 2.5 G (100m, 1g): SINGLE-OWNER tier.** The TX request funnels to
  `owner_worker_id` — the map Path C wants to make rate-aware. These two
  classes are ALREADY protected (94% in `small4+24g`, #1692 §1).
- **≥ 2.5 G (3g, 6g, 9g … 24g): SHARED-EXACT tier.** When the processing
  worker has a LIVE local TX binding to the egress
  (`iface_fast.tx_owner_live.is_some()`), each worker drains its OWN
  RSS-placed flows locally and `owner_worker_id` is NOT consulted.

The shared-exact bail, verbatim — **note the `tx_owner_live.is_some()`
conjunct**, which §3.C below shows holds on every worker for reth0.80:

1. `cos/cross_binding.rs:69` —
   `step1_bail = (queue_fast.shared_exact && iface_fast.tx_owner_live.is_some()) || queue_fast.owner_worker_id == current_worker_id;`
2. `cos/cross_binding.rs:123` and `:187` (Local and Prepared redirect
   helpers) both open with
   `if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() { return Err(req); }`.
3. `tx/dispatch/cos.rs:91-99` `enqueue_local_request_to_target_or_owner`:
   if `request_runs_under_shared_exact_policy(...)` (i.e.
   `queue_fast.shared_exact`), the request is
   `pending_tx_local.push_back(req)` — **kept on the current
   (RSS-placed) worker.** Only the non-shared-exact branch (`:100-108`)
   funnels to `owner_live` / `owner_worker_id`.

When `tx_owner_live.is_some()` for the egress (the loss-cluster case,
§3.C), the 3g/6g shards land on whatever worker the 5-tuple RSS-hashed
to and are gated there by the v8 per-worker fair-share lease (L1) —
**`owner_worker_by_queue` has no effect on their placement.** Re-homing
the owner of a 3g queue moves nothing.

### 3.C — the loss-cluster symmetric-binding invariant (the narrowing)

`tx_owner_live` for an egress is `Some` on the current worker iff that
worker holds a binding whose `ifindex == egress tx_ifindex`
(`worker/cos/mod.rs:221` reads `tx_owner_live_by_tx_ifindex`, built at
`worker/loop_body/mod.rs:150-154` from `bindings.iter().map(|b|
(b.ifindex, b.live))` — the current worker's own bindings only;
`build_worker_cos_owner_live_by_tx_ifindex`, `worker/cos/mod.rs:85-96`).

#1614 runs on the loss userspace cluster (CLAUDE.md topology): reth0 (WAN
egress, ge-0-0-2/enp9s0) is a single mlx5 VF exposing **6 combined RX
queues → 6 workers**; the planner creates a binding per (interface,
queue) and assigns `worker_id = queue_id % workers`
(`server/helpers.rs:618,625,636`; `workers 6` per
`docs/ha-cluster-userspace.conf:286` /
`loss-userspace-shared-umem-phase0-node0.json:29`), so queue IDs 0-5
give workers 0-5 a reth0 binding (Codex r2 verified). Therefore EVERY
worker holds a reth0 binding ⇒ `tx_owner_live` for reth0's tx_ifindex is
`Some` on every worker ⇒ the shared-exact bail
(`cross_binding.rs:69,123,187`) ALWAYS fires for reth0.80's 3g/6g
queues ⇒ the foreign-egress owner path (§3.D) is unreachable for the
#1614 workload. The 3g/6g iperf flows egress ONLY reth0.80 (single
egress NIC; no transit to a foreign egress). This invariant is the one
empirical fact the active experiment (§5) confirms: 3g/6g drain
RSS-local, owner map unused.

**Degraded-state caveat (Codex r2):** a partial-binding state CAN make
`tx_owner_live == None` even on the loss cluster — `set_binding_state`
can unregister one binding (`server/handlers/binding.rs:27`), bringup
skips unregistered bindings (`coordinator/reconcile/bringup.rs:42`), and
a worker binding-creation failure leaves it out of the worker-local map
(`worker/loop_body/mod.rs:115`). That is a DEGRADED topology, not the
chartered healthy loss-cluster steady state, and the §5 experiment's
job-(a) empirical invariant check (every worker carries 3g/6g shards)
guards against silently reasoning over a degraded binding set. It does
not change the verdict for the healthy environment #1614 measures.

### 3.D — the foreign-egress owner path exists but is out of #1614 scope
(Codex r1 + AGY r1 finding, folded)

Both reviewers correctly found that when `tx_owner_live == None` (the
processing worker has NO local binding to the egress tx_ifindex —
asymmetric / multi-egress / transit-to-foreign-NIC topologies), Step 1
does NOT bail and the shared-exact request routes via `owner_worker_id`
(`cross_binding.rs:74` `Step1Action::Command(queue_fast.owner_worker_id)`;
`:126`, `:190`; drain dispatch `tx/drain/mod.rs:517-534`). This refutes
v1's ABSOLUTE "zero effect" claim. Two reasons it does not revive #1693:
1. **Out of #1614's chartered scope.** #1693 exists to fix the #1614 §3.B
   loss-cluster gap, which is single-egress symmetric (§3.C) — the owner
   path is unreachable there. A foreign-egress fairness concern is a
   DIFFERENT, UNFILED question; #1693's title and the #1614 Path C note
   are both about the loss-cluster simul-load case.
2. **Even there, the owner map is primarily a cross-binding HANDOFF
   target, not the §3.B fairness lever.** When `tx_owner_live == None` the
   request MUST be handed to some binding that owns the egress;
   `owner_worker_id` selects WHICH one (`cross_binding.rs:71`;
   `tx/drain/mod.rs:517`). That is correctness routing (get the frame to a
   worker that can TX the egress). CAVEAT (Codex r2): off-topology, the
   chosen destination worker's queue runtime DOES update the v8
   per-worker active-flow counters that feed `my_share`
   (`cos/queue_ops/accounting.rs:70`; `rotate_epoch_v8.rs:306`), so the
   handoff is not entirely fairness-neutral in the abstract. It does NOT
   revive #1693 because §3.C makes this path unreachable for reth0.80 in
   #1614, and because a "rate-aware handoff" would still only choose
   among egress-OWNING workers (a correctness-constrained set), not
   re-place the RSS-distributed shards that the v8 share split actually
   gates. An off-topology multi-egress fairness concern is a separate,
   unfiled issue — NOT the #1614 loss-cluster §3.B gap #1693 charters.

### 3.E — the project DELIBERATELY removed owner-routing for this tier

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

### 3.F — even #1614 §2.4's own data refutes the placement premise

#1614 §2.4: **18g reached 14.25 Gbps from a SINGLE owner worker**
(q8/worker 2), and **3g degrades monotonically with COMPETITOR COUNT**
(94% solo → 69% +1 → 54% +4). The deficit is set by HOW MANY classes are
simultaneously backlogged sharing the ~24 G ceiling and the v8 per-worker
share split — NOT by which worker owns a queue. A placement re-home
cannot change competitor count or the v8 active-flow-proportional share.
The §1614 Path C note "placement DOES matter (18g hit 14 G on one
worker)" is a NON-SEQUITUR: it shows one worker is not CPU-capped, which
makes the deficit a SHARING/LEASE problem (L1), not a placement problem.

**Conclusion of §3:** On #1614's loss-cluster topology (§3.C symmetric
single-egress), Path C's lever does not touch the under-protected tier:
the tier is RSS-placed and L1-gated by design (#1598), the owner-map bail
always fires, and the only path that consults the owner map (§3.D
foreign-egress) is unreachable for the #1614 workload and is a handoff
target rather than a fairness lever. #1614's own decisive sweep (§3.F)
attributes the deficit to competitor-count / share-split, not
ownership. This is a topology-conditional PLAN-KILL; the active
experiment (§5) confirms the one empirical premise (symmetric binding).

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

## 5. The mandated active/perturbative experiment (confirms the symmetric
invariant; cannot point at placement as the §3.B gating layer)

Per the issue comment and the task charter, the FIRST deliverable of any
#1693 attempt must be an ACTIVE experiment (not passive counters, not a
mechanism) to break the #1692 closed-loop collapse and establish whether
placement is the cause. It has TWO jobs here: (a) empirically confirm
the §3.C symmetric-binding invariant (3g/6g drain RSS-local on reth0.80,
owner map unused — e.g. via the existing per-(class,worker)
`cos_active_flow_count` showing every worker carries 3g/6g shards, never
a single owner); and (b) run the #1692 §12 option-(A) A/B to fingerprint
the §3.B gating layer. The decisive A/B:

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

**Why E1/E2 cannot rescue Path C (the key point):** given the §3.C
symmetric-binding invariant (which job (a) confirms), the owner map does
not place reth0.80's 3g/6g shards at all — they drain RSS-local. So none
of the E1/E2 outcomes points to placement: the A/B can only land on L1
(v8 share-cap by-design), L3 (selector — a separate #1614 Path A issue),
or demand-bound — all already-killed or non-placement. There is no E1/E2
outcome that reads "placement (owner_worker_by_queue) is the gating
layer," because on this topology the owner map is not in the
shared-exact drain path. Running E1/E2 hardens the kill record and
confirms the invariant; it cannot revive Path C. **A reviewer who wants
to keep #1693 alive must either refute the §3.C symmetric invariant (show
3g/6g taking the §3.D foreign-egress owner path on reth0.80) or show an
E1/E2 outcome that legitimately implicates the owner map — not merely
demand the experiment be run.**

If reviewers nonetheless require the run before kill, it executes on the
loss userspace cluster (`loss:xpf-userspace-fw0`, node 0 primary), per-
class ports 5201-5211, v4 172.16.80.200 + v6 2001:559:8585:80::200 (NOT
172.16.100.x), deploy WIPES CoS → `apply-cos-config.sh` first,
`<!-- AWAITING-DIAG -->` to serialize on the shared cluster.

## 6. The transaction-safety leg (#761, only reached if §3.C is refuted)

Even granting (contrary to §3.C) that placement mattered, the current
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
| Behavioral regression | HIGH | Re-introduces owner-routing for shared-exact ⇒ re-funds the #1598 funnel regression (§3.E). |
| Architectural mismatch (#961/#946-P2) | **FATAL on #1614 topology** | Lever (owner map) doesn't control target tier on the loss-cluster symmetric single-egress binding (§3.A+§3.C). Off-topology (§3.D) it's a handoff target, not a fairness lever. |
| HA portability / mid-flight slot shift (#761) | HIGH | Current builder is the #761-killed round-robin; needs tombstoned ledger (§6). |
| Performance regression | HIGH | Owner-funnel for ≥2.5 G tier caps reverse throughput (the #1598 smoke regression). |

## 8. Decision matrix (mirrors both reviewers' r1 matrices)

| If reviewers find … | Verdict |
|---|---|
| §3.C symmetric invariant holds (loss cluster: every worker binds reth0 ⇒ shared-exact bail always fires ⇒ owner map unused for 3g/6g) | **PLAN-KILL** (recommended; both r1 matrices agree) |
| §3.C refuted (3g/6g take the §3.D foreign-egress owner path on reth0.80) | re-open design; run E1/E2; revisit #761 ledger |
| §3.C holds but reviewer wants E1/E2 run | run E1/E2 as confirmer of the invariant + gating layer, then PLAN-KILL on its result (§5) |
| asymmetric/multi-egress topology (NOT #1614's) | out of #1693 charter (§3.D); a different unfiled question |

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

1. **§3.C symmetric-binding invariant is now the load-bearing claim
   (v1's absolute §3.A was correctly refuted by both r1 reviewers).**
   On the loss cluster, does EVERY worker hold a reth0 (WAN egress)
   binding (6 RX queues → 6 workers) so `tx_owner_live` for reth0's
   tx_ifindex is `Some` on every worker, making the shared-exact bail
   (`cross_binding.rs:69,123,187`) ALWAYS fire for reth0.80's 3g/6g?
   If a worker can lack a reth0 binding while still processing reth0.80
   egress traffic, §3.C is refuted — cite the binding-distribution path.
   (The active experiment §5 job (a) confirms this empirically.)
2. **Shared-exact threshold confirmed** (Codex r1 + AGY r1): 3g = 375
   MB/s, 6g = 750 MB/s, both ≥ 312.5 MB/s
   (`worker/cos/mod.rs:31,168`; `compiler_protocols.go:840-843`;
   `cos_port_grid_test.py:24-25`). Closed.
3. **Does #1614 §2.4 (18g=14 G one worker; 3g monotonic in competitor
   count) actually attribute the deficit to share-split not placement?**
   Or is there a placement reading of that data I'm missing?
4. **Is the #1598-funnel-revival risk (§3.E) real** — would owner-routing
   the ≥2.5 G tier re-cap reverse throughput, or has the TX path changed
   since #1598 such that it wouldn't?
5. **Is the §3.D foreign-egress carve-out fair?** When `tx_owner_live ==
   None` the owner map IS consulted — but is it genuinely only a
   cross-binding HANDOFF target (correctness routing), not a per-class
   fairness lever over the §3.B gating layer? Is there an asymmetric
   topology where rate-aware handoff WOULD move the v8 share split? If
   so, that is a new issue, not #1693 (which is the #1614 loss-cluster
   case) — agree/disagree?
6. **Does the #761 transaction-safety leg (§6) stand** — is the current
   builder the round-robin-over-queue-order #761 killed, with the
   mid-flight slot-shift + HA-divergence hazard? (Both r1 reviewers
   ratified: yes.)

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

## 12. KILL SUMMARY (converged 3-of-3)

**PLAN-KILLED.** Rate-aware queue→worker placement cannot address the
#1614 §3.B 3g/6g guarantee under-protection on the environment #1614
measures. Three independent legs, all reviewer-verified:

1. **Architectural mismatch (primary, §3):** the lever
   (`owner_worker_by_queue`) does not place the under-protected
   shared-exact tier on #1614's loss-cluster symmetric single-egress
   topology. Verified: `worker_id = queue_id % workers` ⇒ all 6 workers
   bind reth0 ⇒ `tx_owner_live` always `Some` ⇒ shared-exact bail always
   fires ⇒ 3g/6g drain RSS-local, owner map unused. #1598 deliberately
   removed owner-routing for this tier.
2. **Unmet prerequisite (§4):** #1692 (3-of-3 PLAN-KILL) established the
   §3.B gating layer is L1 (v8 share, by-design) / L3 (selector, a
   separate #1614 Path A issue) / demand (#1630 cause-2) — none placement.
3. **Transaction-safety (§6):** the current owner builder is the
   #761-killed round-robin (mid-flight slot shift → HA misroute); a
   tombstoned ledger would be required even if placement mattered.

The mandated active experiment (§5) was specified as the empirical
confirmer of the symmetric invariant; both reviewers independently
confirmed no E1/E2 outcome can implicate the owner map (it can only land
on L1/L3/demand), so the kill stands on the code-level invariant and the
experiment can only harden it. No production source changed; no mechanism
shipped (so no CoS smoke / `test-failover` needed — those gate a shipping
mechanism).

### Reviewer convergence

| round | Codex | AGY | Claude-SMR |
|-------|-------|-----|------------|
| r1 (v1) | PLAN-NEEDS-MAJOR (absolute §3.A false; bail conditional on `tx_owner_live`) | PLAN-KILL-IS-WRONG (absolute §3.A false) + matrix: symmetric ⇒ KILL | found the conditional bail independently; drove the v2 narrowing |
| r2 (v2) | **PLAN-READY** (ratify KILL; §3.C invariant verified via `worker_id=queue_id%workers`) | **PLAN-READY** (ratify KILL; §3.C sound, §3.D handoff-not-lever correct) | **PLAN-READY** (verified `tx_owner_live` setter chain + v8 share split independence) |

Convergent verdict: the Path C lever is structurally bypassed for
#1614's tier on its own environment; PLAN-KILL.

### What a future revisit needs (NOT this issue)

- An ASYMMETRIC / multi-egress topology where 3g/6g traffic actually
  takes the `tx_owner_live==None` foreign-egress owner path AND where the
  destination-worker v8 active-flow accounting (Codex r2 / AGY r3
  caveat) measurably skews per-class delivery. That is a separate,
  unfiled question, not #1614's loss-cluster §3.B gap.
- OR the #1614 Path A successor (a controlled active A/B, #1692 §12
  option A) fingering the **L3 selector** budget as fixable — which is a
  selector change (#1614 Path A candidate 4), NOT placement.
