# Claude SMR plan-review r2 — #1625 per-queue epoch-cap (PLAN-KILL update)

Reviewer role: domain SMR — CoS scheduler / token-bucket math /
WFQ-class scheduling theory / Junos guarantee-rate semantics.

**Round-2 verdict revision: PLAN-KILL.**

## Why I changed my mind from r1 PLAN-NEEDS-MINOR

In r1 I bought the plan's §2 diagnosis at face value and proposed
four MEDIUM fixes. Codex plan-r1 (task-mppkt4ad-g3gtz0) and AGY
plan-r1 (adversarial-review-mppk1nwa-s66mo9) both ran independent
review rounds and surfaced facts I had not verified.

### Codex's finding I should have caught — the mechanism already exists

Codex evidence at
`userspace-dp/src/afxdp/coordinator/mod.rs:1092-1127` shows
that **every exact queue with a non-zero transmit_rate gets a v8
shared lease**. And at
`userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:215-225`:

```rust
let elapsed_ns = if start == 0 {
    EPOCH_DURATION_NS
} else {
    (now_ns - start).min(EPOCH_DURATION_NS)
};
let new_cap_raw =
    ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
```

This is **literally the same formula** the plan proposes:
`rate × epoch_ns / 1e9`. The cap is published to
`epoch_total_grant_cap` and consumed at
`shared_cos_lease/mod.rs:1089-1092`:

```rust
if (class_granted as u64) >= cap { break; }
let class_room = cap - class_granted as u64;
```

So the mechanism PR-1625 proposes is **already implemented** in
production code at the shared-lease layer (#1229 Phase 6 v8). The
v8 lease caps each class at `rate × 200 µs` per epoch.

Adding a SECOND cap inside the selector at
`select_exact_cos_guarantee_queue_waterfill` is:
1. **Redundant**: the v8 lease already enforces it.
2. **Worse than redundant**: applies on top of the lease, so a
   class that's at-cap on the lease is double-throttled (lease
   cap AND selector cap both stop it).
3. **Wrong abstraction layer**: per-queue rate enforcement
   belongs at the lease, not the selector. The selector picks
   WHICH queue to service; the lease decides HOW MUCH the queue
   can transmit.

This contradicts plan §3 fundamentally. The plan is solving a
problem that — at the algorithm level — is already solved.

### So why does the smoke show 20%/class?

If the v8 lease enforces per-class rate caps, why does the #1618
smoke show roughly equal `% of shape` across classes? Possible
explanations:

1. **The bypass-grace surplus path**
   (`rotate_epoch_v8.rs:182-205`) fires under simul-load and
   lets classes consume MORE than their `epoch_total_grant_cap`.
   The bypass arms when `any_active_worker_signaled &&
   aggregate_underuse && any_peer_cpu_bound_under_util`. Under
   11-class saturation, `aggregate_underuse` (prev_granted +
   slack < cap) MAY be true if individual classes can't drain
   their cap (CPU bound). If so, the cap is bypassed and we
   degenerate to work-conserving RR.

2. **The selector RR cadence**: if the selector visits each
   class roughly equally often, and on each visit the v8 lease
   has fresh cap room (early in the epoch), then each class
   gets equal `secondary_budget` per pass. After 200 µs, all
   leases rotate, all classes get fresh cap → equal-per-pass
   converges to equal-bytes-per-time. The cap is per-class but
   the selector's visit-cadence is class-uniform.

3. **`worker_fair_share` interaction**: per
   `rotate_epoch_v8.rs:230-235`, the worker's share is
   `cap × my_count / total_flows`. With 12 flows per class × 11
   classes = 132 flows per worker (if all funnel to one binding),
   each flow's fair share is `cap × 12/132 = cap/11`. If the
   selector visits each class with a 1/11 share, and the lease
   only releases cap/11 per call, we get the observed
   equalization.

Cause (2) or (3) is the more likely root cause than the plan's
diagnosis. The plan's mechanism does NOT address either:
- (2) is the bypass-grace surplus path inside the lease — needs
  tightening at the lease layer, not the selector.
- (3) is the worker_fair_share computation — needs revisiting
  how share is computed under multi-class saturation.

### Codex's accounting finding (also fatal)

Even if the diagnosis were correct, Codex's MAJOR #2 stands: the
plan debits `epoch_bytes_serviced` by `candidate_budget` (the
selector's offered budget), not by actually-sent bytes. TX ring
partial inserts at `service.rs:155-166` would burn allowance
without sending bytes. This is a known accounting hazard in this
codebase (`apply_direct_exact_queue_accounting` uses
`sent_bytes` precisely to avoid this).

### Codex's smoke-fixture finding (also fatal)

`test/incus/cos-iperf-config.set:69-70` does NOT enable
`oversubscription-policy guarantee-rate`. The plan claims Pass C
is the blocking gate, but the fixture as-checked-in doesn't
activate the GuaranteeRate path. The smoke would be testing the
SAME code path PR-1618 already passes (proportional baseline).

### AGY's jumboframe finding (independent fatal)

`queue_service/mod.rs:889-893` does `break` (not `continue`)
when `candidate_budget > pass1_remaining_bytes`. This means if
ANY queue's quantum exceeds remaining pass1 budget, ALL
subsequent ascending queues are skipped this pass. Under heavy
load with mixed-rate queues, this is a real Phase-1 priority
inversion. The plan's per-queue cap doesn't fix this either —
it's a separate bug in the existing scaffold.

## Revised verdict

**PLAN-KILL** for plan v1 as written. The mechanism is
structurally redundant with the existing v8 shared lease. Even
if we fixed the implementation defects (Codex MAJOR #2/#3/#5),
the result would be double-throttling at best.

## What plan v2 should look like (if this work is to continue)

The correct work is NOT a new per-queue cap. It is one of:

### Option A: Investigate the actual root cause empirically

Add the instrumentation Codex requested in his "§11 plan-kill
conditions" finding — per-class trace counters for selector
phase entered, queue skipped by epoch cap, queue skipped by
lease/token cap, selected budget vs actual committed bytes,
binding/queue id. Run the simul-load smoke with the
guarantee-rate fixture explicitly applied, capture per-class
data, IDENTIFY which mechanism is actually causing
equalization. THEN propose a fix targeted at that mechanism.

This is the right next step. It would close out #1625's framing
("the algorithmic refinement that makes #1614 step-1 produce a
different per-class distribution") with a proper root-cause
investigation, not a redundant mechanism.

### Option B: Tighten the v8 bypass-grace surplus path

If empirical investigation shows the bypass path fires under
simul-load, the fix is in
`rotate_epoch_v8.rs:182-205`: tighten the
`any_peer_cpu_bound_under_util` predicate so it doesn't fire
when 11 classes are saturating evenly. The current predicate
fires when "any peer < 60% util" — but with 11 saturated
classes, all peers are CPU-bound at 100% of their share, so
NONE should be <60%. Verify this.

### Option C: Fix `worker_fair_share` for multi-class saturation

If the equalization comes from `cap × my_count / total_flows`
giving each class a uniform 1/11 share, the fix is to weight
shares by configured rate, not flow count. This is a v9 lease
work — much larger.

### Option D: Address the Phase-2 lock-in + jumboframe bugs

The existing PR-1618 scaffold has the Phase-2 lock-in bug
(Codex MAJOR finding) and the jumboframe `break` bug (AGY
finding). These are real defects in the scaffold that should
be fixed regardless. They're surgical bug-fixes, not the broad
mechanism PR-1625 proposes. Could be a follow-up bug-fix PR
under #1614 umbrella.

## Recommended action

1. **PLAN-KILL #1625** as currently scoped.
2. **Label**: `plan-kill` per `feedback_plan_kill_label_required`.
3. **File new issue** for the empirical root-cause
   investigation (Option A) — that's the right next step.
4. **File separate issue** for the Phase-2 lock-in + jumboframe
   scaffold bugs (Option D) — surgical bug-fix PR.
5. **Document this kill** in `MEMORY.md` under
   `project_1625_plan_killed.md` so future agents don't
   re-propose the same redundant mechanism.

## Bottom line

I owe Codex and AGY the credit here. My r1 verdict was
PLAN-NEEDS-MINOR; both other reviewers caught structural facts
about the existing v8 lease and the smoke fixture that I had
not verified. The lesson per `feedback_gemini_lazy_reviews`:
quote-line evidence and demand verified counter-examples
BEFORE handing out MERGE-READY. The Codex evidence at
`coordinator/mod.rs:1092-1127` and
`rotate_epoch_v8.rs:220-225` is dispositive — the mechanism
exists already. PLAN-KILL.
