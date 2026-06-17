# Claude SMR — hostile plan review r1 (#1921 queue/arm-gate re-research)

Reviewing `docs/research/1921-queue-arm-gate/plan.md` @ r1. Stance: hostile.
Goal is to break the plan, not bless it.

## Verified-correct claims (with my own line checks)

- **armed is a request flag.** `set_bindings_forwarding_armed`
  (`helpers.rs:485-490`) sets `binding.armed = armed && binding.registered`
  for *every* registered binding, independent of bind success. The
  `enabled` gate (`helpers.rs:210-217`) is `forwarding_armed &&
  forwarding_supported && !bindings.is_empty() && all(registered &&
  armed)`. A failed bind keeps `registered=true` (set in `replan` at
  `:785`) and `armed` stays true. So `enabled` is NOT tripped by a partial
  bind. **The issue body's Defect B mechanism is genuinely wrong; the plan
  is right to refute it.** Good — this is the self-correction the prior
  research already made; the re-research correctly inherits it.

- **Black-hole chain confirmed.** `queueCountFromBindings`
  (`maps_sync.go:1649`) keys on `Registered && Ifindex>0`, returns
  `max(QueueID)+1`. `select_userspace_queue` (`lib.rs:1374`) returns
  `rx_queue_index % queue_count`, == `rx_queue_index` for `q <
  queue_count`. READY gate (`lib.rs:427`) → `drop_degraded_transit`
  (`:441`) → XDP_DROP (`:984`). Redirect target is `binding.slot`
  (`lib.rs:680`) in the XSKMAP — queue-bound. Chain holds.

- **Queue-bound-redirect wall confirmed.** `USERSPACE_XSK_MAP.redirect(
  binding.slot, 0)` (`lib.rs:680`) — XSKMAP redirect delivers only if the
  target XSK shares the packet's RX queue. The shim's own comment
  (`lib.rs:1387`) states it. So II-b/II-d cannot deliver a stranded-queue
  packet to a bound XSK on another queue. R3 is real. Good.

## Findings (attacks)

### F1 (MAJOR) — the plan does not prove the bug still reproduces, and the recommended fix may be solving a non-problem
The plan is honest that static evidence is stale (venue warning predates
the fixes) and routes the Case-1/Case-2 decision to Phase 0. But the FULL
fix scope (Phases 1-3) is substantial for a bug that **may already be
closed**. MEMORY says "#1921 RESOLVED ... forwards 5000 pps v4+v6". If that
proof was on a 4-channel virtio NIC, Case 1 holds and almost everything in
this plan is dead weight. The plan must NOT present Phases 1-2 as
committed scope until Phase 0 confirms Case 2. **Required change:** make
Phase 1 explicitly *conditional* — the only thing shippable in Case 1 is
(a) the doc correction and (b) at most the `queue_count`-from-bound +
not-ready→PASS guard AS A PURE DURABILITY GUARD, justified on its own
merits (defence-in-depth against any future partial bind), NOT as "the
#1921 fix". If even the durability guard isn't independently justifiable,
Case 1 should CLOSE the issue with the doc fix only. The plan's §2 Case-1
bullet says this but §6 Phase 1 says "ship in BOTH cases" without
re-justifying — tighten.

### F2 (MAJOR) — II-c (PASS-to-kernel) is a silent security downgrade and may be unacceptable at any duration
The plan waves this away as "non-strict only + health-visible + transient".
But: (1) the kernel path has no SNAT — for an interface-SNAT config, PASSed
packets egress with the **private source address**, which on a real WAN is
dropped upstream anyway, so II-c doesn't even reliably *forward*; it may
just move the black-hole from XDP to the upstream router while *appearing*
to forward. (2) "transient" depends on Phase 2 converging; if Phase 2 is
Case-2-only and Phase 0 says Case 1, II-c ships with NO convergence
mechanism and is permanent fail-open on any future partial bind. **Required
change:** the plan must either (a) default stranded-queue transit to DROP
(fail-closed) and make PASS an explicit opt-in operator knob with a loud
log + health-red, or (b) demonstrate (Phase 0) that PASSed packets actually
reach the destination under interface-SNAT before claiming II-c "forwards".
OQ2 already surfaces this — but the *recommended path* should default
fail-closed, not fail-open. Flip the default.

### F3 (MEDIUM) — queue_count-from-bound: Bound vs Ready key + bootstrap deadlock
OQ4 raises this but the plan doesn't resolve it. `Ready` =
`registered && bound && xsk_registered && heartbeat_fresh`
(`refresh_bindings.rs:226`). If `queue_count` keys on `Ready`, a queue that
*bound* but hasn't yet seen a heartbeat/RX is excluded from `queue_count`
during bring-up → its packets steer to `rx % (smaller count)` → wrong queue
→ drop, until heartbeat arrives. That's a transient self-inflicted strand.
Keying on `Bound && XSKRegistered` (not full Ready) avoids it. **Required
change:** specify the key as `Bound && XSKRegistered` and add a test that a
just-bound-not-yet-ready queue still counts. Also confirm this doesn't
reintroduce the `:207-209` ctrl=0→no-RX→not-ready deadlock the enable gate
was rewritten to avoid — the enable gate uses `armed`, queue_count uses
bound; they're independent, but the plan must state that explicitly.

### F4 (MEDIUM) — Phase 2 per-queue adaptive drop vs the global-min uniform planner
The plan flags R4 but underspecifies. `replan_bindings_from_candidates`
plans `queue_count = candidates.min(rx)` (`:759`) uniformly across all
interfaces. If virtio if3 can bind 2 of 4 but if4 binds all 4, an adaptive
*global* drop to 2 strands 2 good queues on if4. A per-interface drop
collides with uniform planning (the exact collision #1921 plan v5/v6 scoped
out). **Required change:** Phase 2 must state up front whether the adaptive
drop is global (simpler, may waste good queues) or per-interface (needs the
planner redesign the prior research deferred), and explicitly defer the
per-interface variant. As written it's hand-wavy.

### F5 (MINOR) — missing-binding fallback nuance
Plan §2.4 says the `:404-407` fallback "does NOT fire (only on flags==0)".
Correct, but note it ALSO only redirects to `rx_queue_index` which for the
stranded queue is itself unbound — so even extending it to fire on
READY==0 wouldn't help (same queue-bound wall). The plan should add this so
a reviewer doesn't propose "just extend the fallback" as a cheap fix.

### F6 (MINOR) — Phase 0 must record the ethtool refusal semantics
The "too low for existing zerocopy AF_XDP sockets" message means SOME
queues bound ZC. Phase 0 should explicitly capture which queues reported
`XDP_OPTIONS_ZEROCOPY` (`bind.rs:401,458`) vs EBUSY, because that
distinguishes "structural reservation" (Path C territory) from "lifecycle
EBUSY on a queue that COULD bind". The plan mentions the matrix but should
name the ZC-confirm field.

## Verdict

**PLAN-NEEDS-MINOR → conditional PLAN-READY.** Diagnosis is code-correct
and the queue-bound-redirect wall is the right central insight. But the
recommended path ships a fail-OPEN default (F2) and presents contingent
scope as committed (F1) — both must be tightened before this is safe to
hand to /engineer. F3/F4 need the key + planner-interaction spelled out.
None are fatal; the core (Phase 0 first, queue_count-from-bound, no silent
black-hole) is sound. Fix F1/F2 (flip to fail-closed default, conditional
scope) → PLAN-READY.
