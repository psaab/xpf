# #1921 — virtio_net multi-queue AF_XDP forwarding: reconciliation + durability

- Issue: #1921 (OPEN) — AF_XDP dataplane fails to forward on virtio_net
  multi-queue (over-provisioned queue plan + arm/READY gate → EBUSY → 0
  forwarding).
- Mode: `/research` — STOP at PLAN-READY / PLAN-KILL. No PR, no code.
- Branch: `research/1921-queue-arm-gate-reconcile`
- Revision: **r2** (folds Codex r1 PLAN-NEEDS-MAJOR + AGY r1
  PLAN-NEEDS-MAJOR + Claude SMR r1)
- Base: origin/master @ 26e4a112d.

## TL;DR — research outcome

**PLAN-KILL of the original forwarding bug.** The #1921 transit outage on
4-channel virtio **no longer reproduces on current master.** It was closed
by the three already-merged fixes — definitively #1929 (`e5e751448`), whose
own validation was run on a **4-queue virtio** venue (`t1921-fw`) and shows
v4+v6 transit 0% loss, `tx_completions_total` nonzero across LAN+WAN
bindings, SNAT proven, and a sustained `rx≈tx≈fwd=5000 pps` flood with
`ha_inact=0`, `tx_err=0` (`docs/research/1928-virtio-copy-xsk-rx/plan.md:83-95`;
ledger `docs/pr/1929-virtio-ha-gate/reviewer-ids.md:25-31`). A black-holing
multi-queue path would show drops + reduced fwd under that flood; it does
not. **The reported defect is fixed; close #1921.**

A genuine **latent durability gap remains** (a registered-but-unbound queue
would XDP_DROP transit on that queue), but on virtio it is never entered
because all queues bind post-`016bc7634` dedup. It is worth a **small,
separate, low-priority follow-up** — re-scoped per all three reviewers
(fail-closed, `max(BOUND QueueID)+1`, no global rebind). It is NOT a
re-open of #1921's forwarding bug.

## 1. Reconciliation against the three merged fixes

Issue #1921 was filed describing **Defect A** (sysfs queue enumeration) and
**Defect B** (all-or-nothing arm gate → XDP_PASS). Both were re-diagnosed
during the prior research and three fixes merged (all 2026-06-15, AFTER the
issue body):

- **#1927 / `76e78848a`** — `rebind::handle` no longer double-stops workers;
  restores the 500ms ZC-teardown quiesce → fixed the *rebind* EBUSY loop.
- **#1927 / `016bc7634`** — dedup replan candidates by Linux netdev → fixed
  the physical+unit (`ge-0/0/0` + `ge-0/0/0.0`) **double-bind** that planned
  two XSKs per `(ifindex, queue)`. This was the *actual* over-provisioning
  source (not the sysfs-vs-bindable gap the issue hypothesised). LIVE PROOF
  recorded: planned_bindings 16→8, EBUSY 8→0, redirects on all 4 queues.
- **#1929 / `e5e751448`** — standalone no longer ships 16 phantom inactive
  HA groups → fixed the HA-gate that dropped transit AFTER XSK RX. This was
  the residual outage after the bind fixes.

### Defect A — refuted as a live cause
`rx_queue_count()` (`helpers.rs:834`) / `userspaceRXQueueCount()`
(`interfaces.go:481`) still count `/sys/class/net/<if>/queues/rx-*`
verbatim. On virtio_net there is **no** structural reservation that makes
the bindable set smaller than the sysfs `rx-*` count (the issue body's
"virtio reserves queue pairs for XDP_TX" hypothesis was retracted in the
issue's own deep-research comment: virtio supports per-queue binding
`0..N-1`). After the `016bc7634` dedup removed the duplicate-netdev
over-count, sysfs count == bindable count on virtio, and all queues bind
(proven by the #1929 5000pps flood across all bindings). So the raw-sysfs
enumeration is **benign** here. Defect A as a forwarding cause is dead.

### Defect B — refuted as written; the would-be variant is latent, not live
The issue's mechanism ("failed bind → `armed=false` → `enabled=false` →
XDP_PASS everywhere") is **false**: `set_bindings_forwarding_armed`
(`helpers.rs:485-490`) sets `binding.armed = armed && binding.registered`
— a forwarding *request* flag, decoupled from bind success — so the
`enabled` gate (`helpers.rs:210-217`) is NOT tripped by a partial bind
(confirmed by Codex r1 #1 and AGY r1 #1).

A **different**, worse-in-theory consequence exists in code: a
registered-but-unbound queue inflates `queue_count`
(`queueCountFromBindings`, `maps_sync.go:1649`, keyed on `Registered`),
the shim steers `rx % queue_count` onto that queue (`lib.rs:1395`), the
binding's READY/flags is 0 (because `bindingForwardingLive` requires
`Ready`, `maps_sync.go:97` + `refresh_bindings.rs:226`), so the packet
falls into `binding_missing` → `drop_degraded_transit` → **XDP_DROP**
(`lib.rs:404,424,984`; the `:404-407` fallback can't help — it only fires
on `flags==0` and redirects to the same unbound `rx_queue_index`; AF_XDP
delivery is queue-bound so no cross-queue redirect delivers — kernel
`xsk_map_redirect` rejects `xs->queue_id != queue_id`, AGY r1 §1.3).

**But this path is never entered on virtio post-merge** because every queue
binds. It is a latent fragility, not the reported bug. Treating it as the
#1921 fix would be solving a non-problem (Codex r1 #2, SMR r1 F1).

## 2. Why PLAN-KILL (not a full fix PR under #1921)

- The reported symptom (4-channel virtio, 0 sessions, 100% loss) is
  **proven fixed** on the same venue class it was reported on (#1929
  validation, 4-queue virtio). Re-opening a fix under #1921 would re-fix a
  closed bug.
- The original Defects A and B do **not** reproduce: A is benign (sysfs ==
  bindable on virtio post-dedup), B-as-written is architecturally
  impossible (armed is a request flag).
- The genuine residual is a *latent* durability gap that virtio never hits;
  shipping the full Phase-1/2 scope of r1 against #1921 fails its own pass
  criterion ("validate ACTUAL RX delivery" — there is nothing to repair on
  virtio because delivery already works).

**Action:** close #1921 (`bug` already fixed). File a separate low-priority
**durability** follow-up (label `refactor`/`hardening`) for the
stranded-queue path, scoped as below.

## 3. Follow-up durability scope (separate issue, re-scoped per reviewers)

This is the ONLY work that should ship, and only as defence-in-depth — NOT
as a forwarding fix. All three reviewer corrections are folded:

1. **`queue_count` = `max(QueueID where Bound && XSKRegistered) + 1`** —
   NOT count-of-ready, NOT keyed on `Ready`.
   - Reviewer basis: a scalar `queue_count` only steers correctly when the
     deliverable set is a contiguous prefix `0..N-1`. Using the *count*
     (e.g. 3 for bound {0,1,3}) maps a packet on queue 3 to `3%3=0` whose
     XSK is on queue 0 → kernel drops (`xs->queue_id != queue_id`) — AGY r1
     §2.1, Codex r1 #6. Using `max(BOUND)+1` keeps the prefix semantics and
     stops a *registered-but-unbound* tail queue from inflating the modulo.
   - Keying on `Bound && XSKRegistered` (not `Ready`) avoids `Ready`'s
     `heartbeat_fresh` leg making `queue_count` flap with worker liveness
     (Codex r1 #7, AGY r1 §2.1). It is independent of the `enabled` gate
     (which keys on `armed`), so it does not reintroduce the
     ctrl=0→no-RX→not-ready bootstrap deadlock (`helpers.rs:207-209`).
   - **Hard limitation (must be documented, not worked around):** an
     *interior* hole (bound {0,2,3}, queue 1 unbound) cannot be represented
     by any scalar `queue_count`. `max(BOUND)+1 = 4` re-strands queue 1;
     a smaller value mis-steers queues 2/3. A correct interior-hole fix
     needs a per-queue deliverable **bitmap** in the ctrl/binding map (shim
     consults `ready[q]` before steering), or channel pinning so holes
     can't form. Bitmap is the clean design if interior holes ever occur in
     practice; on virtio they don't (contiguous bind). Scope the bitmap
     OUT of the first follow-up; document the prefix assumption.

2. **Stranded-queue transit policy: fail-CLOSED (XDP_DROP) by default,
   health-visible.** REJECT r1's II-c PASS-to-kernel default.
   - Reviewer basis: `architecture.md:27-29` mandates degraded non-local
     transit "fails closed in both compat and strict modes instead of
     bypassing policy, NAT, or conntrack"; `ModeUserspaceCompat` is
     documented "degraded transit fails closed" (`manager.go:41`). PASS is
     a silent security + correctness regression (no SNAT → asymmetric, TCP
     hangs) — Codex r1 #8, AGY r1 §2.3, SMR r1 F2.
   - Keep the existing DROP; the durability win is **observability**: a
     distinct fallback reason + counter + Prometheus gauge
     (`xpf_userspace_stranded_queue_drops`) + a `show` surface so a future
     partial bind is loud, not silent. (PASS could be a future explicit
     operator opt-in with a loud health-red, but is NOT the default and NOT
     in this scope.)

3. **Adaptive queue-drop: do NOT extend the global rebind watchdog.**
   - Reviewer basis: `hasBusyBindingsWedgeLocked` (`maps_sync.go:1285`)
     only fires when `bound==0` — a partial bind (3/4) never triggers it,
     so this is **new design, not an extension** (Codex r1 #9). Worse,
     making the watchdog fire on *any* failure and issuing a global
     `rebind` tears down ALL healthy sockets; for a structural failure it
     loops every 15s → periodic total outage (AGY r1 §2.2).
   - Correct shape (if ever needed): the coordinator tracks per-worker
     bind outcomes and drops a persistently-EBUSY `(ifindex,queue)` from
     the candidate plan **without** a global rebind of healthy sockets.
     This is non-trivial and contingent on a venue where partial binds
     actually occur — defer it entirely until such a venue exists.

## 4. What the engineer phase would do IF the follow-up is approved

Minimal, additive, no-op when all queues bind (the virtio case):
- Go: `queueCountFromBindings` → key on `Bound && XSKRegistered`, return
  `max(QueueID)+1` over that set. Unit test: a registered-but-unbound
  surplus binding does NOT raise `queue_count`; a bound-but-not-yet-ready
  (no heartbeat) binding DOES still count.
- Shim/Go: add the stranded-queue drop counter + gauge; keep DROP.
- Docs: correct the stale `docs/image-validation.md` VENUE WARNING
  (`:79`, dated 2026-06-15 12:39, predates the fixes) to the post-fix
  reality (virtio MQ forwards); document the prefix assumption + degraded
  fail-closed semantics in `pkg/dataplane/README.md`.
- Validation: pure unit/regression (no live forwarding repro needed —
  there is nothing broken to repro). mlx5 `make test-failover` no-regression
  if any shim byte changes.

## 5. Multiple Path Options considered (recorded for the follow-up)

| Decision | Options | Verdict |
|---|---|---|
| Bindable-queue discovery | bind-probe / topology-query / observed-bound feedback / `ethtool -L` pin | **None needed** — virtio binds all sysfs queues post-dedup. If a structural-reservation venue ever appears: `ethtool -L combined N` pin is the cleanest source-fix (no holes possible), observed-bound feedback the fallback. |
| Stranded-queue policy | DROP (fail-closed) / cross-queue redirect / PASS-to-kernel / shrink queue_count | **DROP + observability.** Redirect is undeliverable (queue-bound). PASS violates `architecture.md:27`. Shrink-queue_count only fixes the bound-set modulo, can't deliver stranded-queue packets. |
| queue_count key | registered / Ready / Bound&&XSKRegistered + max+1 vs count | **Bound&&XSKRegistered, `max+1`.** |
| Interior hole | scalar queue_count / per-queue bitmap / channel pin | **Document prefix assumption; bitmap only if interior holes are ever observed.** |

## 6. Reviewer convergence (r1)

- **Codex r1** (`/tmp/codex-1921-r1.log`): **PLAN-NEEDS-MAJOR** — key catch:
  static evidence already records post-fix 4-queue virtio success (#1928
  plan + #1929 ledger) ⇒ Case 1, bug closed; scalar queue_count can't
  represent interior holes; key on Bound&&XSKRegistered; II-c violates
  documented fail-closed; watchdog is new design.
- **AGY r1** (`adversarial-review-mqi27l23-37ol4s`): **PLAN-NEEDS-MAJOR** —
  verified the full black-hole chain + queue-bound-redirect kernel source;
  `max(BOUND)+1` not count; Bound not Ready; II-c security/TCP regression;
  global-rebind watchdog causes cascading outages.
- **Claude SMR r1** (`claude-smr-plan-r1.md`): **PLAN-NEEDS-MINOR** —
  conditional scope (F1), flip II-c to fail-closed default (F2),
  Bound-vs-Ready key (F3), planner collision (F4).

All three independently drove the plan to: **the bug is fixed (kill the
forwarding-fix scope); the residual is a small fail-CLOSED durability guard
with `max(BOUND)+1` queue_count, not a PASS-to-kernel degraded mode and not
a global-rebind watchdog.** r2 reflects that convergence.

## 7. Recommendation

1. **Close #1921** — the reported virtio multi-queue forwarding outage is
   fixed on master (proven on 4-queue virtio in #1929). Add a closing
   comment citing the merged fixes + the 5000pps validation.
2. **Optionally file a low-priority durability follow-up** for the
   stranded-queue fail-closed observability + `max(BOUND)+1` queue_count,
   scoped per §3-4. Do NOT block #1921 closure on it.
3. Correct the stale `docs/image-validation.md` venue warning regardless
   (cheap, prevents future misdiagnosis).
