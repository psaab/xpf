# #1921 — virtio_net multi-queue AF_XDP forwarding: queue-enumeration + arm/READY-gate design

- Issue: #1921 (OPEN) — AF_XDP dataplane fails to forward on virtio_net
  multi-queue (over-provisioned queue plan + black-hole-on-unbound-queue).
- Mode: `/research` — STOP at PLAN-READY. No PR, no production code.
- Branch: `research/1921-queue-arm-gate-reconcile`
- Revision: **r1 (draft)**
- Base: origin/master @ 26e4a112d (post #1927, #1928/#1929, #1930, #1922, #1924).

---

## 1. Problem statement

A freshly-deployed #1879 appliance on virtio_net NICs with **4 combined
channels** (Tier-2 of `docs/image-validation.md`) boots, applies day-0
config, brings interfaces up, and answers host-inbound pings — but
**transit forwarding is 0 sessions / 100% loss**. The helper loops on
`libxdp private bind: Device or resource busy` (EBUSY) against a subset of
virtio queues; the kernel additionally refuses an `ethtool -L` channel
reduction with *"requested channel counts are too low for existing
zerocopy AF_XDP sockets"*.

Three #1921/#1928 fixes have **already merged** (all 2026-06-15, AFTER the
issue body was written) and each addressed a *different* cause than the
"queue enumeration + arm gate" the issue title names:

- **PR #1927 / `76e78848a`** — `rebind::handle` must not `afxdp.stop()`
  before `tear_down`, restoring the 500ms ZC-teardown quiesce; fixed the
  *rebind* EBUSY loop.
- **PR #1927 / `016bc7634`** — dedup replan candidates by Linux netdev;
  fixed the physical+unit (`ge-0/0/0` + `ge-0/0/0.0`) **double-bind** that
  planned two XSKs per `(ifindex, queue)`.
- **PR #1929 / `e5e751448`** — don't ship phantom HA groups on standalone;
  fixed an HA-gate that dropped all transit AFTER XSK RX (unrelated to
  binding).

This research **reconciles** those merges against the issue's two original
defects (A: enumeration; B: arm/READY gate) and decides whether a live
defect remains and, if so, what to ship.

## 2. Reconciliation: what is still live on current master

Static code reading of base @ 26e4a112d:

### Defect A (queue enumeration) — PARTIALLY live

- `rx_queue_count()` (`userspace-dp/src/server/helpers.rs:834`) and
  `userspaceRXQueueCount()` (`pkg/dataplane/userspace/interfaces.go:481`)
  **still count `/sys/class/net/<if>/queues/rx-*` verbatim** — unchanged by
  any merged fix.
- `replan_bindings_from_candidates()` (`helpers.rs:746`) still plans
  `queue_count = candidates.min(rx)` (global min, `:759`) queues per
  interface, slot per `(queue_id, iface)` (`:766`), worker round-robin
  (`:777`). The `016bc7634` dedup (`:709-711`) removed only the
  *physical+unit duplicate netdev* source of over-provisioning, **not** the
  sysfs-vs-bindable mismatch.
- So if the raw sysfs `rx-*` count exceeds the number of queues that
  actually accept an AF_XDP pool after the shim is attached, the helper
  still plans surplus queues that fail to bind.

### Defect B (arm gate) — REFUTED as written, but a STRONGER live defect exists

The issue body's exact claim — "a failed bind leaves `registered=true,
armed=false`, so `all(... armed)` is false → `enabled=false` → XDP_PASS
everywhere" — is **false** on current code:

- `set_bindings_forwarding_armed()` (`helpers.rs:485`) sets
  `binding.armed = armed && binding.registered` for *every registered
  binding* — it is a forwarding **request** flag, decoupled from bind
  success. A failed bind does NOT clear `armed`. So `all(registered &&
  armed)` (the `enabled` gate, `helpers.rs:210-217`) stays satisfied.
- Therefore `enabled` does NOT go false on a partial bind, and there is
  no global XDP_PASS. **The issue's "XDP_PASS everywhere" story is wrong.**

But the real consumer behaviour is **worse** than XDP_PASS — it is
**black-hole (XDP_DROP)** on the unbound queue:

1. `queueCountFromBindings()` (`pkg/dataplane/userspace/maps_sync.go:1649`)
   = `max(QueueID where Registered && ifindex>0) + 1`. **Registered, not
   bound.** A registered-but-unbound surplus queue still raises
   `queue_count`.
2. The shim writes that scalar to `userspace_ctrl.queue_count`
   (`maps_sync.go:357`), and `select_userspace_queue()`
   (`userspace-xdp/src/lib.rs:1374`) steers `rx_queue_index % queue_count`
   — i.e. each packet stays on its **ingress** queue for `q < queue_count`.
3. The per-binding READY flag is gated by `bindingForwardingLive()`
   (`maps_sync.go:~76`) = `Registered && Armed && Ready &&
   !deadWorker`, where `Ready` (`refresh_bindings.rs:226`) =
   `registered && bound && xsk_registered && heartbeat_fresh`. An unbound
   queue has `bound=false` → `Ready=false` → its `userspace_bindings[idx]`
   READY bit is **0**.
4. A transit packet arriving on the unbound queue: `select_userspace_queue`
   keeps it on its own queue (`q % queue_count == q`), the binding lookup
   finds `flags != 0` but `READY == 0` (`lib.rs:427`), the
   missing-binding fallback at `:404-407` does NOT fire (it triggers only on
   `flags == 0`, and only redirects to the *same* rx_queue_index anyway),
   and the packet hits `drop_degraded_transit()` (`:441`) → **XDP_DROP**.

**Net:** one unbindable virtio queue does not disable the box globally — it
**silently black-holes every flow whose RSS hash lands on that queue**.
With 4 queues and `--workers 1`, ~3/4 of transit can be dropped while
`show ... session` shows a trickle from the bound queue(s). This is the
live defect; it is a *steering / READY-gate* defect, not an enable-gate
defect. The issue title's spirit ("over-provisioned plan + all-or-nothing
gate → 0 forwarding") is correct; the precise mechanism is
black-hole-on-the-stranded-queue, not enable=false.

### Does it still reproduce post-merge? (the open empirical question)

The only live evidence on master is the `docs/image-validation.md` VENUE
WARNING — but that text was committed at **2026-06-15 12:39** (`#1879`),
which **predates** all three fixes (16:45-22:36 the same day). It is
**stale** and cannot prove current behaviour.

MEMORY records #1921 "RESOLVED" with the HA-gate fix "forwards 5000 pps
v4+v6" — but does **not** state the channel count of that proof venue, and
the #1928 marathon repeatedly ran on instrumented single-purpose VMs whose
queue topology is unrecorded. **We cannot conclude from static evidence
alone whether a 4-channel virtio NIC now binds all 4 queues.** Two cases:

- **Case 1 — all queues bind post-fix.** Then queue_count == bound count
  (identity modulo), every queue READY, forwarding works. Defect A's
  over-provision is benign (sysfs count == bindable count on virtio when
  no double-bind), and the black-hole path is latent (never entered).
  Outcome: **the live bug is closed**; ship only a *durability* guard +
  doc correction (so a future partial-bind cannot silently black-hole),
  and close #1921.
- **Case 2 — a subset still EBUSYs** (e.g. virtio reserves a queue pair for
  XDP_TX under an attached prog on this kernel, or the ZC socket-lifecycle
  EBUSY survives initial bring-up). Then the black-hole path is **live** and
  the box drops most transit. Outcome: ship the full degraded-mode +
  bound-aware-queue_count fix.

**Phase 0 (a live instrumented virtio-MQ repro) decides which case we are
in.** The fix design below is written so its *durability* core (Path
recommendation) is correct and worth shipping in **both** cases, and the
*queue-discovery* half is gated on Phase 0 confirming Case 2.

## 3. Goals / non-goals

**Goals**
- Establish ground truth: does 4-channel virtio bind all 4 queues on the
  baked-image kernel post-#1927/#1929? (Phase 0.)
- Guarantee that a partial-bind can NEVER silently black-hole transit: a
  packet on a stranded queue must fall back to a bound queue or to the
  kernel, not XDP_DROP, and `queue_count` must reflect *deliverable*
  queues.
- Forward on the queues that did bind ("degraded mode"), surface the rest
  as a health warning.

**Non-goals**
- Re-litigating the merged #1927/#1929 fixes (they stand).
- mlx5/i40e venues (they bind all advertised queues — unaffected; must
  remain a no-op / regression-clean).
- A general RSS-reprogramming / ntuple-steering subsystem (that is #1748/
  #1751 territory; out of scope).
- Pinning channel counts via `ethtool -L` as the *primary* fix unless
  Phase 0 proves it is the only viable route (see Path C risk).

## 4. Affected code (blast radius)

| File | Symbol | Role |
|---|---|---|
| `userspace-dp/src/server/helpers.rs` | `rx_queue_count` `:834`, `replan_bindings_from_candidates` `:746`, `set_bindings_forwarding_armed` `:485`, `enabled` gate `:210` | queue plan + arm/enable |
| `userspace-dp/src/afxdp/bind.rs` | `bind_flag_candidates_*` `:169-199`, EBUSY retry `:423`, ZC verify `:401` | per-queue bind + retry |
| `userspace-dp/src/afxdp/mod.rs` | `BIND_RETRY_ATTEMPTS=20` `:310`, `BIND_RETRY_DELAY=250ms` `:311` | retry budget |
| `userspace-dp/src/afxdp/worker/loop_body/setup.rs` | `live.set_error` `:131` | retry-exhausted → stuck binding |
| `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` | `binding.ready =` `:226` | Ready = bound&&xsk_reg&&hb |
| `userspace-xdp/src/lib.rs` | `select_userspace_queue` `:1374`, READY gate `:427`, missing fallback `:404`, `drop_degraded_transit` `:984` | shim steering + drop |
| `pkg/dataplane/userspace/maps_sync.go` | `queueCountFromBindings` `:1649`, `bindingForwardingLive` `:76`, ctrl write `:357`, busy-binding watchdog `hasBusyBindingsWedgeLocked` `:1250` / `shouldAutoRebindBusyBindingsLocked` `:1288` | ctrl/READY publish + watchdog |
| `pkg/dataplane/userspace/interfaces.go` | `userspaceRXQueueCount` `:481` | sysfs enumeration |
| `docs/image-validation.md` | VENUE WARNING `:79` | stale doc to correct |

## 5. Multiple Path Options (THE DESIGN DECISION)

Two orthogonal decisions: **(I) how to determine the bindable queue set**
and **(II) what to do with packets on a stranded queue**. Each fix path is
a (I,II) pairing.

### Decision I — bindable-queue discovery

- **I-a: bind-probe at bring-up.** After attaching the shim, attempt one
  throwaway XSK bind on each `rx-N`; the set that succeeds == bindable set.
  Pro: empirically exact, driver-agnostic. Con: extra socket churn at
  startup; the probe bind itself could leave a transient `xsk_pool` that
  EBUSYs the real bind (must close + quiesce — same ZC-teardown timing the
  rebind fix handles).
- **I-b: post-attach topology query.** Query bindable queues from the
  attached-prog topology (e.g. `bpf_xdp_query` channel info / ethtool
  channels after attach). Pro: no extra binds. Con: no kernel API cleanly
  reports "queues that accept an AF_XDP pool"; virtio's reservation isn't
  surfaced as a queryable count — likely unavailable, would still guess.
- **I-c: observed-bound feedback (reactive).** Plan all sysfs queues
  (status quo), but **derive `queue_count` from successfully-BOUND
  bindings**, not registered. On persistent per-queue EBUSY, drop that
  queue from the plan and re-plan (adaptive). Pro: no speculative probe;
  reuses the existing watchdog; converges to the real bindable set. Con:
  one bring-up cycle of partial drop before convergence (mitigated by II).
- **I-d: pin channels first.** `ethtool -L <if> combined N` to `N=workers`
  before binding, so advertised == bound. Pro: deterministic, removes
  surplus at the source. Con: xpf does NO `set_channels` today (new
  netlink/ioctl dependency + privilege); the kernel **refuses** the
  reduction once ZC XSKs exist ("too low for existing zerocopy AF_XDP
  sockets") so it must run *before any bind* and survive rebinds; changes
  RSS width for every driver, not just virtio; risk of fighting the Go
  interface manager.

### Decision II — stranded-queue packet policy

- **II-a: black-hole (status quo).** `drop_degraded_transit` → XDP_DROP.
  Rejected — this IS the bug.
- **II-b: redirect to a bound queue.** Make `select_userspace_queue` /
  the missing-binding fallback map a packet on a stranded queue to a
  *ready* binding (e.g. `rx % ready_count` over the bound set, or fall to
  slot 0). Pro: keeps traffic in the AF_XDP firewall fast path. Con:
  **AF_XDP redirect is queue-bound** — `XDP_REDIRECT` into an XSKMAP slot
  bound to a *different* RX queue is dropped by the kernel post-redirect
  (the shim's own comment at `lib.rs:1387` warns of exactly this). So a
  cross-queue redirect to a bound XSK on another queue does NOT deliver.
  This option is **only** viable if the bound XSK shares the packet's
  actual RX queue — which by definition the stranded queue's isn't. ⇒ not
  generally workable for transit on the stranded queue.
- **II-c: XDP_PASS to kernel (degraded fallback).** On a stranded
  (registered-but-not-ready) transit queue, `XDP_PASS` instead of
  `XDP_DROP`, letting the kernel forward (with `ip_forward=1`). Pro: no
  black-hole; the box forwards (unfirewalled on that fraction) instead of
  dropping. Con: the kernel path has no SNAT/policy → asymmetric/leaky
  forwarding; security posture degraded silently unless surfaced. Must be
  a **health-visible** degraded state, and arguably gated behind
  non-strict mode (strict mode keeps DROP, fail-closed).
- **II-d: make queue_count == bound count so no queue is stranded.**
  If `queue_count` counts only BOUND queues, then `rx % queue_count`
  for a packet arriving on an unbound queue `q >= queue_count` maps to a
  *bound* lower queue — but again hits the queue-bound-redirect wall
  (II-b): the lower bound XSK isn't on queue `q`'s ring. So shrinking
  queue_count alone still can't *deliver* a packet that physically arrived
  on an unbound queue; it can only stop *bound* queues from being
  mis-counted. II-d is necessary for correct steering of bound queues but
  insufficient on its own for stranded-queue traffic.

**The queue-bound-redirect constraint (II-b/II-d wall) is the crux:** a
packet that physically lands on a queue with no bound XSK *cannot* be
delivered into the AF_XDP firewall at all. The only honest choices for
that packet are XDP_DROP (fail-closed) or XDP_PASS (fail-open to kernel).
Therefore the real fix must **prevent queues from being stranded in the
first place** (Decision I) and only use II as a transient/strict-mode
safety net.

### Recommended path: **I-c (observed-bound feedback) + II-c (PASS in non-strict, DROP in strict) + queue_count-from-bound (II-d for the bound set)**

Rationale:
- I-c needs no speculative probe (avoids I-a's self-EBUSY hazard) and no
  new `ethtool -L` dependency (avoids I-d's privilege + ZC-pin + RSS-width
  hazards). It reuses the existing busy-binding watchdog
  (`maps_sync.go:1288`) which already detects `registeredArmed>0 &&
  bound==0` and rebinds — we extend it to *per-queue persistent EBUSY*
  ("this queue never binds across K rebind cycles → drop it from the plan")
  rather than only the all-queues-wedged case.
- `queue_count` switches from `max(registered QueueID)+1` to `max(BOUND
  QueueID)+1` (or, more precisely, count of ready bindings), so bound
  queues steer correctly and surplus queues stop inflating the modulo.
- II-c converts the residual black-hole into a kernel-PASS **only in
  non-strict mode** during the convergence window, with a health counter
  + Prometheus gauge + `show` surface so the degradation is never silent;
  strict mode keeps fail-closed DROP. This bounds the blast radius to "a
  few packets PASS to kernel during the first second of bring-up" instead
  of "3/4 of transit black-holed indefinitely".
- I-d (`ethtool -L`) is held as a **contingent Path C** — pursued ONLY if
  Phase 0 shows virtio *structurally* reserves queues that never bind
  regardless of lifecycle (i.e. the bindable set is permanently < sysfs
  count). In that case pinning combined channels to the bindable count at
  bring-up is the cleanest source-fix, and I-c's adaptive drop is the
  fallback. Decision deferred to Phase-0 evidence; not in the committed
  scope.

## 6. Phased plan

**Phase 0 — instrumented virtio-MQ repro (MANDATORY FIRST, decides Case 1 vs 2).**
- Venue: the standalone baked-image VM on incus/virtio with **4 combined
  channels** (NOT the loss mlx5 cluster — it can't repro). Confirm
  `ethtool -l ge-0/0/0` shows 4 combined.
- Deploy current master. Capture per-queue: bind outcome (bound vs
  EBUSY-exhausted), `binding.ready`, `userspace_bindings[idx].flags`,
  `userspace_ctrl.queue_count`, and the redirect-stage trace
  (`USERSPACE_TRACE_STAGE_*` with rx_queue/selected_queue/slot) +
  `drop_degraded_transit` reason counters.
- Drive LAN→WAN transit (v4 + v6); record sessions, per-queue drop counts,
  tx_completions.
- **Decision gate:** if all 4 queues bind & forward → **Case 1** (durability-
  only scope + close issue). If a subset EBUSYs / black-holes → **Case 2**
  (full scope). Record which kernel reservation/lifecycle mechanism (attach
  `git show`/dmesg/ethtool refusal) so Path C can be ruled in/out.

**Phase 1 — durability core (ship in BOTH cases).**
- `queue_count` from BOUND/ready bindings, not registered
  (`queueCountFromBindings` → key on `Ready` or `Bound && XSKRegistered`).
  Regression test: a registered-but-unbound surplus binding does not raise
  `queue_count`.
- Stranded-queue policy II-c: in `lib.rs`, a registered-but-not-ready
  *transit* packet on a queue with no ready binding takes XDP_PASS in
  non-strict mode (kernel forwards) and XDP_DROP in strict mode; add a
  distinct fallback reason + counter (`USERSPACE_FALLBACK_REASON_*`) and a
  Prometheus gauge `xpf_userspace_stranded_queue_*`. Keep the existing
  local/control PASS behaviour. Test: shim unit test asserting
  non-strict→PASS, strict→DROP on not-ready transit.
- Doc: correct `docs/image-validation.md` VENUE WARNING to the post-fix
  behaviour established by Phase 0 + document the degraded-mode semantics
  in `pkg/dataplane/README.md` / a userspace-dp doc.

**Phase 2 — adaptive queue-drop (ship in Case 2 only).**
- Extend the busy-binding watchdog to track *per-(ifindex,queue)*
  persistent EBUSY across K rebind cycles; on persistence, drop that queue
  from the candidate plan and re-plan with the reduced `queue_count` so the
  shim steers only over bindable queues (closes the stranded-queue window
  for good). Regression test: a queue that EBUSYs K times is removed from
  the plan and the remaining queues forward.
- Interaction guard: the global-`min` planner (`helpers.rs:759`) means a
  single-queue fabric parent already clamps every interface to 1 queue; any
  per-interface queue-drop must NOT resurrect the per-interface-vs-uniform
  planning collision the v6 plan scoped out (#1921 plan history). Keep
  uniform planning; the adaptive drop reduces the *global* bindable count,
  not per-interface asymmetric counts. This sub-decision gets its own
  review pass at /engineer time.

**Phase 3 — CONTINGENT Path C (ethtool -L), Case 2 + structural-reservation only.**
- Only if Phase 0 proves the bindable set is permanently < sysfs count
  regardless of socket lifecycle. Pin `combined = bindable_count` before
  any bind, survive rebinds, coordinate with the Go interface manager.
  Separate review round; explicitly NOT in the committed PR.

## 7. Acceptance criteria

- **Phase 0**: documented per-queue bind+forward matrix on 4-channel
  virtio establishing Case 1 or Case 2, with the kernel mechanism named.
- **No silent black-hole**: a forced partial-bind (test harness marks one
  binding not-ready) yields PASS-to-kernel (non-strict) or DROP (strict)
  with a non-zero health counter — never a silent transit loss with
  `enabled=true`.
- **Bound-aware steering**: `queue_count` equals deliverable-queue count;
  unit test proves a registered-but-unbound surplus binding does not
  inflate it.
- **Live forwarding**: on the 4-channel virtio venue, LAN→WAN v4+v6 transit
  yields non-zero sessions + tx_completions across the bound queue set
  (RX-delivery proof, not "all planned ready"), measured per the #1928
  signal discipline (sessions + tx_completions_total, NOT rx_packets_total).
- **No regression**: mlx5 loss cluster `make test-failover` 14/14 and
  line-rate smoke unchanged (the change is a no-op when all queues bind).

## 8. Risks

- **R1 — Case 1 (already fixed).** Static evidence can't rule this out; the
  whole full-fix scope may be unnecessary. Mitigated by Phase 0 as the
  first, cheap step; durability core still worth shipping.
- **R2 — II-c fail-open security posture.** PASS-to-kernel forwards
  unfirewalled on the stranded fraction. Mitigated: non-strict only,
  health-visible, transient (Phase 2 closes the window); strict mode stays
  fail-closed.
- **R3 — queue-bound redirect wall.** Tempting "redirect to a bound queue"
  (II-b/II-d) does NOT deliver (kernel drops cross-queue XSK redirect).
  The plan explicitly avoids relying on it.
- **R4 — adaptive-drop vs uniform planner collision** (Phase 2). The
  global-min planner + per-interface queue-drop can interact badly; scoped
  to a dedicated /engineer review round.
- **R5 — Path C `ethtool -L`** introduces a new privileged netlink
  dependency + RSS-width side effects + ZC-pin ordering; quarantined to
  contingent Phase 3.
- **R6 — venue.** Only the standalone virtio VM repros; the loss cluster
  cannot. Engineer-phase must bake/boot the virtio venue, not smoke on
  loss for the forwarding proof (loss only for the no-regression gate).

## 9. Test / validation plan

- Rust shim unit tests: not-ready transit → PASS(non-strict)/DROP(strict)
  with the right counter; `queue_count` from bound set.
- Go unit tests: `queueCountFromBindings` ignores registered-but-unbound;
  watchdog per-queue persistent-EBUSY drop (Phase 2).
- Live (engineer-phase): Phase-0 matrix; 4-channel virtio LAN→WAN v4+v6
  forwarding proof; mlx5 `make test-failover` 14/14 + smoke no-regression.

## 10. Rollback

Pure additive guards + a counted policy branch; revert is a single PR
revert. `queue_count`-from-bound is behaviourally identical when all queues
bind (the all-bind case). No schema/wire changes beyond new counter enums
(append-only).

## 11. Open questions (for reviewers)

- OQ1: Is Phase 0 Case 1 or Case 2? (Empirical — engineer-phase resolves;
  research can only design for both.)
- OQ2: Should II-c PASS-to-kernel be allowed at all, or is strict-DROP the
  only acceptable stranded-queue policy (i.e. forbid silent unfirewalled
  forwarding even transiently)? This is the central security/availability
  tradeoff the user should rule on.
- OQ3: If Case 2 is structural, is Path C (`ethtool -L combined N`) the
  preferred source-fix over I-c adaptive drop, accepting the new ethtool
  dependency?
- OQ4: Does `queue_count`-from-bound interact with the heartbeat/READY
  bootstrap deadlock the `:207-209` comment warns about (ctrl=0 → no RX →
  not ready)? Need to confirm Bound (not Ready) is the right key so a queue
  that bound but hasn't seen RX still counts.
