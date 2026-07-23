# Plan of Action — #6177 RETH failover two-owner residual

- **Issue:** #6177 — "close the RETH VIP-removal sub-ms two-owner residual +
  harden barrier delete-by-key + add daemon-barrier unit test — #5640 follow-up"
- **Research branch:** `research/6177-reth-twoowner`
- **Base:** origin/master @ `11e23b49ac1e`
- **Prior art:** #5640 (merged #6174) fixed the ack-before-fence window; #6367
  (CLOSED, unsound) tried to extend the ack barrier to VIP removal.
- **Revision:** r3 (post Claude-SMR-r1/r2 + Codex-r2)
- **Status:** PLAN-READY (narrowed scope) — Residual-1's VIP-gate code change is
  **PLAN-KILLED**; **Residual-2 DROPPED** (partial hardening, Codex F4); **Residual-3
  (expanded to a branch-level demotion-order test) + a doc-accuracy fix are
  PLAN-READY**; a newly-discovered failure-path forwarding hazard (failed
  `SetRGActive(false)` still signals actuation) is **FILED as a new issue** for
  dedicated research (Codex F2/F3 — has an abort→blackhole tradeoff, not ship-ready).

---

## 1. Problem statement

#6177 bundles three residuals the #5640 hostile review flagged:

1. **Residual-1 (headline):** on the RETH-VRRP path, the #5640 applied-ack
   releases after the local demotion is *signaled* (VRRP priority-0 set +
   `resignCh` fired), not after the physical RETH VIPs are removed. The issue
   asks to gate `signalFailoverActuated` on `becomeBackup` completion to close a
   claimed "sub-ms residual two-owner window."
2. **Residual-2 (LOW, latent):** `disarmFailoverActuation`/timeout delete
   `failoverActuateWait[rgID]` by KEY without a channel-identity check; an older
   timed-out same-RG waiter could nuke a newer waiter's entry. Unreachable today
   (initiator serializes per-RG).
3. **Residual-3 (MINOR):** the novel #5640 barrier code
   (`armFailoverActuation`/`signalFailoverActuated`/`waitFailoverActuated`) has
   **no** direct daemon-side unit test.

The core research question the earlier #6367 attempt got wrong: **is Residual-1 a
real, closable two-owner window, and is the coordination-ACK the lever that
closes it?** #6367 was closed because it was firsthand-confirmed to close no real
window. This plan settles the design question, then scopes what actually ships.

## 2. Blast radius / affected code (read firsthand @ 11e23b49ac1e)

| Path | Role in the failover |
|------|----------------------|
| `pkg/vrrp/instance.go:1009-1035` | run-loop `resignCh` case: sends 3× `sendAdvert(0)` **then** `becomeBackup`→`removeVIPs` |
| `pkg/vrrp/instance.go:1107-1128` | `handleBackupRx`: on priority-0 advert, `masterDownTimer.Reset(1ms)` + `skipNextPreemptHold=true` |
| `pkg/vrrp/instance.go:760-819` | `stepBackup` masterDownTimer.C: skipHold → `becomeMaster` (addVIPs + GARP) |
| `pkg/vrrp/instance.go:1042-1046` | comment: post-resign takeover flows through the **ungated** masterDownTimer path, not the gated `preemptNowCh` — true even under sync-hold |
| `pkg/vrrp/instance.go:1365-1380` | `becomeBackup` → `surfaceStaleVIP(removeVIPs())` |
| `pkg/vrrp/instance_vip.go:24-129` | #5482 `surfaceStaleVIP` + bounded async reconcile (200ms×≤5) on removeVIPs failure |
| `pkg/vrrp/manager.go:721-737` | `ResignRG`: sets priority-0 synchronously + `triggerResign` (non-blocking) |
| `pkg/vrrp/manager.go:767-781` | `ForceRGMaster`: **no-op** for instances already `StateMaster` (:772) |
| `pkg/daemon/daemon_ha.go:340-390` | demotion branch: preflight fabric-redirect → `ResignRG` → blackhole → `SetRGActive(false)` → `signalFailoverActuated` |
| `pkg/daemon/daemon_ha.go:142-210` | the #5640 barrier: `armFailoverActuation`/`disarm`/`signal`/`waitFailoverActuated` |
| `pkg/daemon/daemon_ha.go:367,389` | failed `SetRGActive(false)` logs `Warn` and proceeds; `signalFailoverActuated` fires anyway (the Codex-F2 forwarding hazard) |
| `pkg/daemon/daemon_ha.go:604-620` | `reconcileRGStateLoop` — 2 s ticker re-drives `rg_active`, bounding the failed-`SetRGActive` dual-forward window |
| `pkg/cluster/sync_failover.go:71-124` | `SendFailover`: per-RG serialization (:82), `failoverAckTimeout` wait |
| `pkg/cluster/sync_failover.go:443-450` | `handleRemoteFailover`: `WaitFailoverApplied` gates the ack |
| `pkg/cluster/failover.go:313-352` | `commitRequestedPeerFailover` → `runElection` → (requester) ForceRGMaster no-op |

Scope of any code change is small and confined to `pkg/daemon` (barrier hardening
+ test) + docs. No dataplane/Rust change. No wire-protocol change.

## 3. Firsthand evidence — the failover timeline (verified, not inherited)

Requester **R** wants the RG; current owner **O** holds the RETH VIPs and is VRRP
MASTER. `t_p0` = the instant O emits its first priority-0 advert.

**Owner O (demoting), run-loop `resignCh` case:**
1. `sendAdvert(0)` ×3 — socket writes, ~µs each. Priority-0 is on the wire at `t_p0`.
2. `becomeBackup` → `removeVIPs` — netlink `RTM_DELADDR` per VIP. O stops answering
   ARP at `t_p0 + δ_remove`. (The figures below for `δ_remove` are **illustrative,
   not load-bearing** — see §4: the benign conclusion holds for ANY `δ_remove`,
   including the ~1 s failed-removal case, because the harm is masked independent of
   window width. No `δ_remove` measurement is claimed.)

**Peer R (promoting):**
3. Receives priority-0 at `t_p0 + δ_net`; `handleBackupRx` sets `masterDownTimer` to
   **1 ms** + `skipNextPreemptHold`.
4. masterDownTimer fires → `becomeMaster` → `addVIPs` → GARP. R starts answering ARP
   at `t_p0 + δ_net + 1ms + δ_add`.

**Two-owner overlap** = `O_stop − R_start` = `δ_remove − (δ_net + 1ms + δ_add)`.

- **Normal case:** `δ_remove` (sub-ms) < `1ms + δ_net + δ_add` ⇒ overlap is
  **negative** — i.e. there is a **~1 ms blackhole gap** (O has released, R has not
  yet added), NOT a two-owner window. This is bit-identical to the documented
  "planned shutdown → peer takes over in ~1 ms" path (CLAUDE.md, Chassis Cluster).
- **Slow-removal case:** if `δ_remove` exceeds ~1 ms (netlink contention, many
  VIPs, run-loop scheduling delay), overlap = `δ_remove − ~1ms > 0`. A genuine
  two-owner window bounded by removeVIPs latency — realistically sub-ms to a few ms.
- **Failed-removal case:** `removeVIPs` errors → O keeps the VIP until the #5482
  `surfaceStaleVIP` reconcile clears it (typically within ~1 s; the reconcile is
  bounded to 5 attempts at 200 ms, and a pathological netlink wedge logs Error and
  defers to the next transition — a pre-existing #5482 property, not introduced here).
  Two-owner for that span. **Independent of the ack barrier**; the ack-barrier levers
  under debate do nothing for it either.

**Why the coordination-ACK is not the lever on the dominant path (the #6367 error),
and the one corner where it CAN order (Codex F1):**

- On the **priority-0 path** — which covers every failover where at least one of O's
  three priority-0 adverts arrives, i.e. essentially all planned/requested failovers —
  R's VIP takeover is driven by the **ungated** masterDownTimer 1 ms path
  (`handleBackupRx` instance.go:1110-1128; `recordMasterAdvert` :1042-1046 confirms it
  is taken even under sync-hold — the #2082 preempt gate applies only to the
  `preemptNowCh` shortcut). The requester's post-ack commit (`SendFailoverCommit` →
  `commitRequestedPeerFailover` → `runElection` → `ForceRGMaster`) is a **no-op** when
  the instance is already `StateMaster` (manager.go:772). R is already MASTER via
  priority-0, typically **before** the ack round-trip completes. So on this path
  gating the ack on VIP removal adds **no** ordering guarantee — #6367's premise
  ("hold the ack → peer promotes later") is false.
- **The narrowing (Codex F1):** in the pathological case where **all three** priority-0
  adverts are lost, R does NOT enter the 1 ms path; it promotes via the **ungated
  masterDown safety timer** (~97 ms) or, if the ack round-trip is faster, via the
  post-ack `ForceRGMaster`. In that sub-case the ack CAN order R's promotion. But this
  requires a 3-advert loss burst on the dataplane VF at the exact failover instant AND
  (for a two-owner window) O's removeVIPs to be slow/failed too — a compound-rare
  corner, and it is not what #6177's "sub-ms VIP-removal window" describes. The honest
  claim is therefore: **the ack is not the lever on the dominant priority-0 path;
  gating it on VIP removal does not close the general window, only a compound-rare
  lost-advert subset — for which #6367's mechanism was still the wrong tool** (it gated
  on VIP removal, not on the actual forwarding property, see §3-forwarding below).

**What the ack barrier genuinely does (retained #5640 value):** it withholds the
applied-ack until O's `rg_active` is cleared (daemon_ha.go:367 precedes :389), so
the requester does not treat the failover as "applied" — RG0 config-write
ownership handoff, fabric-redirect teardown — while O is still cluster-active
**forwarding**. That is a coordination/forwarding property, not a VIP property.

**Harm — split the SUCCESS path from the FAILURE paths (Codex F2 correction):**

*Success path (removeVIPs + SetRGActive both succeed) — BENIGN:*
- Transit traffic landing on O is **fabric-redirected to R** — the demotion preflight
  `tryPrepareUserspaceRGDemotion` is a **best-effort, bounded (5 s) blocking** prep
  that runs BEFORE `ResignRG` (daemon_ha.go:348-354) and shifts the flow cache to
  `FabricRedirect` (on a prep failure it logs `Warn` and proceeds — brief
  TCP-recoverable loss, not a durable blackhole).
- `rg_active` is cleared on O, so O does not cluster-forward for the RG.
- R's GARP re-points ARP within ms; RETH uses a **per-node** virtual MAC — the overlap
  is a transient duplicate-ARP nuisance. No RST, no durable blackhole, no dual-forward.
  On this path the sub-ms VIP window is benign and closing it buys nothing.

*Failure paths — NOT unconditionally benign (r2 overclaimed; Codex F2):*
- **Failed `removeVIPs`:** #5482 bounds retry **effort**, not stale-VIP **lifetime** —
  after `vipRemoveReconcileMax` (5) attempts at 200 ms it logs Error and leaves the VIP
  until the next transition (instance_vip.go:125). So a wedged netlink can leave a stale
  VIP for longer than ~1 s. Transit is still fabric/rg_active-covered, but the plan may
  not claim "benign for any δ_remove."
- **Failed `SetRGActive(false)`:** the control-socket call at daemon_ha.go:367 only logs
  a `Warn`; `signalFailoverActuated` (:389) still fires. So the ack is released with O's
  `rg_active` **still true** — O keeps cluster-forwarding for the RG. Combined with R's
  priority-0 promotion + commit, **both nodes can forward** for up to the reconcile
  period. Firsthand bound: `reconcileRGStateLoop` (daemon_ha.go:604-620) re-drives
  rg_active every **2 s** (+ immediate `reconcileNowCh` nudge), so the dual-forward
  window is **~2 s and self-heals** — real, bounded, but NOT what the r2 "universal
  benign" implied. This is the genuinely security-relevant residual, and it is on the
  **`SetRGActive`-failure axis, not the VIP-timing axis** — so it is out of Residual-1's
  stated scope (VIP removal) and is filed separately (§5 Option D / §11).

**Security threat model (the issue is labeled `security`).** (a) **Not
attacker-triggerable** — the window opens only on an operator-/weight-driven planned
failover coincident with a rare control-socket or netlink failure, not on demand from
the data path. (b) The benign VIP-timing overlap (success path) is a transient
duplicate-ARP with per-node MACs. (c) The **dual-active forwarding** condition — the one
with real security weight — arises only on a **failed `SetRGActive(false)`**, is bounded
to the ~2 s reconcile horizon, and #5640's *stated* "ack ⇒ rg_active cleared" invariant
does not actually hold on that failure (the ack signals anyway). Closing THAT is the
security-relevant work — see §5 Option D — but it has its own abort→blackhole tradeoff
and is filed for dedicated research rather than bundled here.

## 4. Design question Q1 — is there a real two-owner window at all?

**Answer (refined after Codex F2): the VIP-*timing* window is benign; a distinct
forwarding hazard on the failure path is real but out of Residual-1's scope.**

- On a normal (success-path) failover there is **no VIP overlap** — a ~1 ms blackhole
  gap, identical to the documented planned-shutdown takeover. A VIP overlap appears
  only on slow/failed removal; on the success path it is a benign duplicate-ARP
  nuisance masked by fabric-redirect + rg_active-clear + GARP/per-node-MAC. Closing this
  VIP-timing window (Residual-1's literal ask) buys nothing.
- **The r2 "benign for ANY δ_remove / any failure" claim was too strong** (Codex F2). A
  **failed `SetRGActive(false)`** signals actuation anyway (daemon_ha.go:367→389),
  producing a real **~2 s reconcile-bounded dual-forwarding** window; a **failed
  removeVIPs** can persist past the #5482 5-attempt reconcile until the next transition
  (instance_vip.go:125). These live on the `SetRGActive`/netlink-failure axis, not the
  VIP-timing axis. They do NOT resurrect Residual-1 (gating the ack on VIP removal
  addresses neither), but they ARE the security-relevant residual — see §5 Option D +
  §11 (filed separately).
- **PLAN-KILL for Residual-1 stands**: its lever (gate ack on VIP removal) is wrong for
  BOTH the benign VIP-timing window (nothing to gain) and the real forwarding hazard
  (wrong property — that needs the rg_active fence, §5-D). The unmeasured `δ_remove`
  is non-load-bearing for the KILL: the success-path window is benign at any width, and
  the failure-path harm comes from rg_active/forwarding state, not VIP timing.

## 5. Design question Q2 — if we wanted to close it, what is the lever? (Multiple Path Options)

### Option A — reorder O's resign: `removeVIPs` BEFORE priority-0 adverts
Move `becomeBackup`/`removeVIPs` ahead of `sendAdvert(0)` in the `resignCh` case.
- **Closes:** the slow-removal overlap (O has released before it tells R to take over).
- **Costs / rebuttal:**
  - Does **not** close the failed-removal window — the more dangerous one. Either
    (i) still send priority-0 on failure ⇒ identical to today (#5482 reconcile), or
    (ii) withhold priority-0 on failure ⇒ R only takes over via the ~120 ms
    masterDown **safety timer** (instance.go:1031) — a catastrophic failover-latency
    regression on the exact path (netlink trouble) where fast failover matters most.
  - **Lengthens the normal-path blackhole** by `δ_remove`: today O's removal overlaps
    R's 1 ms timer; serializing them adds the removal time to the gap.
  - Regresses the documented ~1 ms planned-takeover budget; requires
    `make test-failover` re-validation on the loss cluster.
  - **Hybrid** ("remove first; on success send priority-0, on failure send priority-0
    anyway"): it DOES close the overlap for every SUCCESSFUL slow removal (Codex fairly
    rebuts the r2 "buys nothing"). But you cannot know the removal outcome without
    attempting it, and attempting-first IS the reorder — so it adds `δ_remove` to EVERY
    normal failover and does nothing for the dangerous FAILED-removal case (still sends
    priority-0 with a stale VIP present, identical to today). Net: taxes every good case
    to shrink a benign slow-success nuisance; still net-negative, same as A.
  - **Verdict: NET NEGATIVE** — trades a benign, already-covered sub-ms window for a
    real latency/availability loss and does not even close the failed case.

### Option B — VRRP-layer: delay R's priority-0 fast-takeover until O confirms removal
Have O signal "VIPs removed" over the sync channel and hold R's takeover until then.
- **Closes:** all overlap (R never adds before O removes).
- **Costs / rebuttal:**
  - Adds a full sync round-trip (tens of ms) to the ~1 ms priority-0 fast-path — it
    reintroduces exactly the ack-round-trip dependency the fast-path exists to avoid.
  - New failure mode: a lost confirm ⇒ R never takes over ⇒ both nodes secondary
    (no primary) until a timeout. Strictly worse than a benign duplicate-ARP.
  - **Verdict: NET NEGATIVE** — large failover-latency regression + a new split-none
    hazard to close a benign window.

### Option C — accept the window as benign; PLAN-KILL the Residual-1 code change
Do not change the resign ordering or the ack barrier's VIP semantics. Document the
analysis (Q1–Q3) in the HA docs so the decision is durable and the next reviewer
does not re-derive #6367.
- **Verdict: RECOMMENDED.** The window is benign and both real levers regress the
  ~60 ms/~1 ms failover budget or introduce a worse failure mode.

### Option C+ (optional add-on to C) — observability only
Emit a `Warn` + a counter/metric when a resign's `removeVIPs` exceeds the
masterDownInterval (i.e. when the benign window could become non-trivial). Purely
additive, no behavior change; converts "benign in theory" into "measurable in
practice." Offered as optional; not required for PLAN-READY.

### Option D — hard rg_active forwarding fence (Codex F3; the security-relevant lever) — FILE SEPARATELY
Codex correctly notes the plan cannot dismiss Residual-1 without evaluating a hard
forwarding fence, and that the real closable property is `rg_active`-clear, not VIP
timing. Two sub-variants:
- **D1 (Codex's literal proposal):** reorder so `rg_active` is cleared **successfully
  before** `ResignRG`/priority-0; if the clear fails, do not advertise resignation or
  ack — retain the owner, fail the transfer. **Conflicts directly with #485**
  (daemon_ha.go:341-347 deliberately does `ResignRG` BEFORE clearing `rg_active` so the
  demoting node keeps forwarding via the fabric path during the transition — clearing
  first re-introduces a self-blackhole while it is still VRRP-master). So D1 is not free.
- **D2 (#485-compatible refinement):** keep the ordering, but make
  `signalFailoverActuated` (:389) **conditional on the `SetRGActive(false)` at :367
  succeeding** — downgrade to `failoverAckFailed` on failure so the requester HOLDS
  instead of committing. This makes #5640's *stated* "ack ⇒ rg_active cleared"
  invariant actually hold and prevents the requester from reaching dual-active
  forwarding.
- **Why NOT ship D here (firsthand tradeoff):** withholding the ack cannot un-take the
  peer's **priority-0 VIP move** (already done at ~1 ms). On a failed clear, D2 makes
  the requester ABORT — leaving the peer holding the VIP with `rg_active=false` while O
  is demoted, which can produce a **longer blackhole** (both `rg_active=false`, peer owns
  L2, cluster must re-elect via the #5079 lease path) than today's ~2 s
  dual-forward-then-reconcile-settle. Whether D2 is a net win depends on a careful
  comparison of "bounded dual-forward" vs "bounded blackhole + re-election," the #485
  interaction, and the #5079 lease timing — a **design pass in its own right**.
- **Verdict:** Option D targets the RIGHT property (forwarding, not VIP timing) but is
  **not ship-ready** — it has a real abort→blackhole tradeoff and a #485 conflict.
  **File it as a new issue for dedicated `/research`** rather than bundling it into the
  #6177 follow-up. This keeps the #6177 PR small and honest and does not dismiss the
  hazard (it is tracked). See §11.

## 6. Design question Q3 — independent residuals worth landing regardless

Both are real, cheap, and **do not depend on Q1/Q2**. They harden and cover the
**existing** #5640 barrier we are keeping:

- **Residual-2 — delete-by-key identity hardening → DROPPED (Codex F4).** #6367's
  version hardened only `disarm`/`timeout` to channel-identity while
  `signalFailoverActuated` stays key-only (can close a newer generation) and
  `armFailoverActuation` can overwrite an existing entry — i.e. it half-hardens a
  forbidden state, backed by tests that manufacture that state. The clean choices are
  EITHER a coherent generation/identity model across all four of arm/signal/timeout/
  disarm (only worth it once concurrency is actually reachable) OR keep today's
  serialized invariant. Since same-RG concurrency is unreachable (initiator serializes
  per-RG at sync_failover.go:82), **YAGNI → drop Residual-2**. (This also resolves the
  r2 §11 Q-b in favor of dropping.)
- **Residual-3 — daemon-barrier unit test, EXPANDED to branch-level (Codex F5).**
  Keep the primitive coverage (arm → signal | timeout → release/downgrade + no
  stale-channel leak) AND add a **branch-level demotion-order test** that drives the
  `watchClusterEvents` demotion branch with `SetRGActive(false)` **succeeding** and
  **failing**, asserting the current behavior (signal fires in both cases today) and
  the #5640 invariant (rg_active clear is attempted before the signal). This both
  closes the #5640 coverage gap AND documents-in-test the exact failed-`SetRGActive`
  behavior that Option D would later change — so the follow-up research has a pinned
  baseline. Primitive-only tests must NOT claim to protect the ordering (Codex F5).
- **Doc-accuracy fix.** `docs/session-sync-architecture.md` describes the #5640
  release as gating on the demotion being actuated; ensure the RETH wording says
  "resign **signaled** + priority-0 set + rg_active clear **attempted**", NOT "VIPs
  removed", and record the Q1–Q3 rationale: the VIP-timing window is benign, the
  failed-`SetRGActive` forwarding hazard is the real residual (tracked in the new
  Option-D issue), and #5640's "ack ⇒ rg_active cleared" invariant does not currently
  hold on a `SetRGActive` failure.

## 7. Recommended path (overall)

**PLAN-READY with a narrowed scope**, delivered as one small `/engineer 6177` PR:

1. **PLAN-KILL Residual-1's code change** (Option C). Do NOT gate the ack on VIP
   removal, do NOT reorder the resign. Record the rationale in the HA docs.
2. **DROP Residual-2** (partial delete-by-key hardening) — Codex F4, YAGNI.
3. **Land Residual-3, expanded to a branch-level demotion-order test** covering
   `SetRGActive(false)` success + failure (Codex F5) — `pkg/daemon` only.
4. **Land the doc-accuracy fix** + the Q1–Q3 design-decision writeup in
   `docs/session-sync-architecture.md` (and a pointer from `pkg/vrrp/README.md` /
   the HA cluster doc as appropriate).
5. **FILE a new issue** for Option D (the failed-`SetRGActive(false)` → signal-anyway
   dual-forwarding hazard / the rg_active forwarding fence). It targets the right
   property but has a real abort→blackhole + #485 tradeoff → dedicated `/research`, not
   this PR. Do NOT close #6177's security concern silently — it is tracked in the new
   issue. (Per `feedback_triage_new_issue_per_finding`.)
6. **Optional:** Option C+ observability warn/metric — engineer's discretion; deferrable.

**Alternative framing (X):** PLAN-KILL #6177 wholesale and spin #3+doc into a fresh
issue. Rejected — #3+doc are small, cohesive, already tracked here; a fresh issue adds
process for no gain. The `plan-kill` label semantics apply to the Residual-1 sub-goal
(and the dropped Residual-2), documented inside an otherwise PLAN-READY plan; the
security-relevant Option-D hazard moves to its own tracking issue.

## 8. Risk analysis

- **Keeping the benign window:** the only realistic exposure is a duplicate-ARP
  nuisance on slow/failed removal, already masked by fabric-redirect + rg_active +
  GARP + #5482. No new risk introduced (status quo).
- **Residual-2 change:** the identity check is strictly more conservative than the
  key-only delete; the nil-ch legacy path preserves current behavior. Risk: a subtle
  mismatch between the armed channel and the one passed to disarm — covered by the
  Residual-3 tests (`SignalReleasesAndCleansUp`, `TimeoutDowngradesAndCleansUp`,
  `DisarmIdentityChecked`).
- **Docs-only Residual-1 decision:** zero runtime risk.
- **Regression surface:** none touches the VRRP run-loop, the resign ordering, or
  the dataplane, so the ~60 ms/~1 ms failover budget is unchanged. `make
  test-failover` still required per CLAUDE.md because the file set touches
  `pkg/daemon` HA code, but no timing change is expected — the smoke is a
  **regression gate, not a measurement of the window** (nothing closes the window;
  the smoke proves nothing regressed).
- **Invariant to protect (#5640).** The retained genuine property is
  `SetRGActive(false)` (daemon_ha.go:367) ordered BEFORE `signalFailoverActuated`
  (:389) — the ack releases only after rg_active is cleared. The Residual-2 edit
  touches the barrier's disarm/arm signatures; the /engineer PR MUST NOT let that
  refactor move `signalFailoverActuated` ahead of `SetRGActive(false)`. Call it out
  in the PR and cover it with the existing ordering (a review-checklist item; the
  demotion-branch order is unit-observable via the barrier tests).

## 9. Test plan

- **Unit (Residual-3, primitive):** `pkg/daemon` barrier tests — arm→signal→release
  (nil err), arm→timeout→downgrade + entry cleaned up. Fail-on-revert per project
  discipline (neutralize → bound test RED → revert → green).
- **Unit (Residual-3, branch-level — Codex F5):** drive the `watchClusterEvents`
  demotion branch (or an extracted testable seam) with a mock dataplane where
  `SetRGActive(false)` SUCCEEDS and where it FAILS; assert the demotion-order invariant
  (rg_active clear attempted before `signalFailoverActuated`) and pin the current
  failed-`SetRGActive` behavior (signal still fires) so the Option-D follow-up has a
  baseline. This is the test that actually protects the ordering — primitive tests do
  not.
- **No Residual-2 test** — Residual-2 is dropped.
- **No new VRRP timing test** — no timing behavior changes.
- **Smoke:** `make test-failover` on the loss userspace cluster (v4+v6, push +
  reverse) once, to confirm the `pkg/daemon` HA touch did not regress failover.
  Expectation: unchanged ~zero-drop failover; this is a **regression gate**, not a
  measurement of the (unchanged) window.

## 10. Docs to update

- `docs/session-sync-architecture.md` — correct the RETH release wording; add the
  Q1–Q4 "why the RETH VIP window is intentionally not closed" subsection.
- `pkg/vrrp/README.md` and/or the HA cluster doc — one-line pointer to the decision.
- `_Log.md` — per project logging rules, on implementation.
- This plan doc is the durable research artifact; link it from the #6177 comment.

## 11. Open questions / decisions for the user

- **Q-a:** Adopt the narrowed-scope PR (Framing Y, recommended) or the fresh-issue
  split (Framing X)? Default: Y (land Residual-3 branch-level test + doc fix on #6177).
- **Q-b:** Confirm **dropping Residual-2** (Codex F4, YAGNI) — no half-hardening.
  Default: drop.
- **Q-c:** File the Option-D issue now (failed-`SetRGActive` forwarding fence,
  security-relevant, needs its own research)? Default: yes — file before closing
  #6177's security label so nothing is silently dismissed.
- **Q-d:** Include Option C+ observability (warn/metric on slow resign removal) in the
  same PR, or defer? Default: defer (keep the PR minimal).
- **Q-e:** Confirm the `plan-kill` label applies to Residual-1 + Residual-2 sub-goals,
  while #6177 proceeds to a narrowed `/engineer` for the branch-level test + doc.
