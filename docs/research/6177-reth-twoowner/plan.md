# Plan of Action — #6177 RETH failover two-owner residual

- **Issue:** #6177 — "close the RETH VIP-removal sub-ms two-owner residual +
  harden barrier delete-by-key + add daemon-barrier unit test — #5640 follow-up"
- **Research branch:** `research/6177-reth-twoowner`
- **Base:** origin/master @ `11e23b49ac1e`
- **Prior art:** #5640 (merged #6174) fixed the ack-before-fence window; #6367
  (CLOSED, unsound) tried to extend the ack barrier to VIP removal.
- **Revision:** r2 (post Claude-SMR-r1)
- **Status:** PLAN-READY (narrowed scope) — Residual-1 code change is
  **PLAN-KILLED**; Residuals #2+#3 + a doc-accuracy fix are PLAN-READY.

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

**Why the coordination-ACK is provably not the lever (the #6367 error):**

- R's VIP takeover is driven by O's **priority-0 advert** via the **ungated**
  masterDownTimer 1 ms path (`handleBackupRx` instance.go:1110-1128; the
  `recordMasterAdvert` note at :1042-1046 confirms this path is taken even under
  sync-hold — the #2082 preempt gate applies only to the `preemptNowCh` shortcut).
- The requester's post-ack commit (`SendFailoverCommit` →
  `commitRequestedPeerFailover` → `runElection` → `ForceRGMaster`) is a **no-op**
  when the instance is already `StateMaster` (manager.go:772). R is already MASTER
  via priority-0, typically **before** the ack round-trip completes.
- Therefore gating the ack on O's VIP removal adds **no** ordering guarantee over
  when R adds VIPs. #6367's premise ("hold the ack → peer promotes later → no
  overlap") is false: the peer promotes on VRRP, not on the ack.

**What the ack barrier genuinely does (retained #5640 value):** it withholds the
applied-ack until O's `rg_active` is cleared (daemon_ha.go:367 precedes :389), so
the requester does not treat the failover as "applied" — RG0 config-write
ownership handoff, fabric-redirect teardown — while O is still cluster-active
**forwarding**. That is a coordination/forwarding property, not a VIP property.

**Harm during any VIP overlap (slow/failed removal):**
- Transit traffic landing on O is **fabric-redirected to R** — the demotion preflight
  `tryPrepareUserspaceRGDemotion` is a **best-effort, bounded (5 s) blocking** prep
  that runs BEFORE `ResignRG` (daemon_ha.go:348-354) and shifts the flow cache to
  `FabricRedirect`. It is ordered-before VIP removal but not a hard guarantee: on a
  prep failure it logs `Warn` and proceeds (readiness.go:23-27), leaving the residual
  exposure as brief **packet loss** (TCP-recoverable), not a guaranteed zero-loss
  redirect. Either way transit is not durably blackholed.
- `rg_active` is cleared on O, so O does not cluster-forward for the RG.
- R's GARP re-points ARP caches within ms; RETH uses a **per-node** virtual MAC, so
  the overlap is a transient duplicate-ARP nuisance, resolved by the gratuitous ARP.
- Net: no TCP RST, no durable transit blackhole, no forwarding-correctness violation,
  no lasting dual-owner. The window is **benign**.

**Security threat model (the issue is labeled `security`).** The window is (a) **not
attacker-triggerable** — it occurs only on an operator-/weight-driven planned
failover, not on demand from the data path, so an adversary cannot induce it at will;
(b) bounded to a transient duplicate-ARP with per-node MACs, resolved by GARP; (c)
the dual-active **forwarding** hazard — the one with real security weight (two nodes
forwarding/NATing the same flows, asymmetric state) — is **already closed by #5640's
`rg_active`-clear-before-ack gate, which this plan retains**. What remains after
#5640 is an on-wire ARP-answering nuisance with no forwarding, no session
duplication, and no attacker lever. The `security` residual is therefore empty
beyond what #5640 already fenced.

## 4. Design question Q1 — is there a real two-owner window at all?

**Answer: not on a normal failover** (it is a ~1 ms blackhole gap, not overlap).
A genuine VIP overlap exists only on slow/failed removal, is sub-ms to a few ms
(or ~1 s on outright failure), and is **benign**: fabric-redirect (best-effort)
covers transit, `rg_active`-clear covers forwarding, GARP + per-node MAC covers ARP,
and #5482 covers failed removal. The "two-owner window" the issue names is a
duplicate-ARP nuisance already masked by existing mechanisms, not a correctness or
security hole.

**The benign conclusion is independent of the window's width.** Crucially the
argument does NOT rest on `δ_remove` being small: even the worst case (outright
removal failure, up to the #5482 reconcile clearing it — typically ~1 s, with a
bounded-reconcile tail on a wedged netlink) is masked by the same four mechanisms. So the unmeasured `δ_remove` magnitude is not load-bearing — widening
the window does not create harm, it only lengthens a nuisance that the existing
mechanisms already absorb. This is why no `δ_remove` measurement is needed to reach
PLAN-KILL, and why closing the window (which only shrinks the nuisance) buys nothing.

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
  - **Hybrid rebuttal** ("remove first; on success send priority-0, on failure send
    priority-0 anyway"): you cannot know the removal outcome without attempting it,
    and attempting-first IS the reorder — so the hybrid adds `δ_remove` to EVERY
    normal failover while, on the failed path, still sending priority-0 with a stale
    VIP present (identical to today). It buys nothing on the dangerous case and taxes
    every good case. Same net-negative as A.
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

## 6. Design question Q3 — independent residuals worth landing regardless

Both are real, cheap, and **do not depend on Q1/Q2**. They harden and cover the
**existing** #5640 barrier we are keeping:

- **Residual-2 — delete-by-key identity hardening.** Change
  `disarmFailoverActuation(rgID)` → `disarmFailoverActuation(rgID, ch)` deleting the
  map entry only when the stored channel is still the exact one the caller
  armed/waited on; `armFailoverActuation` returns that channel; the timeout path and
  the ManualFailover error paths pass their own. Latent today (initiator serializes
  per-RG at sync_failover.go:82) but a correct defense-in-depth + symmetry fix.
  **YAGNI weighing:** it hardens an unreachable-today path, which cuts against
  keep-it-simple. The case FOR landing it anyway: (i) the #5640 hostile review
  explicitly flagged it; (ii) it is a ~10-line change with no behavior change on the
  reachable path (nil-ch legacy delete preserved); (iii) the Residual-3 barrier tests
  we are adding would otherwise exercise a half-hardened barrier — the identity check
  and its fail-on-revert test are cohesive with that coverage. Decision: land it, but
  this is a genuine judgment call — if the user prefers minimalism, dropping Residual-2
  (keeping #3 + the doc fix) is a defensible narrower scope (see §11 Q-b).
- **Residual-3 — daemon-barrier unit test.** Add direct coverage of
  arm → (signal | timeout) → release/downgrade + no stale-channel leak, with no
  cluster/VRRP manager. Closes the coverage gap the #5640 review flagged.
- **Doc-accuracy fix.** `docs/session-sync-architecture.md` describes the #5640
  release as gating on the demotion being actuated; ensure the RETH wording says
  "resign **signaled** + priority-0 set + rg_active cleared", NOT "VIPs removed",
  and record the Q1–Q4 rationale for why the VIP window is intentionally not closed.

## 7. Recommended path (overall)

**PLAN-READY with a narrowed scope**, delivered as one small `/engineer 6177` PR:

1. **PLAN-KILL Residual-1's code change** (Option C). Do NOT gate the ack on VIP
   removal, do NOT reorder the resign. Record the rationale in the HA docs.
2. **Land Residual-2** (delete-by-key identity hardening) — `pkg/daemon` only.
3. **Land Residual-3** (daemon-barrier unit test).
4. **Land the doc-accuracy fix** + the Q1–Q4 design-decision writeup in
   `docs/session-sync-architecture.md` (and a pointer from `pkg/vrrp/README.md` /
   the HA cluster doc as appropriate).
5. **Optional:** Option C+ observability warn/metric — engineer's discretion; can be
   deferred to a follow-up without blocking.

**Alternative framing (X):** PLAN-KILL #6177 as written and spin #2+#3+doc into a
fresh scoped issue. Rejected in favor of the narrowed-scope PR because #2/#3/doc are
small, cohesive, and already tracked here; a fresh issue adds process for no gain.
The `plan-kill` label semantics apply to the Residual-1 sub-goal, documented inside
an otherwise PLAN-READY plan.

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

- **Unit (Residual-3):** `pkg/daemon` barrier tests — arm→signal→release (nil err),
  arm→timeout→downgrade + entry cleaned up, and the identity-checked disarm
  (`TestFailoverActuationDisarmIdentityChecked`). Each fix verified fail-on-revert
  (neutralize → bound test RED → revert → green), per project discipline.
- **Unit (Residual-2):** the disarm-identity test is the fail-on-revert guard —
  reverting to the key-only `delete` must go RED.
- **No new VRRP timing test** — no timing behavior changes.
- **Smoke:** `make test-failover` on the loss userspace cluster (v4+v6, push +
  reverse) once, to confirm the `pkg/daemon` HA touch did not regress failover.
  Expectation: unchanged ~zero-drop failover; this is a gate, not a measurement of
  the (unchanged) window.

## 10. Docs to update

- `docs/session-sync-architecture.md` — correct the RETH release wording; add the
  Q1–Q4 "why the RETH VIP window is intentionally not closed" subsection.
- `pkg/vrrp/README.md` and/or the HA cluster doc — one-line pointer to the decision.
- `_Log.md` — per project logging rules, on implementation.
- This plan doc is the durable research artifact; link it from the #6177 comment.

## 11. Open questions / decisions for the user

- **Q-a:** Adopt the narrowed-scope PR (Framing Y, recommended) or the fresh-issue
  split (Framing X)? Default: Y.
- **Q-b:** Include Option C+ observability (warn/metric on slow resign removal) in
  the same PR, or defer? Default: defer (keep the PR minimal).
- **Q-c:** Confirm the `plan-kill` label applies to the Residual-1 sub-goal only,
  while #6177 proceeds to a narrowed `/engineer` for #2+#3+doc.
