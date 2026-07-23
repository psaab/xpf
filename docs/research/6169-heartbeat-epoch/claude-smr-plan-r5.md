# Claude SMR — hostile plan review, #6169 boot-epoch, round 5 (plan v5)

Stance: HOSTILE re-attack of v5. Verified against `origin/master` @ `11e23b49a`.
Independent verdict written before reading Codex r5.

## Round-4 findings — resolution check (traced the failure schedules)

- **Ownership hold (r4 §1/§2).** I traced all three cases against the actual
  election paths and they hold:
  - *Asymmetric* (A persist-fails at bring-up → held/demoted; B healthy): B is
    **not** held, receives no *accepted* frames from A, times A out on the normal
    went-silent path (`handlePeerTimeout`) and promotes; A stays held. → exactly
    one primary. ✓
  - *Both-fail* (both held, both hold a prior epoch): each rejects the other's
    markerless frames, so neither refreshes `lastSeen`, but rejected frames still
    arrive → a held node does not promote via went-silent and (with the
    `noteRejectedFromPeer` gate on never-seen) does not reach never-seen either →
    **safe outage, not dual-primary**. ✓
  - *Sole node* (persist-fail, peer never existed): no frames at all → never-seen
    fires → promotes. ✓
  A useful sharpening: the epoch is persisted **once per incarnation at bring-up**,
  so a *mid-life* disk fault does **not** disable an already-persisted marker —
  the hold only ever arms at **bring-up / live key-enable persist-failure**, which
  makes the both-fail case rarer (both must fail to persist at boot). **Resolved.**
- **Checksummed never-regress (r4 §3).** Trusting a crc-valid value (even
  far-future) is safe: the `+1` floor lets the node exceed its own persisted
  value, so a crc-valid far-future value does **not** self-lock the local node
  (Codex r4's regression is gone and no new self-lock appears). **Resolved.**
- **Serialized read-max-write (r4 §4).** Re-read-and-`max` before every write kills
  the stale-retry overwrite. **Resolved.**
- **Single `m.mu` transaction / `lastSeen` / +68 reserve / #5639 drain (r4
  defects).** All addressed; `handlePeerHeartbeatLocked` avoids the reentrancy;
  no callee re-enters the admission path; ~10 Hz contention is negligible.
  **Resolved.**

## Must-carry into /engineer (implementation-precision, not redesign)

These are correctly *stated* in v5 but are the load-bearing details the PR must
get exactly right — they are the only remaining risk, and they are bounded:

1. **The `noteRejectedFromPeer` gate must be applied to the HELD node's never-seen
   path, and NOT to a healthy node's went-silent promotion.** The asymmetry is
   what makes both cases correct: a *healthy* node must take over despite receiving
   the failed peer's rejected markerless frames (asymmetric case), while a *held*
   node must treat rejected frames as "peer present" and refuse never-seen
   promotion (simultaneous-boot both-fail). Getting this backwards yields either a
   stuck-secondary outage in the asymmetric case or a dual-primary at boot. The PR
   must add this gate at `checkTimeout`/`handlePeerNeverSeen` precisely.
2. **The epoch-ownership hold must be a SEPARATE flag from `kernelUpgradeHold`,
   with the same demote+guard semantics.** Literally reusing `kernelUpgradeHold`
   conflates two sources — `ClearKernelUpgradeHold` on a real kernel promote would
   wrongly clear the epoch hold. The election guard checks
   `kernelUpgradeHold || epochOwnershipHold`; each source sets/clears its own flag.
3. **The hold must guard EVERY promotion site** (`runElection`, `electSingleNode`,
   the preempt shortcut, readiness-driven and monitor-driven election), exactly as
   the kernel hold already does — a missed site reopens the markerless dual-primary.

## Verdict

Five rounds in, the design has converged: the key-derived marker + separated
`(epoch,counter)` total order is the validated center, and the failure-mode state
machine (persist-before-emit + checksummed never-regress + serialized persistence
+ the epoch-ownership hold with never-seen-only promotion) now resolves every
schedule the prior rounds surfaced — I could not construct a new dual-primary,
regression, or unpersisted-escape schedule against v5. The remaining risk is
implementation precision (the three must-carry items), which is appropriate to
carry into `/engineer` behind the #5639 prerequisite rather than another plan
round. Given the four prior rounds each found a real issue I hold this at
moderate-high (not absolute) confidence, but the design is sound and complete.

VERDICT: PLAN-READY

---

## Self-correction (post-Codex-r5, same round)

My PLAN-READY was WRONG. Codex r5 refuted my three-case ownership proof with a
schedule I missed, and it is a **fundamental** point, not a fixable detail:

- **A one-way receive partition is indistinguishable from a genuinely-absent
  peer.** In my "both-fail" analysis I assumed a held node always receives the
  peer's (rejected) frames, so `noteRejectedFromPeer` proves presence. But if the
  **B→A direction is partitioned** (A→B still works), A receives **nothing** →
  A classifies B "never seen" → v5 permits held A to promote → **dual-primary**
  while B stays primary. UDP silence cannot tell "single-node deployment" from
  "one-way partition," so the claimed *sole-node-availability + partition-safety*
  is **impossible from heartbeat absence alone** (the split-brain/CAP reality).
- Corollary defects Codex found and I under-weighted: the reused kernel hold is
  a one-time demote (not revocable); the asymmetric takeover fails when B has
  `sawEpoch=false` (B accepts A's markerless and a higher-priority held A
  preempts → both-secondary outage) unless the hold is **peer-visibly
  ineligible**; `max(durable,candidate)` is not a **strict successor** (a reboot
  can re-publish `P` and reset the counter → dual-primary); key rotation cannot
  repair an ongoing write fault; the sender reads the key *after* snapshotting the
  body (a stale K1 body can be signed under K2); and `noteRejectedFromPeer` is
  both outside the txn and **attacker-gameable** (replayed frames become a
  liveness signal holding a survivor secondary).

**The correct resolution is to CHOOSE CONSISTENCY:** in a *configured* two-node
cluster a persist-failed node is **epoch-ineligible** (advertises ineligibility,
never promotes) → safe outage + operator override for availability; a genuinely
standalone deployment is an **explicit config** (no peer → no epoch → no hold).
This removes the impossible availability claim, the never-seen exception, and the
attacker-gameable presence signal.

**Corrected verdict: PLAN-NEEDS-MAJOR.**

VERDICT: PLAN-NEEDS-MAJOR
