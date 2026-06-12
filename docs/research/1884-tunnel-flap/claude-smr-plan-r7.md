# Claude SMR hostile plan review — #1884 r7 (plan v7, ef6539bc642c)

Verdict: **PLAN-READY**.

The guarded transfer makes the claim kernel-state-faithful by
construction: `appliedRI[name]` now only ever names a VRF the link was
OBSERVED enslaved to (stanza bind we issued, or 0a bind we verified).
I walked the §11 r7 edges:

- **Q1a — retained-A then 0a-bind-B succeeds later**: the next apply's
  veto branch observes master == vrf-B and transfers the claim to B;
  list removal then unbinds B. No wrong unbind, no stuck claim.
- **Q1b — permanently failing 0a bind**: claim stays A while the
  kernel stays mastered to A — faithful; list-removal then unbinds A,
  which is correct (config wants none, kernel has A, A was ours).
- **Q1c — VRF A deleted out from under a retained claim**: the kernel
  frees the slave when vrf-A is deleted by the VRF reconcile; the
  later unbind path hits VRF-not-found ⇒ claim cleared, nothing to
  unbind. No leak.
- **Q1d — same-apply stanza re-bind**: stanza nonempty short-circuits
  the veto branch entirely (bind + claim overwrite) — no interaction.
- **Q2 — fold blast**: v7 touches the A.5 transfer guard and two MTU
  text passages (now consistent with the A.3 switch); §9 rows updated.
  Nothing else moved; no earlier closure re-opened. The extra
  `LinkByName("vrf-"+RIListMember)` on the veto branch is one netlink
  lookup per tunnel per apply — negligible at commit cadence.

My r4 and r6 soft-passes are recorded in this trail; for this round I
specifically re-attacked the claim state machine as a whole
(stanza/list/none × bind-success/failure × VRF-exists/deleted ×
restart) and found no remaining transition that strands a master we
own, touches a master we do not, or loses retry state on a transient
error. Converged.
