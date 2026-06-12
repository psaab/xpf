# Claude SMR hostile plan review — #1884 r8 (plan v8, bdb205688381)

Verdict: **PLAN-READY**.

(My r7 pass validated the list-branch guard but missed that the stanza
branch had the identical blindness — Codex r7's catch. Recorded; this
round I re-derived the claim state machine from the v8 invariant
rather than re-checking individual traces.)

- **Q1 — remaining stale-claim/stale-master sequences**: with both
  branches guarded, `appliedRI[name]` is set ONLY from (i) a
  successful `BindInterfaceToVRF` return or (ii) a directly observed
  `MasterIndex == index(vrf-<RIListMember>)`. By induction every claim
  value was a REAL master at write time. Divergence after the write
  (out-of-band master change, VRF delete, kernel auto-unslave) is
  caught at unbind time by the identity check (mismatch / not-found ⇒
  clear, never unbind) — so no sequence can unbind a master that is
  not simultaneously (a) the claim, (b) currently on the link, and
  (c) a vrf-* device the daemon owns. Stranding requires a claim to
  vanish while a master we set remains: claims are only cleared on
  successful unbind, mismatch (master already not ours), not-found
  (master already gone), or removal/Clear (link deleted) — none
  leaves an owned master behind. Persistent-failure loops (stanza
  bind retried every apply; unbind retried via retention) converge
  when the operation eventually succeeds and remain kernel-faithful
  while it does not.
- **Q2 — r7 fold blast**: one bullet in A.5, one comment block in
  A.3, two test rows. The MTU contradiction is resolved in the only
  consistent direction (prose now matches the switch and row 6b).
  Nothing else moved; no earlier closure re-opened.

Converged. The plan has survived seven adversarial rounds with every
verified counterexample folded; I have no remaining findings and
recommend PLAN-READY as the final research verdict, contingent only on
the parallel Codex/AGY r8 ratifications.
