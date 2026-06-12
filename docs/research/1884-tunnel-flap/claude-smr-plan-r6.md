# Claude SMR hostile plan review — #1884 r6 (plan v6, a59e367cb513)

Verdict: **PLAN-READY**.

SMR5-1 (mine, = Codex r5 Q2) is closed by the transfer rule exactly as
prescribed. I attacked the transfer on the §11 r6 edges:

- **Q1 — transferred claim vs a later non-tunnel master**: any
  non-VRF enslavement (bridge/bond/operator) yields
  `MasterIndex != index(vrf-<claim>)` ⇒ identity mismatch ⇒ no unbind,
  claim cleared. The identity gate is evaluated at decision time
  against fresh kernel state in the serialized applyConfig goroutine —
  there is no window where the transfer makes the manager unbind a
  master that is not the config-desired VRF device itself.
- **Stanza+list both set (different RIs)**: stanza wins, claim =
  stanza RI, manager re-binds over 0a's list bind — identical to
  today's effective ordering (0a then tunnel apply). Parity.
- **Transient-unbind-failure then list re-added**: the retained claim
  is overwritten by the transfer next apply; the stale unbind intent
  correctly evaporates because the config wants the RI again.
- **Removal path**: A.1 deletes the appliedRI entry with the link —
  no claim survives a removed tunnel.
- **Failed-0a transferred claim**: self-clears via identity mismatch
  (MasterIndex 0) — pinned in §9 test 6.
- **Q2 — fold blast**: the r5 folds touch the A.5 claim table, the
  A.3 MTU switch, and §9/§10 only. The MTU switch is
  exhaustive-by-construction (`tc.MTU > 0` / `adopting` / neither ⇒
  no write) and the owned-unzoned reconcile cannot fight the compiler
  (same source value, both `!=`-guarded). No earlier closure
  re-opened: keepalive rules (A.7), address rules (A.4), reuse checks
  and EEXIST handling (A.3), ownedNames (A.1) are untouched by v6.

Residuals remain as documented in §10 (restart-window stale master /
LL / anchors; 0a unit>0 follow-up; WG LL follow-up). Converged.
