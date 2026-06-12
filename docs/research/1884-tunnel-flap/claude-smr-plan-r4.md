# Claude SMR hostile plan review — #1884 r4 (plan v4, 56c8fb8ffe93)

Verdict: **PLAN-READY**.

The v4 fold is strictly narrower than the v3 rule my r3 review accepted
(I had taken bind-wins-last as today-parity; Codex's master-identity
check eliminates even the transition-apply unbind). I attacked the
identity test on the two §11 edges:

- **Q1a — VRF rename**: a renamed RI is a delete+create of the VRF
  device. Stanza nonempty ⇒ the unbind path is not taken at all (bind
  to the new RI overwrites the master). Stanza emptied in the same
  commit ⇒ `LinkByName(appliedRI[name])` fails (old VRF gone) ⇒ no
  unbind, claim cleared — and the kernel has already freed the slave
  when the master device was deleted, so nothing of ours leaks.
- **Q1b — ifindex reuse**: `MasterIndex` and the VRF index are both
  read fresh from the kernel within one serialized applyConfig (step
  0a and ApplyTunnels run in the same goroutine; the CLI path has no
  0a at all), and kernel ifindexes are unique at any instant — if the
  resolved VRF's index equals the link's MasterIndex, the master IS
  that device. The only residual ambiguity is a same-name VRF
  delete+recreate between applies, where unbinding the current
  incarnation is still semantically "our named claim" — correct either
  way.
- **Q1c — lapse rule**: clearing the claim in every empty-stanza
  branch is right; in the only branch where we skip the unbind with a
  master still present (index mismatch), that master is by definition
  not ours, and retaining a claim against it would re-create the exact
  stale-authority bug the check removes.
- **Q2**: the fold touches only A.5 + two map-hygiene lines; nothing
  in A.1/A.3/A.4/A.6/A.7 changed; no earlier closure re-opened. The
  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
  symmetrically.

No findings. Converged.
