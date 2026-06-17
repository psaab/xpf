# Claude SMR hostile plan-review — #1919 r3 (final rev)

Reviewer: Claude SMR. Stance: HOSTILE. Verdict: **PLAN-READY**.

## History
- r1: PLAN-NEEDS-MAJOR (F1 broken retry signal) — all three converged.
- r2: folded F1/F2/F3 fixes. AGY → PLAN-READY; Codex → PLAN-NEEDS-MAJOR
  on a residual AddrList-fallback edge.
- r3: fixes the AddrList edge via `(failed, retry)`.

## Verification of the r3 fix

The r2 residual (Codex): `pruneAppliedAddrsLocked` on `AddrList` failure
returned `applied`, and the caller retained only on `len(failed)>0`. With
`applied` empty + a real stale address present + transient `AddrList`
failure → returned empty → caller dropped tracking → leak, no retry.

r3 changes the contract to `(failed, retry)`:
- `AddrList` failure → `return applied, true` (retry unconditionally,
  regardless of whether `applied` is empty).
- delete loop → `return failed, len(failed) > 0`.
- caller retains `nextWG[name]=true` on `retry`, not on `len(failed)`.

I traced the r2 counterexample against r3: stale `172.16.0.1/30` present,
`appliedAddrs[name]` empty, `AddrList` errors → helper returns
`(empty, true)` → caller sets `appliedAddrs[name]=empty`, `nextWG[name]=
true` → retried next apply. When `AddrList` later succeeds, the address
is deleted (non-link-local, gate does not apply). **Leak closed.** ✔

No new hazard from the refactor:
- The empty-`applied` carry-forward on `AddrList` failure keeps the
  link-local gate correct (an empty `applied` means "delete no
  configured link-local", which is the safe default — autoconf fe80 is
  still gated by `IsLinkLocalUnicast`). ✔
- `retry=len(failed)>0` on the normal path is exactly the F1 fix
  (all-family failed deletes). A clean prune returns `(empty,false)` →
  caller drops tracking → idempotent no-op next round. ✔
- The `retry` bool is independent of `failed` content, so the two
  failure modes (cannot-enumerate vs delete-failed) are no longer
  conflated — this is strictly more correct than r2. ✔

## Re-confirm prior items (unchanged in r3)
- F2 (isLinkNotFound gate): unchanged from r2, correct.
- F3 (prune scope = all non-link-local, §4b): unchanged, accurate.
- FRR §1a (+ connected-route nuance): unchanged, correct.
- VRF §4a A1 + routing-instance-removed residual: unchanged, sound
  deferral to #1434.
- R5 restart boundary + test §6.9: unchanged, encoded.
- clearLocked / ensureReconcileStateLocked `wgConfigured` wiring:
  unchanged, both sites covered.
- #1918: no interaction (WG has no keepalive). Confirmed.
- Tests §6: now 10 cases incl. the non-link-local retry (§6.4),
  transient-lookup (§6.6), AddrList-failure-empty-applied (§6.8),
  restart-boundary (§6.9). Coverage matches every failure path.

## Verdict

**PLAN-READY.** The three r1 MAJORs and the r2 residual are all resolved.
The design (Path A, dedicated prune helper with `(failed,retry)`,
isLinkNotFound gate, FRR-clarify, VRF A1 deferral) is correct, minimal,
idempotent, and confined to the WG branch. No production code touched —
this is a research plan. Ready for `/engineer 1919`.
