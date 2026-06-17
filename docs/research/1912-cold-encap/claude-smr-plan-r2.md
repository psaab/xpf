# Claude SMR plan review r2 — #1912 (convergence)

**Verdict: PLAN-READY**

All three reviewers (Codex `task-mqi4b2zc-fxrp3p`, AGY
`adversarial-review-mqi4bptc-m0k909`, Claude SMR) reached PLAN-NEEDS-MINOR
on r1 with the SAME convergent minors, and r2 resolves every one. The root
cause was independently code-verified by all three.

## What r1 got wrong and r2 fixes

- **r1 "~15 literal sites" → actually 100+** (AGY counted, Codex confirmed).
  My r1 SMR MINOR-2 recommended the explicit-field-on-all-literals approach
  — that was wrong on the churn estimate. r2 commits to **Option B (cold-path
  helper `outer_neighbor_ifindex`)**: no struct field, no 100+-literal churn,
  no wire change. The logic-duplication objection against the old Option C is
  removed by factoring a shared `resolve_tunnel_outer(state, id)` that BOTH
  `resolve_tunnel_forwarding_resolution` and the helper call.
- **HA-sync (my r1 MINOR-3) → moot.** Both reviewers verified
  `SessionSyncRequest` carries no neighbor ifindex (control.rs:692,
  protocol.go:1664) and synced sessions re-resolve on upsert
  (upsert_synced.rs:39) + peer-sync hit (session_glue/mod.rs:1021). Option B
  computes from live state, so there is nothing to serialize or trust.
- **Codex `>0` fallback** (safer than `==0`) adopted in the helper.
- **Death-site localization** (my r1 MINOR-1) folded into the live repro:
  record `tunnel_encap_unresolved_drops` — nonzero before, ~zero after.
- **Resolver-for-tunnel enhancement** (my r1 MINOR-4) included; no reviewer
  objected.

## Why PLAN-READY now

The fix is minimal, cold-path-only, byte-identical off the tunnel path,
preserves R-C/R-E plaintext-leak protection, needs no struct/wire/HA change,
and has a concrete live repro with a pass criterion that directly falsifies
or confirms it (who-has 10.0.61.102 on ge-0-0-1 after flush + reply recovery
within one ping). No reviewer raised a PLAN-KILL concern; all three agreed
Option B is the right shape. Ready for `/engineer`.
