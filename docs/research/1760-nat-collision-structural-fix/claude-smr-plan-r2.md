# Claude SMR plan-review — #1760 round 2 (v2 @ 7e9ec0cd1)

**Verdict: PLAN-NEEDS-MINOR.** v2 resolves my round-1 MAJOR (HA divergence
is no longer divergent-by-default) and folds the shared-map, disposition,
liveness, and lifecycle-gap findings. One genuine design choice remains
open — the active/active import-time conflict resolution (§10 Q2) — and it
must be *pinned* (not left open) before `/engineer`, because the fix's value
in the active/active window depends entirely on which rule is chosen.

## Round-1 MAJOR resolved

The publish-path determinism argument (§7) is the right reframe and it
holds for the **steady-state (one-active-node-per-RG) case**, which is the
common case: a refused session is never published → the peer never learns
it → symmetric absence, no divergence. The importer correctly does *not*
run the guard (synced sessions are authoritative). That dissolves the
"A-refuses / B-admits → split-brain" failure I raised, *for steady state*.

## Remaining MINOR — the active/active window is "no worse than today", not "fixed"

§7 is honest that an active/active (or failover-transition) window remains:
both nodes install independently, collide, and one admits before the other's
delta arrives. v2 says this "self-corrects via SYN retransmit." Two gaps:

1. **Non-retransmitting flows** (long-lived UDP, the §10 Q3 case) have no
   SYN to retransmit; the dropped side may never recover. The plan must
   state that the active/active window is fixed only for retransmitting
   flows and is "no worse than today" (single-valued overwrite) otherwise —
   and that this is acceptable because steady-state (the dominant case) IS
   fixed and live incidence is 0.
2. **§10 Q2 (import-time conflict resolution) is left OPEN.** That's the
   load-bearing choice for the active/active window. "Keep-both" = no worse
   than today (defensible, minimal). "Prefer-synced + drop local" = the
   importer now drops a locally-admitted session, which must itself be
   proven not to create a *new* divergence (the importer dropping S2 while
   its own peer still has S2 from a yet-later delta...). My recommendation:
   **pin Q2 to keep-both** for v1 of the fix — it makes the active/active
   window provably "no worse than today" with zero new importer logic,
   and the steady-state correctness win stands alone. Defer prefer-synced
   to a follow-up if active/active collisions are ever observed.

## Validated

- §5(a) two-map guard + `key_to_handle` fallback closes AGY's lifecycle gap.
- §5(b) guard-at-publish / not-at-import is the correct split (synced =
  authoritative).
- §5(c) hard-drop disposition is the right Junos-parity behavior; the
  packet-path rollback ordering is a code-review concern, flagged.
- §5 displaceable-incumbent predicate (expired/closing/half-open/
  peer-synced-unconfirmed displaceable) correctly prevents TIME_WAIT-reuse
  false refusals — the one thing I'd add: a half-open *forward* SYN
  retransmit from the SAME flow must not be treated as a colliding S2 (it's
  the same key+handle → the existing `h != new_handle` guard covers it, but
  state it).

## Recommendation

PLAN-NEEDS-MINOR → pin §10 Q2 to **keep-both** (active/active = no worse
than today; steady-state fixed), add the non-retransmitting-flow caveat to
§7, then this is PLAN-READY. The mechanism is sound and slow-path-only;
given the operator chose to build at 0 incidence, the honest scope is
"fix the common case correctly, document the active/active residual."
PLAN-KILL is no longer warranted now that the divergence-by-default is gone.
