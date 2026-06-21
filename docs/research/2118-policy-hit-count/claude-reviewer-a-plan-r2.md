# Hostile Claude reviewer A — plan-review r2 (on plan r2)

Verdict: **PLAN-NOT-READY** (r2) → all findings folded into plan r3.

## MAJOR
- The chain map (§2) and risk (§7/§11) miss a SECOND policy-eval/increment
  site: `evaluate_policy_result_with_len` is called at BOTH
  poll_descriptor/mod.rs:1110 (ForwardCandidate) AND mod.rs:2342
  (MissingNeighbor cold path, #1913). Both call `try_match_rule` →
  `hit_counter.add` (policy.rs:1068). The :2342 arm re-evaluates per
  packet for an unresolved-neighbor flow ("never seeds a session, never
  buffers in pending_neigh", mod.rs:2318-2326), so the "single increment
  site / once per flow" claim (§7, §11) is false. Any relocate/gate/
  assert-single fix must handle BOTH sites; the over-count risk belongs
  in §11.
- §4 vs §12 ranking contradiction: §12 led with H1a as leading candidate
  while §4 ranks it unlikely. The smoke uses explicit permit rules
  (cluster config `default-policy deny-all` + explicit permits, no
  explicit deny), so H2 does not explain the permit-row 0s. Reconcile and
  state that for explicit-permit matches 0 is anomalous.

## MINOR
- "0" may actually be "1": once-per-new-flow + a single iperf3 TCP flow
  yields packets=1, misread as 0. Make this an explicit Step-1
  disambiguation (read exact value; drive many flows).
- Cited smoke doc `docs/smoke/security-matrix-2026-06-20.md` is not in the
  worktree/branch/master — treat as uncommitted external artifact, not a
  citable premise; Step 1 regenerates evidence.
- Display vs read-path nil/skip asymmetry (server_show_policies_text.go:52
  no nil-check + increments policySetID on filtered skip; policycounters.go
  nil-checks + does not increment on nil) — align when Step 3 adds gating;
  add a golden fixture with an odd zone-pair to lock the positional decode.
- The two-site invariant must be tested end-to-end, not just at
  try_match_rule.

## Confirmed sound
Wire reuse #1961-safe; rule-id format parity; PolicyStatsEnabled
un-transmitted (display-only gate is the minimal fix); Arc identity across
reload; M4 Prometheus-only gate real; golden gap real; Option A correct.

## Resolution in r3
All MAJOR + MINOR folded: §2 maps both sites; §4 re-ranks H2 primary for
deny rows + adds H2b "0 may be 1"; §7/§11 add the MissingNeighbor
over-count caveat + test; §1 adds the missing-smoke-doc caveat; §6 fixes
Option-B file:line + adds the nil-handling/synthetic-counter notes; §8
adds the two-site invariant test. Note: reviewer A's "per-packet
steady-state cost" was refined by reviewer B — :2342 is a transient
over-count (resolves when the neighbor resolves), not steady-state; r3
states it as transient.
