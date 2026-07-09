# Claude SMR — hostile plan-review r3 (#4455 HI-1) — convergence

**Reviewer:** Claude SMR (self-review, adversarial). **Target:** plan.md r3.
**Verdict: CONVERGED — PLAN-KILL Component A; PLAN-READY Component B.**

## Reconciling my r2 (PLAN-KILL) with Codex r2 (PLAN-KILL-WRONG)

Codex r2 was NOT a reflexive disagreement — it agreed the drop enforcement should
be killed (it did not dispute C1–C8) and made one correct, verifiable factual
point I had missed: the shipped #4454 advisory only fires when a multicast token
is already present.

**I verified it independently.** `validateHostInboundMulticastWarnings`
(`pkg/config/compiler_validate_warn.go:1652`) guards on
`hostInboundMulticastTokensPresent(protocols)` being non-empty (`:1658-1661`) and
only walks `zone.HostInboundTraffic` / per-interface overrides (`:1680-1695`). It
has no cross-reference to what FRR is actually running. So a zone running OSPF in
FRR with NO `protocols ospf` token — the exact silent fail-open #4455 is about —
produces zero advisory today. My r2 terminal-state claim ("the shipped advisory
already surfaces the gap") was therefore wrong for the case that matters. Codex
was right and I was incomplete.

## Why the split verdict is the correct convergence

- **Component A (drop enforcement) stays PLAN-KILL.** Nothing in Codex r2 revives
  it; both of us reject it on the C1/C4/C5/C6 + HA-risk grounds. The value is
  thin and the correctness surface (four independent mechanisms) is large.
- **Component B (warn-only managed-FRR-mismatch advisory) is PLAN-READY.** It is
  the genuinely valuable, genuinely low-risk subset: a pure control-plane commit
  string with NO nft/Rust/`iifname`/RETH/GRE/HA surface, closing the observability
  gap the shipped advisory misses. It is strictly better than my r2 "do nothing
  more." I was wrong to stop at pure-KILL; r3 fixes that.

## Adversarial check on Component B (did r3 overclaim?)

- **Is it really zero dataplane risk?** Yes — §5A adds only
  `validateHostInboundManagedRoutingMismatch`, a WARN string; it neither builds
  nft rules nor touches the Rust classifier nor forwarding. A warning cannot drop
  a packet. Confirmed no HA/routing hazard.
- **Can it false-positive and annoy operators?** Only for a real
  FRR-protocol-without-token mismatch — which is exactly the condition worth
  flagging. `all` and the #3362 override must count as "token present" (r3 §5A
  states this); the test matrix (b)/(c) guards it. Acceptable.
- **PIM gap honestly stated?** Yes — §5A/C3 note PIM is unmanaged
  (`docs/feature-gaps.md:460`), so it is out of scope with a documented residual,
  not silently dropped.
- **Does Component B reintroduce any Component-A risk by the back door?** No — it
  deliberately does NOT resolve kernel netdev names or emit any drop; it operates
  on config refs + FRR render intent only.

## Verdict

**CONVERGED (2-of-3, AGY infra-down): PLAN-KILL Component A (drop enforcement),
PLAN-READY Component B (managed-FRR-mismatch WARN-only advisory).** `/engineer
4455` implements Component B only. Recommend the issue stay open as the tracked
design record for Component A (labeled to reflect the killed enforcement) with
Component B as the approved follow-up.
