# Claude SMR — hostile plan review r2 (#3607)

Reviewing `plan.md` v2 (consumer-split token bucket). Round-1 Codex + AGY both
returned NEEDS-REVISION and converged on the same direction; v2 adopts it.

## Verdict: PLAN-READY on Option B (consumer-split), with PLAN-DEFER-operator as the honest fallback

## Retraction from r1
My r1 **MINOR-5 was WRONG**. I argued not-counting-rejected on the SYN aggregate
is safe because cookie deactivation is time-latched. AGY BLOCKER-1 and Codex
BLOCKER-2 correctly show the problem is not cookie *duration* but a `threshold`-per-
second **cookie bypass**: with count-only-admitted the first `T` SYNs/sec never
trip `over_attack`, so they skip the challenge, and the lingering `cookie_active`
state also skips the per-source cap. v2 retains the aggregate unchanged. Retraction
stands.

## Round-1 findings → v2 resolution (all addressed)
- **SYN-aggregate invariant / cookie bypass** (AGY BLOCKER-1, Codex BLOCKER-2):
  aggregate NOT migrated; count-all sticky retained; documented as a deliberate
  defense-latch (§5, §7, §10). ✓
- **Low-threshold roughness of Option A** (AGY MINOR-3, Codex BLOCKER-1):
  recommendation flipped to token bucket, which is exact at `T=1`; a `T=1` test is
  in the plan (§9). ✓
- **Dual-threshold 32-byte blow-up under token bucket** (AGY MAJOR-2, Codex
  MAJOR): the only dual-threshold consumer (aggregate) is not migrated, so no dual
  bucket exists; `TokenBucket` stays 16 B (§5). ✓
- **Over-throttle math** (Codex MAJOR, my MAJOR-1): corrected to
  `max(0, min(c, T−c))`; both-defects-jointly-necessary proof and the Option C
  `T,0,T,0` flood-evasion waveform added (§4a). ✓
- **`loop_now_ns` "already reaches screen" false** (Codex MAJOR, my MINOR-6): §4
  now states the plumbing (loop_body → forwarding → poll_stages → screen → sketch)
  is real work; only the clock *read* is zero-cost. ✓
- **L14 largely moot** (my MAJOR-4): token bucket bounds tokens ≤ threshold ⇒ no
  saturation; L14 resolved structurally, no dedicated metric (§5). ✓

## Residual hostile checks on v2 (no blocker)
- **Sketch fail-closed with token-bucket cells (v2 Q4).** A token bucket refills
  over time, so a cell that was saturated will refill during a gap — but that is
  the SAME "returning victim after an idle gap gets a fresh budget" property the
  old two-bucket window had (`gap_clears_previous_bucket`). Collisions still only
  *raise* a cell's consumption (over-count), never lower it within the window, so
  "victim always trips" holds. Not a blocker; must be pinned by a test (already in
  §9). 
- **Two primitives in rate.rs (v2 Q2).** Acceptable — the two consumers have
  genuinely different security semantics (shaper vs defense-latch); a single
  mode-flag type would bury that distinction and invite a caller passing the wrong
  mode. Keep them separate and named for their semantics.
- **Value vs blast radius (v2 Q6).** The standby-ACK failover case and the
  busy-dest false-positive are concrete and user-visible; the plan honestly offers
  PLAN-DEFER-operator if the reviewer/user disagrees. This is the correct posture
  for a design-fork issue.

## Bottom line
v2 is internally consistent, addresses every round-1 finding, and picks the
option the two companions recommended. PLAN-READY on Option B (consumer-split),
with PLAN-DEFER-operator explicitly available. Issue stays open, label
`plan-deferred-research`, awaiting manual `/engineer`.
