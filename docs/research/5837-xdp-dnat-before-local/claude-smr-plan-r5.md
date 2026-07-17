# Claude SMR — hostile plan review r5 (#5837)

**Verdict: PLAN-READY.** v5 incorporates Codex r4's three material correctness findings —
each of which I confirmed firsthand against the code — and the residual asks are
implementation-execution per §13, not design blockers.

## Codex r4 material findings — verified + resolved
- **Degraded-path bypass (the important one) — real, now closed.** Confirmed
  `is_degraded_local_or_control` (lib.rs:1037-1057) calls `is_local_destination` →
  `pass_local_control` → `cpumap_or_pass`, so a configured interface-address DNAT tuple is
  passed to the kernel whenever the helper is degraded (ctrl-disabled / binding-missing /
  heartbeat-stale) — literally #5837 during degradation. v5 §5e makes a matching non-AH
  intent tuple **fail-closed DROP** (`drop_degraded_transit`) in those branches, which is
  the security-correct behavior (a flow that can't be translated must not leak to the local
  host). This is the right call and it is exactly the kind of residual /research should surface.
- **AH before session-hit — real, closed.** `live_userspace_session_action` runs at
  lib.rs:584 before the miss arm; v5 §5a places the `ah_present` + `is_local_destination`
  decline *before* the live-session lookup, so an IPv6 AH-to-self packet colliding with a
  translated session can't be steered. Correct.
- **Generation-reuse delete race — closed.** v5 §5d makes stale-delete synchronous under the
  server-state writer mutex (control requests serialize, handlers/mod.rs:122), recomputed at
  apply, with no deferred cross-generation retry — so a delayed delete can't remove a key a
  later generation re-desires. Correct.
- Completeness (NDP, ingress-iface, IP-only PROTO_ANY→TCP+UDP with dead-ICMP-key avoidance,
  §5d≡§11 with enumerated reduced-scope outcomes), capability bitmask (dataplane-computes,
  passes to config — avoids the dataplane→config import cycle), and the joint packet+byte
  availability bucket (no counter double-count) — all present and code-matched.

## The convergence judgment
This is round 5. Codex accepted the architecture and verifier bounding at r3; r4 surfaced
three genuine correctness holes (now fixed); the plan is now specified well past a typical
research deliverable. §13 draws the honest line: the design decisions /research owns are all
answered, and what remains (exact struct byte layouts, JSON tags, the capability-bitmask wire
encoding, the precise `shimverify` runs) is implementation-execution — a research doc that
authored those would be the implementation, not a plan. Continuing to iterate would only
convert design-complete prose into pre-written code, which is `/engineer`'s job and gated on
the verifier verdict anyway.

## The one irreducible unknown (correctly surfaced, not a blocker)
The verifier crux is now *larger* than v1 assumed — the intent probe must live in the miss
arm, the degraded/early-return branches, and behind an AH guard, all under the 1M cap with
tail-call forbidden. v5 honestly frames this (§2 ladder, §9 HIGH) with a v4-exact-only /
reclaim / PLAN-KILL fork. For a shim-gated change, "the design is sound and bounded; the
go/no-go is a mechanical `shimverify` run the implementer makes first" is the correct
research outcome — and it materially raises the PLAN-KILL probability, which the user should
weigh before `/engineer`.

## Bottom line
Every material correctness edge-case is designed and code-verified; the architecture and
verifier bounding were accepted rounds ago; the remainder is implementation-execution. This
is a genuinely implementation-ready plan. **PLAN-READY.** Green-light `/engineer 5837` with:
build Phase-1 exact-both **including the §5e degraded-path drop**, run `shimverify` FIRST on
both kernels, and treat REJECT as the §2 ladder fork — not a surprise.
