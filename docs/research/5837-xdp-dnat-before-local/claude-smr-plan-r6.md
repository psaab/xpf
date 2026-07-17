# Claude SMR — hostile plan review r6 (#5837)

**Verdict: PLAN-READY.** v6 closes Codex r5's six concrete design blockers with precise,
code-anchored design statements. The architecture, verifier bounding, AH/generation-race/
mandatory-pins/availability were already CLOSED by r5; what remained were the last
security-relevant design decisions, and they are now decided — not deferred.

## Codex r5 blockers — resolution check
1. **Transaction order — closed.** §5d is now the literal, correct order:
   insert-new → publish-new-forwarding-generation → synchronous stale-delete *after* the swap.
   This is the security-correct sequence: an old-only intent key is never removed while its
   rule is still the live generation, and the §5b superset invariant states exactly that. The
   post-commit delete-failure result (succeed-with-warning + meter + reap next apply/restart)
   is right — surplus stale keys only over-steer, never bypass.
2. **Incomplete-state fail-closed — closed.** The new `intent_authoritative` ctrl bit is the
   right mechanism: it fails closed independently of intent-map *membership* (the gap Codex
   identified — the degraded path can only drop a key that exists). Coupling binding-READY to
   it bounds the not-authoritative window to *before a generation is live*, and during it the
   fail-safe is the pre-fix status quo, not a new bypass. Sound.
3. **Ingress-interface — closed with a real proof.** §5b/§5e now resolve the fork instead of
   deferring it: a DNAT public address sits on a zone dataplane interface, which
   `buildUserspaceIngressIfindexes` (maps_sync.go:1502) always includes; skipped
   mgmt/tunnel/fabric/loopback addresses are out-of-scope + §5d-warned. I confirmed the
   builder's zone-and-not-skipped predicate. Correct.
4. **Disarmed refresh — closed by picking the safe branch.** §5d now *requires*
   publish-before-accept and explicitly rejects the defer-publication branch as unsafe (it
   would pass unmatched local to the kernel via the ctrl-disabled path). The right call.
5. **Instruction-reclaim scope — closed.** §2 now targets exact-both first, falls to v4-only,
   with the capability bitmask reflecting what passed. Deterministic.
6. **Absent/malformed/legacy capability — closed.** §5c now defines zero-enforcement ⇒
   warn-every-rule and mandates threading the capability through every `CompileConfig*`
   surface. This is what makes the loud-diagnostic guarantee actually hold on a
   reduced-capability/rollback shim.

Plus the ICMP over-warning fix (port-0 is an exact Phase-1 key, so explicit ICMP rules aren't
Phase-2 casualties) and the pseudocode/cite nits.

## Convergence assessment
Across six rounds Codex has been a genuinely valuable adversary — it caught the shared-key
collision (killed Option A), the tail-call ban, the byte-order mismatch, the IPv6-AH
regression, the degraded-path bypass, and the transaction/generation edge cases. Each was
real; each is now resolved. What remains after v6 is, by Codex's own r5 labeling and §13's
boundary, implementation-execution: exact struct byte layouts / JSON tags, the
capability-bitmask wire encoding, the injected-clock seam for the availability test, and the
mechanical `shimverify` runs. A research plan that authored those would be the implementation.

## The honest headline for the user
The verifier crux is real and, after all the correctness work, *larger* than it first looked:
the intent probe must live in the healthy miss arm, the degraded/early-return branches, and
behind an AH guard, all under the 1M-insn cap with tail-call forbidden and no headroom metric.
The plan is sound and bounded, with a v4-exact-only / instruction-reclaim / PLAN-KILL fork —
but the PLAN-KILL probability is non-trivial and is settled only when `/engineer` runs
`shimverify` on the first candidate. That is the correct shape for a shim-gated research
outcome, and the user should green-light `/engineer 5837` knowing the first task is that gate.

**PLAN-READY.**
