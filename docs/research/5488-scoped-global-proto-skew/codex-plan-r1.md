# Codex — hostile plan review r1 (#5488)

- Model: `gpt-5.6-sol` (codex-cli 0.144.0 default; named models rejected on a
  ChatGPT account — see reviewer-ids.md). Reviewed the plan at r2 working tree
  (SMR F1/F2 already folded).
- Effort: medium (a prior ultra-effort run rabbit-holed the codebase without
  converging; retried with a tight verdict-first prompt).

## Verdict (verbatim)

**PLAN-READY-WITH-NITS.**

1. Path C’s deny/reject lowering is monotonic: replacing either scoped dimension
   with `Any` only enlarges the denied tuple set. Under first-match evaluation,
   shadowing a later permit is over-denial, never fail-open.
2. Path C fully restores #5488’s DENY/REJECT coverage across gen1, gen2, and
   gen3. Path A alone also closes old-Go/new-helper skew and the gen1
   scoped-permit hole.
3. Path A is genuinely an all-config flag-day in both directions: v4 Go→v3
   helper and v3 Go→v4 helper both fail strict equality. It also retargets the
   scheduler/NAT `>= ProtocolVersion` checks from 3 to 4, despite those features
   not changing.
4. Mixed versions are demonstrably within the system’s defensive model:
   scheduler, NAT, and disarm gates explicitly handle older helpers. Whether
   operators call that state “supported” is immaterial to a security invariant
   already enforced elsewhere; PLAN-KILL is unwarranted.
5. The fail-on-revert test is sound if it asserts effective old-helper coverage,
   not merely `singular == ""`. Cover multi-zone source and destination scopes
   plus both `deny` and `reject`; verify the test fails against current lowering.
6. Nit: calling the plural fields a “pure optimization” is misleading. They are
   the authoritative full-fidelity representation for current readers; the
   singular fields become a conservative compatibility projection. Tighten that
   wording and avoid implying Path C fixes scoped permits against gen1.

Path recommendation: Choose Path C for #5488; track a future coordinated Path
A/versioning cleanup separately if complete bidirectional skew safety becomes
worth the deployment boundary.

## Disposition

Converges with Claude SMR on Path C + PLAN-READY. Findings 1–4 independently
confirm SMR F1/F2/F3/F6 and reachability. Nits 5 (test design) and 6 (wording)
folded into plan **r3**.
