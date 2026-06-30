# Claude SMR — hostile plan review r2 (convergence) (#2387)

**Reviewing:** `docs/research/2387-vrf-flow-identity/plan.md` v3 @ `a620dc727`
**Posture:** HOSTILE convergence check — did v3 actually close r1's defects, or
paper over them?
**Verdict:** **PLAN-DEFER (research-converged).** Convergent with AGY r1 + Codex
r1. No remaining blocker. The plan correctly stops at "real reachable bug,
minimal fix identified, awaiting a maintainer scope decision + /engineer."

---

## r1 defects — disposition check (each must be genuinely fixed, not reworded)

- **S1 / AGY-Attack-1 / Codex-Escalation (PBR reachability):** CLOSED. §3 now
  states "latent in default mode, LIVE via PBR"; §4b carries the ordering proof
  (`poll_descriptor/mod.rs:474` short-circuit before `:1208`, conntrack lookup by
  bare `flow.forward_key` at `shared_ops.rs:563-599`) plus the config-validity
  citations (`firewall_ri_*_test.go`). This is a real escalation, not a hedge —
  the verdict basis moved from "unreachable" to "cost/benefit for a niche config."
- **AGY-Attack-4 (A.1 over-rejects):** CLOSED. A.1 is now a commit *warning* by
  default, hard-reject only under an explicit "no overlapping subnets" product
  posture. This is the right call — hard-rejecting a working PBR VRF to paper over
  a fast-path bug would be a self-inflicted regression. Note it correctly stops
  citing the NPTv6 *reject* gate as the pattern (that was a category error in v2).
- **AGY-Attack-5 (phase ordering):** CLOSED, and this is the most important
  structural improvement. The split into B-min (P0+P2+P3) vs B-ext (per-VRF
  default FIB) is correct: PBR already supplies per-VRF forwarding, so the key
  widening delivers PBR-mode isolation *without* B-ext. The §8 architectural-
  mismatch row was rewritten (the old "B-P2 before B-P1 is the dead-end" claim was
  itself the dead-end thinking). Good.
- **Codex citation fixes:** CLOSED. `CurrentHAProtocolVersion` corrected to
  `heartbeat.go:27-31` (with the `sync.go:36` alias noted); path-shorthand note
  added for the `src/afxdp/` subtree; upgrade-gate `cluster_cli.go:246-248` cited.
- **§4c / §4d / §7 (confirmed accurate by all three in r1):** unchanged in
  substance, wording still holds.

## Residual hostile probes (none rise to a blocker)

- **Is B-min's leaked-flow domain-0 scoping safe?** Yes for B-min: it preserves
  *today's* behavior for leaked flows (they already get no VRF discrimination),
  so it cannot regress them — it only declines to *improve* them until B-ext.2.
  The §7 hard-gate wording ("shipping the key widening without this scoping would
  silently regress leaked-flow conntrack") is the correct guardrail: an engineer
  must explicitly exempt leaked flows, not silently key them by ingress-domain.
- **Does Q5 (additive trailing-domain wire encoding) undercut the §4d
  hard-break?** No — it sharpens it. The hard-break is real *if* domain rides
  inside the key block; Q5 raises the legitimate alternative of carrying domain as
  a trailing length-gated value field with domain-0 implied for old peers
  (graceful degradation, no corruption). That is a /engineer-time design choice,
  correctly left open rather than over-committed. It could materially lower
  B-min's cost — worth flagging to the maintainer as the single biggest lever.
- **Is the perf claim (+4B key, one FastMap lookup) honest?** Yes — B-P0 reuses
  the dead `meta.routing_table` slot (no `UserspaceDpMeta` size change), and the
  domain id is a dense interned u32, not an RI-name hash. The hot-path cost is one
  added u32 in the key hash + one ingress-time map lookup. Must still be measured
  (the plan says so in §9).
- **Did v3 over-rotate toward "ship B-min now"?** No. The recommendation remains
  PLAN-DEFER pending a product-scope decision (§11 Q1), which is correct for
  `/research` — the bug is real but the fix carries an HA wire change and a
  product-support question that the maintainer must answer before /engineer.

## Verdict

**PLAN-DEFER (research-converged).** The plan honestly characterizes a real,
reachable (PBR-mode) wrong-VRF forwarding/NAT/policy bug; identifies the minimal
real fix (B-min: domain id + key + HA wire) distinct from the larger optional
feature (B-ext: per-VRF default FIB); offers a non-regressing interim mitigation
(A.1 warning + A.3 docs); and lays out the correctness traps (symmetric
discriminator only; leaked-flow scoping; HA wire). Awaiting the maintainer's
product-scope call and explicit `/engineer` approval. No code should be written
until that approval.
