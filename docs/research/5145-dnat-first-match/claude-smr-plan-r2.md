# Claude SMR — hostile plan review r2 (convergence) — #5145

Position update after the Codex-lane hostile review + my own firsthand
re-verification of its decisive blocker.

## I concur: PLAN-KILL (Option A).

My r1 verdict was ITERATE-leaning-to-C and flagged the fall-through citation
(H4) and the HA replay assumption (H3) as PLAN-READY gates. The Codex-lane
review found a blocker I **missed**, and I verified it firsthand — it is
decisive and moves me from ITERATE to PLAN-KILL.

### B2 (LocalDelivery) — verified firsthand, this is the killer.

I read `destination_ips_scoped` (userspace-dp/src/nat/destination.rs:1028-1083)
and the forwarding-build local-set install (forwarding_build/mod.rs:479-486)
directly. Confirmed:
- `destination_ips_scoped` skips a row ONLY when `entry.off` is true. It exports
  **every** non-off translate destination into the local-delivery set,
  regardless of whether a higher-precedence `off` rule covers that IP.
- So in the plan's own motivating example (`/24 off` before `/32 translate` for
  10.0.0.5): the `/32` translate registers 10.0.0.5 into `state.local_v4`. Under
  Option A the `/24 off` wins the *lookup* (→ `None` → no translation → original
  destination 10.0.0.5 kept), but 10.0.0.5 ∈ `local_v4` → the packet is
  classified `LocalDelivery` and consumed by the firewall stack, **not routed to
  the real host**.

Option A's entire premise is that making the `off` win the lookup restores the
exemption. It does not — the security outcome is decided at
local-address-registration time, which Option A leaves untouched (and the plan
explicitly, wrongly, claimed "unaffected"). **The fix as scoped cannot achieve
its own goal.** That is a PLAN-KILL, not an iterate.

### B1 (rule-set identity / fall-through) — I accept this too.

The flat snapshot has no rule-set id (I confirmed protocol.go:680 carries only
`Name` + `FromZone`/`FromInterface`/`FromRoutingInstance`). A global argmin
therefore implements rule-level fall-through, which Junos's documented
select-one-rule-set pipeline does not do (fall-through remains an unproven
external-doc inference — so we'd be shipping the *opposite* of a security-
relevant behavior on uncertainty). This is my r1 H4, sharpened: it is not a
"defer to /engineer" citation gate — it is a data-model defect.

### On my own r1 miss.

Per the SMR-soft-pass self-correction pattern this project has seen: my r1 was
factually careful but I did not trace the local-address-registration path to the
LocalDelivery classifier. That omission would have let a "PLAN-READY gated on
H3/H4" verdict through — and the resulting implementation would have passed unit
tests (which exercise the matcher, not the forwarding/local-delivery path) while
failing the real scenario. This is exactly the failure mode `/research` exists
to catch before code is written. It was caught.

## Go-forward (agreeing with Codex-lane)

- **Kill Option A.** Do not implement the global-ordinal rewrite.
- **Option C is the proportionate direction** but is NOT plan-ready — it needs
  its own concrete plan (disposition strict-vs-warn, canonical-expanded overlap
  model, scope, dynamic-feed handling, tests incl. an end-to-end LocalDelivery
  case).
- **File B2 as a separate latent bug.** It may already affect the current
  common more-specific-`/32`-off idiom when a covering translate prefix expands
  to include the off host. It is independent of the precedence question and
  should not be lost inside a killed plan.

## Verdict

**PLAN-KILL (Option A).** The reverse-to-first-match rewrite is architecturally
wrong-shaped (no rule-set identity → undocumented fall-through) and, decisively,
does not achieve its own security goal because local-address registration —
which decides LocalDelivery — is computed independently of lookup precedence.
The documented most-specific-wins contract stands; the proportionate response is
a re-scoped Option C lint (separate plan) plus a separately-tracked fix for the
LocalDelivery/exemption interaction.
