# Claude SMR — hostile plan review r1 (#2387)

**Reviewing:** `docs/research/2387-vrf-flow-identity/plan.md` v1 @ `c88ff7850`
**Posture:** HOSTILE. Goal: break the plan's central claim.
**Verdict:** **PLAN-NEEDS-REVISION** → then PLAN-DEFER (the recommendation
survives, but the severity framing in §3/§4b is materially wrong and must be
corrected before convergence).

---

## SHOWSTOPPER S1 — the "unreachable in a forwarding-correct config" claim is FALSE (PBR counterexample)

The plan's load-bearing argument (§3, §4b, §8 PLAN-KILL line) is: the collision
is latent because the overlapping-subnet trigger "does not forward correctly
today irrespective of the session key." That is **only true for the default
(non-PBR) forwarding mode.** It is **false** once PBR `then routing-instance` is
in play — which is exactly the mechanism the plan itself cites as the "sole
per-packet table override."

Concrete reachable counterexample, verified against source:

- Two ingress interfaces in two routing-instances, **overlapping client
  addressing** (e.g. both tenants use `10.0.0.0/24`), each with an interface
  filter `then routing-instance <ri>` so the destination lookup is steered to
  the per-VRF table (`foo.inet.0` / `bar.inet.0`). Per-VRF forwarding now
  **works** — `ingress_route_table_override` returns the per-VRF table
  (`forwarding/mod.rs:1211`) and the session-miss resolution honors it
  (`poll_descriptor/mod.rs:1208-1216` → `:1244-1248`).
- **Ordering proof (the kill shot):** the established-session lookup
  `resolve_flow_session_decision` runs at `poll_descriptor/mod.rs:474` and
  short-circuits *before* the PBR override + route resolution at `:1208-1248`
  (comment at `:503` confirms it "never runs policy"). The session lookup uses
  the bare 5-tuple (`flow.forward_key`, `shared_ops.rs:563-599`).
- So: flow 1 (VRF-A) creates a session caching egress-A. Flow 2 (VRF-B), **same
  5-tuple**, hits flow 1's conntrack session at line 474 and is handed flow 1's
  cached decision (egress-A, VRF-A's NAT, VRF-A's policy verdict) — its **own**
  PBR/route/policy is never evaluated. Result: wrong-VRF forwarding + wrong NAT
  + wrong policy on flow 2. The flow-cache `(SessionKey, physical_ifindex)`
  discriminator does **not** save it: even on a different physical port, flow 2
  misses the flow cache but still hits the ifindex-less conntrack table.

This is a **real, reachable, forwarding-correct-config** correctness/isolation
breach — it is precisely #2387's multi-tenant overlapping-address scenario. The
bug is therefore **"latent in default mode, LIVE (if niche) in PBR-steered
overlapping-address multi-VRF mode,"** not purely defensive. The plan must say
so. (This also retroactively corrects the prior campaign-8 comment, which made
the same too-strong "doesn't forward correctly today" claim.)

**Impact on recommendation:** PLAN-DEFER still stands (the *complete* fix is
still Track B; the literal key-widening is still the last phase), but:
- §3/§4b must be rewritten from "unreachable" to "reachable via PBR; latent only
  in default forwarding mode."
- Track A.1's justification flips: it is no longer "reject a config that doesn't
  forward anyway" but "**reject a config that DOES forward (via PBR) but whose
  flows we cannot isolate at the session layer** — fail-closed until Track B."
  That is a stronger, more honest fail-closed posture, and it means A.1 must
  reject the overlap **even when** a PBR filter is present (Q4 in the plan asked
  whether A.1 falsely rejects working PBR configs — the answer is it must reject
  them *deliberately*, because "works" ≠ "isolated").
- The "PLAN-KILL acceptable if unreachable" line is no longer satisfied on the
  unreachability prong; PLAN-KILL would now rest only on "churn outweighs the
  win for a niche config," which is a weaker basis. PLAN-DEFER is the honest
  verdict.

## M1 — A.2 (flow-cache logical-ifindex key) is a near-no-op for this issue; don't oversell it

Given S1, the conntrack table (no ifindex) is the authoritative collision
surface; the flow cache already carries the physical ifindex and still doesn't
prevent the cross-VRF hit. A.2 only stops same-parent-VLAN flow-cache reuse and
does nothing for the conntrack-level breach. Keep A.2 as a tidy-up
(logical-ifindex SSOT alignment per #2370/#3021) but stop implying it materially
mitigates #2387. Re-rank it below A.1 and A.3.

## M2 — Track B-P2 "+4 bytes" is optimistic given the dead `meta.routing_table`

§4e established `routing_table` is dead/always-0. B-P0 can reuse that slot for a
domain id with **no `UserspaceDpMeta` size change** (good). But the plan should
state explicitly that the domain id must be a *dense interned u32* (not the
RI-name hash) so the per-packet key hash cost is a single added u32, and that the
SessionKey grows by 4 bytes only (not 8). Tighten §5 B-P0 wording.

## m3 — inter-VRF route-leaked reverse-match corner (§7) needs a concrete config path or an explicit "out of scope for B-MVP"

§7 flags that next-table/rib-group leaked flows make the routing-domain id
asymmetric. The plan should either (a) cite the rib-group/next-table config that
produces it (`pkg/routing/`) and require storing both ingress+egress domain, or
(b) explicitly scope leaked flows OUT of B-MVP with a documented
known-limitation. Leaving it as prose invites an engineer to ship B-P2 and
silently regress leaked-flow conntrack.

## What the plan gets RIGHT (verified, not rubber-stamped)

- §4a bare-5-tuple key + map inventory: confirmed against `key.rs:9-17`,
  `session_manager.rs:13-15`, `session/mod.rs:453-457`.
- §4c #3096 coherence gap: confirmed — NAT scope is computed at create
  (`nat_scope_ctx_for_flow`, `forwarding/mod.rs:120-145`) and the established
  path reuses the cached decision without re-checking it
  (`session_glue/mod.rs:1004-1044`). Real and well-stated.
- §4d HA-wire hard-break: confirmed against `sync_protocol.go` (key portion
  fixed-layout, reverse-key embedded in the value, only value-trailing
  length-gated). This is a genuine correction of campaign-8 and the strongest
  cost argument for deferring the key widening.
- §7 symmetric-discriminator-only argument (zone/ingress-ifindex asymmetric
  across forward/reply via `reverse_wire_key`/`reverse_canonical_key`): correct
  and is the key design insight that kills the issue's "and/or zone" suggestion.

## Required for r2

1. Rewrite §3/§4b: "reachable via PBR, latent in default mode" (S1).
2. Reframe A.1 as deliberate fail-closed reject of overlap even with PBR (S1/Q4).
3. Demote A.2; correct its scope (M1).
4. Tighten B-P0 to dense-interned-u32 / +4B (M2).
5. Resolve the leaked-flow corner: in-scope-with-dual-domain or out-of-B-MVP (m3).
