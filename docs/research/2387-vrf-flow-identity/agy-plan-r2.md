# AGY — adversarial plan review r2 (convergence) (#2387)

Job `adversarial-review-mr0wp66c-c5nu8h`, reviewed plan v3. Verbatim verdict:

---

**Verdict: PLAN-DEFER**

Round 2 adversarial review of revised plan v3; verified all four findings from
Round 1.

1. **Attack 1 (PBR makes collision LIVE):** Confirmed the execution order in
   `poll_descriptor/mod.rs:474` and `poll_descriptor/mod.rs:1208`.
   `resolve_flow_session_decision` runs before PBR resolution, confirming that
   identical 5-tuples in VRF-B cache-hit VRF-A's established session.
2. **Attack 4 (Warning posture):** Verified that softening A.1 to a commit warning
   avoids breaking legitimate multi-tenant configs where subnets overlap.
3. **Attack 5 (Separation of B-min and B-ext):** Confirmed that Track B-min
   (widening key and interning routing-instance names via the dead
   `meta.routing_table` slot) functions correctly as a minimal fix on PBR
   configurations without needing the per-VRF default FIB (Track B-ext).
4. **HA-wire & Route Leaking Invariants:** Verified that the Go sync protocol at
   `sync_protocol.go:136-145` serializes keys inline, making key widening a hard
   break requiring a bump of `CurrentHAProtocolVersion` (`heartbeat.go:31`).
   Checked route recursion at `forwarding/mod.rs:1579-1604` and confirmed that
   scoping leaked flows to domain-0 in B-min is necessary to avoid reply matching
   failures.

**We agree with the PLAN-DEFER verdict.** The bug is real and reachable under PBR,
but resolving it requires a product-level scope decision and introduces a breaking
change to the HA wire sync format.

Key open decisions for maintainer input:
1. **Product Scope (§11 Q1):** Do we officially support overlapping-subnet VRFs via
   PBR? AGY recommends **Option (a)**: support it, ship the Track A.1 warning + A.3
   docs now, and schedule Track B-min for future implementation.
2. **Leaked Flow Scoping (§11 Q4):** Confirm that scoping leaked inter-VRF flows to
   domain-0 is acceptable for the first iteration (B-min) to avoid immediate
   conntrack reply matching failures.
