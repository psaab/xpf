# AGY — adversarial plan review r1 (#2387)

Job `adversarial-review-mr0wcll0-pk94mc`, reviewed plan v1. Verbatim verdict:

---

**Verdict: PLAN-NEEDS-MAJOR-REVISION**

**1. Attack 1: Refuting the Latency Claim (PBR Routing is Fully Functional Today)**

The headline PLAN-DEFER relies on the premise that the collision is latent because
the forwarding layer cannot isolate VRFs anyway (global `inet.0` + global local
sets). This premise is incorrect. Under PBR `then routing-instance`, the slow-path
forwarding layer is fully table-scoped and correctly isolated today:
`ingress_route_table_override` returns the overridden table
(`forwarding/mod.rs:1211-1289`); `lookup_forwarding_resolution_v4` is strictly
table-scoped for static and connected routes (`forwarding/mod.rs:1494-1550`). For
transit traffic packets never hit the global `local_v4` check. So two routing
instances reusing a subnet and forwarding transit (differentiated by ingress port
+ PBR table) work correctly on the slow path. But the conntrack lookup
`lookup_session_across_scopes` (`shared_ops.rs:563-605`) queries by only the bare
5-tuple `SessionKey` (`session/key.rs:9-17`), so the second flow matches the first
flow's session and the fast path returns the first flow's cached `SessionDecision`,
cross-forwarding to the wrong egress. This is a LIVE, active bug today for anyone
deploying overlapping subnets with PBR-based routing instances. Not latent.

**2. Attack 2: Validating the HA-Wire Hard Break** — §4d is CORRECT. Widening
`SessionKey` is a hard HA wire break. `encodeSessionV4Payload`
(`sync_protocol.go:80-171`) serializes the primary key at bytes 0-15 then value
fields from offset 16; the `ReverseKey` is embedded in the value at offset 136
(`:136-145`). `decodeSessionV4Payload` (`:315-425`) assumes a fixed 16-byte key at
offset 0 and reads value fields at fixed offsets. Widening the key shifts every
subsequent field; an old peer reads wrong bytes → deserialization corruption. Not
length-gated in a backward-compatible way.

**3. Attack 3: Symmetry of the Discriminator and Inter-VRF Route Leaking** — §7 is
CORRECT. Reply matching relies on `reverse_wire_key`/`reverse_canonical_key`
(`session/key.rs:84-138`). Ingress ifindex and ingress zone are asymmetric (reply
enters on the forward egress). Routing-domain id is symmetric for intra-VRF flows.
The inter-VRF route-leaked corner is real: a packet leaked VRF-A→VRF-B has forward
ingress domain VRF-A but reply ingress domain VRF-B; a simple routing-domain id in
the key breaks reply matching for leaked flows. Track B must store both ingress and
egress domains or exempt leaked flows.

**4. Attack 4: The Commit-Time Overlap Guard (Track A.1) False Rejections** — Track
A.1 falsely rejects legitimate, working configurations. Users can legitimately
reuse subnets across distinct routing-instances via PBR table override + forwarding
isolation — standard VRF design. A.1 would reject this at compile time to work
around a fast-path bug, stripping multi-tenant overlapping-subnet support.

**5. Attack 5: Phase Ordering Critique** — the assertion that B-P2 (key widening)
before B-P1 (per-VRF FIB) is a dead-end is incorrect. PBR table overrides already
handle table-scoped forwarding on the slow path, so doing B-P2 first would
immediately resolve fast-path session collisions for PBR-based VRF configs —
functioning VRF isolation on the fast path without waiting for the larger per-VRF
default FIB. Phase ordering should prioritize key widening + PBR support.
