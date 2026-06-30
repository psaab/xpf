# Codex — hostile plan review r1 (#2387)

Reviewed plan v1. Codex ran successfully (NOT infra-blocked). Verbatim verdict:

---

**PLAN-NEEDS-MAJOR-REVISION**

**1. ESCALATION CHECK — CONFIRMED**

A forwarding-correct live path exists via input FBF/PBR, so the plan's "latent
only" premise is wrong. Valid input `then routing-instance` is explicitly allowed:
`pkg/config/firewall_ri_output_direction_3432_test.go:59-69` and
`pkg/config/firewall_ri_conflict_3308_test.go:81-97`. On a session miss, PBR
produces a per-packet table override: `userspace-dp/src/afxdp/forwarding/mod.rs:1211-1225`,
evaluates the routing-instance filter at `mod.rs:1239-1251`, returns
`<ri>.inet.0`/`<ri>.inet6.0` at `mod.rs:1283-1288`. The miss path passes that
override into FIB lookup at `poll_descriptor/mod.rs:1208-1216`, `1244-1249`.
Overlapping per-table forwarding works when a table is supplied:
`forwarding/tests.rs:2455-2460, 2510-2536, 2539-2546, 2602-2626`. Local delivery
is table-scoped too. The session key is still bare `flow.forward_key` at
`poll_descriptor/mod.rs:2217-2224`. A later same-5-tuple packet hits session
lookup **before** DNAT/PBR/policy miss logic at `poll_descriptor/mod.rs:473-493`,
`session_glue/mod.rs:1037-1044`; that lookup uses only the 5-tuple key at
`shared_ops.rs:563-604`. Plan citation error: `userspace-dp/src/types/forwarding.rs`
does not exist; current file is `userspace-dp/src/afxdp/types/forwarding.rs`.

**2. WIRE-BREAK CHECK §4d — CONFIRMED**

The session-sync key block is fixed-width, not length-gated. V4 encodes a fixed
`keySize := 16` then value bytes: `sync_protocol.go:80-98`. V4 decode requires
only `len(payload) >= 16`, parses exactly 16 key bytes, treats offset 16 as value
start: `sync_protocol.go:315-331`. Length-gated fields are value/trailing only:
`sync_protocol.go:343-344, 368-390, 409-422`. V6 same with a fixed 40-byte key:
`:180-192, 429-445`. The embedded reverse key is also fixed-width inside the value:
V4 `:136-145`, V6 `:231-240`. Widening either primary or reverse key shifts later
fields for old decoders — hard wire break confirmed. Plan citation error:
`CurrentHAProtocolVersion` is at `pkg/cluster/heartbeat.go:27-31`, not `sync.go:36`.
The upgrade gate treats mismatched HA protocol versions as non-rolling-compatible
at `pkg/upgrade/cluster_cli.go:246-248`.

**3. SYMMETRY CHECK §7 — CONFIRMED**

`reply_matches_forward_session` accepts only `reverse_wire_key`/`reverse_canonical_key`:
`session/key.rs:19-25`; transforms carry identity from the forward key
`:84-121, 124-138`. `ingress_zone` is asymmetric (`poll_descriptor/mod.rs:2174-2176`
forward, `:2422-2424` + `shared_ops.rs:658-660` reverse; zone derivation depends on
ingress+egress ifindex `forwarding/mod.rs:275-292`). Ingress ifindex also asymmetric
(`forwarding/mod.rs:583-591`). Symmetric: a routing-domain/VRF id keyed by ifindex
`afxdp/types/forwarding.rs:64-69`. Caveat: route leaking/`next-table` can cross
domains (recursion `forwarding/mod.rs:1579-1604`), so inter-VRF flows need design
beyond a single ingress-domain field.

**4. COHERENCE GAP CHECK §4c — CONFIRMED**

Plan path error: `userspace-dp/src/session/session_glue/mod.rs` does not exist;
correct is `userspace-dp/src/afxdp/session_glue/mod.rs`. NAT scope IS enforced at
session creation (`nat/mod.rs:34-47`, `nat/source.rs:294-318`,
`poll_descriptor/nat_exception.rs:43-80`, DNAT `poll_descriptor/mod.rs:953-1002`).
The established fast path does NOT re-run that scope gate:
`resolve_flow_session_decision` calls `lookup_session_across_scopes(..., &flow.forward_key, ...)`
at `session_glue/mod.rs:1037-1044`, reuses `resolved.decision` at `1072-1089`; the
lookup helper takes no NAT scope / ingress RI / egress RI / zone args at
`shared_ops.rs:563-570`. The coherence gap is real.

**Final verdict: PLAN-NEEDS-MAJOR-REVISION** — the PLAN-DEFER rationale rested on
"overlapping-subnet flows cannot be forwarded correctly today regardless of session
key," which is refuted: valid PBR `then routing-instance` produces table-scoped
per-miss forwarding that works, and the bare-5-tuple key then causes the second
VRF's established flows to hit the wrong session entry. Live bug for any operator
using input firewall filters with `then routing-instance` across overlapping
subnets. The HA wire-break, symmetry constraint, and NAT-coherence gap assessments
are confirmed accurate (modulo the path/line citation errors noted).
