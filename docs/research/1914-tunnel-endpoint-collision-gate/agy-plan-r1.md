# AGY adversarial plan review — #1914 r1

Job: adversarial-review-mqi20z89-0y1ddu (succeeded 2026-06-17)

**Verdict: PLAN-NEEDS-REVISION**

## Finding 1 (High) — Peer-group expansion failure is a fatal regression path
ast_groups.go:163-167: expanding for node1 when only `groups node0` exists
errors (`undefined group "node1"`), aborting validation and failing commit
on node0 for a config valid on node0. Path 1 must NOT let a per-node
expansion error become the gate verdict.

## Finding 2 (Critical) — Infinite recursion / stack overflow
compiler.go:115-119 + :176-180: CompileConfig*/CompileConfigForNode call
validateTunnelEndpointIDCollisionAST FIRST. If the gate calls those public
entry points to build views 2/3 → infinite recursion. Gate must run a
direct sub-compiler on the expanded interfaces subtree (or a pure
candidate emitter), NEVER the public CompileConfig* APIs.

## Finding 3 (Medium) — O1 crux: group-supplied src/dst in an un-applied
nested-apply-groups group → false ACCEPT if view 1 is narrowed to
complete-only. Counter-example: group-c declares `gr-0/0/0.0` mode gre +
apply-groups my-group (src/dst), group-c un-applied. View 1 (narrowed)
drops it (no src/dst literally present); views 2/3 never expand un-applied
group-c → ref never registered → collision missed. Violates the
group-scoped symmetry invariant. Keep view 1 presence-only OR define
explicit latent-group analysis.

## Finding 4 (Low) — Emitter is config-pure, NOT byte-identical to the
emitted snapshot: builder filters against runtime InterfaceSnapshot rows
(tunnels.go:65-68), which don't exist at commit. Emitter returns the
CONFIGURED candidate set; builder intersects with runtime ifaces + applies
usedIDs. State this boundary explicitly.
