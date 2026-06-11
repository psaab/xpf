# #1873 plan v3 — Claude SMR hostile review (round 3)

Reviewer: Claude (domain SMR). Posture: hostile. I attacked the one
open design question (conditional R-C gate) with the strongest trace
I could construct, plus the §11 round-3 questions.

## Attack — Q1, conditional gate: VRF-table divergence (NOT a kill)

Strongest candidate for a NON-transient resolvable-id plaintext case:
a tunnel interface inside a routing-instance whose INNER route exists
only in the VRF table. The userspace FIB resolves the inner dst via
that VRF route (tunnel-marked decision, id resolvable); the slow-path
reinjector is a plain `IFF_TUN` device (`slowpath.rs:17-19`
TUNSETIFF, IFF_TUN|IFF_NO_PI) with NO VRF binding — a reinjected
inner packet is routed in the MAIN table, which may lack the tunnel
route and default-route the packet out plaintext.

Why this does NOT kill the conditional gate:

1. It is PRE-EXISTING and tunnel-agnostic: today the same packets
   reinject with NO gate at all, and non-tunnel VRF traffic
   reinjected to the main-table TUN has the same divergence. The
   conditional gate strictly REDUCES the leak surface (absent ids
   now drop); it introduces no new path.
2. Blanket-drop would NOT fix the class either — it would only mask
   the tunnel-flavored instance while regressing WG cold start
   (pre-handshake traffic depends on reinjection into the wgN route,
   `wg_control.rs:214-249,547`).
3. VRF socket/table binding is explicitly deferred S6/#1434 territory
   (`wg_control.rs` bind_wg_socket VRF note: "owned by the S6
   multi-instance work").

**Required (editorial, fold into v3 final):** add this VRF residual
to §5 R-C and §10 with the trace above, so the implementation knows
the conditional gate's correctness domain is "kernel main-table view
matches the userspace FIB for tunnel inner routes" — true for the
default-table configs the project supports today on this path.

## Q2 — R-E admission rerouting: ratified

The kernel performs its own neighbor resolution for reinjected
packets (ARP/ND on the outer path after wgN/GRE encap). Userspace
outer-neighbor buffering existed to avoid the slow path for ordinary
ethernet egress; tunnel egress through the kernel devices does not
need it. No tunnel mode harmed; cold first-packets take the kernel
path instead of the buffer — strictly better than today's plaintext.

## Q3 — counter visibility: ratified

Additive `ProcessStatus` JSON with both-sides serde defaults is the
established pattern (#1865/#1876). No objection.

## Q4 — purge-walk coverage: confirmed display-only elsewhere

`purge_queued_flows_for_closed_deltas` (`session_delta.rs:14-36`)
already drops queued pending-forward frames for Close deltas — R-D
purges ride the same machinery, so queued frames die with the
session. Post-encap TxRequests in CoS/cross-binding queues carry
ALREADY-ENCAPSULATED bytes (encap happens at build) — safe.
`recent_session_deltas` ring and eventstream buffers are
display/replay surfaces, not forwarding state. `pending_neigh` is
emptied of tunnel-marked frames by R-E. No additional store found.

## Q5 — remaining holes: none found

The v3 invariant set (§7.4 id-owner injectivity, §7.6
encapsulated-or-not-at-all, §7.1 config-pure determinism) closes
every defect class traced in rounds 1-2. Path A v3 is strictly
better than shipping nothing on every axis measured.

## Verdict

PLAN-READY — conditional on the editorial VRF-residual paragraph
(§5 R-C + §10), which I am folding into the plan in this same
commit. No code-design changes required.
