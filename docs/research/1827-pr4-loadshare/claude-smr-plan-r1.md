# Claude SMR hostile plan-review — #1827 PR-4 (weights/load-share), round 1

Reviewer: Claude (domain SMR — dataplane architecture, CPU/hot-path, HA).
Subject: `docs/research/1827-pr4-loadshare/plan.md` v1 (commit a1c222b28).
Posture: hostile. The plan recommends PLAN-KILL; a kill recommendation is
the easiest thing to rubber-stamp, so this review attacks (a) the audit's
evidence quality, (b) whether the kill criteria are genuinely met rather
than conveniently met, and (c) whether the value case for shipping is
being undersold.

## Verification performed

Re-walked every §3 citation against origin/master 7cd20a6d2 in the
worktree, plus counter-example hunts the plan did NOT document:

- `grep -rn "ecmp|multipath" userspace-dp/src -i` → zero hits. Confirms
  §3.1's central negative.
- `forwarding_build/fib.rs:162,196` — `route.next_hops.first()` at FIB
  build; all non-first next-hops are discarded before the hot path ever
  sees them. Confirmed.
- `types/forwarding.rs:123-140` — `RouteEntryV4/V6` single
  `next_hop: Option<Ipv*Addr>`. Confirmed.
- `forwarding/mod.rs:1213-1220` (v4) / `:1361-1368` (v6) — LPM `find`
  over prefix-len-sorted vec; `choose_v4/v6_route` (`:1624-1683`) has no
  flow input. Confirmed.
- **Counter-example hunt (plan gap — see Finding 2):** the PBR path
  (`resolve_pbr_table`, `forwarding/mod.rs:984-989`) returns only a
  TABLE NAME (`{ri}.inet.0`); resolution then re-enters the same
  single-next-hop lookup. Tunnels resolve via `tunnel_endpoint_id` to a
  single endpoint; fabric is a fixed peer link (`fib.rs:115-149`). No
  per-flow multi-next-hop choice anywhere. The plan's claim survives,
  but v1 doesn't SHOW the hunt — an audit-of-record must.
- FRR ECMP render comment `pkg/frr/config_render.go:125` ("One line per
  next-hop → FRR creates ECMP") + `daemon_ipmon.go:165-173` sysctl.
  Confirmed.
- Cluster config `docs/ha-cluster-userspace.conf:231-233,259` — all
  statics single-next-hop. Confirms §3.2's "invisible at the loss
  cluster" aside (v1 asserted this without evidence).

## Findings

**F1 (HIGH — factual error in the audit of record, §3.3).** v1 says
"`egress_ifindex` is node-local and re-mapped on sync receive". Wrong as
stated. Verified mechanics: the RECEIVING node's Go manager mirrors the
synced session into its own helper via `syncSessionV4Locked` →
`buildSessionSyncRequestV4` → `sessionSyncEgressLocked`
(`pkg/dataplane/userspace/manager_ha.go:744,1038-1061`), which looks up
the wire `FibIfindex` against the receiving node's OWN snapshot
(`findUserspaceEgressInterfaceSnapshot`) and normalizes egress/tx/RG
from it; the Rust receiver then consumes those values as-is
(`server/helpers.rs:263-268`, `handlers/sync_session.rs`). So cross-node
ifindex agreement is an EXISTING ASSUMPTION of the sync path (the local
lookup is keyed by the wire ifindex), not a re-mapping that PR-4 hash
symmetry could lean on. The audit conclusion (HA symmetry of established
flows is carried by sync, not symmetric computation) STANDS, but the
mechanism description must be corrected — this doc is the §-of-record
and will be quoted later.

**F2 (MEDIUM — undocumented counter-example hunt, §3.1).** The kill
pivots on "no ECMP selection anywhere". v1 cites the main lookup only.
The PBR/tunnel/fabric walk above must be IN the plan, with file:line,
so a future reader doesn't have to re-derive that the negative was
checked beyond one function. (Per `feedback_verify_whole_function_body`
discipline: a "missing X" claim's burden is the whole surface.)

**F3 (MEDIUM — unverified side-claim, §3.4.1).** "FRR staticd also
exposes no per-nexthop weight knob" is asserted from background
knowledge, not verified against FRR docs/source in this round. It is
NOT load-bearing (the verified fact that the dp FIB is config-derived
kills Path C alone — `routes.go:14-19`, program plan §3). Mark it as
such or drop it; an audit-of-record must separate verified from
believed.

**F4 (MEDIUM — value case stress-test, §2/§11).** Steelman the ship
case before killing: the one operator story FBF cannot cover is
*asymmetric-capacity uplinks with unclassifiable traffic* (e.g. 1 G +
100 M, generic browsing). Weighted new-flow hashing would auto-balance
where FBF needs hand-partitioned classes. The honest rebuttals — (a)
new-flow-only convergence under session pinning (§3.5), (b) elephant-
flow physics per the #840 precedent, (c) SRX itself offers no weighted
static ECMP so the operator coming from Junos has never had this, (d)
2 uplinks means the gain is bounded by one hand-tuned FBF split — are
all in v1 but scattered. Consolidate into one paragraph that names the
steelman explicitly and rebuts it. A kill that never states the best
ship argument is not an earned kill.

**F5 (LOW — disposition hygiene, §5/§10).** After the kill,
`docs/multi-wan.md:9` ("Health-gated load-sharing is a later PR") goes
stale. The plan waves at "a trivial docs commit at close-out (or left
to the next docs touch — reviewer call)". Make it definite: the
close-out includes the one-line docs amendment (project rule: docs are
part of the module contract; a doc promising a PR that was killed is a
contract bug, not a nice-to-have).

**F6 (LOW — §3.3 sort.Slice edge).** Correctly scoped as pre-existing
and out of scope, but the plan should state whether a hygiene issue
WILL be filed or not (current text: "if reviewers want it" — decide;
recommend: do not file, the colliding-key shape requires a config
already flagged by the §3.2 divergence, fold both into one optional
follow-up note in the close comment).

## On the kill criteria themselves

The stage row's criterion — "Kill if dp ECMP selection is not per-flow
stable across nodes without Rust work" — is met in the strongest
possible form: there is no dp ECMP selection AT ALL, so the entire
"health-gated ECMP overlay + weighted flow-hash" stage premise
(weighting an existing mechanism) is void; the stage would actually be
"build per-flow multi-next-hop forwarding from scratch in the Rust hot
path, then weight it". That is a new feature program, not a final
stage. The second criterion (churn vs value at 2 uplinks) follows: §3.4
path 3's honest cost (entry-type rewrite + wire change + new HA hash-
symmetry invariant + SNAT-interplay constraints) against new-flow-only
balancing at 2 uplinks. I find the kill EARNED subject to F1-F5
corrections.

## Verdict

**PLAN-NEEDS-REVISION** — endorse Path D (PLAN-KILL the stage, close
#1827 as completed by PR-1..3) contingent on: F1 corrected (factual),
F2 hunt documented, F3 marked unverified/non-load-bearing, F4
steelman consolidated, F5 made definite. No finding changes the
direction; all change the evidentiary quality of the §-of-record.
