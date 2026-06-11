# #1827 PR-4: weights/load-share — mandated audit + kill/ship decision

**Status:** DRAFT v1 — fresh /research round mandated by the program plan
(`docs/research/1827-multiwan/plan.md` §5, PR-4 row: "Requires auditing dp
ECMP next-hop determinism + HA symmetry first", gate "PR-3 merged + a fresh
/research round (NOT pre-authorized)").

**Recommendation: Path D — PLAN-KILL the PR-4 stage and close #1827 as
completed by PR-1..3.** The mandated audit (§3, the section of record)
shows the stage's own kill criteria are met: (a) there is **no ECMP
selection in the userspace dataplane at all** — any flow-distribution
mechanism, weighted or equal-cost, requires new Rust hot-path work; and
(b) at 2 uplinks, with health-gated failover (PR-1), health-gated
per-policy FBF steering (PR-2), and per-uplink SNAT (PR-3) all shipped,
weighted hashing does not justify the churn.

---

## 1. Issue framing

#1827's program plan staged four PRs. PR-1a/1b (RPM hardening +
ip-monitoring engine + routes-only actuator, merged via #1843 with #1851
DHCP-tracked next-hops), PR-2 (FBF table rendering + recipe, #1848), and
PR-3 (NAT interplay, #1856) are merged. PR-4 — "Weights/load-share:
health-gated ECMP overlay, weighted flow-hash" — was explicitly NOT
pre-authorized; its gate is this research round, and its stage-local
kill criteria are:

> Kill if dp ECMP selection is not per-flow stable across nodes without
> Rust work; weighted hashing may not justify churn at 2 uplinks.

This document is the mandated audit plus the honest kill/ship analysis.

## 2. Honest scope/value framing

The operator-visible promise of PR-4 would be: traffic automatically
load-shares across both healthy uplinks (weighted by capacity), and the
weights are health-gated (a degraded uplink sheds load before it fails
outright).

What the operator already has after PR-1..3:

- **Failover** (PR-1): probe-driven preferred-route injection; dead
  uplink is abandoned end-to-end (FRR + kernel + dp snapshot + FIB-gen
  bump) within one debounce window.
- **Deterministic load distribution by traffic class** (PR-2): the FBF
  recipe in `docs/multi-wan.md` steers classes of traffic to the
  alternate uplink via `instance-type forwarding` + firewall-filter
  `then routing-instance`, health-gated by an ip-monitoring policy that
  repoints the FBF instance's default at the surviving gateway. This IS
  the Junos-documented dual-WAN load-sharing pattern.
- **Per-uplink SNAT** (PR-3): zone/rule-set matchers verified sufficient;
  sessions pin to their resolved uplink until timeout/clear; fib-gen bump
  invalidates only the flow cache.

The marginal value of PR-4 on top of that is automatic per-flow
distribution of *unclassified* traffic at exactly 2 uplinks. §11 argues
this is thin, non-parity (weighted static ECMP is not an SRX feature),
and poorly matched to the deployment's traffic shape (long-lived flows
defeat flow-hash balancing — same physics as the #840 RSS-rebalance
dead-end).

## 3. AUDIT OF RECORD — dp ECMP determinism, HA symmetry, actuation surfaces

All file:line references verified on `origin/master` (7cd20a6d2).

### 3.1 There is no ECMP selection in the userspace dataplane

- The wire carries a multi-next-hop shape:
  `RouteSnapshot.next_hops: Vec<String>`
  (`userspace-dp/src/protocol/snapshot.rs:128-129`; Go side
  `pkg/dataplane/userspace/protocol.go:503`). The Go builder emits one
  `"addr@iface"` string per config next-hop, in config order
  (`pkg/dataplane/userspace/routes.go:46-55`).
- The dp FIB **flattens that vec to ONE next-hop at build time**:
  `resolve_route_target_v4` / `_v6` call `route.next_hops.first()` and
  ignore every other entry
  (`userspace-dp/src/afxdp/forwarding_build/fib.rs:162`, `:196`).
- The in-memory entry types carry a single hop:
  `RouteEntryV4 { next_hop: Option<Ipv4Addr>, .. }`
  (`userspace-dp/src/afxdp/types/forwarding.rs:123-140`).
- Lookup is longest-prefix `find` over a per-table vec sorted by
  prefix-len descending only (`forwarding_build/fib.rs:89-96`,
  `forwarding/mod.rs:1213-1220` v4, `:1361-1368` v6) into
  `choose_v4_route`/`choose_v6_route` (`forwarding/mod.rs:1624-1683`).
  **No hash of any flow field appears anywhere in route resolution.**
  `grep -rn "ecmp\|multipath" userspace-dp/src --include="*.rs" -i`
  returns nothing.

**Consequence:** "dp ECMP next-hop determinism" is trivial — every flow
matching a prefix resolves to `next_hops[0]`. There is no per-flow
selection to audit for stability. Conversely, **no load-share of any
kind (weighted or equal) can be built without new Rust hot-path work**:
the entry type, the build-time flattening, and the resolution path all
assume a single next-hop.

### 3.2 Kernel slow path vs dp fast path already diverge on ECMP

FRR render emits one static line per next-hop — "One line per next-hop →
FRR creates ECMP" (`pkg/frr/config_render.go:125-127`) — and
`applyFRRConfig` enables L4 multipath hashing when `consistent-hash` is
configured (`pkg/daemon/daemon_ipmon.go:165-173`). So for a multi-NH
static today: kernel-forwarded (punted/slow-path) traffic per-flow
load-balances across all next-hops, while ALL dp fast-path transit uses
`next_hops[0]`. This divergence is pre-existing, invisible at the
loss-cluster topology (no multi-NH statics configured), and recorded
here for the program record; it is an argument that multi-NH statics are
already only half-supported, not an argument to build weighting on top.

### 3.3 HA symmetry

- **Snapshot determinism:** both nodes build the dp FIB from the synced
  config; next-hop vec order is config order
  (`pkg/config/compiler_routing.go:163,179,213,235`; same-destination
  statics merge into one entry's NextHops at `:246`), and route
  snapshots sort by (table, family, destination)
  (`pkg/dataplane/userspace/routes.go:148-156`). Same config ⇒ same
  `next_hops[0]` ⇒ both nodes resolve a given flow identically. (Edge:
  `sort.Slice` is unstable, so two snapshot entries sharing
  (table,family,destination) — e.g. a static plus an ip-rule
  `next_table` leak for the same prefix — have node-nondeterministic
  relative order; pre-existing, out of PR-4 scope.)
- **Synced sessions don't re-resolve:** `SessionSyncRequest` carries the
  owner's resolved `egress_ifindex`, `tx_ifindex`, `next_hop`,
  `neighbor_mac` (`userspace-dp/src/protocol/control.rs:512-525`), so
  the standby inherits the owner's uplink choice rather than recomputing
  it; fabric-forwarded packets are forwarded by the session owner. HA
  symmetry for established flows is **carried by sync**, not by
  symmetric computation.
- **Consequence for a hypothetical weighted hash:** new flows after
  takeover would hash on the new primary against the same snapshot —
  symmetric if and only if the hash inputs are wholly flow+snapshot
  derived (no node-local state like ifindex numbering, which differs
  per node — note `egress_ifindex` is node-local and re-mapped on sync
  receive). Achievable, but it is a NEW invariant to design, test, and
  hold forever; nothing existing provides it.

### 3.4 What health-gated weighting could actuate through

1. **FRR/kernel weights** — structurally dead for the fast path: the dp
   FIB is config-derived; FRR/kernel runtime routes never reach the
   helper (`pkg/dataplane/userspace/routes.go:14-19` doc comment;
   program plan §3). FRR staticd also exposes no per-nexthop weight
   knob for statics (weighted ECMP in FRR is BGP link-bandwidth
   machinery). Kernel-side weighting would shape only punted traffic.
2. **The shipped route overlay** (`RouteOverlayEntry`,
   `pkg/config/types_system.go:339-352`; actuator
   `pkg/daemon/daemon_ipmon.go`) — whole-entry replacement by
   construction (`routes.go:14-19`): it can express 100/0 steering
   (which is exactly health-gated failover, already shipped), never a
   weighted split, unless the dp learns to hash (path 3).
3. **dp-side weighted flow-hash** — the only real path. Requires, at
   minimum: `RouteEntryV4/V6` single `next_hop` → per-entry next-hop
   array with weights; build-time flattening removed; a per-flow hash in
   `lookup_forwarding_resolution_v4/v6` (cold-path resolution, but
   invoked per session establish and per fib-gen re-resolution);
   per-next-hop neighbor lookup + missing-neighbor fallback semantics;
   a wire-additive weights field in `RouteSnapshot` (serde default →
   fixture regen → `protocol.go` → key-absent pins both sides); overlay
   schema growth (weights per overlay entry) + engine weight resolution;
   the HA hash-symmetry invariant of §3.3. Estimated 1.5-2.5k LOC
   across Rust hot path + wire + Go engine + tests.

### 3.5 Session-pinning interplay (PR-3 finding, binding here)

PR-3 established that direct sessions PIN to their resolved uplink until
timeout/clear; a fib-generation bump invalidates only the flow cache,
not session resolutions. Therefore a weight change (the entire point of
*health-gated* weighting) redistributes **new flows only**. Actual load
convergence depends on flow churn; with the long-lived elephant flows
this deployment is dominated by, convergence is slow-to-never — the same
physics that killed runtime RSS rebalancing in #840. Forcing
convergence would mean clearing established sessions on weight change,
i.e. deliberately breaking healthy connections for a balancing
objective. Both options are poor.

## 4. Concrete design (what PR-4 would be, if shipped)

Recorded for completeness; §11 recommends not shipping it. The honest
minimal design is §3.4 path 3 plus:

- Config surface: Junos has no weighted-static-ECMP analog. The nearest
  parity surface is equal-cost per-flow load-balance via
  `policy-options policy-statement LB then load-balance per-flow` +
  `routing-options forwarding-table export LB` (SRX `per-packet` is
  historical spelling of per-flow). Weights would be an invention
  (charter violation) — e.g. `qualified-next-hop ... weight <n>`
  borrowed from other vendors.
- Health gating: ip-monitoring engine computes effective weights
  (FAIL ⇒ weight 0) and publishes them through the overlay; actuator
  unchanged otherwise.
- Hash: symmetric-safe 5-tuple hash → weighted rendezvous or fixed
  bucket table per route entry; must be identical across nodes and
  stable under weight change for surviving next-hops (consistent
  hashing), else every weight nudge re-paths live (new) flows.

## 5. Staging

Single PR if shipped (Path A/B). Not staged further — the program plan
already staged it as the final stage. If killed (Path D): no code; close
#1827; `docs/multi-wan.md` "load-sharing is a later PR" line is amended
in a trivial docs commit at close-out time (or left to the next docs
touch — reviewer call).

## 6. Public API / compatibility preservation

- Path D (kill): zero changes anywhere. The wire `next_hops` vec already
  tolerates multi-NH snapshots; behavior unchanged.
- Path A/B (ship): wire-additive weights field (serde default, fixture
  regen, both-sides pins); new config leaves additive; no Go exported
  API breaks. Rust hot-path struct change (`RouteEntryV4/V6`) is
  internal.

## 7. Hidden invariants (Path A/B only; all NEW)

1. **Hash symmetry across nodes** — hash inputs must exclude node-local
   identifiers (ifindex, binding ids); named cross-node test required.
2. **Hash stability under weight change** — surviving-next-hop flows
   must not re-path (consistent hashing); named test.
3. **Session-sync precedence** — synced resolution always wins over
   local re-hash (already the mechanism, must stay).
4. **Whole-entry overlay replacement** (program plan invariant 8)
   extends to weights — no partial weight merge.
5. **Missing-neighbor fallback** must not silently re-shift load
   (a next-hop with no neighbor entry ⇒ MissingNeighbor punt today;
   with hashing, falling over to another hop changes the distribution
   and breaks per-uplink SNAT zone expectations).
6. **Per-uplink SNAT consistency** — the hashed egress decides the SNAT
   pool; re-hash ⇒ re-NAT is forbidden mid-session (PR-3 pinning
   preserves this; weight-change session-clear would violate it).

## 8. Risk assessment

| Class | Path D (kill) | Path A/B (ship) |
|-------|---------------|-----------------|
| Behavioral regression | NONE | MED-HIGH — route resolution rewritten for every transit flow |
| Hot-path perf | NONE | MED — per-resolution hash + bigger route entries; cold path but session-establish rate sensitive |
| HA risk | NONE | MED — new cross-node symmetry invariant |
| Wire risk | NONE | LOW-MED — additive field, both-sides discipline |
| Value delivered | Program already complete | Thin at 2 uplinks (§2, §3.5) |

## 9. Test & smoke plan

- Path D: none (no code). The close-out comment records the audit.
- Path A/B (for the record): unit tests per §7 invariants; two-upstream
  incus topology (PR-2 deliverable) extended with per-uplink byte
  counters; smoke = N-flow iperf3 distribution within tolerance, weight
  flip mid-run, RG failover mid-run with distribution continuity,
  `make test-failover`.

## 10. Out of scope (all paths)

- Per-packet load balancing (program plan §10).
- The pre-existing kernel-vs-dp multi-NH divergence fix (§3.2) — if
  anyone wants multi-NH statics to mean something on the fast path,
  that is its own issue with its own value case; PR-4's kill must not
  silently absorb it.
- The `sort.Slice` duplicate-key nondeterminism edge (§3.3) —
  pre-existing, cosmetic until someone configures overlapping
  static + leak entries; separate hygiene issue if reviewers want it.
- `qualified-next-hop preference` floating statics (program plan §10).

## 11. Path options

- **Path A — weighted dp flow-hash (the PR-4 row as written).**
  Rejected: meets the stage's own kill criteria. (1) §3.1 — there is no
  dp ECMP selection; weighted hashing is new Rust hot-path machinery
  (§3.4.3), precisely what the kill criterion excludes. (2) §2/§3.5 —
  at 2 uplinks the value is marginal: new-flows-only convergence,
  elephant-flow physics (#840 precedent), and the FBF recipe already
  gives operators deterministic, health-gated load distribution.
  (3) §4 — weighted static ECMP has no Junos analog; shipping it
  violates the parity charter that anchored the whole program.
- **Path B — equal-cost per-flow load-balance only (Junos
  `forwarding-table export` parity).** Honest parity surface, but the
  Rust cost is identical to Path A minus the weight field (§3.4.3 —
  the single-next-hop assumption is the cost, not the weights), and the
  value at 2 uplinks is the same thin slice. If genuine demand for SRX
  load-balance-per-flow parity materializes, file it as its own issue
  with its own value case — it is not a multi-WAN failover deliverable.
- **Path C — kernel-side weighting only.** Structurally dead: shapes
  only punted traffic (§3.4.1); the fast path never sees kernel routes.
- **Path D — PLAN-KILL the stage (RECOMMENDED).** PR-1..3 delivered the
  program's operator value (failover, per-policy steering, NAT
  interplay). Close #1827 as completed; label the stage kill per
  `plan-kill` convention; preserve this audit as the section of record;
  note the §3.2 divergence and §10 hygiene edges as optional follow-up
  issues rather than silent absorption.
