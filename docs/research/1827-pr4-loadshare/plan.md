# #1827 PR-4: weights/load-share — mandated audit + kill/ship decision

**Status:** DRAFT v2 — r1 fold. Round-1 verdicts: Claude SMR
PLAN-NEEDS-REVISION (F1-F6), Codex PLAN-NEEDS-REVISION (8 findings, 1
High), AGY PLAN-READY (endorsing the kill). v2 folds: **§3.3 rewritten**
(Codex High 1 + SMR F1 — synced sessions ARE re-resolved locally; the
v1 "symmetry is carried by sync" mechanism was wrong, and the corrected
mechanics make the kill case STRONGER); §3.1 claim narrowed + the
counter-example hunt documented (Codex 2/3, SMR F2); §3.2/§3.4 evidence
completed (Codex 4/6, SMR F3); steelman consolidated (SMR F4); close-out
docs amendment made mandatory (Codex 8, SMR F5); sort.Slice edge
disposition decided (SMR F6).

**Recommendation: Path D — PLAN-KILL the PR-4 stage and close #1827 as
completed by PR-1..3.** The mandated audit (§3, the section of record)
shows the stage's own kill criteria are met: (a) there is **no ECMP
next-hop selection in the userspace dataplane at all** — any
flow-distribution mechanism, weighted or equal-cost, requires new Rust
hot-path work, and because peer-synced sessions re-resolve locally, it
additionally requires a brand-new cross-node hash-symmetry invariant;
and (b) at 2 uplinks, with health-gated failover (PR-1), health-gated
per-policy FBF steering (PR-2), and per-uplink SNAT (PR-3) all shipped,
weighted hashing does not justify the churn.

---

## 1. Issue framing

#1827's program plan (`docs/research/1827-multiwan/plan.md` §5) staged
four PRs. PR-1a/1b (RPM hardening + ip-monitoring engine + routes-only
actuator, merged via #1843 with #1851 DHCP-tracked next-hops), PR-2
(FBF table rendering + recipe, #1848), and PR-3 (NAT interplay, #1856)
are merged. PR-4 — "Weights/load-share: health-gated ECMP overlay,
weighted flow-hash" — was explicitly NOT pre-authorized; its gate is
this research round, and its stage-local kill criteria are:

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
  recipe in `docs/multi-wan.md:92-152` steers classes of traffic to the
  alternate uplink via `instance-type forwarding` + firewall-filter
  `then routing-instance`, with per-policy counters, health-gated by an
  ip-monitoring policy that repoints the FBF instance's default at the
  surviving gateway. This IS the Junos-documented dual-WAN load-sharing
  pattern.
- **Per-uplink SNAT** (PR-3): zone/rule-set matchers verified
  sufficient; direct sessions pin to their resolved uplink until
  timeout/clear (`docs/multi-wan.md:215-234`).

**The steelman for shipping, stated and rebutted (SMR F4):** the one
operator story FBF cannot cover is asymmetric-capacity uplinks carrying
unclassifiable traffic (e.g. 1 G + 100 M, generic browsing), where a
weighted new-flow hash would auto-balance what FBF needs hand-
partitioned classes for. Rebuttal: (a) under PR-3 session pinning,
hashing redistributes **new flows only** — actual load convergence is
slow-to-never with long-lived flows, the same physics that killed
runtime RSS rebalancing (#840); (b) at exactly 2 uplinks the achievable
gain is bounded by what one hand-tuned FBF split already provides;
(c) SRX itself offers no weighted static ECMP — the operator coming
from Junos has never had this knob (equal-cost per-flow load-balance
via `forwarding-table export` is the only SRX analog, and that is Path
B, not PR-4-as-written); (d) the cost side is not an increment but a
new feature program (§3.4.3). The kill criteria anticipate exactly this
shape.

## 3. AUDIT OF RECORD — dp ECMP determinism, HA symmetry, actuation surfaces

All file:line references verified on `origin/master` (7cd20a6d2),
re-verified independently by Codex and AGY in round 1.

### 3.1 There is no ECMP next-hop selection in the userspace dataplane

- The wire carries a multi-next-hop shape:
  `RouteSnapshot.next_hops: Vec<String>`
  (`userspace-dp/src/protocol/snapshot.rs:128-129`; Go side
  `pkg/dataplane/userspace/protocol.go:503`). The Go builder emits one
  `"addr@iface"` string per config next-hop, in config order
  (`pkg/dataplane/userspace/routes.go:46-55`).
- The dp FIB **flattens that vec to ONE next-hop at build time**:
  `resolve_route_target_v4` / `_v6` call `route.next_hops.first()` and
  discard every other entry
  (`userspace-dp/src/afxdp/forwarding_build/fib.rs:162`, `:196`).
- The in-memory entry types carry a single hop:
  `RouteEntryV4 { next_hop: Option<Ipv4Addr>, .. }`
  (`userspace-dp/src/afxdp/types/forwarding.rs:123-140`).
- Lookup is longest-prefix `find` over a per-table vec sorted by
  prefix-len descending only (`forwarding_build/fib.rs:89-96`,
  `forwarding/mod.rs:1213-1220` v4, `:1361-1368` v6) into
  `choose_v4_route`/`choose_v6_route` (`forwarding/mod.rs:1624-1683`),
  which take no flow input.

**Counter-example hunt (documented per SMR F2; independently walked by
Codex and AGY with no deviation found):**

- PBR (`then routing-instance`) returns only a TABLE NAME override
  (`forwarding/mod.rs:984-989`), fed back into the same single-next-hop
  lookup (`poll_descriptor/mod.rs:656-661`).
- Tunnels resolve via a single `tunnel_endpoint_id` and recurse through
  the same route lookup (`forwarding/mod.rs:1511-1527`).
- Fabric is a fixed peer link (`forwarding_build/fib.rs:115-149`).
- SNAT consumes the already-resolved egress
  (`poll_descriptor/mod.rs:1158-1167`); the flow cache stores the
  chosen decision (`poll_descriptor/mod.rs:1992-2017`); NAT64 has no
  separate resolver.
- **Scope of the negative (Codex 2):** the claim is "no flow hash in
  route next-hop selection", NOT "no flow hash anywhere" — the dp does
  flow-hash for fabric QUEUE spreading (`fabric_queue_hash`,
  `worker/mod.rs:237-274`, consumed by `fabric_target_index`,
  `types/forwarding.rs:396-405`), which selects among queues of the one
  fabric link, never among route next-hops.

**Consequence:** "dp ECMP next-hop determinism" is trivial — every flow
matching a prefix resolves to `next_hops[0]`. There is no per-flow
selection to audit for stability. Conversely, **no load-share of any
kind (weighted or equal) can be built without new Rust hot-path work**:
the entry type, the build-time flattening, and the resolution path all
assume a single next-hop.

### 3.2 Kernel slow path vs dp fast path already diverge on ECMP

The config model declares multi-next-hop statics as ECMP
(`pkg/config/types_routing.go:99-105` — "multiple next-hops = ECMP").
FRR render emits one static line per next-hop — "Multiple next-hops
produce one line each (FRR creates ECMP)"
(`pkg/frr/config_render.go:82-85`, loop at `:125-167`) — and
`applyFRRConfig` enables L4 multipath hashing when `consistent-hash` is
configured (`pkg/daemon/daemon_ipmon.go:165-173`). The dp never ingests
kernel ECMP state: `StartFIBSync` is a documented no-op on in-tree
backends (`pkg/dataplane/dataplane.go:391-397`) and the helper FIB is
config-derived (`pkg/dataplane/userspace/routes.go:14-19`).

So for a multi-NH static today: kernel-forwarded (punted/slow-path)
traffic per-flow load-balances across all next-hops, while ALL dp
fast-path transit uses `next_hops[0]`. This divergence is pre-existing
and invisible on the loss cluster — every static there is
single-next-hop (`docs/ha-cluster-userspace.conf:231-233,259`). It is
recorded here for the program record; it is an argument that multi-NH
statics are already only half-supported, not an argument to build
weighting on top.

### 3.3 HA symmetry — synced sessions re-resolve locally (v2 rewrite)

v1 claimed synced sessions "don't re-resolve" because
`SessionSyncRequest` carries the owner's resolved `egress_ifindex`,
`tx_ifindex`, `next_hop`, `neighbor_mac`
(`userspace-dp/src/protocol/control.rs:512-525`). **That mechanism
description was wrong** (Codex r1 High; SMR F1). Verified mechanics:

1. **Go receive-side normalization:** the receiving node's manager
   mirrors a synced session into its own helper via
   `buildSessionSyncRequestV4` → `sessionSyncEgressLocked`
   (`pkg/dataplane/userspace/manager_ha.go:744,1038-1061`), which looks
   up the wire `FibIfindex` against the receiving node's OWN snapshot
   and normalizes egress/tx/RG from it.
2. **Rust receipt-time re-resolution:** `handle_upsert_synced`
   re-resolves the synced forward session with LOCAL egress regardless
   of HA state — "Synced sessions arrive with the remote node's
   interface indices and MACs which don't work on this node"
   (`userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:3-17`,
   re-resolve at `:39-44`, overwrite at `:55-60`).
3. **Packet-time lookup-first:** the cached-resolution fast path is
   DISABLED for peer-synced sessions
   (`session_glue/mod.rs:122-134`); `docs/multi-wan.md:231-234`
   documents the consequence (peer-synced and tunnel-backed sessions DO
   move onto an injected route; locally-created direct sessions stay
   pinned).

**HA symmetry today is therefore achieved by deterministic
re-resolution from the config-derived snapshot**, not by carrying the
decision: both nodes hold the same synced config, next-hop vec order is
config order (`pkg/config/compiler_routing.go:163,179,213,235`;
same-destination statics merge into one entry's NextHops at `:246`,
order asserted by `parser_routing_test.go:179-183`), and route
snapshots sort by (table, family, destination)
(`pkg/dataplane/userspace/routes.go:143-151`) — so `next_hops[0]` is
identical on both nodes and every re-resolution agrees. (Edge:
`sort.Slice` is unstable, so two snapshot entries sharing
(table,family,destination) — e.g. a static plus an ip-rule `next_table`
leak for the same prefix — have node-nondeterministic relative order;
pre-existing, noted in §10.)

**Consequence for a hypothetical weighted hash — the kill gets
stronger, not weaker:** because the standby re-resolves synced sessions
against its own FIB, a per-flow hash CANNOT be smuggled in via "the
owner decides and sync carries it". Cross-node hash symmetry becomes a
hard new invariant: identical hash inputs (flow-tuple + snapshot only —
no node-local identifiers), identical weight state, and identical
tie-breaking on BOTH nodes at all times, including mid-transition
windows where the two nodes hold different overlay/weight epochs. A
flow whose standby re-resolution picks the other uplink would, on
takeover, exit with the wrong SNAT binding (per-uplink pools, PR-3) and
break. Nothing existing provides or tests any of this.

### 3.4 What health-gated weighting could actuate through

1. **FRR/kernel weights** — structurally dead for the fast path: the dp
   FIB is config-derived; FRR/kernel runtime routes never reach the
   helper (§3.2). Kernel-side weighting would shape only punted
   traffic. (Whether FRR staticd even exposes a per-nexthop weight knob
   was NOT verified this round and is non-load-bearing — the verified
   config-derived-FIB fact alone kills this path; SMR F3.)
2. **The shipped route overlay** — single next-hop by construction at
   every layer: the engine resolves ONE winner per prefix
   (`pkg/ipmon/ipmon.go:351-358`), `RouteOverlayEntry` carries a single
   `NextHop` (`pkg/config/types_system.go:339-359`), the snapshot fold
   emits a single-element `NextHops` list
   (`pkg/dataplane/userspace/routes.go:160-191`, single element at
   `:172-177`), and the FRR render emits one `NextHopEntry`
   (`pkg/frr/config_render.go:283-288`). It can express 100/0 steering
   (which is exactly health-gated failover, already shipped), never a
   weighted split, unless the dp learns to hash (path 3).
3. **dp-side weighted flow-hash** — the only real path. Requires, at
   minimum: `RouteEntryV4/V6` single `next_hop` → per-entry next-hop
   array with weights; build-time flattening removed; a per-flow hash in
   `lookup_forwarding_resolution_v4/v6` (invoked per session establish,
   per fib-gen re-resolution, AND per synced-session receipt/packet —
   §3.3); per-next-hop neighbor lookup + missing-neighbor fallback
   semantics; a wire-additive weights field in `RouteSnapshot` (serde
   default → fixture regen → `protocol.go` → key-absent pins both
   sides); overlay schema growth (weights per overlay entry) + engine
   weight resolution; the §3.3 cross-node hash-symmetry invariant and
   its tests. Estimated 1.5-2.5k LOC across Rust hot path + wire + Go
   engine + tests. This is not an increment on an existing selector —
   it is building per-flow multi-next-hop forwarding from scratch and
   then weighting it.

### 3.5 Session-pinning interplay (PR-3 finding, binding here)

PR-3 established (`docs/multi-wan.md:215-234`): a fib-generation bump
invalidates only the flow cache; locally-created direct sessions reuse
their stored resolution (`session_glue/mod.rs:104-107`) and stay PINNED
to their uplink until timeout/clear (peer-synced and tunnel-backed
sessions are the two exceptions that do move). Therefore a weight
change — the entire point of *health-gated* weighting — redistributes
**new flows only**. Actual load convergence depends on flow churn; with
long-lived elephant flows it is slow-to-never (#840 precedent). Forcing
convergence would mean clearing established sessions on weight change,
i.e. deliberately breaking healthy connections for a balancing
objective, and re-NAT mid-session is forbidden (PR-3). Both options are
poor.

## 4. Concrete design (what PR-4 would be, if shipped)

Recorded for completeness; §11 recommends not shipping it. The honest
minimal design is §3.4 path 3 plus:

- Config surface: Junos has no weighted-static-ECMP analog. The nearest
  parity surface is equal-cost per-flow load-balance via
  `policy-options policy-statement LB then load-balance per-flow` +
  `routing-options forwarding-table export LB` (SRX `per-packet` is the
  historical spelling of per-flow). Weights would be an invention
  (charter violation) — e.g. `qualified-next-hop ... weight <n>`
  borrowed from other vendors.
- Health gating: ip-monitoring engine computes effective weights
  (FAIL ⇒ weight 0) and publishes them through the overlay; actuator
  unchanged otherwise.
- Hash: symmetric-safe 5-tuple hash → weighted rendezvous or fixed
  bucket table per route entry; identical across nodes (no node-local
  inputs — §3.3), stable under weight change for surviving next-hops
  (consistent hashing), else every weight nudge re-paths live (new)
  flows.

## 5. Staging

Single PR if shipped (Path A/B). If killed (Path D), close-out is:

1. Post the converged verdicts + this audit on #1827; label the stage
   kill `plan-kill`; close #1827 as completed by PR-1..3.
2. **Mandatory** (Codex 8, SMR F5): amend `docs/multi-wan.md:3-9` in a
   doc-only micro-PR so the module contract stops promising a later
   load-share PR. Wording: PR-4 was killed by its own research-gate
   criteria; PR-1..3 completed the multi-WAN operator deliverables
   (failover, FBF per-policy steering, per-uplink SNAT); equal-cost or
   weighted per-flow load-balance parity remains unimplemented and
   would be its own issue with its own value case if demand
   materializes. The close-out must NOT read as if load-sharing
   shipped.

## 6. Public API / compatibility preservation

- Path D (kill): zero code changes anywhere. The wire `next_hops` vec
  already tolerates multi-NH snapshots; behavior unchanged. The only
  artifact is the §5 docs amendment.
- Path A/B (ship): wire-additive weights field (serde default, fixture
  regen, both-sides pins); new config leaves additive; no Go exported
  API breaks. Rust hot-path struct change (`RouteEntryV4/V6`) is
  internal.

## 7. Hidden invariants (Path A/B only; all NEW)

1. **Hash symmetry across nodes** — hash inputs must exclude node-local
   identifiers (ifindex, binding ids); REQUIRED, not optional, because
   synced sessions re-resolve locally (§3.3); named cross-node test.
2. **Hash stability under weight change** — surviving-next-hop flows
   must not re-path (consistent hashing); named test.
3. **Transition-window agreement** — both nodes must converge weight
   epochs fast enough that takeover-time re-resolutions agree with the
   owner's original choice, or per-uplink SNAT breaks (§3.3).
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
| Hot-path perf | NONE | MED — per-resolution hash + bigger route entries; session-establish and synced-receipt rate sensitive |
| HA risk | NONE | HIGH — new cross-node hash-symmetry + transition-window invariants (§3.3, §7) |
| Wire risk | NONE | LOW-MED — additive field, both-sides discipline |
| Value delivered | Program already complete | Thin at 2 uplinks (§2 steelman, §3.5) |

## 9. Test & smoke plan

- Path D: no code, no smoke. The close-out comment records the audit;
  the docs micro-PR is prose-only.
- Path A/B (for the record): unit tests per §7 invariants including a
  cross-node hash-agreement fixture test; two-upstream incus topology
  (PR-2 deliverable) extended with per-uplink byte counters; smoke =
  N-flow iperf3 distribution within tolerance, weight flip mid-run, RG
  failover mid-run with distribution continuity (synced-session
  re-resolution agreement), `make test-failover`.

## 10. Out of scope (all paths)

- Per-packet load balancing (program plan §10).
- The pre-existing kernel-vs-dp multi-NH divergence (§3.2) — if anyone
  wants multi-NH statics to mean something on the fast path, that is
  its own issue with its own value case; PR-4's kill must not silently
  absorb it. Disposition (SMR F6): recorded in the #1827 close-out
  comment alongside the `sort.Slice` duplicate-key edge (§3.3) as one
  combined optional-follow-up note; no new issue filed unless an
  operator configures multi-NH statics or overlapping static+leak
  prefixes on a production topology.
- `qualified-next-hop preference` floating statics (program plan §10).

## 11. Path options

- **Path A — weighted dp flow-hash (the PR-4 row as written).**
  Rejected: meets the stage's own kill criteria in the strongest form.
  (1) §3.1 — there is no dp ECMP selection; the stage premise
  ("weight an existing mechanism") is void — the real work is building
  per-flow multi-next-hop forwarding from scratch in the Rust hot path
  (§3.4.3), precisely what the kill criterion excludes. (2) §3.3 —
  synced-session local re-resolution makes cross-node hash symmetry a
  hard new HA invariant. (3) §2 steelman — at 2 uplinks the value is
  marginal: new-flows-only convergence, elephant-flow physics (#840),
  and the FBF recipe already gives operators deterministic,
  health-gated load distribution. (4) §4 — weighted static ECMP has no
  Junos analog; shipping it violates the parity charter that anchored
  the whole program.
- **Path B — equal-cost per-flow load-balance only (Junos
  `forwarding-table export` parity).** Honest parity surface, but the
  Rust cost is essentially identical to Path A minus the weight field
  (§3.4.3 — the single-next-hop assumption is the cost, not the
  weights), and the value at 2 uplinks is the same thin slice. If
  genuine demand for SRX load-balance-per-flow parity materializes,
  file it as its own issue with its own value case — it is not a
  multi-WAN failover deliverable.
- **Path C — kernel-side weighting only.** Structurally dead: shapes
  only punted traffic (§3.4.1); the fast path never sees kernel routes.
- **Path D — PLAN-KILL the stage (RECOMMENDED).** PR-1..3 delivered the
  program's operator value (failover, per-policy steering, NAT
  interplay). Close #1827 as completed; label the stage kill per
  `plan-kill` convention; preserve this audit as the section of record;
  ship the §5 mandatory docs amendment; record the §10 edges in the
  close-out comment rather than silently absorbing them.
