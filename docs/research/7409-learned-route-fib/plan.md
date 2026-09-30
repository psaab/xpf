# #7409 — the helper FIB carries no learned routes: decision document

**Status:** PLAN-READY. No production code written.
**Verified at:** `30c99fa70` (origin/master at time of writing).
**Scope of this document:** choose ONE branch of #7409's either/or acceptance
criterion, with evidence, and reject the other with reasons.

Every cite below was re-derived at `30c99fa70`. Cites inherited from #7409 and
#6664 that had drifted are listed in §8.

---

## 1. The decision, up front

**Adopt Branch B — kernel-learned routes reach the helper FIB — implemented as a
gap-filling importer in `pkg/routing/` consumed by `buildRouteSnapshots`.**

**Reject Branch A — refuse to arm when a dynamic routing protocol is
configured.** Reasons in §5. In short: keyed on protocols it closes nothing (the
DHCP vector needs no protocol stanza, and two configs that ship in this repo hit
it today); made sound by extending it to DHCP it bricks 20 of 23 shipped
configs including the entire smoke/HA substrate; and it is unsound *in principle*
because FRR runs whatever sits outside the managed markers, which `cfg.Protocols`
cannot see.

**Scope Branch B to the importer only.** Dropping `NoRoute` instead of
reinjecting it — #6664's shapes 1-tail, 3 and 4 — is explicitly NOT in this work.
§6.4 explains why the importer narrows the window but does not close it, so the
reinject must stay.

---

## 2. What is actually true at HEAD

### 2.1 The divergence is real and the mechanism is as described

`buildRouteSnapshots` (`pkg/dataplane/userspace/routes.go:34`) derives the helper
FIB from exactly four sources, and its own doc comment at `:20-22` names three of
them:

1. config statics — `cfg.RoutingOptions.StaticRoutes` / `Inet6StaticRoutes`, plus
   per-routing-instance statics;
2. connected prefixes derived from `InterfaceSnapshot`;
3. kernel **ip rules** via `ruleListFn = netlink.RuleList` (`routes.go:18`),
   mirrored as synthetic next-table leak routes;
4. the ip-monitoring overlay, applied last (`applyRouteOverlay`, `routes.go:378`).

`grep netlink. pkg/dataplane/userspace/routes.go` yields exactly two hits:
`netlink.RuleList` (`:18`) and `netlink.SCOPE_UNIVERSE` (`:585`). **There is no
kernel route read anywhere in the snapshot build.** The repo states it itself at
`docs/multi-wan.md:665-670`: *"The dataplane FIB baseline is config-derived and
carries no DHCP-learned routes."*

`deriveUserspaceCapabilities` (`pkg/dataplane/userspace/capabilities.go:44-113`)
has exactly three disarm reasons — SYN-cookie screen material, color-aware
three-color policers, and persistent SNAT under HA. **None is routing-related.**
Nothing signals the degraded state.

### 2.2 `NoRoute` is reinjected, and the reinject is unadjudicated

`is_slow_path_eligible` (`userspace-dp/src/afxdp/types/forwarding.rs:1210-1218`)
includes `NoRoute`. Its own doc comment at `:1185-1186` states the design intent:
*"(e.g. a route the helper has not yet learned); let the kernel try,
rate-limited."*

The flowless policy gate runs only for `ForwardCandidate`
(`poll_descriptor/mod.rs:3568`), and the chokepoint at
`poll_descriptor/mod.rs:5443` reinjects anything the predicate admits.

Nothing downstream catches it. Each re-verified at HEAD:

- **No nft forward chain.** `grep ChainHook` across `pkg/` returns only
  `ChainHookInput` (`pkg/nftables/netlink_installer.go:161`) and
  `ChainHookOutput` (`pkg/nftables/rst_suppress.go:121`). `ChainHookForward`
  appears nowhere. `pkg/daemon/daemon_transit_gate.go:19-21` says it in prose.
- **`ip_forward` is 1 whenever armed** — `daemon_transit_gate.go:54-56`: *"the
  gate NEVER lowers the knob while armed."*
- **`rp_filter` is driven to 0 on `xpf-usp0`** after every networkd reload —
  `pkg/networkd/networkd.go:550-563`.
- **No `ip rule` scopes `xpf-usp0`.** Zero hits for `xpf-usp0` in `pkg/routing/`.
  PBR/FBF rules carry `IifName` scoped to real NICs (`pkg/routing/rules.go:820-830`,
  #5117), so they never match a packet arriving on the TUN. The reinjected packet
  resolves in **main**.
- **The rate limit is not a mitigation** — `userspace-dp/src/slowpath.rs:16-17`:
  1,000,000 pps / 4 GiB/s.

### 2.3 Two corrections to the issue text

**(a) `NoRoute` is not what most learned destinations resolve to.** The Rust FIB
lookup is longest-prefix-match with fallback:
`routes.iter().find(|entry| entry.prefix.contains(ip))` over a list sorted
descending by prefix length (`forwarding/fib.rs:392`, `forwarding_build/fib.rs:161-184`).

So a **config default route in the helper FIB masks the divergence**. #7409 says
*"every transit packet toward a learned prefix resolves `NoRoute`"* — that holds
only when no less-specific helper route covers the destination. With a
`route 0.0.0.0/0` static configured (which is most shipped configs), the packet
matches the default, is **adjudicated normally**, and is forwarded to the *static
default's* next-hop — not the learned one.

That is a second, distinct failure mode from the same root cause:

| helper FIB has a covering route? | disposition | outcome |
|---|---|---|
| No (no default configured) | `NoRoute` | reinject → kernel forwards via learned route, **no policy, no session, no NAT, no screen** — the #7409 security hole |
| Yes (config default) | `ForwardCandidate` | policy IS evaluated, but the packet goes to the **wrong next-hop** — silent misrouting/blackhole, not a bypass |

Both are caused by the same missing import and both are fixed by Branch B. The
security framing is correct for the first row; the second row is probably the
more common production symptom and #7409 does not mention it. Neither is a reason
to weaken the fix; stating it correctly matters because **the smoke cluster sits
in the second row** (§7.4), so a smoke run cannot red on the first.

**(b) A mgmt-interface DHCP lease does NOT create this exposure.** Leases on
management interfaces (`fxp*`/`fab*`/`em*`) are excluded from FRR entirely —
`collectDHCPRoutes` skips them (`pkg/daemon/daemon_flow.go:47-56`) and they are
programmed by netlink into **mgmt VRF table 999** stamped `RTPROT_DHCP`
(`daemon_flow.go:203-211`). A packet reinjected on `xpf-usp0` resolves in main and
never reaches table 999. #7409's *"or simply taking a DHCP default route"* is
therefore true only for a **non-management** interface.

---

## 3. Question 1 — what is the actual exposure today?

**The exposed set is: any route in a kernel table a reinjected packet can reach
(main, or a VRF table an ip rule steers it into) that the helper FIB does not
carry.** Concretely, four populations:

| population | reaches main table? | needs a protocol stanza? |
|---|---|---|
| FRR BGP/OSPF/OSPFv3/IS-IS/RIP routes | yes | **yes** |
| DHCP default on a **non-mgmt** interface, when no renderable static default of the same family exists | yes, AD 200 (`pkg/frr/config_render.go:332`) | **no** |
| DHCP RFC 3442 classless routes (option 121/249) on a **non-mgmt** interface — **never suppressed**, suppression applies only to the default (`config_render.go:305-310`) | yes, AD 200 | **no** |
| Routes from operator content **outside** the managed markers in `/etc/frr/frr.conf` (`pkg/frr/manager.go:606-636`; `pkg/frr/README.md:85-89`) | yes | **no — and invisible to `cfg` entirely** |

Not exposed: connected prefixes and config statics (both in the helper FIB);
ip-monitoring preferred routes (carried by the overlay); `backup-router` and the
HA cluster-mode default (both `Null0`/blackhole, so a kernel forward is a drop
anyway).

**Answer to "is a DHCP default route alone sufficient?" — yes, on a non-management
interface.** Two configs that ship in this repo hit it with zero protocol
stanzas:

- `examples/deploy/standalone.conf:26` — `ge-0/0/1 { unit 0 { family inet { dhcp; } } }`,
  and the file has **no `routing-options` stanza at all**, so the DHCP default is
  the only default route and nothing suppresses it.
- `test/incus/xpf-internet-test.conf:75,78` — `dhcp` + `dhcpv6` on the WAN data
  port `enp10s0`, likewise with no static default.

**Answer to "does `deriveUserspaceCapabilities` disarm on any input that would
save this?" — no.** Its three reasons are listed in §2.1. It is a `cfg`-only
gate and would not see the unmanaged-FRR population even if a routing reason were
added.

---

## 4. Question 2 — is there a route-source signal already available?

**Yes, and it is complete, in-tree, and regression-pinned. It should be reused,
not reinvented.**

`pkg/routing/routes.go:317-357` — `rtProtoName(netlink.RouteProtocol) string`
maps every RTPROT value this deployment can produce, including FRR's private
`RTPROT_ZSTATIC = 196` declared at `:315` with a `zebra/rt_netlink.h` citation.
Its doc comment at `:320-331` records zebra's stamping convention verbatim:
`bgpd→RTPROT_BGP(186)`, `ospfd/ospf6d→RTPROT_OSPF(188)`, `isisd→RTPROT_ISIS(187)`,
`ripd→RTPROT_RIP(189)`, `staticd→RTPROT_ZSTATIC(196)`,
`connected/local/kernel→RTPROT_KERNEL(2)`. Pinned by `pkg/routing/rtproto_test.go`.

It is **display-only today** — consumed by `routeToEntry` (`routes.go:220`) for
`show route` and the `show route protocol <x>` filter. Nothing in the snapshot
path sees it.

What else exists, and what does not:

- **Kernel route dumps exist**: `netlink.RouteList` / `RouteListFiltered` are
  already used in eleven places, including `RT_FILTER_PROTOCOL` filtering at
  `pkg/daemon/daemon_flow.go:278`. The read primitive needs no new dependency.
- **No route-event subscription exists**: `RouteSubscribe` /
  `RouteSubscribeWithOptions` / `unix.RTM_*` / `RTNLGRP_ROUTE` return **zero hits
  repo-wide**. But `NeighSubscribeWithOptions` is used at
  `pkg/daemon/daemon_neighbor_listener.go:137` and pushes to the helper — that is
  the exact working precedent for the refresh trigger (§6.4).
- **No zebra API**: no zapi, no zserv socket, no FRR northbound/gRPC. FRR is read
  only via `vtysh` stdout. `GetRouteDetailJSON` (`pkg/frr/status_parse.go:502`)
  parses `show ip route json` and carries `Protocol`, `Selected`, `Installed`,
  `Distance`, `Metric` and per-next-hop `Active`/`FIB`/`Recursive` — the richest
  source attribution in the tree, wired only to `show route detail`. It is a
  plausible alternative input but is a subprocess-per-call and gives FRR's RIB,
  not the kernel FIB the reinject actually consults. **Prefer netlink**: it is
  what the packet will meet.
- **`RouteSnapshot` has no source field** (`pkg/dataplane/userspace/protocol_routes.go:3-22`).
  Adding one is a wire change gated by `CONFIG_SNAPSHOT_PROTOCOL_VERSION`'s
  exact-equality check (`userspace-dp/src/server/handlers/snapshot.rs:22-31`).
  §6.2 avoids needing one.

---

## 5. Question 3a — what breaks under "refuse to arm", and why it is rejected

Inventory of all 23 checked-in xpf config files (14 `.conf`, 6 `.set`, 3 captured
`show configuration` transcripts), plus the day-0 fixture inside
`scripts/image/validate.py:1291-1293`:

**Dynamic routing protocols: zero hits. Not one shipped config configures BGP,
OSPF, OSPFv3, IS-IS, RIP or RIPng.** Every `protocols` stanza in every config is
either `router-advertisement` (handled by `pkg/ra`, installs no routes) or the
`host-inbound-traffic { protocols { router-discovery; } }` admit token.

**DHCP client (`family inet { dhcp; }`): 20 of 23 files.** Including:

| file | line | effect of a DHCP-keyed arm gate |
|---|---|---|
| `docs/ha-cluster-userspace.conf` | 15, 44 (`fxp0`) | **blocked** — this is `CLUSTER_CONF` in `test/incus/loss-userspace-cluster.env`, the substrate for every smoke and `test-failover` run |
| `docs/ha-cluster.conf` | 15, 44 | blocked |
| `docs/ha-cluster-loss.conf` | 15, 44 | blocked |
| `test/incus/xpf-test.conf` | 5 | blocked — the standalone VM config |
| `test/incus/xpf-cluster-fw0.conf` / `fw1.conf` | 58 / 56 | blocked |
| `test/incus/xpf-internet-test.conf` | 75, 78 | blocked |
| `examples/deploy/standalone.conf` | 18, 26 | blocked — a shipped customer example |
| `examples/deploy/ha-pair.conf` | 34, 51 | blocked — a shipped customer example |
| `scripts/image/validate.py` | 1291 | blocked — the day-0 image fixture |

Only `test/incus/xpf-vlan-test.conf` and the six `.set` overlays survive, and one
of those overlays (`test/incus/fbf-two-upstream-config.set:4`) explicitly bases on
a blocked file.

### Why Branch A is rejected — three independent reasons, any one sufficient

1. **Keyed on protocols, it closes nothing.** The protocol half fires on zero
   shipped configs while the DHCP vector — which needs no protocol stanza — is
   live on two of them today (§3). It would ship as a gate that costs a BGP
   customer their entire dataplane and buys no coverage of the vector that
   actually reaches this repo's own fleet.

2. **Made sound, it bricks the fleet.** Extending it to DHCP disarms 20 of 23
   configs. And "disarm" here is not a graceful degradation to kernel forwarding:
   #5275's transit gate drives `ip_forward` and `ipv6.conf.all.forwarding` to **0**
   on every path landing in `setDataplane(nil)` (`daemon_transit_gate.go:29-33`).
   A refused arm therefore produces a box that forwards **nothing**. Trading a
   policy bypass for a guaranteed total outage on the entire shipped fleet,
   including the smoke substrate, is a strictly worse posture.

3. **It is unsound in principle.** `writeManagedSection`
   (`pkg/frr/manager.go:606-636`) strips and rewrites only the marker-delimited
   block; operator content outside it is preserved verbatim across every apply
   (`pkg/frr/README.md:85-89`). `/etc/frr/daemons` is not referenced anywhere in
   the repo, so which routing daemons run is outside xpf's control entirely. A
   hand-written `router bgp` outside the markers installs main-table routes that
   `cfg.Protocols` cannot see. **A config-keyed gate can never be sound about what
   FRR actually runs** — so even the "safe" branch would still be silently
   fail-open for the case an operator is most likely to have created deliberately.

An explicit decision is owed either way, so: the gate is rejected, and the
rejection should be recorded in `capabilities.go` as a comment in the same style
as the existing class-(i)/class-(ii) note, so the next reader does not re-propose
it. That is a comment-only change to a file already in scope.

---

## 6. Question 3b — Branch B: the design, and what breaks under it

### 6.1 Shape

A **gap-filling kernel-FIB importer** in `pkg/routing/`:

- Enumerate kernel routes per relevant table with `netlink.RouteListFiltered`,
  the primitive already used at `pkg/daemon/daemon_flow.go:278`.
- Classify each by `route.Protocol` using the existing `rtProtoName` mapping
  (`pkg/routing/routes.go:317-357`) — exported or mirrored as a
  `learned`/`not-learned` predicate. This is the "route-source signal already
  available" from §4; no new mechanism.
- Return a typed list that `buildRouteSnapshots` consumes as a **fifth source**,
  appended after the existing four and before `applyRouteOverlay`.

### 6.2 The precedence rule — refined by #11323, without a wire change

**The importer is preference-aware, not unconditional gap-fill.** For each
canonical `(table, family, prefix)`, the snapshot builder finds the best
configured ordinary route. When its preference is 200 or better, the imported
route is discarded and the configured route remains the sole candidate. When
the configured route has a worse preference (for example a floating static at
250), both candidates are emitted and the Rust FIB's #2390 ascending-
preference tie-break selects the kernel-selected route imported at preference
200. #11323 corrected the original gap-fill-only implementation, which let a
floating static remain active while FRR had selected a better learned route.

FRR renders config statics, generate-routes, DHCP defaults, `backup-router`,
cluster blackholes and ip-monitoring preferred routes through staticd, so
their kernel entries can share `RTPROT_ZSTATIC(196)`. The preference gate keeps
an imported route from replacing a config candidate that is at least as good;
it deliberately allows a better learned route to sit beside a lower-preference
config fallback.

The existing boundaries still hold:

- the `#3770` dedupe key includes `Preference`, so distinct configured/imported
  candidates survive as separate entries;
- the `#2390` sort tie-break makes the lower-preference candidate win;
- the overlay's whole-entry replacement contract (`routes.go:422-443`), which
  #1827 guarantees, still prevents an ECMP half-override.

The preference-aware rule reuses `RouteSnapshot.Preference`, so it needs no
`CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump and Go and Rust need not ship together.

Exclusions the importer must carry, each with a concrete reason:

- the HA blackhole sentinel — `Type: RTN_BLACKHOLE` with `Priority == 4242`
  (`pkg/daemon/daemon_ha.go:1421-1425`): xpf owns it and the helper has its own
  HA disposition;
- mgmt VRF table 999 (`daemon_flow.go` `mgmtVRFTableID`): not reinject-reachable
  (§2.3b), and importing it would give the fast path a route to a management
  gateway it must not use for transit;
- `RTPROT_REDIRECT` (1): ICMP-redirect-installed, not a routing decision xpf
  should adopt.

### 6.3 Ordering against the overlay

`applyRouteOverlay` must still run **last**, and must replace imported entries for
its `(table, family, prefix)` exactly as it replaces config-derived ones —
otherwise an ip-monitoring failover route could be shadowed by a stale imported
route for the same prefix, silently undoing #1827. This is one line of ordering
discipline in `routes.go` and needs an explicit test (§7.1, case 5).

### 6.4 What breaks — the honest weaknesses

**(a) The route can change between snapshot and packet.** Today the FIB is pushed
only on operator commit and on ipmon actuation (debounce 1s, throttle 3s —
`pkg/ipmon/ipmon.go:58,61`). There is **no trigger on a kernel route change**.
Two sub-cases, with different severities:

- **Stale-present** — the helper holds a route the kernel has withdrawn. The
  helper forwards toward a next-hop that may be gone, gets `MissingNeighbor`,
  and reinjects; the kernel then decides. Self-healing, and the flowless
  `MissingNeighbor` arm now enforces zone policy (#4024,
  `poll_descriptor/mod.rs:3557-3562` comment). **Acceptable.**
- **Stale-absent** — the kernel has learned a route the helper has not imported
  yet. `NoRoute` → reinject → exactly today's behaviour.

**So the importer converts a permanent bypass into a bounded-window one. It does
not close it.** This is the single most important honest statement in this
document, and it is why the `NoRoute` drop must NOT ride along: #6664's shape-1
tail (*"then dropping it is safe"*) is only true once the window is closed, and a
push-on-commit importer does not close it.

**(b) Closing the window needs a route-event listener, and that is outside the
loan.** The pattern exists: `pkg/daemon/daemon_neighbor_listener.go:137`
subscribes to `RTM_NEWNEIGH`/`DELNEIGH` and drives a helper push. A
`RouteSubscribeWithOptions` sibling is the natural follow-on, in `pkg/daemon/`.

**(c) A route-event listener must be throttled, or it will starve session
installs.** Every publish is a **full snapshot replace** — the Rust side rebuilds
from `ForwardingState::default()` (`forwarding_build/mod.rs:407`) — over a 64 MiB
control socket whose deadline scales at 3s + 1s/MiB
(`pkg/dataplane/userspace/process_control.go:34-56`). CLAUDE.md's control-socket
rule is explicit that a new caller above 1/s starves session installs during bulk
sync. Under BGP churn a per-event push would do exactly that. The importer's
refresh **must** reuse ipmon's debounce/throttle discipline (1s/3s) and must never
push per netlink event. A naive implementation gets this wrong and the failure
mode is a control-plane brownout, not a visible error.

**(d) Snapshot size.** A box holding a full BGP table would push hundreds of
thousands of `RouteSnapshot` entries through a JSON control socket on every
publish. This design is **not** viable for a full-table BGP speaker, and the plan
should say so rather than discover it. A bounded import (a configurable cap with
a loud degraded-state diagnostic, mirroring `maxPBRRules` /
`config.NextTableRuleWindow` precedent) is the right shape; choosing the cap needs
a measurement this plan does not have.

### 6.5 Question 4 — the third shapes, and why they are not the fix

**Kernel-side nft `hook forward` chain applying policy to reinjected transit.**
Viable in principle — #5275's `docs/research/5275-arm-failclosed/plan.md` §6
already contemplates an inet FORWARD barrier — but wrong as *this* fix. It
requires mirroring zone policy, application matching, NAT and screen semantics
into nftables: a second policy engine with its own divergence surface, which is
the precise defect class #6664 invokes when it says "change both paths in one PR,
or neither". It also cannot be a blanket FORWARD drop, because
`daemon_transit_gate.go:49-53` records legitimate armed paths that rely on kernel
forwarding — route-based-VPN plaintext leaving an xfrm interface, and SNAT'd
frames passed up for kernel routing. **Rejected as the fix; worth filing as
defence-in-depth.**

**Adjudicate-then-reinject (#6664's own prescription).** Confirmed dead at HEAD,
independently of #6664's comment: `no_route_resolution`
(`userspace-dp/src/afxdp/forwarding/fib.rs:794-806`) sets `egress_ifindex: 0`
unconditionally, so `to_id` is always 0, and the `#3110` guard
(`userspace-dp/src/policy.rs:2676-2687`) then refuses zone-pair **and**
`junos-global` rules and falls through to `default_action` (default `Deny`). The
verdict is constant, so it is an unconditional drop wearing a policy costume — it
would black-hole every learned destination. **Rejected.**

**Ingress-zone-only adjudication (#6664 shape 2).** A new evaluation mode where
`to_id` unknown consults `from-zone X to-zone any`. It needs a policy-engine
change in `userspace-dp/src/policy.rs` that #3110's author explicitly rejected for
unzoned transit, and it cannot express "this destination is legitimately reachable
via BGP" — a permissive from-zone rule gives no protection, a strict one
black-holes. **Rejected as primary.** It becomes a reasonable residual guard only
*after* the FIB divergence closes, when `NoRoute` is rare and truthful.

---

## 7. Test strategy

### 7.1 Go — `pkg/routing/` importer + `routes.go` wiring

Table-driven against an injected route lister, mirroring the existing
`ruleListFn` seam (`routes.go:18`) and its test
`pkg/dataplane/userspace/routes_rulelist_3772_test.go`:

1. **BGP-learned prefix, no covering config route** → appears in the snapshot.
   *This is the acceptance-criterion test #7409 asks for.*
2. **Non-mgmt DHCP default (`RTPROT_ZSTATIC`, AD 200), no static default** →
   appears. Covers the no-protocol-stanza vector from §3.
3. **RFC 3442 classless route on a non-mgmt lease** → appears (never suppressed).
4. **Config static for the same prefix already present** → import discarded,
   exactly one entry, at the config preference. Guards §6.2.
5. **Overlay entry for the same prefix** → overlay wins, imported entry replaced,
   not merged. Guards §6.3 and the #1827 no-half-override contract.
6. **Excluded populations** → HA blackhole (`Priority 4242`), mgmt table 999,
   `RTPROT_REDIRECT` each absent from the snapshot.
7. **Lister error** → fails the snapshot build closed, matching the #3772 M9
   contract `routes.go:322` already establishes for `RuleList`. A partial FIB is
   worse than no update.

**Middle/partial states, not just the extremes** (the failure mode this repo keeps
paying for):

8. **Same prefix, different table** → imported into that table only; no
   cross-table leakage.
9. **ECMP learned route (multiple next-hops)** → all next-hops land, or the route
   is rejected whole. A half-imported ECMP set is the #1827 defect in a new place.
10. **Learned route whose next-hop is not resolvable to an ifindex** → follows the
    existing `resolve_route_next_hops_v4` bare-gateway inference
    (`forwarding_build/fib.rs:74-80`, #4446/#2388) or is dropped loudly; must not
    silently produce a route the helper cannot use.
11. **Import cap reached** → the SAME tail is dropped deterministically and the
    build is marked degraded, mirroring the `#6467` window discipline in
    `routes.go:~161`. A nondeterministic tail is a kernel/dataplane verdict split.
12. **Empty import** → snapshot byte-identical to pre-change. This is the
    regression fence for all 20 shipped configs that have no learned routes.

### 7.2 Rust — the two in-tree artefacts

**The false comment** — `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3557`
reads `//     #3292; NoRoute drops anyway; MissingNeighbor keeps its`. Verified
false: `is_slow_path_eligible` at `types/forwarding.rs:1210-1218` includes
`NoRoute`, and the chokepoint at `mod.rs:5443` reinjects on that predicate. It is
a **comment pointing the safe way about a dangerous behaviour**, which is why the
gap survived review. Correct it to state that `NoRoute` is slow-path eligible and
is reinjected to the kernel FIB unadjudicated, and cite #7409.

**`tests_fragment.rs` — the prescribed strengthening is wrong, and I recommend
against it as written.** The brief asks that
`flowless_non_first_fragment_steered_by_pbr_routing_instance_3291`
(`userspace-dp/src/afxdp/tests_fragment.rs:632-680`) *"assert the packet did NOT
reach the slow path"*. Two findings:

- **The obvious assertion is vacuous.** `binding.live.slow_path_no_route_packets`
  is bumped only by `record_slow_path_accept`, which runs only after a reinjector
  is successfully selected (`tx/dispatch/slow_path.rs:225`, `:299`). The test
  harness sets `slow_path: None` (`tests_support.rs:1123`), so that branch is
  never reached — the counter is 0 whether the packet reached the slow path or
  not. Asserting it `== 0` would reproduce the exact expected-value-equals-
  failure-default defect the issue is complaining about, in a new place.
- **The intended assertion is false at HEAD and stays false after this fix.** With
  `slow_path: None`, a packet that reaches the reinject site bumps
  `live.slow_path_drops` and records a `"slow_path_unavailable"` exception
  (`slow_path.rs:283-293`). At HEAD the PBR-steered fragment **does** reach it. The
  importer does not change that: the test builds an empty `scrub` table by
  construction, so `NoRoute` still resolves and the packet is still reinjected.

  **Recommended instead:** assert the *true* behaviour —
  `binding.live.slow_path_drops == 1`, or that the exception ring contains
  `"slow_path_unavailable"` (precedent: `tests_slow_path_disposition.rs:630-637`
  collects reasons; `tests_gre_local_delivery.rs:139` and
  `tests_embedded_poll_filter.rs:2682` already assert on `slow_path_drops`) — and
  fix the test's own comment, which claims *"-> NoRoute -> drop"*. That comment is
  the same false-safe-direction defect as the `poll_descriptor` one, in a test.
  Asserting the packet is reinjected makes the PBR under-steer visible and gives
  the eventual `NoRoute`-drop work a test that will red when the behaviour changes
  — which is the durable outcome. Asserting "did not reach the slow path" today
  would simply fail.

  This is a genuine disagreement with the brief's item 3, raised with evidence.
  If the intent is nonetheless to make "did not reach the slow path" true, that
  requires deciding the `NoRoute`-drop question, which §1 defers.

**New Rust test for the fix itself** — a snapshot carrying an imported learned
route resolves `ForwardCandidate` and is policy-evaluated, red-on-revert by
removing the route from the snapshot. This lives in the Rust suite but exercises
Go-produced snapshot content, so the Go table test (§7.1 case 1) is the primary
proof and this is corroboration.

### 7.3 The Prometheus metric — lands WITH the fix

The counters **already exist end-to-end** and are simply not exported:

- helper: `binding_state/mod.rs:352-355` (`AtomicU64` ×4) →
  `binding_state/snapshot.rs:150-157` → wire
  `userspace-dp/src/protocol/binding.rs:612-618`;
- Go: `pkg/dataplane/userspace/protocol_binding.go:271`
  (`SlowPathNoRoutePackets`), already aggregated with deltas in
  `pkg/monitoriface/monitor.go:108,460,666,711` and rendered in
  `pkg/dataplane/userspace/format/status_sections.go:269`;
- Prometheus: **zero hits for `slow_path` anywhere in `pkg/api/`.**

So this is an export-only change following an exact in-tree precedent:
`emitBindingVMinThrottleCounters` (`pkg/api/metrics_userspace.go:924-935`), whose
own doc comment describes the identical situation — *"have been on the
BindingStatus wire since #941/#943 … but were never exported. Emitted
unconditionally per binding so a 0 is a real 'brake never fired' signal rather
than an absent series."* That last clause is the requirement here too: emit
unconditionally, so a flat zero is evidence rather than absence.

Four counters, `CounterValue`, labelled `slot`/`queue_id`/`worker_id`/`interface`
like every sibling:
`xpf_userspace_binding_slow_path_{no_route,next_table,local_delivery,missing_neighbor}_packets_total`.

Without this, a rising reinject rate reaches no alerting — the symptom of this bug
is unobservable in production even once you know to look for it.

### 7.4 What the smoke can and cannot prove

`docs/ha-cluster-userspace.conf` — the substrate for every smoke and
`test-failover` run (`CLUSTER_CONF` in `test/incus/loss-userspace-cluster.env`) —
has **no dynamic protocols**, DHCP only on `fxp0` (mgmt, so table 999), and static
defaults at `:240-241`. By §2.3 and §3 it therefore has **no learned route in a
reinject-reachable table at all**.

**Consequence: the smoke cannot red on this bug and cannot prove the fix.** Its
role is purely a no-regression fence — that the importer, running against a
kernel table containing only routes xpf itself installed, produces a
byte-identical snapshot and does not perturb forwarding or failover. §7.1 case 12
is the unit-level version of the same fence and is the one that will actually
catch a regression.

Demonstrating the fix needs a config with a learned route in main. The cheapest
honest option is `test/incus/xpf-internet-test.conf` (DHCP on the WAN data port,
no static default) on the standalone VM — but that is not the cluster and is not
part of the standard gate.

---

## 8. Cite corrections — what had to be re-derived

| claim | cited as | actual at `30c99fa70` |
|---|---|---|
| `is_slow_path_eligible` | #6664: `forwarding.rs:1019-1027` | `types/forwarding.rs:1210-1218` — **drifted ~190 lines** |
| `deriveUserspaceCapabilities` | #7409: `capabilities.go:43-113` | `capabilities.go:44-113` (function opens at 44) |
| the false comment | both: `poll_descriptor/mod.rs:3554-3568` | comment block `3553-3566`; the false clause is on **`:3557`** |
| the fragment test | #7409: `tests_fragment.rs:635` | `fn` at `:632`, assertions at `:672-680` |
| `buildRouteSnapshots` sources | both: `routes.go:20-22` | correct — doc comment `:20-22`, function at `:34` |
| `docs/multi-wan.md` self-admission | both: `:666-668` | bullet spans **`:665-670`** |
| transit gate prose | #7409: `daemon_transit_gate.go:20-22` / `:56-58` | "no nftables `hook forward` chain" spans **`:19-21`**; "the gate NEVER lowers the knob while armed" spans **`:54-56`** |
| `rp_filter` on the TUN | #7409: `networkd.go:537-561` | `restoreSlowPathRPFilter` at **`:550-563`** |
| PBR unrepresentable-term deferral | #7409: `rules.go:843-849` | matrix at `:833-850`; the *"userspace filter path still enforces the term exactly"* clause is at **`:849-850`**, repeated at `:896` and `:1212` |
| `nftables` input chain | #7409: `netlink_installer.go:161` | correct |
| slow-path rate limit | #7409: `slowpath.rs:16-17` | correct |

**A substantive correction, not a line-number drift:** #7409 characterises
`rules.go:849-850` as claiming something false. It is more precise than that. The
userspace filter path *does* enforce the PBR term exactly — it steers the packet
to the `scrub` table. What fails is the **consequence**: the steered table is
empty, so the lookup yields `NoRoute` and the reinject sends the packet down the
kernel main table, undoing the steer. The comment's claim is true and its
implication is false. The fix is the same (close the divergence), but a reviewer
told the comment is a lie will look in the wrong place.

---

## 9. Scope — what this needs beyond the loan

In the loan and sufficient for the core fix:

- `pkg/routing/` — the importer (ours outright);
- `pkg/dataplane/userspace/routes.go` — wire it in as the fifth source, plus the
  gap-fill and ordering rules;
- `pkg/dataplane/userspace/capabilities.go` — comment recording the rejected
  arm-gate (§5);
- `poll_descriptor/mod.rs:3557` — the comment correction.

**Outside the loan; each needs an explicit extension:**

1. `pkg/api/metrics_userspace.go` — the Prometheus export (§7.3). The brief
   requires this to land *with* the fix, and it cannot be done from the loaned
   files. **This is the one escalation that is non-negotiable given the brief's
   own conditions.**
2. `userspace-dp/src/afxdp/tests_fragment.rs` — the test change (§7.2). The loan
   names only the `poll_descriptor` comment on the Rust side.
3. `pkg/daemon/` — the route-event listener that closes the staleness window
   (§6.4b). **Recommend deferring to a follow-up issue**, not extending scope: it
   is a separate, testable unit and the importer is useful without it.
4. `pkg/dataplane/userspace/` test files — new tests for §7.1 live beside
   `routes.go` (`routes_*_test.go` convention). Presumably implied by the
   `routes.go` loan, but worth confirming.

Not needed: no `pkg/config` change (no new stanza), no
`CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump (§6.2), no `RouteSnapshot` wire change.

---

## 10. Gate obligations

**Any fix here moves the `userspace-dp` helper binary and therefore owes a cluster
smoke plus `make test-failover`.** The `poll_descriptor` comment correction alone
moves the binary's file hash, and the §7.2 test change and any Rust-side test
addition recompile the crate. Per the standing rule a changed compiled artifact
owes a smoke regardless of whether `.text` moved.

Both gates must be run centrally by whoever owns the cluster. **They were not run
for this document and must not be inferred from it.** Per §7.4, a green smoke on
`ha-cluster-userspace.conf` is a no-regression signal only — it is not evidence
the bug is fixed.

## 11. What cannot be verified without hardware or a cluster

- **That a BGP/OSPF-learned prefix is in fact reinjected unadjudicated on a real
  box.** No shipped config runs a dynamic protocol (§5), so this has never been
  observed in this repo's fleet. It is derived from code — `buildRouteSnapshots`
  has no kernel route read, `NoRoute` is slow-path eligible, no nft forward chain,
  `ip_forward` forced on — each independently verified, but the composition is
  inference, not measurement.
- **The staleness window's real width under route churn** (§6.4a). Needs a live
  BGP peer flapping routes while traffic runs.
- **The snapshot-size ceiling** (§6.4d). Needs a measurement against a real table
  to choose the import cap; this plan deliberately does not guess a number.
- **Whether a per-event refresh would starve session installs** (§6.4c). The
  control-socket contention rule predicts it; confirming needs the cluster.
- **`rp_filter` behaviour on the real reinject path** — `conf/all/rp_filter` is a
  host setting the appliance does not own (`networkd.go:565-575` only warns), so
  the reinject may already be dropped on some hosts. That changes the exposure's
  practical reach and is unknowable from the tree.

---

## Appendix — one-line summary of each verified fact

| fact | cite |
|---|---|
| helper FIB has no kernel route read | `pkg/dataplane/userspace/routes.go:18,34,585` |
| capabilities gate has no routing reason | `pkg/dataplane/userspace/capabilities.go:44-113` |
| `NoRoute` is slow-path eligible | `userspace-dp/src/afxdp/types/forwarding.rs:1210-1218` |
| the reinject chokepoint | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:5443` |
| the false comment | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3557` |
| policy gate is `ForwardCandidate`-only | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3568` |
| no nft forward chain | only `ChainHookInput` `pkg/nftables/netlink_installer.go:161`, `ChainHookOutput` `pkg/nftables/rst_suppress.go:121` |
| `ip_forward` forced on while armed | `pkg/daemon/daemon_transit_gate.go:54-56` |
| `rp_filter` 0 on `xpf-usp0` | `pkg/networkd/networkd.go:550-563` |
| no ip rule scopes the TUN; FBF is iif-scoped | `pkg/routing/rules.go:820-830` |
| reinject rate limit | `userspace-dp/src/slowpath.rs:16-17` |
| FIB lookup is LPM with default fallback | `userspace-dp/src/afxdp/forwarding/fib.rs:392`; sort `forwarding_build/fib.rs:161-184` |
| `NoRoute` always carries `egress_ifindex: 0` | `userspace-dp/src/afxdp/forwarding/fib.rs:794-806` |
| `#3110` refuses zone-pair AND global for `to_id == 0` | `userspace-dp/src/policy.rs:2676-2687` |
| RTPROT source map already exists, display-only | `pkg/routing/routes.go:315-357` |
| no `RouteSubscribe` anywhere | zero hits repo-wide |
| neighbor-listener precedent | `pkg/daemon/daemon_neighbor_listener.go:137` |
| mgmt DHCP → table 999 via netlink | `pkg/daemon/daemon_flow.go:47-56,203-211` |
| non-mgmt DHCP → FRR AD 200 | `pkg/frr/config_render.go:332` |
| static default suppresses only the DHCP *default* | `pkg/frr/config_render.go:279-310` |
| FRR runs unmanaged operator content | `pkg/frr/manager.go:606-636`; `pkg/frr/README.md:85-89` |
| snapshot push is a full replace | `userspace-dp/src/afxdp/forwarding_build/mod.rs:407` |
| ipmon debounce/throttle | `pkg/ipmon/ipmon.go:58,61` |
| slow-path counters on the wire, unexported | `userspace-dp/src/protocol/binding.rs:612-618`; `pkg/dataplane/userspace/protocol_binding.go:271`; zero `slow_path` in `pkg/api/` |
| the Prometheus precedent to copy | `pkg/api/metrics_userspace.go:924-935` |
| test harness has no reinjector | `userspace-dp/src/afxdp/tests_support.rs:1123` (`slow_path: None`) |
| `slow_path_drops` is the sound test discriminator | `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:283-293` |
