# rib-group interface-route leaking (#3876)

Junos `routing-instances <ri> { routing-options { interface-routes { rib-group
inet <rg>; } } }` with a `rib-groups { <rg> { import-rib [ <ri>.inet.0 inet.0 ];
} }` installs the source instance's **direct/interface (connected)** routes into
every secondary rib in the import list. xpf realizes the **import-into-main**
case (the common one) with Linux policy-routing rules.

## Mechanism (Phase 1: import into main)

For each source routing instance whose `interface-routes` rib-group imports the
**main table** (`inet.0` / `inet6.0`), the daemon installs one ip rule **per
connected prefix** of that instance:

```
ip rule to <connected-prefix> lookup <sourceTable> pref 30000
```

These rules sit at priority band **30000-30999**, which is **BEFORE** the main
table's rule (32766) and before the PBR band (31000-31999). Because the rule
matches a *specific* destination prefix, a main-table **default route no longer
shadows it** — a lookup for the leaked prefix consults the source instance's
table (where the connected route lives), while everything else still falls
through to main.

- Source: `pkg/routing/rules.go` — `ribGroupManager.Apply` +
  `ribGroupLeaksIntoMain`; band constant `ribGroupLeakRulePriority = 30000`,
  cap `maxRibGroupLeakRules = 1000`.
- Connected-prefix derivation: `config.RibGroupConnectedPrefixes`
  (`pkg/config/compiler_routing.go`), which walks each instance's member
  interface units and masks their static addresses to network prefixes via
  the shared `config.ConnectedNetworkPrefix`. The **same** helper backs the
  userspace FIB's connected-route builder
  (`pkg/dataplane/userspace/routes.go`), so the leaked ip-rule set matches the
  connected routes actually installed in the source table.
- Plumbing: `pkg/daemon/daemon_apply.go` step 3c passes the derived prefix map
  into `Manager.ApplyRibGroupRules`.

### Both FIBs, by construction

The per-prefix rules carry a `Dst`, so the userspace snapshot builder's
existing `rule.Dst != nil` + table→instance loop auto-captures each as a
`NextTable` leak into the main table (`pkg/dataplane/userspace/routes.go`) —
putting the leak into the **userspace FIB** as well as the kernel FIB.

### A VRF lookup that misses ends there; a source's return path is main (#9819)

The kernel's `l3mdev` rule at priority 1000 is a **lookup** rule. A lookup in
VRF context that missed its own table used to continue down the rule list,
first into this band and then into `main`. Measured in a private network
namespace, and pinned by `TestVRFMissTerminatorOnRealKernel9819`:

| Lookup | Before #9819 | After |
|---|---|---|
| A miss on a VRF slave, or from a VRF-bound socket | resolved by `main` | `Network is unreachable` |
| A VRF lookup for a prefix another instance leaked | resolved in that source's table | `Network is unreachable` |
| `main` to a leaked prefix | the source's table | the source's table |
| The return lookup from the leak source | `main`, by falling through | `main`, by a rule |
| A VRF's own connected, static or default route | resolves | resolves |

Two rule sets produce the right-hand column:

- **The miss terminator**, `ip rule add pref 2000 l3mdev unreachable`, once per
  family. `vrfManager.Reconcile` installs it before creating any VRF device. It
  uses the kernel rule's own `l3mdev` selector, so it matches exactly the
  lookups that consulted a VRF table and missed. It is the rule form of the
  per-VRF `unreachable default` route the kernel's VRF documentation
  recommends. A rule was chosen over a route because a route would sit in each
  VRF table, which FRR's zebra, systemd-networkd and the FBF harness all
  enumerate.
- **Return rules for a leak source**, `ip rule add pref 1500 iif|oif
  vrf-<instance> lookup main`, in each family whose leak installs. A source's
  table has no route to the hosts that use its leaked prefixes, because `main`
  is what reaches them. With the terminator alone, `main`'s lookup of a leaked
  address failed its reverse-path check (`EINVAL`), and the return lookup was
  unreachable.

The return rules are a **named reliance**: *a rib-group source's misses resolve
in `main`.* The fall-through already did that before #9819. It is now narrower,
because `lookup main` is a table action: a lookup that also misses `main` meets
the terminator, never this band or another instance's table. A source with its
own covering route, such as its own default, never consults them.

What an operator can observe:

- **A management-VRF miss is unreachable.** Management traffic to a destination
  that table 999 (`vrf-mgmt`) does not cover used to leave through `main`, that
  is, through the data plane. That happens when there is no default route in the
  management table, a DHCP lease carries no router, or a lease is lost. That
  traffic now fails.
- **A VRF-bound daemon loses a peer it could reach only through `main`.** This
  covers FRR peering, DHCP relay, syslog, RPM probes and IPsec. Route the peer
  inside the instance.
- Priorities 1000-2000 are reserved for VRF-context rules that must run after
  the VRF's table and before the terminator. Their order relative to the
  kernel's rule and to this band is checked at compile time
  (`pkg/routing/rib_group_return_9819.go`).

## Why the pre-#3876 behavior was a no-op

The old applier installed a single blanket rule per leaking source table:

```
ip rule from all lookup <sourceTable> pref 33000
```

This was broken two ways:

1. **Shadowed by any default route** — priority 33000 sits *after* main
   (32766), so a main-table default route matched first and the rule was never
   consulted. In any deployment carrying a default route (i.e. essentially all
   of them) the advertised feature was a silent no-op.
2. **Over-broad** — `from all lookup <sourceTable>` leaked the *entire* source
   table as a catch-all fall-through, far broader than Junos, which leaks only
   the interface/connected routes.

The blanket rule was also `Dst`-less, so the userspace snapshot builder skipped
it — the leak was absent from **both** FIBs.

### Upgrade cleanup

`ribGroupManager.clear()` scans three priority windows on every reconcile: the
current `[30000, 31000)` per-prefix band, the legacy `[33000, 33100)` blanket
band, and the original `[200, 300)` band. An in-place binary upgrade therefore
**removes the stale pref-33000 blanket rule** so the box is never left with the
broken blanket rule alongside the new per-prefix rules.

### Final rib-group removal (zero-transition, #5642)

The daemon's config-apply reconciler (`applyRoutingRules`,
`pkg/daemon/daemon_apply.go`) calls `ApplyRibGroupRules`
**unconditionally** — there is no `len(RibGroups) > 0` gate. `ribGroupManager.Apply`
runs `clear()` **before** its own empty-desired early return, so the transition
that removes the **final** rib-group (`RoutingOptions.RibGroups` → empty) still
deletes the previously-installed per-prefix leak ip-rules. A config that never
carried a rib-group finds nothing in the scanned bands, so `clear()` issues no
`RuleDel` (no churn).

Before #5642 the `len(RibGroups) > 0` gate skipped the whole block on that
zero-transition, so the stale Linux `ip rule to <prefix> lookup <table>`
survived indefinitely. Because the userspace snapshot builder derives its
`NextTable` leak from the **live** ip-rule table (`buildRouteSnapshots` →
`netlink.RuleList`), the stale rule also kept republishing into the **userspace
FIB** — a deleted-VRF leak on both forwarding planes that kernel-forwarded /
local / route-based-IPsec plaintext could follow, despite a successful commit.

**Snapshot ordering (why the gate fix alone is not enough).** The full dataplane
apply (the dataplane `ApplyConfig`) runs **before** `applyRoutingRules`, so it builds and
publishes the userspace route snapshot from the *pre-reconcile* ip-rule table —
it captures the stale leak. After `applyRoutingRules` deletes the rule, the
daemon runs a routes-only republish (`reconcileRouteLeakSnapshot`,
`pkg/daemon/daemon_apply.go`) that rebuilds `buildRouteSnapshots` against the
now-reconciled kernel rules and publishes the leak-free FIB (bumping the FIB
generation so established flows re-resolve). It reuses the ip-monitoring
routes-only publish surface (no `Compile`, no helper restart) and duplicate-skips
an unchanged route set, so a steady-state commit and a never-had-a-rib-group
config publish nothing.

**Hybrid-ACK guard (#5680, composes with #5679).** The routes-only publish
surface (`Manager.PublishRouteOverlaySnapshot`, `manager_overlay.go`) rebuilds
**only** the snapshot's `Routes` section and inherits every compiled policy
section (zones/policies/NAT/screens/address-books) verbatim from
`m.lastSnapshot` — the sections the last full `Compile`-based apply built from
`m.lastSnapshot.Config`. If the passed `cfg` carries a **policy** delta that was
never compiled into that snapshot, stamping `next.Config = cfg` (and the
`markAppliedSnapshotLocked` that follows) would advance the applied identity to
an **old-policy/new-route hybrid** — the operator would be told the new config
is live while the dataplane still enforces the old policy. This is the #5679
residual: an ordinary dataplane `ApplyConfig` failure captures `applyErr` and
continues (fail-closed but complete) **without** advancing `m.lastSnapshot`,
while `store.Commit` has already promoted the new `cfg`; the tail route-leak
republish (and the ip-monitoring actuator) then pass that new `cfg`. The publish
therefore **refuses** (`routeOnlyPublishHybrid`) whenever `cfg` is not the
config `m.lastSnapshot` was compiled from — pointer-identical in every
legitimate route-only publish (`store.ActiveConfig()` == the object handed to
`ApplyConfig`), with a JSON serialize-and-compare content-equality fallback
(`configsContentEqual` — the same encoding shipped to userspace-dp on every
`apply_snapshot`) so a distinct-but-equal config is never falsely refused. The
fallback compares serialized bytes rather than using `reflect.DeepEqual`, which
keeps `pkg/dataplane/userspace` free of `reflect`/`unsafe` per the
retirement-boundary canary (`TestUserspaceManagerDoesNotImportReflectOrUnsafe`,
#5985). On refusal the old, fully-consistent snapshot
stays live, the desired-overlay cache stays at its baseline (the #3760
mutate-after-success contract), and the caller reconverges once a full apply
republishes the policy (`reconcileRouteLeakSnapshot` warns; the ip-monitoring
actuator stays dirty and retries).

## Fail-loud diagnostics (commit-time warnings)

`config.ValidateConfig` (`validateRibGroupLeakWarnings`) warns — rather than
silently no-op — for the cases Phase 1 cannot fully realize:

- **No enumerable static connected prefix**: a source instance whose rib-group
  imports main but whose member interfaces carry no static address (DHCP-only /
  unaddressed). No ip rule is installed because there is no static prefix to
  enumerate at commit.
- **VRF→VRF import target**: a rib-group importing another instance's rib (not
  main). Phase 1 leaks only into the main table; a non-main import target is not
  yet installed.

### Strict rejection — ip-rule window over-subscription (#5854)

The applier programs next-table and interface-routes rib-group leaks into
**fixed ip-rule priority windows** and hard-caps at each boundary: 100 rules for
next-table (`pkg/routing/rules.go`, the `nextTableRulePriority+maxNextTableRules`
cap) and `maxRibGroupLeakRules` (1000) rules for the per-prefix rib-group leak (the
`ribGroupLeakRulePriority+maxRibGroupLeakRules` cap). A config that exceeds a
window used to commit green with only a **warning**
(`validateRoutingRuleWindowWarnings`); the reconciler then silently stopped at
the limit and returned success, so the committed generation **claimed routes the
kernel never programmed** — a blackhole / asymmetric-routing / silent inter-VRF
leak loss with no operator-visible signal.

The over-subscription is now **hard-rejected at commit**
(`validateRoutingRuleWindowsStrict`,
`compiler_validate_strict_routing_rulewindows.go`, wired into `runUniformGates`):
strict on commit / commit-check so the operator sees the over-limit condition
before it truncates, downgraded to a single warning on the tolerant load /
peer-sync paths (`opts.lenientRoutingRuleWindows`, #1960 no-brick) so an
already-committed or peer-synced over-limit generation still boots (the
applier's window hard-cap keeps the excess inert).

**Apply-side degraded error + FIB cap reconcile (#6467).** On the tolerant
load / peer-sync path the commit gate is only a warning, so an over-limit
generation still reaches the applier. There the next-table cap used to
`slog.Warn` and `break` with **no aggregated error**, so `Apply` returned nil
and reported success while truncating the leak set — and, worse, the userspace
FIB (`buildRouteSnapshots`) mirrored **all** config next-table leaks
**uncapped**, so leak #101+ existed in the userspace FIB but not the kernel. A
slow-path packet (XDP_PASS / IPsec-reinjected / non-native-XDP fabric) matching
leak #101+ then resolved into the target VRF on the AF_XDP fast path but the
main table in the kernel — a kernel/dataplane verdict split for the same flow.
The next-table cap now **aggregates a degraded error** naming how many leaks
were dropped (mirroring the rib-group and PBR caps in the same file), and the
FIB config-static path caps GLOBAL next-table leaks at the **same** window,
counting v4 then v6 in the same order as `ApplyNextTableRules`, so both planes
truncate the identical tail.

The FIB mirror also applies the applier's **eligibility** exactly. The applier
installs an ip rule — and advances its window counter — ONLY for a next-table
route whose target names a **defined** routing instance (`tableIDs[sr.NextTable]`
hit; the compiler stores the bare instance name via `parseNextTableInstance`)
AND whose destination parses as a CIDR; it `continue`s (no `prio++`) otherwise.
`buildRouteSnapshots` now gates on the SAME predicate (a `definedInstances` name
set + `net.ParseCIDR`). Without it a dangling (unknown-instance) or unparseable
next-table route consumed a FIB window slot and published a **ghost** leak the
kernel never installs — squeezing a valid leak out of the window (the FIB
missing a leak the kernel HAS while carrying one it LACKS). The applier's
degraded-error drop count likewise counts only **eligible** tail routes so the
"N not leaked" figure is accurate rather than inflated by routes that would
never install. Measured on 50 dangling + 100 valid routes: both planes now hold
100 valid leaks and 0 ghosts.

The rib-group window size (`maxRibGroupLeakRules` = 1000) is duplicated in
`pkg/config` with a keep-in-sync comment because `pkg/config` cannot import
`pkg/routing` (that would be an import cycle — `pkg/routing` imports
`pkg/config`); it MUST stay in lockstep with `pkg/routing/rules.go`. The
next-table window is now the **exported SSOT** `config.NextTableRuleWindow`
(alongside `config.NextTableRulePriorityBase`, mirroring the #4479 PBR band
constants): `pkg/config`'s commit gate (`maxNextTableRules`), the applier
(`pkg/routing.maxNextTableRules`), and the userspace FIB config-static mirror
all reference that one value, so the three cannot drift.

### Ingress scope on the next-table leak rules (#9420)

Every next-table `ip rule` carries an **`FRA_IIFNAME` ingress selector**.

Before #9420 the rule was `Dst` + `Table` + `Priority` + `Family` and nothing
else, installed at priority 100-199 — **ahead of the kernel's l3mdev rule at
1000**. A packet ingressing **any** routing instance whose destination fell in
the leaked prefix was therefore routed out of the **target** instance's table,
on the target instance's device, overriding the ingress instance's own routing.
Measured on a live kernel, with a control, and in the sharper case where the
ingress VRF **has its own route for the same prefix** and still loses — the
measurement is a test, `TestNextTableIngressScopeOnRealKernel_9420` in
`pkg/routing/rules_9420_test.go`, which reproduces the defect (B1/B2) and the
control (B3) in the same run as the fix.

This is the same defect **#5117** fixed for the PBR/FBF band, in the same file;
`nextTableManager.Apply` was not covered by that sweep. **#4073** closed the
broad "VRF traffic is mis-routed" claim as a false positive, correctly, on the
grounds that the rule is destination-scoped — an argument that holds for every
packet *outside* the leaked prefix and says nothing about one inside it.

The scoping set is `routing.DefaultInstanceIngressIfaces(cfg)`: every configured
interface unit **not** claimed by a routing instance. That is exactly the
default instance's ingress, and the default instance is always the authoring
instance — per-instance `next-table` is hard-rejected at commit (#5830, below),
and the applier is fed only `cfg.RoutingOptions.StaticRoutes` +
`Inet6StaticRoutes`.

Three consequences an operator can observe:

1. **One leak costs one ip rule per default-instance ingress interface.** The
   100-slot window is drawn down **leak-atomically** — a leak whose full
   expansion does not fit is dropped whole rather than installed on a subset of
   its interfaces, because a partially-scoped leak works on some ingress
   interfaces and silently not on others. The overflow error names the
   multiplier so the reduced effective leak capacity is visible.
2. **Fail-closed.** With no resolvable default-instance ingress interface,
   nothing is installed and the apply reports degraded, matching
   `BuildPBRRules`. The fail-safe direction is an under-steer (the leak is not
   followed), never a cross-VRF over-steer.
3. **Host-originated traffic no longer follows a next-table leak.** Loopback is
   deliberately excluded from the scoping set. An `iif lo` rule matches locally
   generated traffic — *including traffic from a socket bound to another VRF*,
   which was measured directly — so keeping host-originated default-instance
   traffic on the leak would reintroduce the cross-VRF hijack for every
   VRF-bound daemon (FRR peering, DHCP relay, syslog, RPM probes, IPsec). This
   is a deliberate narrowing, recorded here rather than left to be rediscovered.

The **AF_XDP fast path is instance-scoped only for PBR-steered traffic.** The
userspace FIB follows a `next_table` route found in whichever table a lookup
runs in (`userspace-dp/src/afxdp/forwarding/fib.rs`). A transit lookup runs in
a per-instance table only when a PBR interface filter steers it there. Without
PBR it runs in the global `inet.0`/`inet6.0`, whatever instance the ingress
interface belongs to, so the fast path does no per-instance destination-FIB
selection at all (`userspace-dp/src/afxdp/forwarding/README.md`, "PBR `then
routing-instance` is the ONLY per-VRF forwarding path"). The exposure #9420
closed was on the Linux path: host-originated traffic, slow-path `XDP_PASS`
packets, local delivery, and any interface without native XDP where
`redirect_capable` falls back to kernel forwarding.

### Strict rejection — undefined `next-table` target (#5693)

A static route whose `next-table <target>` names a routing-instance that is
**not defined** in the config is now **hard-rejected at commit**
(`validateNextTableTargetReferencesStrict`, `compiler_validate_strict_routing.go`).
Previously the target was unvalidated: the applier
(`pkg/routing.nextTableManager.Apply`) resolves it through a name→table-id map
built only from defined instances, so an undefined target missed the lookup,
logged `next-table references unknown routing instance`, and **silently skipped
the rule** — the intended inter-VRF leak never happened and matching traffic
followed the ingress table's own routes (often the WAN default). The gate
resolves the target with the same `parseNextTableInstance` the applier uses
(strip the trailing `.inet[6].N` suffix → instance name) so the commit gate and
the runtime applier stay in lockstep on what resolves (the #2226 rib-group
doctrine). The error quotes the operator's **raw** `next-table` token
(`StaticRoute.NextTableRaw`, preserved before the suffix strip) so a
`Comcst.inet.0` typo is named verbatim. Only the global `inet.0` + `inet6.0`
static routes are validated — those are exactly the routes `daemon_apply` feeds
to `ApplyNextTableRules`. Strict on commit / commit-check; downgraded to a
warning on the tolerant load / peer-sync paths (`opts.lenientNextTableRefs`,
#1960 no-brick) since the applier keeps a dangling next-table inert.

### Strict rejection — per-instance `next-table` is unsupported (#5830)

`next-table` is only implemented for the **global** `routing-options` static
routes. A `next-table` authored **under a routing-instance** was accepted at
commit but the three forwarding surfaces diverged:

- the strict definedness gate above only inspected the global `inet.0` /
  `inet6.0` routes, so an undefined per-instance target bypassed the #5693
  protection entirely;
- `daemon_apply` feeds only `cfg.RoutingOptions.Static/Inet6StaticRoutes` to
  `ApplyNextTableRules` (`pkg/routing.nextTableManager.Apply`), and the FRR
  renderer emits nothing for a `NextTable` route
  (`pkg/frr/config_render.go`), so the **kernel/FRR** plane omitted the
  per-instance route entirely;
- the **userspace** FIB builder published it as a live `NextTable` route in the
  instance's `<inst>.inet[6].0` table (`pkg/dataplane/userspace/routes.go`).

The same committed config therefore **leaked traffic in the userspace
dataplane** while the kernel/FRR view had no equivalent route — a
control-plane/data-plane split-brain, not merely a missing diagnostic.

Because per-instance `next-table` is **not programmed on any kernel/FRR
surface**, the fix makes the three surfaces agree that it is *not a live
forwarding route*:

- `validateNextTableTargetReferencesStrict` now **hard-rejects at commit** ANY
  `next-table` under a routing-instance — defined *or* undefined target (an
  undefined target's error additionally names it). Strict on commit /
  commit-check; downgraded to a warning on the tolerant load / peer-sync paths
  (`opts.lenientNextTableRefs`, #1960 no-brick) so an already-persisted or
  peer-synced legacy config still boots.
- `buildRouteSnapshots` no longer publishes a per-instance `next-table` into the
  userspace FIB (`perInstance` guard in `addRoutes`). GLOBAL `next-table` IS
  programmed via `ip rule` and stays published so the Rust FIB can
  cross-reference the target table — but the config-static path now caps the
  GLOBAL next-table leaks it publishes at `config.NextTableRuleWindow`, the same
  window the applier installs, so the FIB never carries a leak past the cap that
  the kernel dropped (#6467). A leniently-loaded legacy per-instance
  `next-table` is thus inert on **both** planes.

Supporting per-instance `next-table` for real is a **feature**, not a bug fix:
the kernel `ip rule` the applier programs is a global destination-only
`to <dst> lookup <table>` with no source-table scoping, so honoring a
per-instance leak would need **source-table-scoped** (`iif`/fwmark) rules —
the same substrate the rib-group **VRF→VRF import** target is deferred to
Phase 2 for (see *Deferred* below). Appending per-instance routes to the
existing global `ApplyNextTableRules` call would lose source-table identity and
could steer traffic from unrelated VRFs, so it is deliberately **not** done.

### Strict rejection — contradictory static-route dispositions (#5633)

A single static-route destination may carry only **one** disposition: a
forwarding `next-hop` (possibly several, for ECMP), a `next-table` VRF leak,
`discard` (silent blackhole), or `reject` (ICMP-unreachable drop). Repeated
same-prefix `set` lines merge into one `StaticRoute` in `compileStaticRoutes`
(`compiler_routing.go`) — next-hops are **appended** and the terminal /
`next-table` fields are **sticky** (`discard`/`reject` latch true, `next-table`
is last-writer-wins). So a config that declared one prefix once as `discard`
(or `next-table X`) and once with a `next-hop` compiled into ONE route holding
**both** a blackhole/leak and a forwarding next-hop, and the strict gate
accepted it. The live snapshot copies every field
(`pkg/dataplane/userspace/routes.go`) and the Rust forwarder resolves
**discard > next-table > next-hop**
(`userspace-dp/src/afxdp/forwarding/mod.rs`), so the stale terminal / leak won
and a later next-hop meant to **restore ordinary forwarding was silently
ignored** — a blackhole or a cross-VRF leak the operator never authored.

`validateStaticRouteDispositionConflictStrict`
(`compiler_validate_strict_routing.go`) now **hard-rejects at commit** any
compiled route carrying ≥2 of {`next-hop`, `next-table`, `discard`, `reject`}.
Legitimate ECMP / qualified-next-hop (multiple next-hops = the single
`next-hop` disposition) still compiles. The gate walks the global `inet.0` +
`inet6.0` route sets and every routing-instance's route sets (per-instance
routes flow through the same merge), reporting the first conflict
deterministically with the offending scope and destination. Strict on commit /
commit-check; downgraded to a warning on the tolerant load / peer-sync paths
(`opts.lenientRouteDispositionConflict`, #1960 no-brick) so an already-persisted
or peer-synced config still boots — the dataplane then resolves the
deterministic disposition precedence.

## Deferred (Phase 2 and beyond)

- **VRF→VRF import targets** — need `iif`-scoped rules or true route-copy;
  warned + deferred.
- **route-copy (Option 1)** — installing real copies of the source's direct
  routes into the target table (à la FRR `import`) would give
  `show route table inet.0` cosmetic parity but requires a new churn-tracking
  reconciler that collides with FRR's ownership of the managed section. It is
  forwarding-equivalent to the per-prefix rules for the dataplane and is
  deferred entirely.
- **Dynamically learned (DHCP) source addresses** — per-prefix cannot enumerate
  them at commit; warned now, would need Phase-2 route-copy or a runtime
  address-watch.

## #4423 routing audit — FIB table-scoping dispositions

The codex routing audit (tracked in issue #4423) raised four static-route /
FIB-table findings against the userspace forwarding pipeline. Verify-first
triage against `origin/master` classified them as follows. The relevant code
is the Go route-snapshot builder (`pkg/dataplane/userspace/routes.go`) and the
Rust FIB (`userspace-dp/src/afxdp/forwarding_build/fib.rs`,
`userspace-dp/src/afxdp/forwarding/mod.rs`) — **not** `pkg/routing` (which owns
netlink VRF/tunnel/ip-rule reconciliation, not FIB next-hop resolution).

### M3 — static next-hop gateway inference is global, not table-scoped — FIXED (#4446)

**Resolved in #4446.** The build-time inference is now table-scoped: the
route's canonical install table is threaded from `populate_routes` through
`resolve_route_next_hops_v[46]` → `resolve_next_hop_target_v[46]` →
`infer_connected_route_target_v[46]`, which filters the connected scan on
`entry.table == table` (mirroring the #2388 lookup-site predicate, but at
BUILD time so the correct ifindex is baked into `RouteEntryV*.next_hops`).
The two contradictory `fib.rs` doc comments are reconciled (both now state
the inference is table-scoped) and the `forwarding/README.md` "stays global"
note is corrected. A route-leak / `next-table` cross-VRF reach is unaffected
— a leaked route is a `NextTable` snapshot with no forwarding next-hop, so
it never touches this inference and is re-resolved in the target table's own
scope by the recursion. Locked by
`static_bare_gateway_infers_ifindex_in_own_table_v4` / `_v6` (RED on the
global scan: with "blue" leading the scan order, red's route bound blue's
ifindex 102 instead of red's 101) plus the
`static_bare_gateway_single_table_still_resolves` anti-regression
(`forwarding_build/tests.rs`). The `native_gre*` fixtures were made
config-realistic — the GRE inner interface now carries
`routing_instance = "sfmix"`, so its connected /30 lands in `sfmix.inet.0`,
the same table as the bare-gateway route it backs.

The original triage write-up follows.



`resolve_route_next_hops_v4` / `resolve_route_next_hops_v6` resolve a static
route's egress ifindex at FIB-build time. When a next-hop carries an explicit
`@interface`, the ifindex comes from that interface; otherwise it is **inferred**
from the connected prefix that contains the gateway IP via
`infer_connected_route_target_v4`/`_v6`. That inference does a **global** scan of
`state.connected_v4` and returns the first `prefix.contains(gateway)` match —
**it never filters by the route's own table**, even though every `ConnectedRouteV4`
already carries its owning `table` (added by #2388 exactly so the *lookup* site
can filter — `forwarding/mod.rs` `entry.table == table`).

Consequence: in a multi-VRF deployment with overlapping gateway subnets across
routing-instances (a normal reason to use VRFs), a bare-gateway static route in
instance A can bind the egress interface of instance B's overlapping connected
prefix. The wrong ifindex is baked into `RouteEntryV4.next_hops` at build time
and consumed verbatim at lookup (`forwarding/mod.rs`, the `ResolvedRouteV4::Static`
arm uses `nh.ifindex` directly), so the #2388 lookup-time connected filter does
**not** correct it — that filter only re-scopes connected-route *destination*
matches, not a static route's pre-resolved next-hops.

Two doc comments in `fib.rs` currently **contradict** each other on this point:
`resolve_route_next_hops_v4`'s doc claims the inference is "scoped to the route's
own table (#2388)", while `infer_connected_route_target_v4`'s own doc says it is
"intentionally NOT table-scoped". The code matches the latter; the former is
stale/aspirational and should be corrected alongside the fix.

**Turnkey fix (Rust, needs `cargo` — out of the Go-only slice scope):** thread
the route's canonical install table (already computed as
`canonical_route_table(&route.table, is_ipv6)` at the `populate_routes` call
site) into `resolve_route_next_hops_v4`/`_v6` → `resolve_next_hop_target_v4`/`_v6`
→ `infer_connected_route_target_v4`/`_v6`, and filter the connected scan on
`entry.table == table`, mirroring the existing #2388 lookup-site predicate. Add a
Rust unit test with two routing-instances that own overlapping connected
prefixes and assert a bare-gateway static route in instance A resolves to A's
ifindex (RED on the current global scan). Fix the two contradictory doc comments.
This is a dataplane (`userspace-dp`) change and must go through the serial cargo
build + `make test-failover` gate, so it is deferred out of this Go-only triage.

### L2 — `canonical_route_table` "silently rewrites cross-family table names" — NOT-A-BUG

The premise ("rewritten into the wrong table → operator confusion") does not
hold. `canonical_route_table` (`forwarding/mod.rs`) only swaps the **family half**
of the table suffix (`.inet.0` ↔ `.inet6.0`, or bare `inet.0` ↔ `inet6.0`) and
**always preserves the VRF prefix** — it can only ever normalize a name into the
same routing-instance's correct family-specific table, never a different VRF.
The Go side already emits correct-family install-table names
(`normalizeRouteSnapshotFamily`, driven by the destination family and the
static-list bucket), and static `next-table` targets are reduced to a bare
routing-instance name (`parseNextTableInstance`, `pkg/config/compiler_routing.go`)
that carries no family suffix to drift. The rewrite is a VRF-preserving
normalization safety net, not a silent corruption. Locked by
`TestNormalizeRouteSnapshotFamily_VRFPreserving_4423`
(`pkg/dataplane/userspace/routes_family_normalize_4423_test.go`).

### L3 — IPv6 link-local next-hop needs `%iface`, not `addr@interface` — NOT-A-BUG

xpf is a Junos-syntax firewall. The operator writes a link-local gateway as
`next-hop fe80::1 interface reth0.50` (separate `interface` clause); the compiler
encodes it for the Rust FIB as the internal `ip@interface` spec (`routes.go`
`buildRouteSnapshots` → `fib.rs` `split_once('@')`). The `%iface` RFC 4007
zone-id form is a Linux getaddrinfo()/`ip route` convention with **no producer or
consumer** anywhere in the xpf pipeline; `ValidateStaticNextHop`
(`pkg/config/schema_validators.go`) correctly rejects it at commit (`net.ParseIP`
does not accept a zone-id and `%` is not an allowed interface-name character).
Accepting `%iface` would introduce a second, silently-degrading link-local
syntax for no gain. Locked by `TestStaticNextHop_ZoneIDPercentRejected_4423`.

### L6 — the #1827 ip-monitoring overlay cannot express an ECMP preferred route — DEFER (feature, not a bug)

`applyRouteOverlay` (`routes.go`) intentionally **replaces the entire
(table, family, prefix) entry set** with the single overlay next-hop — a
whole-entry replacement, documented in the function contract and pinned by
`TestRouteOverlayWholeEntryReplacement` ("the ECMP next-hop set is gone, not
half-merged"). This is the correct #1827 WAN-failover semantics: when a probe
selects a preferred path, steer *all* traffic for that prefix to the single
preferred gateway; on withdrawal the original (possibly ECMP) config route
returns. A multi-next-hop preferred route is a **new feature**, not a bug fix:
it would require `config.RouteOverlayEntry.NextHop` → `NextHops []string`, a
config-schema change to let `services ip-monitoring policy … then preferred-route
… next-hop` take a list, and matching winner-resolution in `pkg/ipmon`. Deferred
with this plan; the Rust FIB already carries multiple next-hops per route
(`RouteEntryV4.next_hops`), so only the Go overlay/config surface needs the work.
