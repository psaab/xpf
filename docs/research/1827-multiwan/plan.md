# #1827 Multi-WAN: uplink model, health probes, failover + PBR policy layer

**Status:** DRAFT v1 — pending adversarial plan review (Claude SMR + Codex + AGY)

This is a **multi-PR feature program** plan. The deliverable of this research
pass is an honest staging: PR-1 small and shippable, later PRs scoped with
explicit gates and per-stage PLAN-KILL criteria. `/research` stops at
PLAN-READY; only PR-1 is pre-authorized for `/engineer` on convergence.

---

## 1. Issue framing

#1827 is the residue split from the #1389 edge-gateway bundle at its
close-out: the two Phases (1-2) that were verified genuinely untracked on
master — (a) a first-class multi-WAN uplink model with health probing and
failover, and (b) a per-policy uplink-selection layer on top of the existing
PBR/VRF machinery. Everything else from #1389 is tracked elsewhere (#1703 WG,
#1387 DDNS, #1828 smart queueing).

The directive for this plan (from the dispatch): **model after Junos where a
natural analog exists**. Real SRX multi-WAN is *not* a `services multi-wan`
subsystem — it is the composition of:

1. `services rpm probe <owner> test <name>` — health probes, with
   `destination-interface` / `next-hop` pinning so a probe exercises a
   *specific* uplink regardless of current routing;
2. `services ip-monitoring policy <name> match rpm-probe <owner> then
   preferred-route route <prefix> next-hop <ip> [preferred-metric <n>]
   [routing-instance <ri>]` — while the matched probe is in FAIL state, the
   preferred route is installed; when it recovers, it is withdrawn;
3. filter-based forwarding (FBF): `firewall filter ... then
   routing-instance`, `instance-type forwarding` instances each holding that
   uplink's default route, rib-groups sharing interface routes — this is the
   per-policy uplink-selection layer.

The #1389 body sketched an invented `set services multi-wan uplink ...` tree.
This plan **rejects that as the base layer** (Section 11 Path B) and follows
the Junos-parity composition instead, consistent with the project's "clone
vSRX capabilities using native Junos syntax" charter.

## 2. Honest scope/value framing

This is a feature program, not a perf change. The value is operator-facing:
dual-uplink edge deployments (the original #1389 customer ask) get
Junos-syntax WAN failover and policy steering without external scripts.

Honest costs:

- PR-1 touches the config schema, the RPM prober, the FRR render, the
  daemon apply path, and the userspace snapshot builder — wide but shallow;
  zero Rust changes, zero hot-path changes.
- The lab has ONE physical WAN path. All dual-uplink validation is
  *simulated* (two VLANs / two zones on one provider). Section 9 states
  exactly what that does and does not prove.
- *If reviewers conclude the value is too small to justify the churn,
  PLAN-KILL is an acceptable verdict.* (For this program the more likely
  kill shape is per-stage: kill PR-3/PR-4 scope, keep PR-1.)

## 3. What's already shipped / partially present (survey of master)

Verified on `origin/master` (d30cfab84):

| Area | State | Evidence |
|------|-------|----------|
| RPM probe manager | EXISTS — probe loops, per-test results, EMA RTT/jitter, events (`ping_test_failed` / `ping_probe_failed` / `ping_test_completed`) | `pkg/rpm/rpm.go` |
| RPM icmp-ping probe | **FAKE** — `DialContext("ip4:icmp", target)` opens a raw socket (no echo sent), falls back to UDP `connect()` (no packet). It is a route-existence check, not reachability. tcp-ping/http-get are real | `pkg/rpm/rpm.go:294-313` |
| RPM lifecycle | Started once at daemon start; **never re-applied on commit** (`d.rpm.Apply` only in `daemon_run.go:601-605`) | `pkg/daemon/daemon_run.go` |
| RPM VRF/source binding | EXISTS — `SO_BINDTODEVICE` to `vrf-<ri>`, source-address | `pkg/rpm/rpm.go:21-45` |
| RPM → automation | `event-options` engine consumes RPM events and does **config commit-and-apply** (30 s policy cooldown). This is the legacy event-script-style failover, not ip-monitoring | `pkg/eventengine/engine.go`, `pkg/daemon/daemon_apply.go:967` |
| PBR (`then routing-instance`) | EXISTS end-to-end: config term → snapshot term → Rust filter eval | `pkg/config/types_system.go:531`, `pkg/dataplane/userspace/filters.go:71` |
| Interface input filters | EXISTS — `FilterInputV4/V6` | `pkg/config/types_interfaces.go:61-63` |
| Routing instances / VRFs | EXISTS — per-VRF static routes, FRR per-VRF render, rib-group + next-table leaking (synthetic snapshot routes from `ip rule` list) | `pkg/dataplane/userspace/routes.go:98-134`, `pkg/frr/manager.go` |
| `instance-type forwarding` | PARTIAL/WART — FRR side renders its static routes into the **default** table (`vrfName = ""`, `daemon_apply.go:760-763`) while the dp snapshot files them under `<ri>.inet.0` (`routes.go:77`). Kernel path and dp path disagree for FBF instances |
| Route preference | StaticRoute.Preference exists (default 5) and renders as FRR distance; DHCP defaults AD 200; backup-router AD 250 | `pkg/config/types_routing.go`, `pkg/frr/config_render.go` |
| `qualified-next-hop` | Parsed, but the per-next-hop **preference is dropped** (only `interface` is read; `NextHopEntry` has no preference field) — floating statics are not real today; multiple next-hops = ECMP | `pkg/config/compiler_routing.go:170-181` |
| Dataplane FIB | **Config-derived snapshot**, NOT kernel-synced: config statics + connected + ip-rule leak entries. FRR/kernel runtime routes (OSPF/BGP/DHCP-default) never reach the helper FIB | `pkg/dataplane/userspace/routes.go:14-146` |
| FIB change propagation | Snapshot push on generation bump; `fib_generation` mismatch re-resolves cached flows | `pkg/dataplane/userspace/builder.go:13`, `userspace-dp/src/afxdp/forwarding/mod.rs:17` |
| Runtime-state → re-apply precedent | `pkg/feeds` calls `d.applyConfig(activeCfg)` when a dynamic-address feed updates | `pkg/daemon/daemon_run.go:590-598` |
| ip-monitoring (name collision) | The repo already has **chassis-cluster** ip-monitoring (RG weight demotion) — a different Junos feature. Ours is `services ip-monitoring`; show command must be disambiguated | `pkg/grpcapi/server_show.go:320` |
| Builder runtime-state input precedent | `buildSnapshotWithSchedulerState(cfg, ..., activeState map[string]bool)` already threads runtime state into the snapshot build | `pkg/dataplane/userspace/builder.go:17` |

**The dataplane-awareness question** (asked in the dispatch): multi-WAN
failover is *not* purely FRR/kernel territory. Because the helper FIB is
config-derived, a health-driven route change MUST be reflected into a new
snapshot or transit traffic keeps using the dead uplink. The good news:
routes are pure data to the helper — no Rust changes are needed; the existing
snapshot-sync + fib_generation machinery already does invalidation. The
single decision point therefore lives in Go and feeds BOTH consumers (FRR
render and snapshot build).

## 4. Concrete design — PR-1 (config model + ip-monitoring engine + route withdrawal/injection)

### 4.1 Config surface (Junos parity)

RPM test additions (under `services rpm probe <p> test <t>`):

```
set services rpm probe WAN test wan-a probe-type icmp-ping
set services rpm probe WAN test wan-a target address 1.1.1.1
set services rpm probe WAN test wan-a destination-interface reth0.50   # NEW
set services rpm probe WAN test wan-a next-hop 172.16.50.1             # NEW
set services rpm probe WAN test wan-a thresholds successive-loss 3
```

- `destination-interface` → `SO_BINDTODEVICE` to the unit's Linux name
  (route lookup restricted to that device).
- `next-hop` → implemented as an always-on **probe pin route**: a /32 (or
  /128) static for the probe target via that next-hop, emitted through the
  same effective-route mechanism as preferred routes (Section 4.3). This is
  exactly the static-/32-per-probe-target recipe SRX operators use, made
  automatic — and it is what makes probing the *backup* uplink possible
  while the primary still holds the default route.
- `target address <ip>` accepted alongside the existing bare
  `target <ip>` form (Junos uses `target address`).

New `services ip-monitoring` tree:

```
set services ip-monitoring policy wan-failover match rpm-probe WAN
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 172.16.80.1
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 preferred-metric 1
set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1
```

Semantics (Junos): while **any** test of the matched probe is in FAIL state,
the policy is FAIL and its preferred routes are installed; when all tests
pass again, they are withdrawn. `preferred-metric` maps to FRR admin
distance (default 1 — beats static AD 5 and DHCP AD 200). Extension beyond
Junos (flagged as such, default 0 = parity): `hold-down <seconds>` to damp
recovery flaps and bound re-apply frequency.

Types (`pkg/config/types_system.go`):

```go
type IPMonitoringConfig struct{ Policies map[string]*IPMonitoringPolicy }
type IPMonitoringPolicy struct {
    Name          string
    MatchRPMProbe string            // rpm probe owner name (commit-checked)
    PreferredRoutes []*PreferredRoute
    HoldDownSecs  int               // extension; 0 = Junos behavior
}
type PreferredRoute struct {
    RoutingInstance string          // "" = master
    Destination     string          // CIDR
    NextHop         string
    PreferredMetric int             // default 1
}
```

Commit checks: `match rpm-probe` must reference an existing probe;
preferred-route next-hop family must match destination family;
routing-instance must exist; `services ip-monitoring` requires at least one
preferred-route.

### 4.2 Real prober + RPM lifecycle fixes (prerequisites in the same PR)

1. **Real ICMP echo prober** — raw ICMP (xpfd runs as root) or
   `ip4:icmp`/`ip6:ipv6-icmp` ListenPacket with echo/reply matching by
   id/seq, honoring `SO_BINDTODEVICE` + source-address. *Behavior change*:
   existing icmp-ping probes that "always passed" can now fail — this is a
   deliberate bug fix, release-noted. Without it, ip-monitoring is fiction.
2. **RPM re-apply on commit** — add `d.rpm.Apply(...)` to the applyConfig
   sequence (today RPM config changes require a daemon restart).
3. **State-transition subscription** — extend `rpm.Manager` with a
   per-test transition callback (or let the engine consume the existing
   events + `Results()` snapshot). The existing `EventCallback` stays for
   eventengine compatibility.

Note: probe replies arrive at the firewall's own IP; the dataplane already
delivers local traffic to the kernel via the local_v4/local_v6 maps (RPM
tcp-ping works today over the userspace dp), so no dataplane change is
needed for probe traffic. Validated explicitly in the smoke plan.

### 4.3 The single decision point: effective-route overlay

New package `pkg/ipmon` (engine, ~400 LOC):

```go
type Engine struct { ... }
func New(onTransition func()) *Engine
func (e *Engine) Apply(cfg *config.IPMonitoringConfig, rpmCfg *config.RPMConfig)
func (e *Engine) HandleRPMEvent(evt rpm.Event)          // wired beside eventengine
func (e *Engine) RouteOverlay() ipmon.Overlay            // snapshot of current decisions
func (e *Engine) Status() []PolicyStatus                 // for show/metrics
```

`Overlay` = the list of currently-active preferred routes **plus** the
always-on probe pin routes, each as `(table, prefix, next-hop, distance)`.

Consumption — both consumers read the SAME overlay inside `applyConfig`:

1. **FRR**: `frr.FullConfig` gains `PreferredRoutes []PreferredRouteEntry`,
   rendered as `ip route <prefix> <nh> [vrf <v>] <distance>` in the managed
   section (new emission step between 6 and 7; the emission-order contract
   comment is updated).
2. **Userspace snapshot**: `buildRouteSnapshots` gains an overlay parameter
   (same pattern as `buildSnapshotWithSchedulerState`). Overlay routes
   **replace** any config route with the same (table, family, prefix) —
   the override is resolved at build time in Go because `RouteSnapshot`
   has no preference field and the Rust FIB must not see two ambiguous
   same-prefix entries. No wire-protocol change, no Rust change.

Transition mechanics: on a policy state transition (fail→active or
recover→withdrawn after hold-down), the engine calls `onTransition`, which
re-runs `d.applyConfig(d.store.ActiveConfig())` — the exact `pkg/feeds`
precedent. This serializes under the apply semaphore with operator commits,
bumps the snapshot generation, pushes one snapshot, and bumps
fib_generation so cached flows re-resolve onto the new route. Failover and
failback both ride one mechanism. Rate bound: transitions are inherently
damped by RPM thresholds (successive-loss × probe-interval) plus optional
hold-down; a worst-case sustained flap produces at most one apply per
test-interval, far below the control-socket contention threshold.
(Alternative narrow-delta mechanism: Section 11 Path D.)

### 4.4 HA gating

- Probes run on both nodes (as today), but the overlay is **published**
  (FRR + snapshot) only when the node is primary for a data RG
  (`cluster.IsLocalPrimary`-gated, mirroring how only the active owner
  publishes route/NAT effects elsewhere). Standby holds its computed state.
- On RG takeover the engine re-evaluates immediately with current probe
  results; if results are stale/unknown (standby probes sourced from a VIP
  the node didn't own can have failed spuriously) the engine triggers an
  immediate re-probe and, until first fresh results, publishes the config
  baseline (no overlay). Failover therefore starts from "config routes" and
  converges within one probe cycle — same shape as #1389's acceptance note
  ("failover must reconstruct selected uplinks from health state or
  immediately re-probe").
- The overlay is runtime state, never config: config-sync is untouched;
  per-node frr.conf divergence on standby is expected and harmless.

### 4.5 Observability

- `show services ip-monitoring status` (cmdtree + grpcapi + both CLIs):
  policy, matched probe, status PASS/FAIL, route APPLIED/NOT-APPLIED,
  last-transition time + reason — disambiguated from the existing
  `show chassis cluster ip-monitoring status`.
- Prometheus: `xpf_ipmon_policy_failed{policy}`,
  `xpf_ipmon_policy_transitions_total{policy}`,
  `xpf_ipmon_routes_applied`.
- `slog.Info` on transitions only (state-transition logging rule).

### 4.6 PR-1 blast radius

`pkg/config` (types/schema/parser/compiler + tests), `pkg/rpm` (real ICMP,
destination-interface, next-hop field, transition hook), new `pkg/ipmon`,
`pkg/daemon` (apply wiring, RPM re-apply, HA gating), `pkg/frr`
(PreferredRoutes render), `pkg/dataplane/userspace` (builder overlay param —
Go only), `pkg/cmdtree`/`pkg/grpcapi`/`cmd/cli` (show), `pkg/api` (metrics),
docs. **Zero Rust changes. Zero wire-protocol changes. Zero hot-path
changes.** Estimated ~1.5-2 kLOC including tests — the largest single risk
surface is the applyConfig wiring, which is additive.

## 5. Staging — the full program

| PR | Scope | Gate to start | PLAN-KILL criteria (stage-local) |
|----|-------|---------------|----------------------------------|
| **PR-1** | Junos-parity `services ip-monitoring` + RPM hardening + effective-route overlay through FRR + snapshot; show/metrics; HA gating. Single uplink-failover decision point. | This plan PLAN-READY | Kill if: (a) the re-apply-per-transition mechanism is shown unsafe (apply semaphore starvation or control-socket contention with realistic probe configs), AND the Path-D delta mechanism is also rejected; (b) real-ICMP probing through the AF_XDP local-delivery path is shown not to work (smoke gate, validated first). |
| **PR-2** | Per-policy uplink selection = FBF composition: validate + fix `instance-type forwarding` end-to-end (the FRR-default-table vs dp-`<ri>.inet.0` divergence), `preferred-route routing-instance` scoping into FBF instances, commit-check + completion polish, per-policy hit counters (existing filter counters), an operator recipe doc (`docs/multi-wan.md`), and a lab smoke. No new config surface beyond what PR-1 added — this stage is composition + closing the FBF wart. | PR-1 merged + smoke-proven flip | Kill/re-stage if the FBF kernel/dp divergence requires Rust FIB table-semantics rework (e.g. same-prefix multi-table resolution changes) larger than the Go-side fix — then PR-2 shrinks to "documented VRF-instance-type recipe" and the FBF fix becomes its own issue. |
| **PR-3** | NAT interplay: per-uplink SNAT pools (rule-sets keyed by egress zone/instance — verify existing matchers suffice), and defined session behavior on uplink transition: fib_generation already re-resolves flows; add invalidation of sessions whose SNAT binding references the failed uplink (filtered session-clear machinery exists), with counters and a `show` reason. | PR-2 merged; semantics proposal reviewed (mini-research round in the PR plan) | Kill if session-invalidation-by-NAT-binding requires per-packet hot-path state the dp doesn't already carry — fallback is Junos-like timeout behavior (document, don't build). |
| **PR-4** | Weights/load-share: health-gated ECMP (overlay emits multi-next-hop routes filtered by uplink health), weighted flow-hash selection. Requires auditing dp ECMP next-hop selection determinism + HA symmetry first. | PR-3 merged + a fresh /research round (explicitly NOT pre-authorized) | Kill if dp ECMP selection is not stable per-flow across nodes (HA asymmetry) without Rust work; weighted (non-equal) hashing may not be worth the churn at 2 uplinks. |

PR-3 and PR-4 are sketches by design; each gets its own plan round before
implementation. Only PR-1 is pre-authorized by this research.

## 6. Public API / compatibility preservation

- No Go exported-API breaks; `rpm.Manager` keeps `Apply/StopAll/Results/
  SetEventCallback`; eventengine continues to receive the same events.
- Config back-compat: all existing `services rpm` stanzas parse unchanged;
  new leaves are additive. `target <ip>` bare form retained.
- **One deliberate behavior change**: icmp-ping becomes a real echo probe.
  Existing configs with unreachable icmp targets will start reporting FAIL
  (and can now trigger event-options policies). Release-noted; reviewers
  asked to confirm this is fix-not-regression (Section 11 Q3).
- Wire protocol: `RouteSnapshot` unchanged (overlay resolved at build);
  no `protocol.rs`/`protocol.go` edits in PR-1 (both-sides rule satisfied
  trivially).
- `show chassis cluster ip-monitoring status` untouched.

## 7. Hidden invariants the change must preserve

1. **Apply serialization** — engine-triggered re-apply must take the same
   commit/apply semaphore as operator and event-engine commits (feeds +
   eventengine precedent); transitions during an in-flight apply coalesce.
2. **Control-socket budget** — snapshot pushes only on transitions
   (bounded by RPM thresholds + hold-down), never periodic; no new >1/s
   control requests.
3. **FRR emission-order contract** — preferred routes are a new numbered
   step in `ApplyFull`; the order comment is part of the contract and gets
   updated in the same commit.
4. **Snapshot content-hash / generation** — re-apply must bump generation
   so `syncSnapshotLocked` fires; overlay must be part of the built
   snapshot so the content hash reflects it (verify the skip-if-identical
   path can't eat a transition).
5. **fib_generation semantics** — flow re-resolution on snapshot change is
   the *intended* failover mechanism for established flows; don't add a
   parallel invalidation path in PR-1.
6. **HA single-publisher** — only the data-RG primary publishes overlay
   effects; takeover re-evaluates + re-probes (Section 4.4). No new
   heartbeat/control-plane traffic.
7. **Logging rules** — transitions at Info; per-probe results at Debug.
8. **networkd/FRR ownership** — overlay routes go through the FRR managed
   section, never raw netlink (one route owner; reconciliation stays sane).

## 8. Risk assessment

| Class | PR-1 | Notes |
|-------|------|-------|
| Behavioral regression | **MED** | applyConfig wiring is additive but central; real-ICMP flips existing probe semantics (deliberate); mitigated by full Go test suite + cluster smoke + failover run. |
| Lifetime/borrow risk | **NONE** | No Rust changes in PR-1/PR-2. |
| Performance regression | **LOW** | Control-plane only; transitions are seconds-scale rare events; one snapshot push per transition. |
| Architectural mismatch | **LOW-MED** | The config-derived dp FIB is the load-bearing constraint; the overlay design works *with* it. The known mismatch is pre-existing (FBF FRR-vs-dp divergence) and is PR-2's first task, with an explicit shrink path. |
| HA risk | **MED** | New publish-gating + takeover re-probe path; must pass `make test-failover` and a manual RG-flip-while-probe-failed scenario. |

## 9. Test & smoke plan (with the honest single-WAN-lab gap)

**Unit/CI (PR-1):**
- Parser/schema: flat-set via `ParseSetCommand()`+`SetPath()` loop AND
  hierarchical AST shape for every new stanza; completion tests.
- Compiler: commit-check failures (unknown probe, family mismatch, missing
  routing-instance).
- Engine: state machine with fake clock — fail threshold, recovery,
  hold-down, takeover re-evaluation, coalesced transitions.
- FRR render goldens with overlay routes (master + VRF, v4 + v6, distance).
- `buildRouteSnapshots` overlay override: same-prefix replacement, pin
  routes, table targeting.
- Real ICMP prober against loopback + an unreachable TEST-NET address.
- `make test` (full Go suite) green.

**Smoke (loss userspace cluster — the only smoke env):**
The lab has one physical WAN provider. We simulate two uplinks as the two
WAN VLANs `reth0.50` (172.16.50.0/24) and `reth0.80` (172.16.80.0/24):
probe a target reachable via the .50 next-hop, ip-monitoring preferred
default via the .80 next-hop. Kill the probe path (drop the probe target on
the upstream host / remove its address) and verify, in order:
1. `show services rpm` shows the test FAIL after successive-loss;
2. `show services ip-monitoring status` flips to FAIL / route APPLIED;
3. FRR + kernel route table show the preferred route (AD 1);
4. helper snapshot resync observed (generation bump) and iperf3 transit
   traffic re-resolves onto the .80 next-hop with no daemon restart;
5. recovery withdraws the route after hold-down; flap damping holds.
Plus `make test-failover` (HA-touching change) and an RG flip while the
policy is in FAIL state (takeover re-probe path).

**What this does NOT prove (honest gap):** real dual-provider failure modes
(provider blackhole beyond first hop is *partially* covered since probe
targets are upstream; physical link-down on one of two NICs is not), dual
public-IP SNAT realism (PR-3 concern), and throughput under true dual-path
load. These need either a second upstream on the loss cluster or a purpose-
built incus topology (two upstream router containers) — building that
topology (`test/incus/` additions) is **in scope for PR-2's smoke**, since
FBF validation is not meaningful without two distinguishable egress paths.
PR-1's simulated-VLAN smoke is sufficient for its claim (route flip end to
end through FRR + dp snapshot), which is topology-independent.

## 10. Out of scope (explicitly)

- DNS proxy, DDNS, WireGuard, smart queueing (other #1389 splits).
- A `services multi-wan` convenience/sugar tree (possible later, ON TOP of
  the parity layer, only if operator demand materializes).
- Per-packet load balancing (Junos doesn't; we won't).
- `qualified-next-hop preference` floating statics (pre-existing gap; noted,
  not fixed here — ip-monitoring sidesteps it; file separately).
- Kernel-routed (non-dp) FBF parity beyond what PR-2's divergence fix needs.
- DHCP-uplink interplay beyond what already exists (AD 200 defaults).
- eventengine changes (it keeps working as-is alongside ip-monitoring).

## 11. Path options (the real forks)

**Fork 1 — config surface (the ip-monitoring-analog vs new-subsystem fork):**

- **Path A (RECOMMENDED): Junos parity** — `services rpm` +
  `services ip-monitoring` + FBF composition, as designed above. Pros:
  charter-consistent, documented-everywhere operator pattern, composes from
  4 existing subsystems, smallest invention surface. Cons: multi-stanza
  config for a simple dual-WAN site (mitigable later with sugar).
- **Path B: invented `services multi-wan` subsystem** (#1389 sketch). Pros:
  friendlier; single tree; uplink as a first-class noun. Cons: violates the
  Junos-syntax charter, duplicates RPM/PBR semantics, every future feature
  (weights, per-app steering) needs bespoke modeling that Junos already
  solved; harder to kill once shipped. Rejected as the base layer.
- **Path C: floating statics only** — implement `qualified-next-hop
  preference` + tie route activation to probes without an ip-monitoring
  tree. Pros: tiny. Cons: not how Junos does probe-driven failover (Junos
  needs ip-monitoring or event-scripts for that), weak observability, no
  per-policy story, still needs the overlay machinery anyway. Rejected.

**Fork 2 — route actuation mechanics (PR-1 internal):**

- **Path D-full-apply (RECOMMENDED for PR-1):** transitions trigger
  `applyConfig(active)` (feeds precedent). Pros: one code path, serialized,
  generation/hash/fib_generation all correct by construction. Cons:
  heavyweight per transition (full FRR render + reload + snapshot push,
  seconds-scale) — acceptable because transitions are seconds-scale events
  by nature and damped.
- **Path D-delta:** a narrow "route overlay update" path (FRR vtysh
  incremental + targeted snapshot rebuild without full apply). Pros: faster
  failover actuation (sub-second after detection). Cons: second route code
  path to keep consistent; snapshot is monolithic today so the dp side
  still pushes a full snapshot. Deferred — adopt only if PR-1 smoke shows
  the full apply adds material latency on top of detection time (detection
  ≥ ~6-15 s with default thresholds dominates regardless).

**Recommendation:** Path A + D-full-apply for PR-1; PR-2 composes FBF; PR-3/
PR-4 each re-enter plan review.

## 12. Open questions for adversarial review

1. **Standby probe semantics** — is "probe on both nodes, publish only on
   primary, re-probe on takeover" right, or should standby suppress probes
   entirely (Junos runs RPM on the primary node only)? Suppression is
   simpler but makes takeover convergence strictly one full probe cycle.
   PLAN-KILL the HA design if neither is acceptable.
2. **preferred-metric → FRR admin distance** — correct mapping? (Junos
   installs preferred routes with route preference = preferred-metric,
   default 1.) Any FRR managed-section pitfall with distance-1 statics vs
   zebra route selection that breaks the withdrawal path?
3. **Real-ICMP behavior change** — fix-in-PR-1 (recommended: ip-monitoring
   on a fake probe is fiction) vs separate prerequisite PR? Does anyone see
   a deployed-config hazard beyond the release note?
4. **Re-apply per transition** — is the full-applyConfig actuation (Path
   D-full-apply) acceptable under reviewer scrutiny, given FRR reload is
   seconds-scale and the apply semaphore serializes with operator commits?
   Counter-example welcome (e.g. a probe-flap storm scenario the damping
   doesn't bound).
5. **Same-prefix override at build time** — overlay replacing (table,
   prefix) entries in Go vs adding a preference field to `RouteSnapshot`
   and letting Rust resolve. The former avoids wire/Rust changes; does it
   hide a case (ECMP route partially overridden) that bites in PR-4?
6. **Pin routes for `next-hop`** — auto-installed /32 probe routes: any
   objection (e.g. probe target also being real traffic's destination gets
   its path silently pinned)? Alternative: require the operator to add the
   /32 manually (documented recipe) and ship `next-hop` as commit-rejected
   until PR-2.
7. **PR-2's FBF divergence** — is fixing `instance-type forwarding` (FRR
   default-table render vs dp `<ri>.inet.0`) correctly scoped as PR-2's
   first task, or is it a PR-1 precondition because ip-monitoring's
   `routing-instance` target already exposes it?

---

*Plan doc lives on branch `research/1827-multiwan`. Reviewer round docs
land beside this file (`codex-plan-rN.md`, `agy-plan-rN.md`,
`claude-smr-plan-rN.md`, `reviewer-ids.md`).*
