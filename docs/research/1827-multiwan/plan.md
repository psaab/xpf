# #1827 Multi-WAN: uplink model, health probes, failover + PBR policy layer

**Status:** DRAFT v2 — revised after round-1 adversarial review (Claude SMR +
Codex + AGY all PLAN-NEEDS-REVISION; r1 docs + verdicts beside this file)

This is a **multi-PR feature program** plan. The deliverable of this research
pass is an honest staging: the PR-1 unit small and shippable, later PRs
scoped with explicit gates and per-stage PLAN-KILL criteria. `/research`
stops at PLAN-READY; only the PR-1 unit (PR-1a + PR-1b below) is
pre-authorized for `/engineer` on convergence.

**v2 changes (r1 convergence):**
1. Path D-full-apply **rejected** (all three reviewers) → routes-only
   actuator (§4.3) with coalescing, config-hash-gated RPM re-apply, and an
   explicit FIB-generation bump.
2. `preferred-metric` semantics **corrected against Junos evidence**: the
   injected route has *preference 1* (Static/1); preferred-metric is a
   metric used to pick among competing injected routes (§4.1). This also
   yields the deterministic same-prefix resolution rule (AGY Critical 1/2).
3. Probe pin routes moved **out of FRR and out of the snapshot** into a
   dedicated kernel table + fwmark rule scoped to the prober (§4.2.4).
4. HA: **primary-only probing** (Junos parity); AGY's probe-on-both
   alternative documented and rejected with rationale (§4.4).
5. Staging split: **PR-1a** (RPM hardening) + **PR-1b** (ip-monitoring)
   per Codex-8/AGY-6 (§5).
6. PR-1b **commit-rejects** `preferred-route routing-instance` targeting
   `instance-type forwarding` (Codex-4/AGY-5); FBF divergence fix stays
   PR-2 but is now unreachable from PR-1.
7. fib_generation invariant rewritten around the actual mechanism
   (`fib_gen_map`, `BumpFIBGeneration`, `bump_fib_generation` control
   message) with a named test (Codex-2).
8. DHCP-learned uplinks declared an explicit v1 limitation (SMR-4).
9. PR-1 smoke claims downgraded to what one provider can prove; the
   two-upstream incus topology is a PR-2 deliverable (Codex-10).

---

## 1. Issue framing

#1827 is the residue split from the #1389 edge-gateway bundle at its
close-out: the two phases verified genuinely untracked on master — (a) a
first-class multi-WAN uplink model with health probing and failover, and
(b) a per-policy uplink-selection layer on the existing PBR/VRF machinery.
Everything else from #1389 is tracked elsewhere (#1703 WG, #1387 DDNS,
#1828 smart queueing).

Directive: **model after Junos where a natural analog exists**. Real SRX
multi-WAN is not a `services multi-wan` subsystem — it is the composition
of:

1. `services rpm probe <owner> test <name>` — health probes, with
   `destination-interface` / `next-hop` pinning so a probe exercises a
   *specific* uplink regardless of current routing;
2. `services ip-monitoring policy <name> match rpm-probe <owner> then
   preferred-route ...` — while the matched probe is FAILED, the preferred
   route is injected (at route preference 1); on recovery it is withdrawn;
3. filter-based forwarding (FBF) for per-policy uplink selection.

The #1389 body sketched an invented `set services multi-wan uplink ...`
tree; rejected as the base layer (Section 11 Path B), consistent with the
project's Junos-syntax charter.

## 2. Honest scope/value framing

Feature program, not perf work. Value: dual-uplink edge deployments (the
original #1389 ask) get Junos-syntax WAN failover and policy steering with
no external scripts. Costs: the PR-1 unit touches config schema, prober,
FRR render, daemon apply path, snapshot builder — wide but shallow; zero
Rust changes, zero hot-path changes. The lab has ONE physical WAN provider;
§9 states exactly what the simulated-uplink smoke does and does not prove.
*If reviewers conclude the value is too small to justify the churn,
PLAN-KILL is an acceptable verdict* (most plausible kill shape is
per-stage: kill PR-3/PR-4 scope, keep the PR-1 unit).

## 3. What's already shipped / partially present (survey of master)

Verified on `origin/master` (d30cfab84); all rows re-verified by Codex and
AGY in round 1:

| Area | State | Evidence |
|------|-------|----------|
| RPM probe manager | EXISTS — probe loops, per-test results, EMA RTT/jitter, events (`ping_test_failed` / `ping_probe_failed` / `ping_test_completed`) | `pkg/rpm/rpm.go` |
| RPM icmp-ping probe | **FAKE** — raw-IP dial (no echo sent) + UDP `connect()` fallback (no packet); a route-existence check. tcp-ping/http-get are real | `pkg/rpm/rpm.go:294-313` |
| RPM lifecycle | Applied once at daemon start; **never re-applied on commit** | `pkg/daemon/daemon_run.go:601-605` |
| RPM VRF/source binding | EXISTS — `SO_BINDTODEVICE` to `vrf-<ri>`, source-address | `pkg/rpm/rpm.go:21-45` |
| RPM → automation | `event-options` engine does config commit-and-apply on RPM events (30 s cooldown) — the legacy event-script-style failover, kept as-is | `pkg/eventengine/engine.go` |
| PBR (`then routing-instance`) | EXISTS end-to-end: config term → snapshot → Rust filter eval; Rust PBR lookup targets `<ri>.inet.0` | `pkg/config/types_system.go:531`, `pkg/dataplane/userspace/filters.go:71`, `userspace-dp/src/afxdp/forwarding/mod.rs:972` |
| Routing instances / VRFs | EXISTS — per-VRF statics, FRR per-VRF render, rib-group + next-table leaking (synthetic snapshot routes from `ip rule`) | `pkg/dataplane/userspace/routes.go:98-134` |
| `instance-type forwarding` | PARTIAL/WART — FRR renders its statics into the **default** table (`vrfName = ""`) while the snapshot files them under `<ri>.inet.0`: kernel vs dp divergence | `pkg/daemon/daemon_apply.go:760-766` vs `routes.go:77` |
| Route preference | `StaticRoute.Preference` (default 5) renders as FRR distance; DHCP defaults AD 200; backup-router AD 250 | `pkg/frr/config_render.go:147` |
| `qualified-next-hop` | Parsed but per-NH **preference dropped** (`NextHopEntry` has no preference field) — floating statics not real today | `pkg/config/compiler_routing.go:170-181`, `types_routing.go:94-97` |
| Dataplane FIB | **Config-derived snapshot** (config statics + connected + ip-rule leaks); FRR/kernel runtime routes never reach the helper FIB | `pkg/dataplane/userspace/routes.go:14-146` |
| FIB invalidation | `fib_gen_map` read at snapshot build (`readFIBGeneration`, `manager.go:776`); `BumpFIBGeneration()` (`manager.go:918`) + lightweight `bump_fib_generation` control message (`manager.go:968`); Rust validates `meta.fib_generation` (`forwarding/mod.rs:17`) | |
| Runtime-state → re-apply precedent | `pkg/feeds` calls `d.applyConfig(activeCfg)` — precedent for the *trigger*, NOT for the actuator (see §4.3; applyConfig's side-effect breadth is why) | `pkg/daemon/daemon_run.go:588-596` |
| applyConfig side effects | Full apply rebinds mgmt-VRF interfaces and **restarts the HA heartbeat** (`daemon_apply.go:718`); serialized under `applySem` with operator commits | |
| ip-monitoring (name collision) | Chassis-cluster ip-monitoring (RG weights) already exists — different Junos feature; ours is `services ip-monitoring` | `pkg/grpcapi/server_show.go:320` |
| Builder runtime-state input precedent | `buildSnapshotWithSchedulerState(..., activeState map[string]bool)` | `pkg/dataplane/userspace/builder.go:17` |

**The dataplane-awareness answer** (asked in the dispatch): multi-WAN
failover is *not* purely FRR/kernel territory. The helper FIB is
config-derived, so a health-driven route change MUST be reflected into a
new snapshot or transit traffic keeps using the dead uplink. Routes are
pure data to the helper — no Rust changes; snapshot push + explicit FIB
generation bump is the invalidation path. The single decision point lives
in Go and feeds BOTH consumers (FRR render and snapshot build).

**Explicit v1 limitation — static uplink next-hops required.** The dp FIB
contains no DHCP-learned routes (`collectDHCPRoutes` feeds FRR only), so a
DHCP-addressed WAN cannot carry dp fast-path transit today without a
static default; multi-WAN v1 inherits that: uplinks must have static
next-hops (consistent with ip-monitoring's explicit-next-hop model).
Documented in `docs/multi-wan.md` + a follow-up issue filed at PR-1b time
for DHCP-uplink support.

## 4. Concrete design — the PR-1 unit

### 4.1 Config surface (Junos parity)

RPM test additions (under `services rpm probe <p> test <t>`):

```
set services rpm probe WAN test wan-a probe-type icmp-ping
set services rpm probe WAN test wan-a target address 1.1.1.1
set services rpm probe WAN test wan-a destination-interface reth0.50   # NEW
set services rpm probe WAN test wan-a next-hop 172.16.50.1             # NEW
set services rpm probe WAN test wan-a thresholds successive-loss 3
```

New `services ip-monitoring` tree:

```
set services ip-monitoring policy wan-failover match rpm-probe WAN
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 172.16.80.1
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 preferred-metric 10
set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1
```

**Corrected semantics (verified against Juniper documentation + field
write-ups in r1):** while **any** test of the matched probe is FAILED, the
policy is FAIL and its preferred routes are injected; on recovery they are
withdrawn. The injected route has **route preference 1** (shows as
`Static/1` on SRX — beats static AD 5 and DHCP AD 200; that is what makes
it "preferred"). `preferred-metric` is a **metric on the injected route**,
i.e. the tie-break among *multiple injected routes for the same prefix*
(e.g. two policies in FAIL both injecting 0/0). It is NOT the route
preference. Mapping here:

- FRR/kernel: the engine resolves the winner per (table, prefix) — lowest
  preferred-metric, tie-break lexicographic policy name — and renders ONE
  static at **distance 1**. (FRR statics carry no usable metric knob, so
  metric resolution happens in the engine; the kernel sees only the
  winner. Observable behavior matches Junos: lowest-metric injected route
  carries traffic.)
- Snapshot: the same single winner replaces the (table, family, prefix)
  entry (§4.3). Kernel and dp therefore agree by construction — resolving
  AGY r1 Critical 1 (distance divergence) and Critical 2 (same-prefix
  non-determinism) in one rule.

Extension beyond Junos (flagged, default 0 = parity): `hold-down <secs>`
to damp recovery flaps.

Types (`pkg/config/types_system.go`):

```go
type IPMonitoringConfig struct{ Policies map[string]*IPMonitoringPolicy }
type IPMonitoringPolicy struct {
    Name            string
    MatchRPMProbe   string
    PreferredRoutes []*PreferredRoute
    HoldDownSecs    int // extension; 0 = Junos behavior
}
type PreferredRoute struct {
    RoutingInstance string // "" = master; forwarding-type REJECTED in PR-1b
    Destination     string // CIDR
    NextHop         string
    PreferredMetric int    // metric among injected routes; default 0
}
```

Commit checks: `match rpm-probe` references an existing probe;
next-hop/destination family match; routing-instance exists AND is not
`instance-type forwarding` (hard commit error pointing at the PR-2 FBF
work — this makes the known FRR-vs-dp FBF divergence unreachable from
PR-1, per Codex-4/AGY-5); at least one preferred-route per policy.

### 4.2 PR-1a — RPM hardening (own PR, prerequisite)

Split out per Codex-8 / AGY-6 so the behavior change ships and soaks
independently:

1. **Real ICMP echo prober** — ICMP/ICMPv6 echo with id/seq matching and
   per-probe timeout (xpfd runs as root; raw or datagram ICMP socket),
   honoring source-address + `SO_BINDTODEVICE`. *Behavior change*:
   icmp-ping probes that "always passed" can now fail and can now trigger
   existing event-options policies — release-noted as a bug fix.
2. **`destination-interface`** — `SO_BINDTODEVICE` to the unit's Linux
   name for all three probe types.
3. **`target address <ip>`** — canonical Junos form accepted alongside the
   existing bare form.
4. **`next-hop`** — probe pin plumbing with **zero transit impact**:
   pin /32 (/128) host routes to the probe target via the configured
   next-hop go into a **dedicated kernel routing table** with an `ip rule`
   `fwmark <probe-mark> lookup <table>`; probe sockets set `SO_MARK`.
   Managed by `pkg/routing` (rules.go machinery exists). NOT in FRR, NOT
   in the snapshot — transit traffic (fast path AND kernel slow path) is
   untouched, satisfying AGY-7 and Codex-3 strictly. Pin state follows the
   prober lifecycle (primary-only, §4.4), not config lifecycle.
5. **RPM re-apply on commit, config-hash-gated** — applyConfig re-applies
   RPM only when the rendered RPM stanza actually changed, so probe state
   (and the future ip-monitoring engine's sensor input) is never wiped by
   unrelated commits or by route actuations.
6. Transition hook on `rpm.Manager` (per-test pass/fail transitions with
   current-state snapshot), keeping the existing `EventCallback` intact
   for eventengine.

Probe replies arrive at the firewall's own IP; the dataplane already
passes local-destined traffic to the kernel (local_v4/local_v6 maps; RPM
tcp-ping works over the userspace dp today). PR-1a smoke validates real
ICMP through the AF_XDP local-delivery path explicitly — it is PR-1a's
PLAN-KILL tripwire.

### 4.3 PR-1b — ip-monitoring engine + routes-only actuator

New package `pkg/ipmon` (~400 LOC): policy state machine (FAIL on any
matched-test fail; recover when all pass + hold-down), overlay
computation, status for show/metrics.

**The single decision point** is the engine's *effective-route overlay*:
the set of currently-injected preferred routes after winner resolution
(§4.1). Both consumers read the same overlay:

1. **FRR**: `frr.FullConfig.PreferredRoutes` rendered as distance-1
   statics in the managed section (new numbered emission step; the
   emission-order contract comment updated in the same commit).
2. **Snapshot**: `buildRouteSnapshots` gains an overlay parameter; an
   overlay winner **replaces the entire (table, family, prefix) entry
   set — never merges next-hops** (ECMP half-override is impossible by
   construction; named test). No `RouteSnapshot` wire change, no Rust
   change.

**Actuator (replaces v1's Path D-full-apply, which all three reviewers
rejected):** a dedicated routes-only function that, under the SAME apply
semaphore as operator commits:

1. re-renders FRR via `ApplyFull` with the active config + overlay
   (touches only the managed frr.conf section; differential frr-reload);
2. rebuilds + pushes the dataplane snapshot (generation bump; content
   hash covers overlay routes — named test that an overlay-only change
   produces a hash delta and a sync);
3. explicitly calls `BumpFIBGeneration()` (existing lightweight
   `bump_fib_generation` control message) so established cached flows
   re-resolve — the invariant Codex-2 flagged as unproven is made
   explicit and tested rather than assumed.

It does NOT touch networkd, ipsec, RPM, event-options, or the cluster /
heartbeat paths — eliminating the r1 Critical feedback loops (heartbeat
restart at `daemon_apply.go:718`; probe-state wipe via `rpm.Apply`).

**Coalescing (Codex-7):** dirty-bit + bounded debounce (default 1 s); at
most one actuation in flight; the actuator snapshots the overlay at run
time (last-writer-wins), so a flap storm across N policies collapses to
one FRR render + one snapshot push per debounce window. Never queues
unbounded applies. Hold-down applies to recovery only (parity); fail is
acted on at the next debounce tick.

**Observability:** `show services ip-monitoring status` (cmdtree +
grpcapi + both CLIs; prefix-collision audit vs `show chassis cluster
ip-monitoring status`), Prometheus `xpf_ipmon_policy_failed{policy}`,
`xpf_ipmon_policy_transitions_total{policy}`, `xpf_ipmon_routes_applied`;
transitions logged at Info, probe detail at Debug.

### 4.4 HA model — primary-only probing (Junos parity)

Probes and pin plumbing run **only** on the node that is primary for the
data RG; overlay publication likewise. Rationale (SMR-2, Codex-9): uplink
addresses are VRRP-owned VIPs; the standby holds no usable source address
on a RETH uplink, so standby probes would fail structurally, not
informatively (the HA code asserts secondary never owns VIPs —
`pkg/daemon/direct_vip_ownership_test.go:16`).

On RG takeover: publish config baseline (no overlay), start probes with a
collapsed-interval first cycle, apply overlay after first fresh results.
Convergence cost: at most one fast probe cycle of config-default routing,
and only when the takeover coincides with an uplink failure (double
fault). **AGY r1 alternative** (probe-on-both from node-local physical
IPs) is documented and rejected for v1: the RETH VIP addressing model has
no per-node WAN addresses to source from. If a deployment configures
node-local addresses on uplink interfaces, standby probing becomes
possible — filed as a follow-up enhancement, not PR-1.

Overlay is runtime state, never config: config-sync untouched; per-node
frr.conf divergence is expected (standby = baseline).

### 4.5 PR-1 unit blast radius

PR-1a: `pkg/rpm`, `pkg/routing` (pin table/rule), `pkg/config`
(schema/parser/compiler for the new test leaves), `pkg/daemon` (gated
re-apply). PR-1b: `pkg/config` (ip-monitoring stanza), new `pkg/ipmon`,
`pkg/daemon` (wiring + HA gating), `pkg/frr` (PreferredRoutes render),
`pkg/dataplane/userspace` (builder overlay param — Go only),
`pkg/cmdtree`/`pkg/grpcapi`/`cmd/cli` (show), `pkg/api` (metrics), docs.
**Zero Rust changes. Zero wire-protocol changes. Zero hot-path changes.**
~700-900 LOC per PR including tests.

## 5. Staging — the full program

| PR | Scope | Gate to start | PLAN-KILL criteria (stage-local) |
|----|-------|---------------|----------------------------------|
| **PR-1a** | RPM hardening: real ICMP echo, `destination-interface`, `next-hop` pin plumbing (fwmark table), `target address`, config-hash-gated re-apply, transition hook | This plan PLAN-READY | Kill if real ICMP echo cannot be validated through the AF_XDP local-delivery path on the loss cluster (smoke gate, run first). |
| **PR-1b** | `services ip-monitoring` config + engine + routes-only actuator + FRR/snapshot overlay + FIB-generation bump + show/metrics + HA primary-only gating | PR-1a merged | Kill if the routes-only actuator cannot be carved out of applyConfig without duplicating reconciliation logic reviewers deem unmaintainable, or the overlay content-hash/fib-generation tests reveal the snapshot path cannot guarantee transition delivery. |
| **PR-2** | Per-policy uplink selection = FBF composition: fix the `instance-type forwarding` FRR-default-table vs dp-`<ri>.inet.0` divergence, lift the PR-1b forwarding-type commit-rejection, `preferred-route routing-instance` into FBF instances, per-policy counters, operator recipe (`docs/multi-wan.md`), **two-upstream incus topology** (`test/incus/`) + smoke | PR-1b merged + smoke-proven flip | Kill/re-stage if the FBF fix requires Rust FIB table-semantics rework larger than the Go-side fix — PR-2 shrinks to a documented vrf-instance-type recipe and the FBF fix becomes its own issue. |
| **PR-3** | NAT interplay: per-uplink SNAT pools (verify existing zone/rule-set matchers suffice), defined session behavior on uplink transition (fib-generation re-resolution + invalidation of sessions whose SNAT binding references the failed uplink, via existing filtered session-clear), counters + show reason | PR-2 merged; semantics mini-review in its PR plan | Kill if NAT-binding-keyed invalidation needs per-packet hot-path state the dp doesn't carry — fallback is Junos-like timeout behavior (document, don't build). |
| **PR-4** | Weights/load-share: health-gated ECMP overlay, weighted flow-hash. Requires auditing dp ECMP next-hop determinism + HA symmetry first | PR-3 merged + a fresh /research round (NOT pre-authorized) | Kill if dp ECMP selection is not per-flow stable across nodes without Rust work; weighted hashing may not justify churn at 2 uplinks. |

## 6. Public API / compatibility preservation

- No Go exported-API breaks; `rpm.Manager` keeps
  `Apply/StopAll/Results/SetEventCallback`; eventengine unaffected.
- Config back-compat: existing `services rpm` stanzas parse unchanged;
  bare `target <ip>` retained; new leaves additive.
- **One deliberate behavior change (PR-1a):** real icmp-ping. Release-
  noted; shipped separately so it soaks before ip-monitoring depends on it.
- Wire protocol: `RouteSnapshot` unchanged; no `protocol.rs`/`protocol.go`
  edits (both-sides rule trivially satisfied).
- `show chassis cluster ip-monitoring status` untouched; CLI prefix-
  matching audit for the new `show services ip-monitoring`.

## 7. Hidden invariants the change must preserve

1. **Apply serialization** — the actuator runs under the same apply
   semaphore as operator/eventengine commits; coalesced, never queued
   unbounded (Codex-7).
2. **No sensor-wipe on actuation** — actuator never re-applies RPM;
   RPM re-apply is config-hash-gated (r1 Critical).
3. **No heartbeat perturbation** — actuator never enters the networkd /
   mgmt-VRF / `RestartHeartbeat` path (`daemon_apply.go:718`).
4. **Control-socket budget** — one snapshot push + one
   `bump_fib_generation` per debounce window; no new periodic traffic.
5. **FRR emission-order contract** — preferred routes are a new numbered
   step; contract comment updated in the same commit.
6. **Snapshot generation/content-hash** — overlay routes are inside the
   hashed content; named test: overlay-only change ⇒ hash delta ⇒ sync
   fired (a silently-skipped transition is a failover-doesn't-happen bug).
7. **FIB generation** — actuator explicitly bumps; named test that an
   established flow re-resolves onto the injected route.
8. **Whole-entry replacement** — overlay replaces the full
   (table, family, prefix) entry set; never merges next-hops (ECMP test).
9. **HA single-publisher** — primary-only probing and publication;
   takeover = baseline + fast probe cycle.
10. **Route ownership** — overlay routes via the FRR managed section; pin
    routes via the dedicated probe table (netlink, pkg/routing-owned);
    neither leaks into the other's reconciliation.
11. **Logging rules** — transitions Info, per-probe Debug.

## 8. Risk assessment

| Class | PR-1a | PR-1b | Notes |
|-------|-------|-------|-------|
| Behavioral regression | MED (real ICMP semantics flip) | MED (new actuator beside applyConfig) | Mitigated by the split, config-hash gating, full Go suite, cluster smoke, `make test-failover`. |
| Lifetime/borrow risk | NONE | NONE | No Rust changes in the PR-1 unit or PR-2. |
| Performance regression | LOW | LOW | Control-plane only; one FRR render + one snapshot push per debounce window. |
| Architectural mismatch | LOW | LOW-MED | Works *with* the config-derived FIB. The FBF wart is commit-fenced until PR-2. The actuator partially duplicates applyConfig's FRR assembly — kept honest by extracting a shared `assembleFRRConfig(cfg, overlay)` helper used by both paths. |
| HA risk | LOW | MED | Primary-only gating + takeover re-probe; `make test-failover` + manual RG flip while a policy is FAILED. |

## 9. Test & smoke plan (with the honest single-provider-lab gap)

**Unit/CI:**
- Parser/schema: flat-set (`ParseSetCommand()`+`SetPath()` loop) AND
  hierarchical shapes for every new stanza; completion tests.
- Compiler: unknown probe, family mismatch, forwarding-type
  routing-instance rejection, missing preferred-route.
- Engine (fake clock): fail threshold, recovery + hold-down, debounce
  coalescing (N transitions ⇒ 1 actuation), takeover re-evaluation,
  winner resolution (preferred-metric, tie-break, withdrawal re-exposes
  config routes).
- FRR render goldens: distance-1 injected routes, master + vrf, v4 + v6;
  emission order.
- Snapshot: overlay whole-entry replacement (incl. ECMP), content-hash
  delta on overlay-only change, generation bump.
- Real ICMP prober: loopback echo + TEST-NET timeout; fwmark pin-route
  table/rule lifecycle (netlink, root test).
- `make test` (full Go suite) green.

**Smoke (loss userspace cluster — the only smoke env):**
- **PR-1a:** real ICMP probe through the AF_XDP local-delivery path on a
  live uplink (pass), then blackholed target (fail at successive-loss);
  `destination-interface`/`next-hop` pin verified via the probe table
  (`ip route show table <probe-table>`) with transit routes unchanged.
- **PR-1b:** two simulated uplinks = the two WAN VLANs `reth0.50` /
  `reth0.80`. Probe a target via the .50 next-hop; ip-monitoring preferred
  default via the .80 next-hop. Drop the probe target upstream and verify
  in order: RPM FAIL → `show services ip-monitoring status` FAIL/APPLIED →
  FRR + kernel show the distance-1 route → snapshot resync + FIB-gen bump
  observed → iperf3 transit re-resolves onto .80 with no restart →
  recovery withdraws after hold-down. Plus `make test-failover` and an RG
  flip while the policy is FAILED (takeover baseline + fast re-probe).

**What this does NOT prove (downgraded claims per Codex-10):** physical
uplink failure on distinct NICs, true dual-provider failure modes, RETH
behavior with two independent WAN VRRP groups, dual-public-IP SNAT
realism, throughput under genuine dual-path load. PR-1 claims are limited
to "route flip propagates end-to-end (FRR + kernel + dp snapshot + flow
re-resolution)". The **two-upstream incus topology is a PR-2
deliverable** (FBF validation is meaningless without two distinguishable
egress paths); PR-3/PR-4 claims ride on it.

## 10. Out of scope (explicitly)

- DNS proxy, DDNS, WireGuard, smart queueing (other #1389 splits).
- A `services multi-wan` sugar tree (only ever ON TOP of the parity layer,
  if demand materializes).
- Per-packet load balancing.
- `qualified-next-hop preference` floating statics (pre-existing gap;
  ip-monitoring sidesteps it; file separately).
- DHCP-learned uplink next-hops (explicit v1 limitation, §3; follow-up
  issue at PR-1b).
- Probe-on-standby via node-local addresses (follow-up enhancement, §4.4).
- eventengine changes.

## 11. Path options (the real forks)

**Fork 1 — config surface (ip-monitoring-analog vs new-subsystem):**

- **Path A (RECOMMENDED, unchanged from v1): Junos parity** —
  `services rpm` + `services ip-monitoring` + FBF composition. Charter-
  consistent, documented-everywhere operator pattern, composes from four
  existing subsystems, smallest invention surface.
- **Path B: invented `services multi-wan` subsystem** (#1389 sketch).
  Friendlier single tree, but violates the Junos-syntax charter,
  duplicates RPM/PBR semantics, and every future knob needs bespoke
  modeling Junos already solved. Rejected as the base layer.
- **Path C: floating statics only** (qualified-next-hop preference tied
  to probes). Tiny, but not how Junos does probe-driven failover, weak
  observability, still needs the overlay machinery. Rejected.

**Fork 2 — actuation mechanics (REVISED in v2):**

- **v1's Path D-full-apply is DEAD** (unanimous r1: heartbeat restart +
  probe-state wipe feedback loops, semaphore starvation, operator-commit
  503s).
- **Path D-routes-only (RECOMMENDED):** dedicated actuator = FRR
  managed-section re-render + snapshot push + FIB-gen bump under the
  apply semaphore, coalesced (§4.3). One decision point, two consumers,
  no side-effect breadth. Cost: still a differential `frr-reload` per
  debounce window (seconds-scale; detection time ≥ ~6-15 s dominates).
- **Path D-delta (AGY's preference, deferred):** incremental vtysh route
  add/del + targeted snapshot diff. Faster actuation but a second route
  code path to keep consistent with the render path, and the snapshot is
  monolithic today. Adopt only if PR-1b smoke shows frr-reload latency
  materially adds to failover time. The actuator API is written so the
  FRR step is swappable.

**Recommendation:** Path A + D-routes-only; PR-2 composes FBF; PR-3/PR-4
re-enter plan review.

## 12. Open questions for adversarial review (round 2)

1. **Winner-resolution parity** (§4.1): engine-side lowest-preferred-
   metric selection rendering ONE distance-1 static — acceptable parity
   stand-in for Junos's install-all-with-metrics behavior, given FRR
   statics have no metric knob? Counter-example welcome (e.g. an operator
   workflow that depends on seeing both injected routes).
2. **Actuator extraction risk**: is `assembleFRRConfig(cfg, overlay)`
   shared between applyConfig and the actuator sufficient to prevent the
   two paths drifting, or do reviewers see a cleaner carve?
3. **Pin-route plumbing**: fwmark + dedicated table + SO_MARK — any
   interaction with existing `pkg/routing` rules (leak rules, mgmt VRF)
   or with the cluster's fabric path that bites? Mark-value allocation
   scheme?
4. **Takeover window**: baseline-then-fast-probe accepts up to one fast
   probe cycle of config-default routing on double fault. Acceptable, or
   should the previous primary's overlay state ride the existing HA sync
   channels (rejected so far: adds a sync surface for state that
   re-derives in seconds)?
5. **Debounce default** (1 s) and hold-down default (0 = Junos): right
   numbers? Any flap pattern where 1 s coalescing + RPM thresholds still
   produce unacceptable FRR-reload churn?
6. **PR-1a/PR-1b split**: any reviewer see a reason the split is wrong
   (e.g. pin plumbing belongs with the engine rather than the prober)?
7. **PLAN-KILL tripwires** (§5): are PR-1b's two kill criteria concrete
   enough to be testable in the first week of implementation?

---

*Round-1 verdicts: Claude SMR PLAN-NEEDS-REVISION
(`claude-smr-plan-r1.md`), Codex PLAN-NEEDS-REVISION
(`task-mq8el1x7-umm9hr`), AGY PLAN-NEEDS-REVISION
(`adversarial-review-mq8ejo4w-90m0gs`); all r1 findings addressed above.
Reviewer IDs in `reviewer-ids.md`.*
