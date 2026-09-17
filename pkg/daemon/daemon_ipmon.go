// daemon_ipmon.go — services ip-monitoring wiring (#1827 PR-1b).
//
// The single decision point is the ipmon engine's effective-route
// overlay; this file owns the two consumers' plumbing:
//
//  1. assembleFRRConfig — the SOLE frr.FullConfig constructor, shared
//     by the full apply path (applyConfigLocked step 3) and the
//     routes-only actuator, so the two paths cannot drift and an
//     unrelated operator commit can never wipe an active failover
//     route (AGY r2-2).
//
//  2. actuateRouteOverlay — the routes-only actuator: under the SAME
//     apply semaphore as operator commits it re-renders FRR, publishes
//     the dataplane snapshot via PublishRouteOverlaySnapshot, and ONLY
//     after a successful publish bumps the FIB generation (ordering is
//     load-bearing, AGY r2-1: bumping first would re-resolve flows
//     against the OLD routes and the later snapshot would not
//     re-invalidate them — traffic would stay pinned to the dead
//     uplink). It touches NOTHING else: no networkd, no ipsec, no RPM
//     re-apply, no cluster/heartbeat paths.
//
//     Consistency + self-heal (#3757): the actuator returns a bool that
//     the ipmon engine uses to decide whether to clear its dirty bit. A
//     HARD FRR reload error means nothing converged (frr manager
//     contract) — the kernel FIB still holds the previous routes — so
//     the actuator ABORTS BEFORE publishing the userspace snapshot
//     (never a split FIB, H1) and returns false. A snapshot-publish
//     error (H2) or an unconfirmed FIB-generation bump (H3) likewise
//     returns false. On any false return the engine keeps the state
//     dirty and retries autonomously on the next throttle-paced sweep
//     (M1); the dirty bit clears only after a fully consistent
//     actuation. A DEGRADED FRR reload (#1880, additive vtysh -f
//     applied) is deliberately treated as success: the new routes ARE
//     live in the kernel, so publishing the matching snapshot keeps the
//     two FIBs in agreement while the frr manager's own retry converges
//     stale-config removal.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
)

// routeOverlaySetter caches the overlay for full snapshot builds.
type routeOverlaySetter interface {
	SetRouteOverlay([]config.RouteOverlayEntry)
}

// routeOverlayPublisher is the routes-only partial republish surface
// of the userspace dataplane manager (#1827 Codex r2-2).
type routeOverlayPublisher interface {
	// PublishRouteOverlaySnapshot returns whether a snapshot was
	// actually published; duplicate-skips return false so the caller
	// does not bump the FIB generation for a no-op (Codex PR #1843
	// MED).
	PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error)
	// BumpFIBGeneration reports whether the helper-side invalidation
	// was confirmed (#1844 plan §4.3, Codex r2-1): a non-nil error
	// feeds the actuator's pendingFIBBump retry — without it, a
	// publish-success/bump-failure ordering followed by a duplicate
	// (hash-skipped) actuation would strand cached flow routes on the
	// pre-failover paths forever.
	BumpFIBGeneration() (uint32, error)
}

// ipmonActiveOverlay returns the engine's current effective-route
// overlay (nil when the engine is absent or publication is gated off).
func (d *Daemon) ipmonActiveOverlay() []config.RouteOverlayEntry {
	if d.ipmon == nil {
		return nil
	}
	return d.ipmon.ActiveOverlay()
}

// commitOverlayForConfig returns the overlay that may ride an
// operator commit's OWN publish: the engine's active overlay filtered
// against the INCOMING config (Codex PR #1843 HIGH-1). The full apply
// caches the overlay before reconcileIPMon installs the new policy
// set, so entries whose policy was removed or whose preferred-route
// spec was edited must be dropped here — otherwise the commit would
// republish the stale overlay to FRR and the snapshot until the
// delayed actuator caught up. Unrelated commits (policy spec
// unchanged) keep the active overlay intact (AGY r2-2).
func (d *Daemon) commitOverlayForConfig(cfg *config.Config) []config.RouteOverlayEntry {
	if cfg == nil {
		return nil
	}
	return ipmon.FilterOverlayForConfig(d.ipmonActiveOverlay(), cfg.Services.IPMonitoring)
}

// assembleFRRConfig builds the complete frr.FullConfig for the given
// compiled config plus the ip-monitoring overlay. It is the sole
// constructor for BOTH the full apply path and the routes-only
// actuator (the complete contract: static routes, generate-routes,
// DHCP routes, policy export, backup-router, interface hints, RethMap,
// IPv6 next-hop interfaces, ClusterMode, per-VRF instances, and the
// overlay's PreferredRoutes).
func (d *Daemon) assembleFRRConfig(cfg *config.Config, overlay []config.RouteOverlayEntry) *frr.FullConfig {
	// Collect interface bandwidths and point-to-point flags for FRR.
	ifaceBandwidths := make(map[string]uint64)
	ifaceP2P := make(map[string]bool)
	// #9821: collect interface bandwidths and point-to-point flags while the
	// shared FRR map constructor covers every interface spelling. #9942's
	// secure-tunnel route refs are resolved there before rendering.
	ipv6NextHopInterfaces := inferIPv6StaticNextHopInterfaces(cfg, overlay)
	declaredNetdevs := frr.DeclaredNetdevsForConfig(cfg, ipv6NextHopInterfaces)
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		linuxName := config.LinuxIfName(name)
		if ifc.Bandwidth > 0 {
			ifaceBandwidths[linuxName] = ifc.Bandwidth
		}
		for _, unit := range ifc.Units {
			if unit.PointToPoint {
				ifaceP2P[linuxName] = true
			}
		}
	}

	fc := &frr.FullConfig{
		OSPF:                  cfg.Protocols.OSPF,
		OSPFv3:                cfg.Protocols.OSPFv3,
		BGP:                   cfg.Protocols.BGP,
		RIP:                   cfg.Protocols.RIP,
		ISIS:                  cfg.Protocols.ISIS,
		StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
		Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
		GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
		DHCPRoutes:            d.collectDHCPRoutes(),
		PolicyOptions:         &cfg.PolicyOptions,
		ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
		BackupRouter:          cfg.System.BackupRouter,
		BackupRouterDst:       cfg.System.BackupRouterDst,
		InterfaceBandwidths:   ifaceBandwidths,
		InterfacePointToPoint: ifaceP2P,
		RethMap:               cfg.RethToPhysical(),
		DeclaredNetdevs:       declaredNetdevs,
		IPv6NextHopInterfaces: ipv6NextHopInterfaces,
		ClusterMode:           d.cluster != nil,
		PreferredRoutes:       overlay,
		// #9405: protocol interface references are stored as the AUTHORED
		// Junos reference (`ge-0/0/1.0`, `reth0.50`). The FRR renderer wrote
		// them verbatim, so `interface ge-0/0/1.0` never bound a netdev and no
		// OSPF/OSPFv3/IS-IS/RIP adjacency formed — on a commit that succeeded
		// with no warning. ResolveKernelIfName is the canonical resolver the
		// RA path already uses (daemon_ra.go), so the two protocol consumers
		// name the same device.
		IfNameResolver: cfg.ResolveKernelIfName,
	}
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		tableID := 0
		forwarding := ri.InstanceType == "forwarding"
		if forwarding {
			// Forwarding instances have no VRF device; their statics
			// render into the instance's dedicated kernel table so the
			// kernel agrees with the FBF/PBR ip rules AND the userspace
			// dataplane's `<ri>.inet.0` snapshot table (#1827 PR-2
			// divergence fix — previously these leaked into the default
			// table).
			vrfName = ""
			tableID = ri.TableID
		}
		inst := frr.InstanceConfig{
			Name:              ri.Name,
			VRFName:           vrfName,
			TableID:           tableID,
			OSPF:              ri.OSPF,
			OSPFv3:            ri.OSPFv3,
			BGP:               ri.BGP,
			RIP:               ri.RIP,
			ISIS:              ri.ISIS,
			StaticRoutes:      ri.StaticRoutes,
			Inet6StaticRoutes: ri.Inet6StaticRoutes,
		}
		if forwarding {
			// #9409: DROP the protocols rather than carry them through.
			//
			// The `vrfName = ""` above is correct for statics and fatal for
			// protocols: generateProtocols reads an empty VRFName as "the
			// GLOBAL instance", so carrying them through activated an
			// instance-scoped IGP in the global routing context and attached an
			// instance-scoped BGP neighbor to the GLOBAL AS. Measured before
			// this change: TWO `router ospf` blocks, neither carrying a `vrf`
			// suffix, and the instance's `peer-as 65002` neighbor rendered under
			// a second `router bgp 65001`.
			//
			// The composition is rejected at strict commit
			// (validateForwardingInstanceProtocolsStrict), so reaching here
			// means the config arrived on a TOLERANT path — boot from an
			// already-persisted config, or HA peer-sync — where #1960 forbids
			// refusing to start. Dropping is what makes that downgrade safe:
			// the box boots and the unsupported stanza is INERT, rather than
			// booting and quietly rewriting the global routing table.
			if ri.OSPF != nil || ri.OSPFv3 != nil || ri.BGP != nil ||
				ri.RIP != nil || ri.ISIS != nil {
				slog.Warn("dropping protocols under instance-type forwarding: "+
					"a forwarding instance has no VRF device, so FRR would "+
					"activate them in the GLOBAL routing instance (#9409)",
					"instance", ri.Name)
			}
			inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS = nil, nil, nil, nil, nil
		}
		fc.Instances = append(fc.Instances, inst)
	}
	return fc
}

// applyFRRConfig applies an assembled FullConfig and handles the
// shared post-ApplyFull consistent-hash sysctl. Both the full apply
// path and the actuator go through here.
//
// Return contract (#9947 F-007): the ApplyFull outcome verbatim — nil on
// a full-diff convergence, ErrFRRReloadDegraded (errors.Is) on an
// additive-fallback reload where the new lines ARE live but stale-config
// removal is deferred to the in-manager retry, or a hard error where
// NOTHING converged. Callers branch: the actuator treats degraded as
// publishable success (new routes live — publishing keeps the kernel and
// userspace FIBs in agreement, #3757/#1880) and aborts only on hard;
// the operator-commit full path (applyFRRFull) fails the commit closed
// on hard AND on transient degraded, tolerating only the persistent
// pytools-missing degraded state (IsFRRReloadPyMissing) with gauge +
// warn, so a removal that did not happen is never reported as an
// unqualified success.
func (d *Daemon) applyFRRConfig(fc *frr.FullConfig) error {
	if d.frr == nil {
		return nil
	}
	err := d.frr.ApplyFull(fc)
	if err != nil {
		if errors.Is(err, frr.ErrFRRReloadDegraded) {
			slog.Warn("FRR reload degraded: additive vtysh -f applied; stale-config removal deferred to the in-manager retry", "err", err)
		} else {
			slog.Warn("failed to apply FRR config", "err", err)
		}
	}

	// Set L4 ECMP hash when consistent-hash is configured. Independent of
	// the reload outcome (an idempotent procfs knob); attempted even on a
	// degraded/hard-failed reload so it is not stranded.
	if fc.ConsistentHash {
		setFibMultipathHashPolicy()
	}
	return err
}

// setFibMultipathHashPolicy enables L4 (5-tuple) ECMP hashing by writing
// net.ipv4.fib_multipath_hash_policy=1 when it is not already set.
// BestEffortKernelKnob procfs write — rename(2) is impossible on procfs, so
// it stays a direct os.WriteFile. Extracted from applyFRRConfig (#1916
// §2.D) so the enclosing function is never allowlisted in the fsatomic
// canary; this single-purpose helper is.
func setFibMultipathHashPolicy() {
	path := "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	current, _ := os.ReadFile(path)
	if strings.TrimSpace(string(current)) != "1" {
		if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
			slog.Warn("failed to set fib_multipath_hash_policy", "err", err)
		} else {
			slog.Info("enabled L4 ECMP hashing (consistent-hash)")
		}
	}
}

// actuateRouteOverlay is the routes-only actuator (#1827 plan §4.3,
// Path D-routes-only). Invoked from the ipmon engine's single run-loop
// goroutine after debounce + throttle; the engine guarantees at most
// one invocation in flight. It snapshots the overlay at run time
// (last-writer-wins under flap storms).
// actuateRouteOverlay returns whether the overlay converged
// consistently; the ipmon engine keeps the state dirty and retries when
// it returns false (#3757).
//
// ctx is the engine's actuation context (cancelled on ipmon.Stop, i.e.
// daemon shutdown/reconcile). It is threaded into the apply-semaphore
// acquire so a shutdown aborts a wait that would otherwise wedge the
// ipmon run loop — and, through it, shutdown — behind an in-flight
// apply that never releases the semaphore (#3758). On cancellation the
// actuator returns false WITHOUT touching FRR or the userspace snapshot
// (no half-actuation): the engine keeps the state dirty and re-actuates
// on the next sweep if the daemon is still up, and shutdown proceeds
// otherwise.
func (d *Daemon) actuateRouteOverlay(ctx context.Context) bool {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return false
	}
	defer d.applySem.Release(1)

	if d.store == nil {
		return true // nothing to actuate — converged
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return true
	}
	return d.actuateRouteOverlayLocked(cfg)
}

// actuateRouteOverlayLocked is the actuator body; MUST be called with
// d.applySem held. Split out so the publish-before-bump ordering is
// directly testable. Returns true only when kernel FRR and the
// userspace snapshot are left in a consistent, converged state; a false
// return signals the engine to keep the state dirty and retry (#3757).
func (d *Daemon) actuateRouteOverlayLocked(cfg *config.Config) bool {
	// #5281: refuse to actuate once a factory reset has entered the terminal
	// reset generation. This actuator re-renders /etc/frr/frr.conf (the WORLD-
	// readable file that carries the xpf-managed BGP-MD5 / OSPF / IS-IS routing-
	// auth keys) from the still-resident in-memory ActiveConfig. In the ~1s
	// wipe→stop window (or the graceful-shutdown drain) an ip-monitoring sweep
	// triggered by a probe flap would otherwise acquire the just-released
	// applySem and re-materialize the ERASED routing-auth keys into a file that
	// SURVIVES the post-zeroize reboot — defeating the wipe. Return false so the
	// ipmon engine keeps the state dirty (no half-actuation); the daemon is
	// being wiped/stopped, so the retry never fires.
	if d.isResetting() {
		return false
	}

	overlay := d.ipmonActiveOverlay()

	// 1. Re-render FRR through the shared constructor. A HARD FRR reload
	// error means NOTHING converged (frr manager contract) — the kernel
	// FIB still holds the previous routes. Publishing the userspace
	// snapshot now would split the FIB (#3757 H1): kernel on the old
	// route, dataplane on the new one. Abort WITHOUT publishing and
	// report failure so the engine keeps the state dirty and retries on
	// the next sweep; the prior consistent kernel+snapshot state is
	// preserved. A DEGRADED reload (#1880) is deliberately publishable:
	// the new routes ARE live, so the matching snapshot publish keeps
	// the two FIBs in agreement while the frr manager's own retry
	// converges stale-config removal. (#9947: applyFRRConfig now
	// returns the degraded sentinel verbatim so the commit path can
	// fail closed on it; the actuator's contract is unchanged and is
	// therefore branched explicitly here rather than via a nil return.)
	if err := d.applyFRRConfig(d.assembleFRRConfig(cfg, overlay)); err != nil {
		if !errors.Is(err, frr.ErrFRRReloadDegraded) {
			slog.Warn("ip-monitoring: FRR reload failed — NOT publishing the userspace snapshot (would split the FIB); staying dirty for retry",
				"err", err)
			return false
		}
		// Degraded: fall through to publish (both FIBs agree on the new routes).
	}

	// 2. Publish the dataplane snapshot (routes-only partial republish,
	// no Compile, no helper restart).
	pub, ok := d.dataplane().(routeOverlayPublisher)
	if !ok {
		// No dataplane publisher (helperless): FRR is the only routing
		// consumer and it converged — nothing more to do.
		return true
	}
	var schedulerState map[string]bool
	if sched := d.scheduler.Load(); sched != nil {
		schedulerState = sched.ActiveState()
	}
	published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)
	if err != nil {
		// #3757 H2: a transient publish failure keeps the state dirty for
		// an autonomous retry (report failure). pendingFIBBump is
		// deliberately unchanged: a pending retry from an earlier bump
		// failure stays pending across a failed publish.
		slog.Warn("ip-monitoring: route overlay snapshot publish failed — NOT bumping FIB generation; staying dirty for retry",
			"err", err)
		return false
	}
	if !published && !d.pendingFIBBump {
		// Duplicate-skip (content unchanged) or helperless caching:
		// the dataplane routes did not move and the previous bump was
		// confirmed, so do not churn established-flow route caches
		// with a FIB-generation bump (Codex PR #1843 MED). Converged.
		return true
	}

	// 3. Only after a REAL apply_snapshot success (or with an
	// unconfirmed bump pending from an earlier actuation, #1844 Codex
	// r2-1): invalidate cached flow routes so established flows
	// re-resolve onto the new routes. pendingFIBBump is mutated only
	// here, under d.applySem — no extra locking.
	if _, err := pub.BumpFIBGeneration(); err != nil {
		d.pendingFIBBump = true
		// #3757 H3: report failure so the engine keeps the state dirty
		// and the bump retries autonomously on the next throttle-paced
		// sweep — not only on a future unrelated actuation.
		slog.Warn("ip-monitoring: FIB generation bump unconfirmed — staying dirty; will retry on next sweep",
			"err", err)
		return false
	}
	d.pendingFIBBump = false
	if !published {
		slog.Info("ip-monitoring: retried FIB generation bump after earlier failure")
		return true
	}
	slog.Info("ip-monitoring route overlay actuated", "overlay_routes", len(overlay))
	return true
}

// reconcileIPMon applies the committed ip-monitoring policy set to the
// engine (preserving FAIL state across unrelated commits) and seeds it
// with the current probe results. Runs as a late applyConfigLocked
// step, after reconcileRPM has the probe set running.
func (d *Daemon) reconcileIPMon(cfg *config.Config) {
	if d.ipmon == nil || cfg == nil {
		return
	}
	var results []*rpm.ProbeResult
	if d.rpm != nil {
		results = d.rpm.Results()
	}
	d.ipmon.Apply(cfg.Services.IPMonitoring, results)
}

// ipmonPublishAllowed implements §4.4 primary-only overlay
// publication: standalone nodes always publish; cluster nodes publish
// while primary for ANY data RG.
//
// The gate is IsLocalPrimaryAny() rather than IsLocalPrimary of the
// lowest data RG (#3764). Probe HA gating is already per-RG
// (filterRPMForHAGating / rpmProbeGatingRGs) — a gated probe runs only
// on the node that is primary for its RETH's RG — so a node only ever
// genuinely FAILs the policies whose RG it owns. Publishing whenever
// this node is primary for ANY RG is therefore both safe and precise:
// in a multi-data-RG cluster with split primaryship (RG1 primary on
// node A, RG2 primary on node B), node B publishes its RG2 overlay and
// node A publishes its RG1 overlay, while a true standby (primary for
// nothing) still publishes nothing. Keying on the lowest data RG alone
// suppressed the ENTIRE overlay on any node that was not primary for
// that lowest RG — so node B never injected the RG2 failover route it
// genuinely owns and detects as failed (a functional failover MISS for
// RG2). With a single data RG (the common case) IsLocalPrimaryAny() is
// identical to IsLocalPrimary(lowestDataRG), so there is zero regression.
//
// This is complete for RETH-bound probes. The residual — an in-scope
// probe with NO RETH binding, which rpmProbeGatingRGs defaults to the
// lowest data RG — is deferred (Layer 2: a per-policy publish allow-set,
// or a commit-check requiring HA-gated probes to bind a RETH).
func (d *Daemon) ipmonPublishAllowed(cfg *config.Config) bool {
	if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return true
	}
	return d.cluster.IsLocalPrimaryAny()
}

// reconcileIPMonGating re-evaluates HA gating after an RG transition:
// the probe set (gated probes run only on the primary) and the overlay
// publication gate. On takeover the engine re-seeds from the freshly
// restarted probes' results (all unknown ⇒ baseline first), and the
// overlay follows the first fresh failure transitions — the plan's
// baseline-then-fast-probe takeover semantics.
func (d *Daemon) reconcileIPMonGating() {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Hash-gated: only re-applies when the gating filter actually
	// changed the effective probe set.
	changed := d.reconcileRPM(cfg)
	if d.ipmon == nil {
		return
	}
	if changed {
		// Probe set changed (gated probes started/stopped): re-seed
		// the engine from the fresh results so stale FAIL state from
		// the pre-transition probe set cannot inject routes.
		d.reconcileIPMon(cfg)
	}
	d.ipmon.SetPublishEnabled(d.ipmonPublishAllowed(cfg))
}
