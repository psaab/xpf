package daemon

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// applyServicesReconcile runs the per-service reconcile phases of a config
// apply that are decoupled from the dataplane-apply / RETH-MAC state: proactive
// neighbor resolution, RA sender config, IPsec config, the Kea DHCP server, and
// DHCP clients. Extracted verbatim from applyConfigLocked (#4407); no early
// return and no crossing input beyond cfg. It produces the IPsec and
// DHCP-server deferred errors (recorded, not returned early, so a later
// per-subsystem failure does not abort the apply) and returns them (ipsecErr,
// dhcpServerErr) for the tail reconcile's six-way errors.Join. Runs in the
// same slot, after the routing rules and before the tail reconciles.
func (d *Daemon) applyServicesReconcile(cfg *config.Config) (error, error) {
	// 4. Proactive neighbor resolution for all known next-hops/gateways.
	// This ensures bpf_fib_lookup returns SUCCESS (with valid MACs)
	// instead of NO_NEIGH for the first forwarded packet.
	// In cluster mode, skip here — RETH VIPs are not yet installed (VRRP
	// hasn't become MASTER), so RouteGet() for WAN next-hops may fail.
	// resolveNeighbors() is triggered on VRRP MASTER in watchVRRPEvents.
	if cfg.Chassis.Cluster == nil {
		d.resolveNeighbors(cfg)
	}

	// 5. Apply RA config (Router Advertisements)
	// In cluster mode, RA/kea are managed by watchVRRPEvents — only
	// the MASTER runs these services to prevent dual-RA / dual-DHCP.
	// The VRRP event fires shortly after startup and calls applyRethServices().
	isCluster := cfg.Chassis.Cluster != nil
	raConfigs := d.buildRAConfigs(cfg)
	if !isCluster {
		if d.ra != nil && len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("failed to apply RA config", "err", err)
			}
		} else if d.ra != nil {
			// No RA configs remain — the operator removed all RA. Gracefully
			// WITHDRAW any previous senders (final lifetime-0 goodbye, #5092)
			// instead of a hard Clear, so hosts drop this router immediately
			// rather than holding the stale default route until Router Lifetime
			// (default 1800s) expires. Withdraw is a no-op when no senders exist.
			if err := d.ra.Withdraw(); err != nil {
				slog.Warn("failed to withdraw RA config", "err", err)
			}
		}
	}
	// Cluster startup: goodbye RAs for stale routes are handled by the
	// reconcile loop (reconcileRGState) after VRRP election settles.
	// Each RETH node has a different virtual MAC (hence different
	// link-local), so both nodes appear as separate routers to hosts.
	// Only the primary sends RAs (via applyRethServicesForRG on MASTER);
	// the reconcile loop sends goodbye RAs for inactive RGs.
	//
	// Stable link-local cleanup: handled by reconcile after election.
	//
	// #5861: a day-2 RA edit on an RG that stays MASTER never fires a VRRP
	// event, so pre-#5861 the primary kept advertising the OLD prefixes/
	// lifetimes/options until failover/restart. Reconcile the cluster RA
	// senders against the union of buildRAConfigs for the RGs this node is
	// CURRENTLY the active owner for — owner-gated + serialized so a commit
	// racing a demotion can't re-arm RA on a now-inactive node. Hash-gated:
	// a no-op when the effective RA set for the owned RGs did not change.
	if isCluster {
		d.reconcileClusterRAServices("commit")
	}

	// 6. Apply IPsec config
	// Always call Apply so stale swanctl config is removed when VPNs are
	// deleted from config.
	//
	// #4433: a swanctl render/reload failure must fail the commit closed
	// rather than be swallowed at WARN — otherwise the OLD tunnels stay
	// active (swanctl --load-all leaves the previously-loaded config in
	// place on failure) while a NEW config is reported committed, so the
	// enforced IPsec runtime silently diverges from the committed policy.
	// The error is joined into the commit result at the tail (alongside
	// networkdErr / dhcpServerErr / hostInboundErr / lo0Err); the remaining
	// apply steps still run and the config stays promoted + peer-synced, so
	// the operator SEES the degraded IPsec state instead of a false success.
	var ipsecErr error
	if d.ipsec != nil {
		if err := d.applyIPsecTracked(cfg); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
			ipsecErr = fmt.Errorf("apply IPsec config: %w", err)
		}
	}

	// 7. Reconcile DHCP server (Kea DHCPv4 + DHCPv6) against actual
	// systemd unit state (#1778).
	//
	// Standalone: Apply runs UNCONDITIONALLY — removing the
	// dhcp-server stanza (or restarting xpfd over a stale Kea left by
	// a previous daemon) stops the units; the pre-#1778 nil-config
	// gate skipped Apply entirely and leaked the old server.
	//
	// Cluster (#1835 F3): VRRP MASTER/BACKUP transitions own
	// start/stop (applyRethServicesForRG / clearRethServicesForRG via
	// ApplyAsync), but a config COMMIT must still reach the running
	// Kea — pre-F3 a dhcp-server change was invisible until the next
	// VRRP transition. Every commit regenerates the config files,
	// filtered to the RGs this node is currently MASTER for (the same
	// shape the VRRP path writes; nil when none match → authoritative
	// clear-if-active), and restarts only units that are currently
	// active (active == this node is serving). Inactive units pick up
	// the fresh config at the next VRRP MASTER transition.
	//
	// Fail-closed on commit (#1778/#1835 F3): restart/stop failures
	// are recorded into dhcpServerErr and returned at the tail of this
	// function, so commitAndApply surfaces them to the operator while
	// the remaining reconcile steps still run. The boot path stays
	// lenient: Run() reaches this via applyConfig(), which only logs
	// the returned error — an unavailable Kea binary cannot brick
	// daemon boot.
	var dhcpServerErr error
	if d.dhcpServer != nil {
		// #2239: gate the Kea control-socket + lease_cmds hook on the cluster
		// `dhcp-lease-synchronization` knob so the generated config carries the
		// read/seed surface only when lease sync is configured. Standalone or
		// knob-off renders bit-identical to pre-#2239. Set BEFORE the apply so
		// the regenerated config reflects the current knob.
		d.dhcpServer.SetLeaseSyncEnabled(d.dhcpLeaseSyncEnabled(cfg))
		if !isCluster {
			// #9141: the STANDALONE sibling of desiredClusterDHCPConfig. This
			// site used to call resolveDHCPRethInterfaces(&cfg.System.DHCPServer,
			// cfg) — passing the shared active config by pointer and letting the
			// resolver rewrite its group interface lists in place.
			desired := desiredStandaloneDHCPConfig(cfg)
			if err := d.dhcpServer.Apply(&desired); err != nil {
				slog.Warn("failed to apply DHCP server config", "err", err)
				dhcpServerErr = fmt.Errorf("apply DHCP server config: %w", err)
			}
		} else {
			// Single-sourced with the RG-transition edge and the #6535
			// reconcile converger: all three must derive the SAME desired
			// state from (config, current master-RG set), because a
			// converger that disagreed with the edge would fight it every
			// 2s tick.
			dhcpCfg := d.desiredClusterDHCPConfig(cfg)
			if err := d.dhcpServer.ApplyClusterCommit(dhcpCfg); err != nil {
				slog.Warn("failed to reconcile DHCP server (cluster commit)", "err", err)
				dhcpServerErr = fmt.Errorf("apply DHCP server config: %w", err)
			}
		}
	}

	// #1387 inc-2: nudge the DDNS reconcile loop so a commit that changes the
	// dynamic-dns policy (enable/disable, backend, zone, TSIG) takes effect
	// immediately rather than waiting up to one poll interval. The nudge is a
	// non-blocking depth-1 send (no control-socket call here — the loop does
	// file I/O + DNS only), so it never blocks the apply path. A
	// disabled/removed block drives withdrawAllLocked on the next pass.
	d.nudgeDDNSReconcile()
	// #2691 P2: a commit may add/remove a Surface A binding or change a
	// provider — nudge the Surface A loop to converge immediately too.
	d.nudgeSurfaceADDNSReconcile()

	// #2239: nudge an immediate lease-sync push so a commit that changes the
	// DHCP-server config (and thus the lease set / serving interfaces) is
	// replicated to the peer within one pass rather than waiting a heartbeat.
	// Non-blocking depth-1 send; the loop's gate decides if this node pushes.
	d.nudgeDHCPLeaseSync()

	// 7b. Reconcile DHCP clients (#1793): start clients for units that
	// gained dhcp/dhcpv6 in this commit, stop clients for units that
	// lost it, restart clients whose options changed. The diff keys on
	// config identity only (interface, family, options) — never lease
	// state — so the DHCP lease-change callback re-entering applyConfig
	// (onDHCPAddressChange) cannot restart clients in a loop. Runs after
	// the dataplane compile (step 2) so HOST_INBOUND_DHCP flags are
	// active before a newly started client puts DHCP packets on the wire.
	d.reconcileDHCPClients(cfg)
	return ipsecErr, dhcpServerErr
}

// applyRoutingRules applies the routing-rules layer during a config apply:
// the FRR config (static + dynamic protocols, best-effort — the error is
// consumed only by the async reconciler), next-table policy-routing rules,
// rib-group route-leaking rules, and firewall-filter policy-based routing (PBR)
// rules. Extracted verbatim from applyConfigLocked (#4407); all steps are
// idempotent ip-rule/FRR reconciles that log-and-continue, so the block has no
// early return. commitOverlay is the ip-monitoring route overlay folded into
// the FRR assembly. Runs in the same slot, after the dataplane apply / RETH-MAC
// sequence and before proactive neighbor resolution.
func (d *Daemon) applyRoutingRules(cfg *config.Config, commitOverlay []config.RouteOverlayEntry) error {
	// #5844: the kernel policy-routing (ip rule) reconciles below —
	// next-table, rib-group, and PBR/filter-based-forwarding — each already
	// RETURN a fail-closed error: a partial clear/add leaves stale-or-missing
	// cross-VRF policy in the kernel, and the immediately-following userspace
	// route snapshot (reconcileRouteLeakSnapshot) canonizes that partial live
	// kernel state. The pre-#5844 call site LOGGED and DROPPED those returns, so
	// a commit was acknowledged after a partial reconcile. Collect them here and
	// return the joined error to applyConfigLocked, which threads it into the
	// tail commit-error join. Fail-closed BUT complete: a single rule-type
	// failure does NOT skip the others — every rule type runs, then the joined
	// error surfaces (mirroring the #5310 ifaceErr / #5696 routeLeakErr pattern).
	var routingErrs []error

	// 3. Apply all routes + dynamic protocols via FRR.
	// assembleFRRConfig is the SOLE frr.FullConfig constructor, shared
	// with the ip-monitoring routes-only actuator (#1827) — the full
	// apply consumes the same (config-filtered) overlay computed in
	// step 1.95, so an operator commit while a policy is FAILED
	// preserves a still-valid injected failover route and drops
	// removed/edited entries on the commit itself.
	if d.frr != nil {
		// The full apply path deliberately warns-and-continues on an FRR
		// reload error (a transient FRR hiccup must not fail an
		// otherwise-valid operator commit; the in-manager degraded-retry
		// loop reconverges FRR without waiting for a restart).
		// applyFRRConfig returns nil on a DEGRADED reload (#1880, the new
		// routes are already live); a non-nil return is a HARD reload
		// failure where NOTHING was applied. We do not fail the commit on
		// it, but we no longer discard it silently (#5109): the frr
		// manager has marked the generation degraded and armed its retry
		// debt (surfaced via the ReloadDegraded() health gauge), so log it
		// and continue rather than reporting an unqualified success.
		if err := d.applyFRRConfig(d.assembleFRRConfig(cfg, commitOverlay)); err != nil {
			slog.Warn("FRR full apply hit a hard reload failure; commit continues, frr manager armed degraded retry debt",
				"err", err)
		}
	}

	// 3b. Apply next-table policy routing rules (ip rule)
	if d.routing != nil {
		// Collect all static routes from main + per-rib. Build the combined
		// list in a fresh slice — appending Inet6StaticRoutes onto
		// cfg.RoutingOptions.StaticRoutes directly would write into that
		// slice's backing array when it has spare capacity (cap > len),
		// mutating the shared active-config object other goroutines read
		// concurrently (same hazard fixed in collectNeighborProbeTargets,
		// fbd159e55 / #1781 r1).
		allRoutes := make([]*config.StaticRoute, 0,
			len(cfg.RoutingOptions.StaticRoutes)+len(cfg.RoutingOptions.Inet6StaticRoutes))
		allRoutes = append(allRoutes, cfg.RoutingOptions.StaticRoutes...)
		allRoutes = append(allRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
		// #9420: scope the leak rules to the ingress interfaces of the instance
		// that authored them. allRoutes above is the DEFAULT instance's
		// routing-options statics, so the scoping set is every configured
		// interface unit not claimed by a routing instance. Without it the
		// pref-100 rule sits ahead of the kernel l3mdev rule (1000) and steers a
		// packet ingressing ANY other VRF into the target instance's table.
		ingressIfaces := routing.DefaultInstanceIngressIfaces(cfg)
		if err := d.routing.ApplyNextTableRules(allRoutes, cfg.RoutingInstances, ingressIfaces); err != nil {
			slog.Warn("failed to apply next-table rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply next-table rules: %w", err))
		}
	}

	// 3c. Apply rib-group route leaking rules (ip rule). #3876: the leak is
	// now per connected prefix (`ip rule to <prefix> lookup <sourceTable>`
	// BEFORE main) so an imported interface route wins over a main-table
	// default route. The connected prefixes are derived from the config
	// addresses on each source instance's member interface units, using the
	// same derivation the userspace FIB uses for connected routes.
	//
	// #5642: the reconcile runs UNCONDITIONALLY (no `len(RibGroups) > 0`
	// gate). ribGroupManager.Apply calls clear() BEFORE its own empty-desired
	// early return, so an EMPTY rib-group set — the transition that removes
	// the FINAL rib-group — still deletes the previously-installed synthetic
	// `ip rule to <prefix> lookup <sourceTable>` leak rules. The old gate
	// skipped the whole block on that zero-transition, so the stale Linux
	// ip-rule (and, because buildRouteSnapshots derives the userspace
	// NextTable leak from the live ip-rule table, the stale userspace FIB
	// entry) kept routing a deleted-VRF prefix into its table indefinitely — a
	// route-leak that kernel-forwarded / local / route-based-IPsec plaintext
	// could follow. A config that never had a rib-group finds no rule in the
	// scanned bands, so clear() issues no RuleDel (no churn); a steady-state
	// non-empty commit reconciles the exact same set as before.
	if d.routing != nil {
		connectedPrefixes := config.RibGroupConnectedPrefixes(cfg)
		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances, connectedPrefixes); err != nil {
			slog.Warn("failed to apply rib-group rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply rib-group rules: %w", err))
		}
	}

	// 3d. Apply policy-based routing rules (ip rule) for firewall filter
	// routing-instance (filter-based forwarding). Rules are derived only from
	// filters attached as an interface input filter (#3430 H1); a degraded
	// build — an unrepresentable except set, a DSCP-0 match, an
	// ip-rule-unrepresentable L4/per-packet predicate (port-except / tcp-flags /
	// icmp / is-fragment / flex, #3730), or an overflow — is surfaced but does
	// not block the rest of the apply. The degraded term is DROPPED (fail-safe
	// under-steer to the main table), never widened to an address-only over-steer.
	if d.routing != nil {
		pbrRules, buildErr := routing.BuildPBRRules(cfg)
		if buildErr != nil {
			// #5844: buildErr is DELIBERATELY not joined into the commit-error.
			// It is a fail-SAFE representability degradation, not a partial
			// kernel mutation. The kernel ip rule (BuildPBRRules) is only a
			// MIRROR of the userspace FBF steer for SLOW-PATH (XDP_PASS) packets
			// (rules.go: "the kernel also honors PBR for XDP_PASS'd packets, e.g.
			// SNAT'd traffic destined for a VRF/GRE tunnel"). The AUTHORITATIVE
			// fast-path enforcement of a `then routing-instance` term — with the
			// FULL L4 match the kernel ip rule cannot express (port-except /
			// tcp-flags / icmp / is-fragment / flex) — is the userspace filter
			// engine: buildFilterTermSnapshots carries term.RoutingInstance +
			// the full match into the FirewallTermSnapshot
			// (pkg/dataplane/userspace/filters.go), and the Rust evaluator sets
			// acc.routing_instance = term.routing_instance on a full-term match
			// (userspace-dp/src/filter/engine/eval.rs
			// evaluate_interface_filter_routing_instance_*). So a term that
			// cannot be mirrored to an ip rule is DROPPED from the kernel mirror
			// only; on the fast path it is still steered, and a slow-path packet
			// UNDER-steers to the main table (the fail-safe direction — never an
			// address-only OVER-steer / cross-VRF leak, rules.go BuildPBRRules).
			// The degradation is already observable (this WARN + the #4422
			// PBRBuildStats degraded gauge), not silent. ApplyPBRRules(pbrRules)
			// below fully reconciles whatever WAS built (deleting any stale
			// rule), so no stale-or-missing cross-VRF policy survives in the
			// mirror — the #5844 bug class is the netlink RuleAdd/RuleDel failure
			// below, not this representability drop. Fail-closing on buildErr
			// would instead REJECT configs with such terms that commit fine
			// today AND are enforced on the fast path, so it stays a
			// warn-and-continue.
			slog.Warn("PBR rule build degraded; some routing-instance filter terms "+
				"are not mirrored to the kernel FBF path and fall back to the main "+
				"table (userspace filter path still enforces them)", "err", buildErr)
		}
		// ApplyPBRRules IS a kernel reconcile: a failed clear/add leaves a
		// half-installed FBF policy in the kernel ip-rule table, so its error is
		// joined into the commit-error (fail-closed).
		if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
			slog.Warn("failed to apply PBR rules", "err", err)
			routingErrs = append(routingErrs, fmt.Errorf("apply PBR rules: %w", err))
		}
	}

	// Fail-closed but COMPLETE: every rule type above ran regardless of an
	// earlier failure; surface the joined error so a partial ip-rule reconcile
	// fails the commit instead of being silently acknowledged (#5844).
	return errors.Join(routingErrs...)
}

// reconcileRouteLeakSnapshot republishes the userspace route snapshot after
// applyRoutingRules has reconciled the kernel policy-routing (ip rule) table
// (#5642). The full dataplane apply (applyDataplaneAndHACore → the dataplane's ApplyConfig)
// runs BEFORE applyRoutingRules and derives its route snapshot from the LIVE
// kernel ip-rules (buildRouteSnapshots → netlink.RuleList). On an inter-VRF
// route-leak transition — most importantly the final-rib-group removal that
// takes RoutingOptions.RibGroups to zero — applyRoutingRules has just deleted
// (or added) the synthetic `ip rule to <prefix> lookup <table>` leak rule, so
// the snapshot ApplyConfig already published still mirrors the PRE-reconcile
// rule table and keeps (or omits) a NextTable leak that no longer matches the
// kernel. Without this reconcile a removed rib-group's deleted-VRF leak would
// survive in the userspace FIB indefinitely (until some later apply happened to
// rebuild it).
//
// This reuses the ip-monitoring routes-only publish surface — no Compile, no
// helper restart — rebuilding buildRouteSnapshots against the now-reconciled
// kernel rules and, only when the content actually changed, publishing the
// leak-free FIB and bumping the FIB generation so established flows re-resolve.
// PublishRouteOverlaySnapshot duplicate-skips an unchanged route set (returns
// published=false), so a steady-state commit and a config that never carried a
// rib-group publish nothing and churn nothing. A nil scheduler-state argument
// keeps the manager's current policy-scheduler view (the one the full apply just
// published) so the unchanged-content hash matches and the skip fires.
//
// #5696 (M19, a #5642 residual): a genuine route-publication or FIB-invalidation
// failure returns a DEFERRED error the caller joins into the tail commit-error
// (fail-closed but complete). This commit-tail reconcile has no dirty-retry
// engine, so swallowing the failure would leave the userspace FIB with a stale
// inter-VRF leak — the exact bug #5642 fixed — while reporting a successful
// commit. Benign no-ops (helperless, duplicate-skip) return nil.
func (d *Daemon) reconcileRouteLeakSnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry) error {
	if cfg == nil {
		return nil
	}
	pub, ok := d.dataplane().(routeOverlayPublisher)
	if !ok {
		// Helperless (no userspace dataplane publisher): the kernel ip-rule
		// reconcile above is the only route-leak consumer and it already ran.
		return nil
	}
	published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil {
		// #5696 (M19): surface the publish failure as a deferred commit error
		// instead of swallowing it. This commit-tail reconcile has no dirty-retry
		// engine (unlike the ip-monitoring actuator), so a swallowed failure would
		// silently reinstate the exact stale inter-VRF leak #5642 removed while the
		// commit reports success. The caller joins this into the tail errors.Join
		// so the commit fails CLOSED — the OLD pre-reconcile snapshot stays live
		// and a re-commit re-runs the reconcile (#5679/#5310 fail-closed pattern).
		slog.Warn("route-leak snapshot reconcile: routes-only republish failed; the "+
			"userspace FIB may retain a stale inter-VRF leak until the next apply",
			"err", err)
		return fmt.Errorf("route-leak snapshot republish: %w", err)
	}
	if !published {
		// Duplicate-skip (route set unchanged) or no published snapshot yet /
		// helper not running: nothing moved, so do not bump the FIB generation
		// (would needlessly churn established-flow route caches). Benign no-op —
		// stays a successful commit.
		return nil
	}
	// Ordering (mirrors the ip-monitoring actuator, #1827 AGY r2-1): bump the
	// FIB generation ONLY after a real publish so established flows re-resolve
	// onto the reconciled routes; bumping before/without a publish would leave
	// flows pinned to the stale leak route.
	if _, err := pub.BumpFIBGeneration(); err != nil {
		// #5696 (M19): the leak-free routes ARE on the wire (publish succeeded),
		// but the FIB generation was not bumped — established flows stay pinned to
		// the stale leak route. With no retry owner for this commit-tail path a
		// swallowed bump leaves that inconsistency unrediscovered; fail the commit
		// closed so a re-commit re-runs the reconcile.
		slog.Warn("route-leak snapshot reconcile: FIB generation bump unconfirmed after "+
			"republish; established flows may re-resolve on a later sweep", "err", err)
		return fmt.Errorf("route-leak snapshot FIB generation bump: %w", err)
	}
	return nil
}
