// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/ipsec"
)

// buildDHCPClientSpecs computes the desired DHCP client set from the
// config: one spec per unit with family inet { dhcp; } or family inet6
// { dhcpv6; }. Specs carry config identity only (interface, family,
// client options) — never lease or address state — so the reconcile
// diff is stable across lease changes (#1793, plan §5.4).
func buildDHCPClientSpecs(cfg *config.Config) []dhcp.ClientSpec {
	var specs []dhcp.ClientSpec
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			// Shared lease-key derivation (#1844): the same helper the
			// ip-monitoring compiler uses for interface-typed next-hops,
			// so the two derivations can never drift.
			dhcpIface := config.DHCPLeaseIfName(ifName, unit)
			if unit.DHCP {
				spec := dhcp.ClientSpec{Iface: dhcpIface, Family: dhcp.AFInet}
				if unit.DHCPOptions != nil {
					spec.V4 = &dhcp.DHCPv4Options{
						LeaseTime:              unit.DHCPOptions.LeaseTime,
						RetransmissionAttempt:  unit.DHCPOptions.RetransmissionAttempt,
						RetransmissionInterval: unit.DHCPOptions.RetransmissionInterval,
						ForceDiscover:          unit.DHCPOptions.ForceDiscover,
					}
				}
				specs = append(specs, spec)
			}
			if unit.DHCPv6 {
				spec := dhcp.ClientSpec{
					Iface:    dhcpIface,
					Family:   dhcp.AFInet6,
					DUIDType: "duid-ll", // default
				}
				if unit.DHCPv6Client != nil {
					if unit.DHCPv6Client.DUIDType != "" {
						spec.DUIDType = unit.DHCPv6Client.DUIDType
					}
					spec.V6 = &dhcp.DHCPv6Options{
						Stateless:      unit.DHCPv6Client.ClientType == "stateless",
						IATypes:        unit.DHCPv6Client.ClientIATypes,
						PDPrefLen:      unit.DHCPv6Client.PrefixDelegatingPrefixLen,
						PDSubLen:       unit.DHCPv6Client.PrefixDelegatingSubPrefLen,
						ReqOptions:     unit.DHCPv6Client.ReqOptions,
						RAIface:        unit.DHCPv6Client.UpdateRAInterface,
						PinnedPrefixes: append([]string(nil), unit.DHCPv6Client.PinnedPrefixes...),
					}
				}
				specs = append(specs, spec)
			}
		}
	}
	return specs
}

// mgmtRouteRefreshFn is the management-VRF route reconcile driven on the
// management-only lease-refresh path under applySem (#14976). A package var
// (like mgmtVRFRouteReconcileFn / webMgmtRebindApply) so a test can observe
// WHETHER the serialized refresh drove the route reconcile without opening
// netlink. Production code must never mutate it.
var mgmtRouteRefreshFn = func(d *Daemon) error {
	return d.applyMgmtVRFRoutes()
}

// onDHCPAddressChange is the (debounced) lease-change callback for the
// DHCP manager. It re-enters applyConfig, which is why the client
// reconcile must key on config identity only — see reconcileDHCPClients.
func (d *Daemon) onDHCPAddressChange() {
	// #2691 P2: a DHCP-learned address change on a WAN interface is the prime
	// Surface A republish trigger (the #1844 hook fires this). Nudge the
	// Surface A loop so a new lease address is republished within one pass
	// (the engine's change-detection then decides whether a wire UPDATE fires).
	d.nudgeSurfaceADDNSReconcile()
	// Full recompile is safe: heartbeat sockets survive VRF rebind
	// (RestartHeartbeat), RETH MAC is set live (no XSK rebind), and
	// BPF compile skips reconcile when the binding plan is unchanged.
	if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
		// #9239: record whether a PD-for-RA existed BEFORE this pass and hand the
		// previous value to the predicate. commitLease has already removed a
		// withdrawn prefix by the time this callback runs, so the predicate's own
		// `len(...) > 0` cannot tell a final withdrawal from a box that never had
		// one. This is the only writer, and it runs once per lease-change event.
		hadPDForRA := d.pdForRAPresent.Swap(
			d.dhcp != nil && len(d.dhcp.DelegatedPrefixesForRA()) > 0)
		if d.dhcpLeaseChangeRequiresRecompile(activeCfg, hadPDForRA) {
			slog.Info("DHCP address changed, recompiling dataplane")
			// applyActiveConfig runs reconcileDNSLocked, so DNS is
			// reconciled with the new lease set on this path.
			//
			// #6716: it re-reads the active config under applySem instead of
			// applying activeCfg, which was captured BEFORE the semaphore wait.
			// A commit landing during that wait was otherwise reverted by this
			// callback. activeCfg above still drives the recompile DECISION —
			// that only chooses how much work to do, and choosing "full apply"
			// from a slightly stale read is safe because the apply itself now
			// reconciles whatever is current.
			if d.preApplyHookForTest != nil {
				d.preApplyHookForTest()
			}
			d.applyActiveConfig()
		} else {
			// #14976: managementOnlyLeaseRefresh holds applySem across
			// the management-route reconcile and the gated IPsec /
			// web-management rebinds, reading the fresh active config
			// AFTER acquiring it (#6716 discipline).
			d.managementOnlyLeaseRefresh()

		}
	}
}

// onDHCPUnchangedLease is the #11497 escape hatch for a content-identical
// T1/T2 renewal. Healthy renewals stay silent for the full-recompile path;
// while a double nft failure is owed, the lease commit nudges the 30s
// host-inbound gap retry owner to re-drive the active config promptly
// instead of waiting for its next tick.
//
// #16773: a content-identical PD renewal is NOT silent for RA. Since
// #15057 the RA desired set carries the ABSOLUTE expiry (Obtained+granted),
// and a fixed-lifetime renewal moves Obtained — so the applied RA config
// must be refreshed with the renewed ValidExpiresAt even though
// leaseContentChanged/delegatedPrefixesChanged stay false. The nudge below
// wakes the RA-scoped renew loop, whose digest-gated reconcile re-applies
// ONLY when the expiry actually moved (a v4 or non-PD v6 renewal leaves
// the digest unchanged and costs one buildRAConfigs). This must NOT trigger
// a full recompile (#1777) and must NOT apply inline (#16559, below).
//
// #16559: this MUST NOT apply inline. It runs on the DHCP client goroutine
// (commitLease -> notifyLeaseStateChanged), and applyActiveConfig may park
// on applySem during normal operation. Shutdown cancellation does not
// prevent the live-apply re-entrancy cycle: if the apply holding applySem
// reaches reconcileDHCPClients and stops/restarts this client, Reconcile
// waits on its done channel — which can never close while this goroutine is
// parked — so applySem never releases and every later commit, rollback,
// sync and background apply hangs until restart. The non-blocking nudge
// keeps the client goroutine free; the retry loop owns the apply.
func (d *Daemon) onDHCPUnchangedLease() {
	if d.hostInboundGapOwed() {
		d.nudgeHostInboundGapReassert()
	}
	d.nudgeStandaloneRARenew()
}

// nudgeStandaloneRARenew requests a prompt standalone RA renew reconcile
// (#16773). Non-blocking depth-1 send that coalesces a burst, for the same
// #16559 client-goroutine reason as nudgeHostInboundGapReassert. Safe
// before the loop starts and on a nil channel (a Daemon built without New).
func (d *Daemon) nudgeStandaloneRARenew() {
	if d.raRenewWakeCh == nil {
		return
	}
	select {
	case d.raRenewWakeCh <- struct{}{}:
	default:
	}
}

// managementOnlyLeaseRefresh drives the management-only lease-change work
// that does not need a full recompile (#14976): the management-VRF route
// reconcile, the DNS reconcile, and the gated IPsec / web-management
// rebinds. It holds ONE applySem acquisition across the route reconcile,
// the fresh-snapshot re-read, and both gated rebinds, so a commit landing
// while this path waits is never reverted by a pre-wait snapshot: the
// rebind gates and applies see the config active AFTER acquiring, not the
// one onDHCPAddressChange read to choose the branch. Pre-fix the route
// reconcile ran with no semaphore and both rebinds received the pre-wait
// snapshot (their own per-call acquisitions did not help — the gate was
// already fixed by then). DNS keeps its own acquisition in
// reconcileDNSFromDHCP (nested semaphore takes deadlock), so it runs
// after this hold is released; DNS merges the live lease set rather than
// the gated-rebind snapshot, so the ordering is immaterial there.
// Callers MUST hold no applySem.
func (d *Daemon) managementOnlyLeaseRefresh() {
	if d.applySem == nil {
		return
	}
	if err := d.acquireBackgroundApplySem(); err != nil {
		slog.Warn("mgmt VRF routes: failed to acquire apply lock for DHCP lease refresh", "err", err)
		return
	}
	func() {
		defer d.applySem.Release(1)
		// #5867: no commit to fail on this DHCP-callback path (it is a
		// lease-change refresh, not a config commit). #11450 latches a
		// failure into management-route debt for the 30s retry owner.
		if err := mgmtRouteRefreshFn(d); err != nil {
			d.noteMgmtRouteReconcileResult(err)
			slog.Warn("mgmt VRF routes: refresh on DHCP lease change had errors", "err", err)
		} else {
			d.noteMgmtRouteReconcileResult(nil)
		}
		if d.store == nil {
			return
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			return
		}
		d.reapplyIPsecLocked(cfg)
		// #14582: same management-only gap for web-management. A
		// lifeline (e.g. fxp0) lease change to a new address does not
		// recompile, so a `web-management https interface fxp0` leg
		// would otherwise keep the stale lease address (or the
		// loopback fallback) until a later commit.
		d.rebindWebMgmtLocked(cfg)
	}()
	// #1715 (fw0 class): a management-only interface (e.g. fxp0 DHCPv4)
	// takes this branch and does NOT recompile, so DNS would never
	// reconcile without this call. Route the DHCP-learned DNS through
	// the locked reconciler so the box always picks up DHCP
	// nameservers, not just on dataplane-relevant interfaces.
	// reconcileDNSFromDHCP acquires applySem itself, so it runs outside
	// the hold above (nested semaphore takes deadlock).
	d.reconcileDNSFromDHCP()
}

// reapplyIPsecLocked re-renders + reloads swanctl when a DHCP lease
// change may have moved the kernel address an IPsec gateway is
// dynamically bound to (#2884). It is driven by
// managementOnlyLeaseRefresh, the management-only branch of
// onDHCPAddressChange, which skips the full recompile; the
// dataplane-facing branch already re-renders IPsec through applyConfig.
//
// The re-render is scoped to lease-dependent gateways
// (ipsec.HasDHCPBoundGateway): a lease refresh on a management interface
// no IPsec gateway uses is a no-op, so an unrelated renew never churns
// swanctl or resets live SAs.
//
// #4899: the swanctl reload is NO LONGER best-effort-and-forgotten. On
// failure strongSwan keeps binding the stale lease address and the tunnel
// cannot re-establish, so the failure is made both RECOVERABLE — a
// single-flight retry loop (ipsecRebindRetryLoop, see
// daemon_ipsec_rebind.go) re-attempts the reapply until it converges —
// and VISIBLE — the ipsecRebindPending health signal backs the
// xpf_ipsec_rebind_pending gauge while local_addrs are stale. The lease
// callback itself stays NON-FATAL: the retry + gauge ARE the recovery, so
// a failed rebind never blocks or fails DHCP lease processing.
//
// The caller MUST hold applySem. The gate lives here (not in the caller)
// so the management-only path's gate is evaluated against the fresh
// snapshot read under the semaphore (#14976).
func (d *Daemon) reapplyIPsecLocked(cfg *config.Config) {
	if d.ipsec == nil || cfg == nil {
		return
	}
	if !ipsec.HasDHCPBoundGateway(cfg) {
		return
	}
	slog.Info("DHCP address changed on IPsec-bound interface, re-rendering swanctl local_addrs")
	if err := d.ipsecApplyForLeaseChange(cfg); err != nil {
		slog.Warn("failed to re-apply IPsec config after DHCP address change; "+
			"local_addrs may be stale until the rebind retry converges", "err", err)
		// Set the health signal and arm the single-flight retry loop. The
		// arm/apply state transition runs while applySem is still held (via
		// the deferred Release), so it is atomic with this Apply attempt and
		// cannot race a concurrent retry-loop attempt (which also holds
		// applySem across its own apply+record).
		d.armIPsecRebind()
		return
	}
	// Success: clear any prior pending state (a no-op on the common healthy
	// path, where nothing was pending and nothing is logged).
	d.clearIPsecRebindPending()
}

// webMgmtRebindApply is the reconcile seam for the #14582 lease-change
// rebind, a package var (like mgmtReassertApply) so a test can observe
// WHETHER the rebind was driven. Production code must never mutate it.
var webMgmtRebindApply = func(d *Daemon, cfg *config.Config) error {
	return d.reconcileWebManagement(cfg)
}

// webMgmtBindsToDHCPInterface reports whether any web-management HTTP/HTTPS
// leg is bound (via resolveAPIBinds' interface resolution) to an interface
// that has a DHCP/DHCPv6 unit in cfg. It gates the lease-change rebind so
// an unrelated renew never churns the management listener (#14582, mirroring
// ipsec.HasDHCPBoundGateway's gating for #2884).
func webMgmtBindsToDHCPInterface(cfg *config.Config) bool {
	if cfg == nil || cfg.System.Services == nil || cfg.System.Services.WebManagement == nil {
		return false
	}
	wm := cfg.System.Services.WebManagement
	for _, ref := range []string{wm.HTTPInterface, wm.HTTPSInterface} {
		if ref == "" {
			continue
		}
		if interfaceRefHasDHCPUnit(cfg, ref) {
			return true
		}
	}
	return false
}

// interfaceRefHasDHCPUnit reports whether the authored Junos ref (e.g.
// "fxp0.0" or "ge-0/0/0.0") names a unit with dhcp/dhcpv6 enabled. A bare
// interface ref matches any unit of that interface. Mirrors
// ipsec.interfaceRefIsDHCP's base/unit parsing (SplitInterfaceUnitRef) so
// the two derivations cannot drift on unit handling.
func interfaceRefHasDHCPUnit(cfg *config.Config, ref string) bool {
	split := cfg.SplitInterfaceUnitRef(ref)
	ifc, ok := cfg.Interfaces.Interfaces[split.Base]
	if !ok || ifc == nil {
		return false
	}
	if !split.HasUnit {
		for _, u := range ifc.Units {
			if u != nil && (u.DHCP || u.DHCPv6) {
				return true
			}
		}
		return false
	}
	unit, err := strconv.Atoi(split.UnitTok)
	if err != nil {
		return false
	}
	u := ifc.Units[unit]
	return u != nil && (u.DHCP || u.DHCPv6)
}

// rebindWebMgmtLocked re-resolves the web-management bind after a
// DHCP lease change on the management-only fast path (#14582). It is
// driven by managementOnlyLeaseRefresh. It mirrors reapplyIPsecLocked:
// gated on the bound interface actually being DHCP-managed, and
// non-fatal — a failed rebind keeps the previous listener (fail-safe in
// reconcileTo) and the degraded state keeps the 30s re-assert owner
// re-driving until it converges.
//
// The caller MUST hold applySem. The gate lives here so the
// management-only path evaluates it against the fresh snapshot read
// under the semaphore (#14976).
func (d *Daemon) rebindWebMgmtLocked(cfg *config.Config) {
	if cfg == nil || d.mgmt.Load() == nil {
		return
	}
	if !webMgmtBindsToDHCPInterface(cfg) {
		return
	}
	slog.Info("DHCP address changed on web-management interface, re-resolving management bind")
	if err := webMgmtRebindApply(d, cfg); err != nil {
		slog.Warn("failed to re-resolve web-management bind after DHCP address change; will retry via re-assert owner", "err", err)
	}
}

// reconcileDHCPClients converges running DHCP/DHCPv6 clients with the
// given config (#1793): newly enabled units get a client, units whose
// dhcp/dhcpv6 stanza was deleted get their client stopped (stop renewing
// + remove the leased address; no protocol RELEASE), and option changes
// restart the affected client. Called from applyConfigLocked on every
// apply, so commit-time enable/disable behaves like Junos instead of
// boot-time-only. The DHCP manager is created eagerly in Run (#1844,
// AGY plan r2-1) — d.dhcp is write-once at boot, so there is no
// lazy-create branch here and no pointer race against the bare reads
// in the ipmon resolver and the CLI/gRPC handlers.
func (d *Daemon) reconcileDHCPClients(cfg *config.Config) {
	if d.opts.NoDataplane || d.dhcp == nil {
		return
	}
	// #10856: keep the IA_PD overlap set current BEFORE the reconcile so a
	// client (re)started by this apply immediately decodes replies against
	// the new configuration. Deliberately not part of the client
	// fingerprint: a configured-prefix change must not restart clients or
	// drop leases — renewals re-validate, and the RA sink refuses overlaps
	// at emission time.
	d.dhcp.SetProtectedIPv6Prefixes(config.ConfiguredIPv6Prefixes(cfg))
	// #14728: v4 analogue — keep the DHCPv4 protected set current on the
	// same apply, before reconcile, with the same non-fingerprint rule.
	d.dhcp.SetProtectedIPv4Prefixes(config.ConfiguredIPv4Prefixes(cfg))
	// #16566: re-adopt persisted leases before the first client start so
	// this apply's FRR/DNS/RA rendering (which precedes or contends with
	// the Reconcile below) sees the pre-restart lease. Idempotent:
	// adoption installs each lease once and later applies find it live.
	d.dhcp.AdoptPersistedLeases(buildDHCPClientSpecs(cfg))
	specs := buildDHCPClientSpecs(cfg)
	if len(specs) == 0 {
		// Reconcile(nil) stops any running clients; with none running
		// it is a no-op.
		d.dhcp.Reconcile(nil)
		return
	}
	d.dhcp.Reconcile(specs)
}

// resolveDHCPNextHop is the ipmon NextHopResolver (#1844): it maps an
// interface-typed preferred-route lease key
// (PreferredRoute.NextHopInterface, derived via config.DHCPLeaseIfName)
// to the unit's current DHCPv4-learned gateway. ok=false — no DHCP
// manager (NoDataplane), no lease yet, or a lease without a router
// option — makes the engine skip the candidate BEFORE winner
// selection. Called under Engine.mu; LeaseFor takes dhcp.Manager.mu
// briefly (the one-way Engine.mu → dhcp.mu lock order) and never calls
// back into the engine.
func (d *Daemon) resolveDHCPNextHop(leaseIface string) (string, bool) {
	dm := d.dhcp // write-once at boot (Run), safe to read bare
	if dm == nil {
		return "", false
	}
	lease := dm.LeaseFor(leaseIface, dhcp.AFInet)
	if lease == nil || !lease.Gateway.IsValid() || lease.Gateway.IsUnspecified() {
		return "", false
	}
	return lease.Gateway.String(), true
}

// hadPDForRA is whether the PREVIOUS pass saw a delegated prefix mapped to an
// RA interface (#9239). It is a parameter rather than a field read so this
// predicate stays pure: the state transition is recorded by the single caller
// that owns the event.
func (d *Daemon) dhcpLeaseChangeRequiresRecompile(cfg *config.Config, hadPDForRA bool) bool {
	if cfg == nil {
		return false
	}
	// Prefix delegation can affect downstream addressing/RA and still needs
	// a full re-apply.
	if d.dhcp != nil && len(d.dhcp.DelegatedPrefixesForRA()) > 0 {
		return true
	}
	// #9239: ...and so does LOSING the last one. The withdrawal is the event
	// that most needs RA re-applied, because in standalone mode this full-apply
	// path is the ONLY RA applier -- reconcileClusterRAServices is explicitly a
	// no-op off-cluster, and the 30s sender loop retries only DEAD senders, not
	// live ones holding stale desired state. Without this the sender keeps
	// refreshing a prefix upstream has withdrawn until an unrelated apply or a
	// restart, while downstream hosts keep autoconfiguring from it.
	//
	// ra.Manager.Apply with an empty set is already the graceful path: it
	// removes the sender and emits a router-lifetime-zero goodbye so the last
	// PIO ages out. The defect was never reaching it.
	if hadPDForRA {
		return true
	}
	// If management VRF bindings are unavailable, stay conservative. Read a
	// single lock-free snapshot (#5113) so the whole classification runs
	// against one consistent map, never a torn/nil-transient publication.
	// (This is a "before-first-apply / VRF-create-failed" liveness guard, not
	// the host-inbound classification below.)
	mgmtSet := d.mgmtVRFIfaceSet()
	if len(mgmtSet) == 0 {
		return true
	}
	// #5791: gate the "skip the full reapply" decision on the config-derived
	// host-inbound LIFELINE set — the SAME authority the host-inbound fence
	// application uses (config.HostInboundLifelineSet, see
	// pkg/dataplane/userspace/zones_host_inbound.go and pkg/daemon/daemon_nft.go)
	// — NOT the broad management-VRF name class (fxp*/fab*/em*). That class wrongly
	// exempted a zoned NON-lifeline fxp1: a standalone config has only fxp0 as a
	// fixed lifeline; cluster control/fabric interfaces count only when explicitly
	// configured. So a DHCP-only zoned fxp1 would start ADDRESSLESS, install no
	// address-scoped host-inbound drop, acquire an address, and then SKIP the reapply
	// that would build the fence for the newly reachable address (a host-inbound gap,
	// #3277). A lease change on a TRUE lifeline (fxp0 or a configured control/fabric
	// interface) still takes the lightweight management-only fast path;
	// only a non-lifeline DHCP interface now forces the recompile that (re)builds
	// its fence. Sharing HostInboundLifelineInterface with the fence keeps the
	// skip decision and the fence application in lockstep by construction, so a
	// future name can never drift the two apart. The base-name mapping
	// (fxp1.0 -> fxp1) is handled inside HostInboundLifelineInterface via
	// LifelineBaseName, exactly as the fence does it.
	lifelines := config.HostInboundLifelineSet(cfg)
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			if !config.HostInboundLifelineInterface(ifName, lifelines) {
				return true
			}
		}
	}
	return false
}

// resolveJunosIfName converts a Junos-style interface name to its Linux
// equivalent. It resolves RETH names to their physical members (e.g.
// reth0.50 → ge-0/0/0.50) and converts Junos slashes to dashes (e.g.
// ge-0/0/0 → ge-0-0-0).
//
// NOTE: Keep in sync with (*Config).ResolveKernelIfName in
// pkg/config/types.go. This helper only does the bare-ref subset of
// the public method; callers that already have unit/vlan context
// build the .VLAN suffix themselves (see resolveConfigSubnetLinuxName).
func resolveJunosIfName(cfg *config.Config, ifName string) string {
	return config.LinuxIfName(cfg.ResolveReth(ifName))
}

func resolveConfigSubnetLinuxName(cfg *config.Config, ip net.IP) (string, string, bool) {
	if cfg == nil || ip == nil {
		return "", "", false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, addrStr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addrStr)
				if err != nil {
					continue
				}
				if !ipNet.Contains(ip) {
					continue
				}
				ifName := resolveJunosIfName(cfg, ifc.Name)
				if unit.VlanID > 0 {
					ifName = fmt.Sprintf("%s.%d", ifName, unit.VlanID)
				} else if unitNum != 0 {
					ifName = fmt.Sprintf("%s.%d", ifName, unitNum)
				}
				return ifName, addrStr, true
			}
		}
	}
	return "", "", false
}

// relayInterfaceRG resolves the redundancy group that owns the DHCP-relay
// interface named ifaceName (the raw config form the relay carries, e.g.
// "reth0.0" or "ge-0/0/0.0"), or 0 when the interface is not RG-owned
// (#2456). It is the positive-group form of config.Config.InterfaceRefRG
// (#17086 SSOT). This package-level form builds a fresh RefRGIndex per
// call for tests and one-shot callers; the per-packet gate below uses
// the daemon's cached index instead. A nil config or unknown interface
// yields 0 (non-HA → always relay at the caller).
func relayInterfaceRG(cfg *config.Config, ifaceName string) int {
	if cfg == nil {
		return 0
	}
	if rg, owned := cfg.RefRGIndexFor().Lookup(ifaceName); owned && rg > 0 {
		return rg
	}
	return 0
}

// relayRefRGIndexFor returns the daemon's cached RefRGIndex for cfg,
// rebuilding it only when the config pointer changes (#17086). The
// relay gate reads it per packet, so the build must not be per packet:
// pointer identity is the invalidation key, the same idiom as
// lastDNSRefreshBase.
func (d *Daemon) relayRefRGIndexFor(cfg *config.Config) *config.RefRGIndex {
	d.relayRefRGIndexMu.Lock()
	defer d.relayRefRGIndexMu.Unlock()
	if d.relayRefRGBase != cfg || d.relayRefRGIndex == nil {
		d.relayRefRGIndex = cfg.RefRGIndexFor()
		d.relayRefRGBase = cfg
	}
	return d.relayRefRGIndex
}

// relayMasterGateOpen reports whether THIS node may relay client requests
// received on ifaceName right now (#2456). It is installed on the DHCP relay
// Manager via SetMasterGate and read PER PACKET, so it reflects live VRRP/
// cluster master state and a backup→master failover is followed immediately
// with no relay restart.
//
// Decision (mirrors the DDNS per-RG writer gate, ddnsReconcileOptions):
//   - Standalone (d.cluster == nil): always relay.
//   - Interface not RG-owned (RG 0): always relay — a non-HA segment is not a
//     duplicate-relay hazard.
//   - RG-owned: relay IFF this node is currently MASTER for that RG
//     (isRethMasterState reads the live rgStateMachine, the SAME source the
//     DHCP server / DDNS gates use).
//
// On a BACKUP node for the relay's RG the gate is CLOSED, so the relay drops
// the client broadcast instead of forwarding a duplicate upstream.
func (d *Daemon) relayMasterGateOpen(ifaceName string) bool {
	if d.cluster == nil {
		return true
	}
	cfg := d.store.ActiveConfig()
	rg, owned := d.relayRefRGIndexFor(cfg).Lookup(ifaceName)
	if !owned || rg == 0 {
		return true
	}
	return d.isRethMasterState(rg)
}

// stripCIDR removes the /prefix from a CIDR string, returning just the IP.
func stripCIDR(s string) string {
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		return s // not CIDR, return as-is
	}
	return ip.String()
}
