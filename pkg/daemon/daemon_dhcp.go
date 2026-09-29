// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

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
						Stateless:  unit.DHCPv6Client.ClientType == "stateless",
						IATypes:    unit.DHCPv6Client.ClientIATypes,
						PDPrefLen:  unit.DHCPv6Client.PrefixDelegatingPrefixLen,
						PDSubLen:   unit.DHCPv6Client.PrefixDelegatingSubPrefLen,
						ReqOptions: unit.DHCPv6Client.ReqOptions,
						RAIface:    unit.DHCPv6Client.UpdateRAInterface,
					}
				}
				specs = append(specs, spec)
			}
		}
	}
	return specs
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
			slog.Info("DHCP address changed on management-only interface, refreshing management routes")
			// #5867: no commit to fail on this DHCP-callback path (it is a
			// lease-change refresh, not a config commit) — a RouteReplace /
			// cleanup failure is logged. The stale-route cleanup still applies
			// (the reconcile removes any route left unapplied).
			if err := d.applyMgmtVRFRoutes(); err != nil {
				slog.Warn("mgmt VRF routes: refresh on DHCP lease change had errors", "err", err)
			}
			// #1715 (fw0 class): a management-only interface (e.g.
			// fxp0 DHCPv4) takes this branch and does NOT recompile,
			// so DNS would never reconcile without this call. Route
			// the DHCP-learned DNS through the locked reconciler so
			// the box always picks up DHCP nameservers, not just on
			// dataplane-relevant interfaces.
			d.reconcileDNSFromDHCP()
			// #2884: the full recompile is skipped on this branch, so an
			// IPsec gateway that binds local_addrs to a management-only
			// DHCP interface would otherwise keep the stale lease address
			// after a renew. The dataplane-facing branch above already
			// re-renders IPsec via applyConfig (step 6); this closes the
			// management-only gap so swanctl re-binds to the new IP.
			d.reapplyIPsecForLeaseChange(activeCfg)
		}
	}
}

// reapplyIPsecForLeaseChange re-renders + reloads swanctl when a DHCP
// lease change may have moved the kernel address an IPsec gateway is
// dynamically bound to (#2884). It is called from onDHCPAddressChange's
// management-only branch, which skips the full recompile; the
// dataplane-facing branch already re-renders IPsec through applyConfig.
//
// The re-render is scoped to lease-dependent gateways
// (ipsec.HasDHCPBoundGateway): a lease refresh on a management interface
// no IPsec gateway uses is a no-op, so an unrelated renew never churns
// swanctl or resets live SAs. It runs under applySem to serialize with a
// concurrent commit's IPsec apply (both write the same swanctl conf).
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
func (d *Daemon) reapplyIPsecForLeaseChange(cfg *config.Config) {
	if d.ipsec == nil || cfg == nil {
		return
	}
	if !ipsec.HasDHCPBoundGateway(cfg) {
		return
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		slog.Warn("IPsec: failed to acquire apply lock for DHCP lease re-render", "err", err)
		return
	}
	defer d.applySem.Release(1)
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
// "reth0.0" or "ge-0/0/0.0"), or 0 when the interface is not RG-owned (#2456).
// It mirrors rgForInterfaces (#2664): strip the unit suffix, then look up the
// base interface in the config table and read its RedundancyGroup. A nil config
// or unknown interface yields 0 (non-HA → always relay at the caller).
func relayInterfaceRG(cfg *config.Config, ifaceName string) int {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return 0
	}
	base := ifaceName
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil {
		if ifc.RedundancyGroup > 0 {
			return ifc.RedundancyGroup
		}
	}
	return 0
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
	rg := relayInterfaceRG(d.store.ActiveConfig(), ifaceName)
	if rg == 0 {
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
