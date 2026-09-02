package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// defaultSynFloodAttackThreshold is the Junos SRX default attack-threshold
// (SYN segments per second) used when a syn-flood screen is enabled without an
// explicit attack-threshold. The config compiler seeds this at parse time; the
// buildScreenConfig gate also applies it defensively (#3024). MUST match
// pkg/config defaultSynFloodAttackThreshold.
const defaultSynFloodAttackThreshold = 200

// protectedInterfaceResolver returns the #1922 management protected set — the
// interfaces (fxp0, the lifeline NIC, an explicit `system
// management-interface` leaf) that the reconcile path must NEVER mark
// Unmanaged / always-down / address-strip, EVEN when the active config is
// empty, absent, or rolled back. The set is resolved by the DAEMON (PCI→name
// sysfs I/O lives there) and injected out-of-band so it is config-independent
// (invariant 3): the designation cannot be removed by the very rollback it
// protects. nil (the default, and in unit tests / non-daemon embedders) means
// "no extra protection beyond what the config carries" — preserving the
// pre-#1922 behavior exactly for every caller that does not set it.
var protectedInterfaceResolver func() map[string]bool

// SetProtectedInterfaceResolver registers the daemon's #1922 protected-set
// provider (Item 4). Called once at daemon startup. Passing nil restores the
// pre-#1922 (no extra protection) behavior. The resolver is invoked during
// compileZones' unmanaged-interface strip; it must be cheap and side-effect
// free (it reads sysfs / the lifeline record).
func SetProtectedInterfaceResolver(fn func() map[string]bool) {
	protectedInterfaceResolver = fn
}

// resolveInterfaceRef parses an interface reference like "enp6s0" or "enp6s0.100"
// and returns the physical Linux name, config name, unit number, and VLAN ID.
// For RETH interfaces, configName stays as "reth0" (for config lookups) while
// physName resolves to the local physical member's Linux name.
func resolveInterfaceRef(ref string, cfg *config.Config) (physName string, configName string, unitNum int, vlanID int) {
	parts := strings.SplitN(ref, ".", 2)
	configName = parts[0]

	// Resolve IRB interfaces to their bridge device name.
	// "irb.0" → bridge device "br-bd0" (looked up via bridge-domains config).
	if configName == "irb" {
		irbMap := config.IRBToBridge(cfg.BridgeDomains)
		if bridge, ok := irbMap[ref]; ok {
			physName = bridge
			if len(parts) == 2 {
				unitNum, _ = strconv.Atoi(parts[1])
			}
			return
		}
	}

	// Resolve RETH to local physical member
	rethToPhys := cfg.RethToPhysical()
	physBase := configName
	if phys, ok := rethToPhys[configName]; ok {
		physBase = phys
	}

	// Secure-tunnel units resolve through the SHARED rule, not a third
	// hand-copied instance of it (#6729).
	//
	// TWO DEFECTS LIVED IN THE `strings.HasPrefix(configName, "st")` TEST THIS
	// REPLACES, and they are independent:
	//
	//  1. It RECONSTRUCTED the device name from the unit REF. The reconciler
	//     creates the xfrmi under the AUTHORED bind-interface string verbatim
	//     (pkg/routing/xfrm.go), and a bare `bind-interface st0` and an
	//     explicit `bind-interface st0.0` derive the same if_id under
	//     DIFFERENT device names — while the unit ref is `st0.0` in both
	//     cases. So the device name is not a function of the ref and has to be
	//     read back from the config. Under the bare spelling this returned
	//     `st0.0`, `cachedInterfaceByName` failed, and mapZoneInterface logged
	//     "interface not found, skipping": the tunnel was dropped from the
	//     zone programming and from the SNAT egress-address walk.
	//  2. `HasPrefix("st")` is not the secure-tunnel predicate. It also
	//     matched an ordinary NIC whose name merely starts with those two
	//     letters — `start0.0` resolved to `start0.0` instead of the base
	//     netdev — which is the same raw-prefix mistake #6730 fixes in
	//     buildInterfaceNetworkdModels below.
	//
	// Config.SecureTunnelUnitNetdev is the single resolver behind the rule
	// (#6691, xfrmi.go); it declines for a name the xfrmi constructor would
	// reject, so an ordinary interface falls through to the resolution below.
	// The IsSecureTunnelIfName arm mirrors ResolveKernelIfName's own fallback:
	// an in-range st<N> unit that no VPN binds keeps the verbatim ref, which
	// is what this returned before. (An in-range st<N> PHYSICAL interface is a
	// separate, deliberate question — #6737 — and is deliberately unchanged
	// here.)
	if len(parts) == 2 {
		if dev, ok := cfg.SecureTunnelUnitNetdev(ref); ok {
			physName = config.LinuxIfName(dev)
			unitNum, _ = strconv.Atoi(parts[1])
			return
		}
		if config.IsSecureTunnelIfName(configName) {
			physName = config.LinuxIfName(ref)
			unitNum, _ = strconv.Atoi(parts[1])
			return
		}
	}

	// Resolve fabric interface to local physical member for BPF attachment.
	// fab0 is an IPVLAN on ge-0-0-0; XDP/TC must attach to the parent.
	if ifCfg, ok := cfg.Interfaces.Interfaces[configName]; ok && ifCfg != nil && ifCfg.LocalFabricMember != "" {
		physBase = ifCfg.LocalFabricMember
	}

	physName = config.LinuxIfName(physBase)

	if len(parts) == 2 {
		unitNum, _ = strconv.Atoi(parts[1])
	}

	// Per-unit tunnel interfaces have their own Linux interface name
	// (e.g. gr-0/0/0 unit 1 → "gr-0-0-0u1")
	if ifCfg, ok := cfg.Interfaces.Interfaces[configName]; ok && ifCfg != nil {
		if unit, ok := ifCfg.Units[unitNum]; ok {
			vlanID = unit.VlanID
			if unit.Tunnel != nil {
				physName = unit.Tunnel.Name
			}
		}
	}
	return
}

// errVLANCreateFailed marks the ONE VLAN failure that must fail the apply
// (#6893 part 2): netlink.LinkAdd itself refused, so the device the config
// asked for does not exist and nothing downstream can be correct.
//
// It is deliberately NOT attached to the other three error returns of
// ensureVLANSubInterface, and the reason is the harm rather than tidiness:
//
//   - "parent interface %s" is the absent-PHYSICAL case, which #6893 itself
//     hedges on as arguably legitimate (an interface configured but not present
//     on this chassis). Out of scope by decision, not oversight.
//   - "find created ..." and "set ... up" both report created=true, so the link
//     EXISTS. compileFirewallFilters then resolves it and the filter IS
//     assigned — the #6893 harm (a binding silently dropped) does not arise, so
//     failing the apply there would refuse a config for a reason this issue is
//     not about.
var errVLANCreateFailed = errors.New("VLAN sub-interface creation failed")

// ensureVLANSubInterfaceFn is ensureVLANSubInterface's test seam, mirroring
// teardownCleanupFn in loader.go: the paired proof for #6893 part 2 needs a
// CREATION FAILURE, which is not reachable in a unit test without netlink and
// CAP_NET_ADMIN. Production leaves it pointing at the real function.
var ensureVLANSubInterfaceFn = ensureVLANSubInterface

// errVLANAdoptRefused marks a device that already occupies "<phys>.<vid>" but
// failed vlanAdoptionRefusal (#6916).
//
// It is deliberately NOT errVLANCreateFailed. #6893 part 2 fails the whole
// apply when LinkAdd itself refused, because the device the config asked for
// does not exist and a filter bound to it would be silently dropped. Here the
// config's device does not exist EITHER, but the reason is a foreign object
// squatting the name — refusing the entire commit for that would take a far
// larger blast radius than #6893 chose, on a condition an operator may not be
// able to clear from the xpf side. The surface takes the existing soft skip:
// WARN, an UnarmedSurface record naming the check that refused, and — the
// point of the fix — the squatter never enters genericXDPIfindexes at all, so
// it is neither adopted nor silently excluded from XDP attach.
var errVLANAdoptRefused = errors.New("VLAN sub-interface adoption refused")

// vlanLinkByNameSeam is ensureVLANSubInterface's lookup seam, mirroring
// linkByIndexSeam in proxyarp.go and linkLister in loader.go. The #6916 proof
// needs an EXISTING device of the wrong kind at "<phys>.<vid>", which is not
// reachable in a unit test without netlink and CAP_NET_ADMIN. Production
// leaves it pointing at the real function.
var vlanLinkByNameSeam = netlink.LinkByName

// #8119/#8120: the netlink MUTATORS on the interface-reconcile path, behind
// seams so a test can drive the real compileZones over a simulated host and
// assert what TWO consecutive applies leave behind.
//
// A single apply is self-consistent, so a single-apply assertion passes on both
// of those defects whichever way the zone map happened to iterate. The second
// apply is the only witness that can contradict a reconcile, because it does
// not share the assumption that one pass converges.
//
// Reads are NOT seamed: CompileResult's ifCache / linkCache / linkIdxMap are
// package-visible maps a test seeds directly, which also reproduces the real
// cache lifetime — one CompileResult per apply, populated once from the host.
var (
	linkSetMTUSeam     = netlink.LinkSetMTU
	addrLinkByNameSeam = netlink.LinkByName
	addrListSeam       = netlink.AddrList
	addrAddSeam        = netlink.AddrAdd
	addrDelSeam        = netlink.AddrDel
)

// ensureVLANSubInterface creates a Linux VLAN sub-interface if it doesn't exist.
// Returns the sub-interface's ifindex and whether this call CREATED it.
//
// #4960: the created bool is the host-mutation signal. This function runs in
// compile Phase 2, and every later phase — plus preflightCheckIfindexCaps and
// attachUserspaceShimXDP in CompileUserspaceShim — can still fail with no undo
// path. An apply that fails after this point has already moved the host, and
// the caller has to be able to say so. A flag that were merely "a VLAN was
// configured" would be true on every apply of a VLAN config and would report
// nothing; it is true only when this call actually added a link.
func ensureVLANSubInterface(parentName string, vlanID int) (int, bool, error) {
	parent, err := vlanLinkByNameSeam(parentName)
	if err != nil {
		return 0, false, fmt.Errorf("parent interface %s: %w", parentName, err)
	}

	subName := fmt.Sprintf("%s.%d", parentName, vlanID)

	// Check if sub-interface already exists
	existing, err := vlanLinkByNameSeam(subName)
	if err == nil {
		// #6916: PROVE it is ours before adopting it. A device merely NAMED
		// "<phys>.<vid>" is not necessarily an 802.1Q child of <phys> — see
		// vlanAdoptionRefusal for what each check stops. Adopting one that is
		// not puts a live foreign link into the delegated-VLAN-child set, and
		// the attach loop then skips it on the theory that its parent covers
		// it, which for a device that is not that parent's child means nothing
		// covers it.
		if why := vlanAdoptionRefusal(existing, parent.Attrs().Index, vlanID); why != "" {
			return 0, false, fmt.Errorf("%w: %s: %s",
				errVLANAdoptRefused, subName, why)
		}
		// Already exists, ensure it's up
		if existing.Attrs().OperState != netlink.OperUp {
			// The error is LOGGED, not returned. A failed nudge leaves the
			// child DOWN, so nothing forwards through it and the #6916 harm
			// (a live surface with no shim) does not arise; turning a
			// transient set-up failure into a skip would instead drop a
			// legitimate child out of the dataplane. Discarding it entirely,
			// which is what this line did before, left the operator with no
			// way to see why a configured child never came up.
			if err := netlink.LinkSetUp(existing); err != nil {
				slog.Warn("could not bring existing VLAN sub-interface up",
					"name", subName, "parent", parentName, "vlan_id", vlanID,
					"err", err)
			}
		}
		// Not counted as a creation: the link was already present. Bringing an
		// existing link up is a state nudge the next apply repeats idempotently,
		// not a new object the operator would have to remove by hand.
		return existing.Attrs().Index, false, nil
	}

	// Create VLAN sub-interface
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        subName,
			ParentIndex: parent.Attrs().Index,
		},
		VlanId: vlanID,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		return 0, false, fmt.Errorf("create VLAN sub-interface %s: %w: %w",
			subName, errVLANCreateFailed, err)
	}

	// Every return from here on reports created=true: the LinkAdd above
	// SUCCEEDED, so the host carries a new link whether or not the follow-up
	// steps do. Reporting false on a later failure would understate exactly the
	// state #4960 is about.
	// Bring it up
	link, err := netlink.LinkByName(subName)
	if err != nil {
		return 0, true, fmt.Errorf("find created VLAN sub-interface %s: %w", subName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, true, fmt.Errorf("set VLAN sub-interface %s up: %w", subName, err)
	}

	// Disable RA acceptance — firewall uses its own configured routes.
	raPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", subName)
	if err := os.WriteFile(raPath, []byte("0"), 0644); err != nil {
		slog.Warn("failed to disable accept_ra on VLAN sub-interface", "name", subName, "err", err)
	}

	slog.Info("created VLAN sub-interface",
		"name", subName, "parent", parentName, "vlan_id", vlanID,
		"ifindex", link.Attrs().Index)

	return link.Attrs().Index, true, nil
}

func isConfiguredVLANSubInterface(name string, cfg *config.Config) bool {
	idx := strings.IndexByte(name, '.')
	if idx < 0 {
		return false
	}
	base := name[:idx]
	suffix := name[idx+1:]
	vid, err := strconv.Atoi(suffix)
	if err != nil {
		return false
	}
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		if !ifCfg.VlanTagging || config.LinuxIfName(ifName) != base {
			continue
		}
		for _, unit := range ifCfg.Units {
			if unit.VlanID == vid {
				return true
			}
		}
	}
	return false
}

// reconcileInterfaceAddresses ensures the interface has exactly the configured
// addresses. Stale addresses are removed and missing ones are added.
// Link-local (fe80::/10) addresses are left untouched since the kernel manages them.
//
// #4960: returns whether it actually CHANGED the host — a successful AddrDel or
// AddrAdd. A converged interface (every desired address already present, nothing
// stale) returns false, so the caller's host-mutation flag distinguishes an
// apply that moved the host from one that found it already correct. Without
// that distinction the flag would be true on essentially every apply and would
// carry no information.
//
// A FAILED AddrDel/AddrAdd does not set it: the address list is unchanged in
// that direction, and those failures already warn on their own line.
func reconcileInterfaceAddresses(ifaceName string, desired []string) bool {
	link, err := addrLinkByNameSeam(ifaceName)
	if err != nil {
		slog.Warn("cannot find interface for address reconciliation",
			"name", ifaceName, "err", err)
		return false
	}
	changed := false

	// List current kernel addresses (both v4 and v6)
	existing, err := addrListSeam(link, netlink.FAMILY_ALL)
	if err != nil {
		slog.Warn("failed to list addresses on interface",
			"name", ifaceName, "err", err)
		// Fall through to add-only mode
		existing = nil
	}

	// #4960: the DECISION of what to delete and add is a pure function of
	// (existing, desired) and is computed first, separately from the netlink
	// calls that act on it. That is #4960's "split pure planning from
	// actuation" clause at this one site — the full split across the compiler
	// is a redesign — and it is what makes the converged case testable without
	// root: an empty plan is the discriminator that keeps the host-mutation
	// flag meaningful.
	del, add := planAddressReconcile(existing, desired, ifaceName)

	for _, addr := range del {
		key := addr.IPNet.String()
		if err := addrDelSeam(link, addr); err != nil {
			slog.Warn("failed to remove stale address from interface",
				"addr", key, "name", ifaceName, "err", err)
		} else {
			changed = true
			slog.Info("removed stale address from interface",
				"addr", key, "name", ifaceName)
		}
	}

	for _, addr := range add {
		if err := addrAddSeam(link, addr); err != nil {
			if !strings.Contains(err.Error(), "exists") {
				slog.Warn("failed to add address to interface",
					"addr", addr.IPNet.String(), "name", ifaceName, "err", err)
			}
			// An "exists" error means the address was already there — the host
			// did not move, so it is NOT a mutation.
			continue
		}
		changed = true
	}
	return changed
}

// planAddressReconcile computes, purely, which addresses must be DELETED from
// and ADDED to an interface to reach the desired set (#4960).
//
// It performs no I/O, so a converged interface (every desired address present,
// nothing stale) is provably an EMPTY plan without a live host. That is the
// property the host-mutation flag rests on: without it the flag would be set on
// every apply of an addressed interface and would tell the operator nothing
// about whether this apply actually moved anything.
//
// Link-local addresses are excluded from the delete set — the kernel manages
// them, and removing one would be a real outage for a config that never asked
// about it. An unparseable desired address is skipped with a warning rather
// than aborting: it was already skipped before this extraction, and turning it
// into a failure here would change apply behaviour for a defect this change
// does not own.
//
// Both slices are ordered deterministically: deletes follow the kernel's list
// order, adds follow the order the addresses were authored, so the netlink call
// sequence does not vary run to run.
func planAddressReconcile(existing []netlink.Addr, desired []string, ifaceName string) (del []*netlink.Addr, add []*netlink.Addr) {
	// Desired set keyed by "ip/mask", plus the authored order for the adds.
	want := make(map[string]*netlink.Addr, len(desired))
	order := make([]string, 0, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("invalid address for interface",
				"addr", addrStr, "name", ifaceName, "err", err)
			continue
		}
		key := addr.IPNet.String()
		if _, dup := want[key]; !dup {
			order = append(order, key)
		}
		want[key] = addr
	}

	for i := range existing {
		addr := &existing[i]
		if addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() {
			continue
		}
		key := addr.IPNet.String()
		if _, ok := want[key]; ok {
			// Already present: neither deleted nor re-added.
			delete(want, key)
			continue
		}
		del = append(del, addr)
	}

	for _, key := range order {
		if addr, ok := want[key]; ok {
			add = append(add, addr)
		}
	}
	return del, add
}

// compileZones programs the zone/interface dataplane maps and derives the
// systemd-networkd interface model. The work is split into four cohesive
// concerns, each lifted into a helper so the ordering contract is explicit
// and behavior-preserving:
//
//   - programZoneMaps: per-zone dataplane config + per-interface map
//     programming and host setup inside mapZoneInterface (disabled non-VLAN
//     interfaces are brought down, then addresses are reconciled, in the
//     original per-interface loop order — interface renaming happens earlier
//     at daemon startup, not here);
//   - buildInterfaceNetworkdModels / buildFabricBondModels /
//     buildBridgeDomainModels: the networkd managed-interface model, threaded
//     through a shared `seen` set so each interface is emitted exactly once;
//   - stripUnmanagedInterfaces: bring down / address-strip unconfigured NICs.
//
// This is a decomposition of a former ~900-line function; the composed
// behavior is identical (#6426).
func compileZones(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// #4960 / #6894 r5: validate EVERY zone's screen reference before the first
	// zone is programmed. programZoneMaps ranges a Go MAP, so which zone is
	// visited first is not fixed run to run — and both of the screen lookups it
	// performs abort the whole compile. An unknown reference on the second zone
	// visited therefore aborts AFTER the first zone has already been through
	// SetZoneConfig and, if it has interfaces, real netlink and /proc/sys
	// writes. That is precisely the half-reconfigured host #4960 exists to
	// prevent, reached by the mechanism it claims to have closed.
	//
	// It is hoisted HERE rather than added to the pre-pass phase table alone
	// because the reference is validated per ZONE inside this call: the pre-pass
	// already runs compileScreenProfiles and it did not catch this, since what
	// is unresolvable is the zone's reference TO a profile, not the profile set
	// itself. Placing the sweep at the top of compileZones makes it structurally
	// impossible for any zone to mutate before every zone's reference has been
	// checked, whatever the caller did first. It is ALSO registered as a
	// pre-pass row (compiler_validate_4960.go) so the pre-pass reports it with
	// the same precedence as its siblings.
	if err := validateZoneScreenReferences(cfg, result); err != nil {
		return err
	}

	st, err := programZoneMaps(dp, cfg, result)
	if err != nil {
		return err
	}

	// Auto-add HOST_INBOUND_GRE to zones carrying GRE tunnel transport.
	applyTunnelHostInbound(dp, cfg, result)

	// Store pending XDP ifindexes for deferred attachment after all compile phases.
	result.pendingXDP = st.xdpIfindexes
	result.tunnelIfindexes = st.tunnelIfindexes

	// Collect managed interface info for networkd config generation. The `seen`
	// set is threaded through every model builder so an interface is emitted
	// once and the unmanaged strip skips already-managed names — preserving the
	// monolithic loop's shared-map semantics.
	seen := make(map[string]bool)
	buildInterfaceNetworkdModels(cfg, result, seen)
	buildFabricBondModels(cfg, result, seen)
	buildBridgeDomainModels(cfg, result, seen)
	stripUnmanagedInterfaces(cfg, result, seen)

	// Delete stale zone/VLAN map entries no longer in the config.
	dp.DeleteStaleIfaceZone(st.writtenIfaceZone)
	dp.DeleteStaleVlanIface(st.writtenVlanIface)

	return nil
}

// buildIfaceTableIDMap builds the interface -> routing-table-ID map from the
// configured routing instances. Forwarding instances use the default table
// (0), so they are skipped.
func buildIfaceTableIDMap(cfg *config.Config) map[string]uint32 {
	ifaceTableID := make(map[string]uint32)
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType == "forwarding" {
			continue
		}
		for _, ifaceName := range ri.Interfaces {
			ifaceTableID[ifaceName] = uint32(ri.TableID)
		}
	}
	return ifaceTableID
}

// zoneMapState accumulates the dataplane map-programming side effects of the
// zone->interface loop (programZoneMaps / mapZoneInterface). Lifting these
// shared accumulators into an explicit struct is what lets the per-interface
// mapping move out of compileZones without changing behavior: every field is
// the same local the monolithic loop carried across zones and interfaces. In
// particular the attached / attachedXDP dedup maps MUST persist across the
// whole loop (a phys interface referenced by two zones is set up once),
// exactly as before. xdpIfindexes / tunnelIfindexes are handed back to the
// caller for result.pendingXDP / result.tunnelIfindexes.
type zoneMapState struct {
	// writtenIfaceZone / writtenVlanIface track written keys for
	// populate-before-clear: write new entries first, then delete stale ones
	// that are no longer in the config.
	writtenIfaceZone map[IfaceZoneKey]bool
	writtenVlanIface map[uint32]bool
	// attached tracks physical interfaces that already had one-time parent setup.
	attached map[int]bool
	// attachedXDP tracks interfaces that already have a deferred XDP attachment queued.
	attachedXDP map[int]bool
	// xdpIfindexes collects ifindexes for deferred XDP attachment.
	xdpIfindexes []int
	// tunnelIfindexes: tunnel interfaces need XDP for ingress but must NOT be in
	// redirect_capable or tx_ports — bpf_redirect_map sends the full Ethernet
	// frame, but POINTOPOINT tunnels expect raw IP.
	tunnelIfindexes map[int]bool
	// #8119/#8120: the merged desired state per physical netdev, decided once
	// per apply, plus the netdevs already actuated from it. Together they are
	// what makes a second reference to one netdev a no-op instead of a second
	// writer with a different opinion.
	physDesired    map[string]*physDesired
	physReconciled map[string]bool
}

func newZoneMapState() *zoneMapState {
	return &zoneMapState{
		writtenIfaceZone: make(map[IfaceZoneKey]bool),
		writtenVlanIface: make(map[uint32]bool),
		attached:         make(map[int]bool),
		attachedXDP:      make(map[int]bool),
		tunnelIfindexes:  make(map[int]bool),
		physDesired:      make(map[string]*physDesired),
		physReconciled:   make(map[string]bool),
	}
}

// buildZoneConfig compiles the per-zone dataplane ZoneConfig (screen-profile
// ID, host-inbound-traffic flags, TCP-RST) for a single security zone.
func buildZoneConfig(zone *config.ZoneConfig, name string, zid uint16, result *CompileResult) (ZoneConfig, error) {
	// Write zone_config
	zc := ZoneConfig{
		ZoneID: zid,
	}

	// Look up screen profile ID for this zone
	if zone.ScreenProfile != "" {
		if sid, ok := result.ScreenIDs[zone.ScreenProfile]; ok {
			zc.ScreenProfileID = sid
			slog.Info("zone screen profile assigned",
				"zone", name, "screen", zone.ScreenProfile, "id", sid)
		} else {
			return ZoneConfig{}, fmt.Errorf("screen profile %q not found for zone %q",
				zone.ScreenProfile, name)
		}
	}

	// Compile host-inbound-traffic flags
	if zone.HostInboundTraffic != nil {
		var flags uint32
		for _, svc := range zone.HostInboundTraffic.SystemServices {
			if f, ok := HostInboundServiceFlags[svc]; ok {
				flags |= f
			} else {
				slog.Warn("unknown host-inbound system-service",
					"service", svc, "zone", name)
			}
		}
		for _, proto := range zone.HostInboundTraffic.Protocols {
			if f, ok := HostInboundProtocolFlags[proto]; ok {
				flags |= f
			} else {
				slog.Warn("unknown host-inbound protocol",
					"protocol", proto, "zone", name)
			}
		}
		zc.HostInbound = flags
		slog.Info("host-inbound-traffic compiled",
			"zone", name, "flags", fmt.Sprintf("0x%x", flags))
	}

	if zone.TCPRst {
		zc.TCPRst = 1
	}

	return zc, nil
}

// programZoneMaps walks the security zones and programs every zone/interface
// dataplane map, returning the accumulated map-programming state so the caller
// can publish the deferred XDP/tunnel ifindex sets and delete stale entries.
func programZoneMaps(dp DataPlane, cfg *config.Config, result *CompileResult) (*zoneMapState, error) {
	st := newZoneMapState()
	// Decide once, before the zone loop, so no ordering of that loop can change
	// what the host ends up looking like.
	st.physDesired = planPhysDesired(cfg)

	// Interface -> routing table ID map from the routing instances.
	ifaceTableID := buildIfaceTableIDMap(cfg)

	for name, zone := range cfg.Security.Zones {
		// A nil zone value is reachable on the tolerant/programmatic and
		// HA-peer-sync config paths (the nil-slot invariant the dataplane
		// SSOT already defends, e.g. userspace/zones.go). Skip it — every
		// deref below (ScreenProfile, HostInboundTraffic, Interfaces)
		// would otherwise panic the apply-path interface reconcile.
		if zone == nil {
			// #5275: mapZoneInterface is the SOLE writer of st.xdpIfindexes,
			// which becomes result.pendingXDP, so skipping the zone drops
			// EVERY interface in it from the required set while the compile
			// succeeds — the same silent-absence hole as the three per-
			// interface soft skips, one frame up, and reachable on the HA
			// config-sync path.
			//
			// The record is ZONE-level and cannot be resolved to per-interface
			// coverage: zone.Interfaces is precisely the deref the guard above
			// exists to prevent, so the surfaces are unknowable here. It is
			// therefore reported as SKIPPED, not uncovered — an enumeration
			// gap the measurement can now see rather than a proven policy-free
			// router. The gating PR has to decide whether an unenumerable zone
			// fails closed; this phase only has to stop hiding it.
			result.recordUnarmedSurface(UnarmedSurface{
				Name: "zone:" + name,
				Reason: "nil zone slot — every interface in this zone was dropped from the " +
					"required set and none can be enumerated",
			})
			continue
		}
		zid := result.ZoneIDs[name]

		zc, err := buildZoneConfig(zone, name, zid, result)
		if err != nil {
			return nil, err
		}
		if err := dp.SetZoneConfig(zid, zc); err != nil {
			return nil, fmt.Errorf("set zone config %s: %w", name, err)
		}

		// Map interfaces to zone
		for _, ifaceRef := range zone.Interfaces {
			if err := st.mapZoneInterface(dp, cfg, result, name, zone, zid, ifaceRef, ifaceTableID); err != nil {
				return nil, err
			}
		}
	}

	return st, nil
}

// mapZoneInterface maps one zone interface reference into the dataplane:
// resolves the physical/VLAN interface, programs the zone map, performs the
// one-time per-phys host setup (tx_port, rxvlan, MTU, ethtool, buffers,
// UP/DOWN, deferred XDP/TC), and reconciles addresses. It mutates st in place
// (the accumulators persist across the whole zone loop) and returns an error
// on a hard failure; a soft skip (interface not found, VLAN create failed)
// returns nil so the caller advances to the next interface.
func (st *zoneMapState) mapZoneInterface(dp DataPlane, cfg *config.Config, result *CompileResult, name string, zone *config.ZoneConfig, zid uint16, ifaceRef string, ifaceTableID map[string]uint32) error {
	physName, cfgName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)

	// Get the physical interface (cached to avoid redundant syscalls)
	physIface, err := result.cachedInterfaceByName(physName)
	if err != nil {
		slog.Warn("interface not found, skipping",
			"interface", physName, "zone", name, "err", err)
		// #5275: the config demanded this surface and the compile still
		// succeeds without it. Record it so the arm-coverage proof can tell a
		// declined surface from one that armed. missingInterfaceRecord decides
		// whether the absence is PROVEN — a netdev-enumeration failure is not
		// the same as a netdev that does not exist — and vlanID is threaded so
		// the record names the CONFIGURED surface: physName is already the
		// resolved parent here, and every VLAN child of one absent parent
		// would otherwise dedup onto that single name.
		result.recordUnarmedSurface(missingInterfaceRecord(physName, vlanID, name, err))
		return nil
	}

	if vlanID > 0 {
		// VLAN sub-interface: create it, populate vlan_iface_map
		subIfindex, vlanCreated, err := ensureVLANSubInterfaceFn(physName, vlanID)
		if vlanCreated {
			// #4960: recorded BEFORE the error branch. LinkAdd succeeded even
			// on the paths that fail afterwards, so the host carries the new
			// link either way.
			result.markHostMutated("created VLAN sub-interface")
		}
		if err != nil && errors.Is(err, errVLANCreateFailed) {
			// #6893 part 2: FAIL THE APPLY. The config asked for a device, the
			// create refused, and the device does not exist — so
			// compileFirewallFilters will miss it and the filter bound to it is
			// silently not assigned. A filter that is absent permits what it was
			// configured to deny, and the commit used to report success.
			//
			// Scoped to the CREATE failure alone: the absent-parent and
			// created-but-unusable cases keep the soft skip. See
			// errVLANCreateFailed for why each.
			return fmt.Errorf("zone %s interface %s.%d: %w", name, physName, vlanID, err)
		}
		if err != nil {
			slog.Warn("VLAN sub-interface failed, skipping",
				"parent", physName, "vlan_id", vlanID, "zone", name, "err", err)
			// #5275: same as above — the child was never created, so nothing
			// forwards through it, but the config asked for it and the compile
			// succeeds regardless.
			//
			// #6916: an ADOPTION REFUSAL reaches here too, and it is a
			// different fact about the host — the name is occupied by
			// something xpf will not touch, which is the one case where a
			// device IS present and forwarding. Reporting it as "create
			// failed" would be a false statement in the operator's own
			// record, and it is the statement that would send them looking
			// for a creation error that never happened.
			what := "create failed"
			if errors.Is(err, errVLANAdoptRefused) {
				what = "not adopted"
			}
			result.recordUnarmedSurface(UnarmedSurface{
				Name:   fmt.Sprintf("%s.%d", physName, vlanID),
				Reason: fmt.Sprintf("VLAN sub-interface %s in zone %s: %v", what, name, err),
			})
			return nil
		}

		if err := dp.SetVlanIfaceInfo(subIfindex, physIface.Index, uint16(vlanID)); err != nil {
			return fmt.Errorf("set vlan_iface_info %s.%d: %w",
				physName, vlanID, err)
		}
		st.writtenVlanIface[uint32(subIfindex)] = true

		// Reconcile addresses on sub-interface (removes stale, adds missing).
		// DHCP-managed and RETH sub-interfaces are skipped — DHCP client
		// manages DHCP addresses, VRRP manages RETH VIP addresses.
		subName := fmt.Sprintf("%s.%d", physName, vlanID)
		var addrs []string
		isDHCPSub := false
		isReth := false
		if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg != nil {
			if unit, ok := ifCfg.Units[unitNum]; ok {
				addrs = unit.Addresses
				isDHCPSub = unit.DHCP || unit.DHCPv6
			}
			if ifCfg.RedundancyGroup > 0 {
				isReth = true
			}
		}
		if !isDHCPSub && !isReth {
			if reconcileInterfaceAddresses(subName, addrs) {
				result.markHostMutated("reconciled VLAN sub-interface addresses")
			}
		}

		// Apply unit-level MTU to VLAN sub-interface
		if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg != nil {
			if unit, ok := ifCfg.Units[unitNum]; ok && unit.MTU > 0 {
				if nl, err := result.cachedLinkByName(subName); err == nil {
					if nl.Attrs().MTU != unit.MTU {
						if err := linkSetMTUSeam(nl, unit.MTU); err != nil {
							slog.Warn("failed to set VLAN sub-interface MTU",
								"name", subName, "mtu", unit.MTU, "err", err)
						} else {
							slog.Info("set VLAN sub-interface MTU", "name", subName, "mtu", unit.MTU)
						}
					}
				}
			}
		}

		slog.Info("VLAN sub-interface configured",
			"parent", physName, "vlan_id", vlanID,
			"sub_ifindex", subIfindex, "zone", name)

		// Native GRE on VLAN transport needs XDP on the child interface
		// itself; packets can ingress via ge-*.VID without ever running
		// the parent's driver XDP hook. VLAN children do not support the
		// fast path reliably here, so keep them on generic XDP only.
		if !st.attachedXDP[subIfindex] {
			st.xdpIfindexes = append(st.xdpIfindexes, subIfindex)
			result.genericXDPIfindexes[subIfindex] = true
			st.attachedXDP[subIfindex] = true
		}
	}

	// Set zone mapping using composite key {physIfindex, vlanID}
	tableID := ifaceTableID[ifaceRef] // 0 if not in any routing instance
	var izFlags uint8
	var rgID uint8
	var screenFlags uint32
	if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg != nil {
		if ifCfg.Tunnel != nil {
			izFlags |= IfaceFlagTunnel
		}
		// Check per-unit tunnel
		if unit, ok := ifCfg.Units[unitNum]; ok && unit.Tunnel != nil {
			izFlags |= IfaceFlagTunnel
		}
		if ifCfg.RedundancyGroup > 0 {
			rgID = uint8(ifCfg.RedundancyGroup)
		} else if ifCfg.RedundantParent != "" {
			// Physical RETH member: inherit RG from the RETH parent.
			// Without this, check_egress_rg_active() in BPF returns
			// rg_id=0 for RETH member VLAN sub-interfaces, bypassing
			// the HA active/inactive check and preventing fabric
			// redirect after RG failover.
			if reth, ok := cfg.Interfaces.Interfaces[ifCfg.RedundantParent]; ok && reth != nil && reth.RedundancyGroup > 0 {
				rgID = uint8(reth.RedundancyGroup)
			}
		}
	}
	if zone.ScreenProfile != "" {
		profile, ok := cfg.Security.Screen[zone.ScreenProfile]
		if !ok {
			return fmt.Errorf("screen profile %q not found for zone %q",
				zone.ScreenProfile, name)
		}
		screenFlags = buildScreenConfig(
			profile,
			cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie",
		).Flags
	}
	if izFlags&IfaceFlagTunnel != 0 {
		st.tunnelIfindexes[physIface.Index] = true
	} else {
		// Optimistically set native XDP flag for non-tunnel
		// interfaces.  Cleared in needGeneric fallback below.
		izFlags |= IfaceFlagNativeXDP
	}
	if err := dp.SetZone(physIface.Index, uint16(vlanID), zid, tableID, izFlags, rgID, screenFlags); err != nil {
		return fmt.Errorf("set zone for %s vlan %d (ifindex %d): %w",
			physName, vlanID, physIface.Index, err)
	}
	st.writtenIfaceZone[IfaceZoneKey{Ifindex: uint32(physIface.Index), VlanID: uint16(vlanID)}] = true

	// Add physical interface to tx_ports and attach TC (once per phys iface).
	// XDP attachment is deferred to after the loop so we can ensure
	// all interfaces use the same XDP mode (native vs generic).
	if !st.attached[physIface.Index] {
		// Skip tx_ports for tunnel interfaces — bpf_redirect_map
		// sends Ethernet frames but tunnels expect raw IP.
		if st.tunnelIfindexes[physIface.Index] {
			slog.Info("skipping tx_port for tunnel interface",
				"name", physName, "ifindex", physIface.Index)
		} else if err := dp.AddTxPort(physIface.Index); err != nil {
			return fmt.Errorf("add tx port %s: %w", physName, err)
		}

		// Disable VLAN RX offload so XDP sees VLAN tags in packet data
		// (otherwise NIC strips them into skb->vlan_tci which XDP can't read).
		// Check current state first — toggling rxvlan on iavf VFs causes a
		// driver reset that drops in-flight packets (kills active TCP sessions).
		// #5268: if the offload cannot be disabled AND this parent carries
		// configured VLAN subinterfaces, FAIL ACTIVATION CLOSED — proceeding
		// to shim attachment would let HW-stripped tagged traffic inherit the
		// parent's zone (cross-zone bypass). A plain parent (no 802.1Q units)
		// tolerates the failure (the disable-failure is still logged inside
		// ensureRxVlanOff).
		if err := rxVlanOffloadActivationError(
			cfg, cfgName, physName, result.ensureRxVlanOff(physName),
		); err != nil {
			return err
		}

		// Single cached netlink lookup for MTU, speed/duplex, and UP/DOWN.
		nl, nlErr := result.cachedLinkByIndex(physIface.Index)

		// #8119/#8120: the ONE MTU write for this netdev, of the value
		// planPhysDesired already resolved from the interface-level leaf and
		// every unit's override.
		//
		// There used to be a second write further down for the unit-level MTU.
		// Both compared against this same cached link, and LinkSetMTU does not
		// write back to the caller's Link — so the second comparison read a
		// pre-write value and the two writes alternated on consecutive applies,
		// flapping the interface MTU between the two configured values forever.
		// One comparison against a cache that is still fresh cannot do that.
		if pd := st.physDesired[physName]; pd != nil && pd.mtu > 0 && nlErr == nil {
			if nl.Attrs().MTU != pd.mtu {
				if err := linkSetMTUSeam(nl, pd.mtu); err != nil {
					slog.Warn("failed to set MTU",
						"name", physName, "mtu", pd.mtu, "err", err)
				} else {
					slog.Info("set interface MTU", "name", physName, "mtu", pd.mtu)
				}
			}
		}

		// Apply interface speed/duplex via ethtool if configured
		if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg != nil {
			result.applyEthtool(physName, ifCfg)
		}

		// Tune ring buffers and txqueuelen BEFORE XDP attachment
		// (ethtool -G can reset the NIC, disrupting attached programs).
		if nlErr == nil {
			result.tuneInterfaceBuffers(nl)
		}

		// Bring the interface UP so XDP can process traffic,
		// unless the interface is administratively disabled.
		// Note: For DPDK-bound ports, LinkSetDown has no effect because
		// DPDK takes over the NIC via VFIO/UIO, bypassing the kernel
		// driver. DPDK ports are disabled by not including them in the
		// worker's poll set (the zone map lookup will miss, causing drop).
		isDisabled := false
		// #5275: a disable whose LinkSetDown did NOT take leaves the netdev UP,
		// still address-reconciled, still in a zone, still forwarded through by
		// the kernel — with no XDP attached. Keep LinkSetDown's own error so
		// disabledSurfaceRecord can tell a proven-down netdev from one that
		// merely got a warning; a bool computed here would be a second place to
		// get that judgement wrong.
		var downErr error
		if ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]; ok && ifCfg != nil && ifCfg.Disable {
			isDisabled = true
			if nlErr == nil {
				if downErr = netlink.LinkSetDown(nl); downErr != nil {
					slog.Warn("failed to bring disabled interface down",
						"name", physName, "err", downErr)
				} else {
					slog.Info("interface administratively disabled", "name", physName)
				}
			}
		} else if nlErr == nil {
			if err := netlink.LinkSetUp(nl); err != nil {
				slog.Warn("failed to bring interface up",
					"name", physName, "err", err)
			}
		}

		// Skip XDP/TC attachment for disabled interfaces — they are
		// administratively down and should not process traffic.
		if isDisabled {
			slog.Info("skipping XDP/TC attachment for disabled interface",
				"name", physName, "ifindex", physIface.Index)
			// #5275: record the declined surface. Both errors are threaded
			// through so disabledSurfaceRecord can promote it from "skipped" to
			// "uncovered" when the netdev was not proven down — an UP, zoned,
			// XDP-less netdev is the policy-free-router state.
			result.recordUnarmedSurface(
				disabledSurfaceRecord(physName, physIface.Index, nlErr, downErr))
		} else if encap, known := netdevFramingKnown(nl, nlErr); known && !netdevCarriesEthernetFraming(encap) {
			// #8279: the shim parses a 14-byte Ethernet header unconditionally.
			// On a netdev that carries no such header its bytes [12..14] are
			// not an ethertype but the first two octets of the IP SOURCE
			// address, so an inner source in 8.0.0.0/16 makes it parse an IPv4
			// header 14 bytes into the real one. Refusing the ATTACH — rather
			// than only re-ordering inside the shim — is what also covers the
			// ctrl-DISABLED path, which never consults the ingress set by
			// design and would otherwise evaluate its local/control exemption
			// against that misparse.
			//
			// Recorded as an unarmed surface, not skipped silently: an UP,
			// zoned netdev with no XDP is exactly the state #5275's arm-
			// coverage proof exists to report, and this is a real adjudication
			// gap for a tunnel (tracked as #8274 / #8276) rather than a
			// no-op — it is simply a better gap than adjudicating on a
			// misparsed header.
			slog.Info("skipping XDP/TC attachment for non-Ethernet netdev",
				"name", physName, "ifindex", physIface.Index, "encap", encap)
			result.recordUnarmedSurface(
				nonEthernetSurfaceRecord(physName, physIface.Index, encap))
		} else {
			// Defer actual XDP/TC attachment to after all compile phases
			// so link.Update() switches to programs with fully-populated maps.
			if !st.attachedXDP[physIface.Index] {
				st.xdpIfindexes = append(st.xdpIfindexes, physIface.Index)
				st.attachedXDP[physIface.Index] = true
			}
			// Skip TC egress for tunnel interfaces — kernel forwards
			// the inner packet to the tunnel device, and TC egress
			// would see it with ingress_ifindex != 0 and drop it.
			// Tunnels need XDP for ingress (decapsulated traffic)
			// but not TC for egress (encapsulation is kernel work).
			if !st.tunnelIfindexes[physIface.Index] {
				result.pendingTC = append(result.pendingTC, physIface.Index)
			} else {
				slog.Info("skipping TC for tunnel interface",
					"name", physName, "ifindex", physIface.Index)
			}
		}
		st.attached[physIface.Index] = true
	}

	// Reconcile addresses for non-VLAN, non-DHCP, non-RETH, non-fabric-parent interfaces.
	// DHCP-managed interfaces are skipped — the DHCP client manages their addresses.
	// RETH interfaces are skipped — VRRP manages their VIP addresses.
	// Fabric parents are skipped — addresses go on the IPVLAN overlay (fab0/fab1).
	// #8120: reconcile the netdev's addresses ONCE per apply, to the union of
	// every untagged unit that resolves to it.
	//
	// This used to run per zone-interface reference, against that unit's own
	// exact desired set. Two units of one interface with no VLAN ID resolve to
	// the same netdev, so whichever the zone map yielded second deleted the
	// addresses the first had just added — and which one that was changed per
	// run, because Go randomises map iteration. The apply reported success
	// either way. Reconciling the union once removes the second writer rather
	// than making it lose consistently; a sort over the zone map would have
	// made the outcome stable and still arbitrary.
	//
	// DHCP / RETH / fabric-parent suppression is folded into the plan: those
	// addresses belong to the DHCP client, VRRP, or the IPVLAN overlay.
	if vlanID == 0 && !st.physReconciled[physName] {
		st.physReconciled[physName] = true
		if pd := st.physDesired[physName]; pd != nil && !pd.skipAddrs {
			if reconcileInterfaceAddresses(physName, pd.addrs) {
				result.markHostMutated("reconciled interface addresses")
			}
		}
	}

	slog.Info("zone interface configured",
		"zone", name, "interface", ifaceRef,
		"phys_ifindex", physIface.Index, "vlan_id", vlanID,
		"zone_id", zid)

	return nil
}

// buildInterfaceNetworkdModels derives the networkd managed-interface model
// from the configured interfaces (RETH member merge, VLAN parents/children,
// fabric IPVLAN parents, VRRP link-local base addresses). Entries are appended
// to result.ManagedInterfaces and names recorded in seen for dedup / the
// unmanaged strip.
func buildInterfaceNetworkdModels(cfg *config.Config, result *CompileResult, seen map[string]bool) {
	// Collect managed interface info for networkd config generation.
	// Iterate over configured interfaces (not zones) to get a clean
	// per-interface view including VLAN parent and sub-interface entries.
	//
	// RETH interfaces (reth0, reth1) are config-only — no bond devices are
	// created. Physical member interfaces (with RedundantParent) inherit the
	// reth's addresses, VLANs, and redundancy group settings.
	//
	// For VRRP-backed RETH, VIP addresses are managed by native VRRP. The
	// networkd .network file gets a link-local base address (169.254.RG.NODE/32)
	// instead — VRRP requires at least one IPv4 for advertisements.
	clusterNodeID := -1
	if cfg.Chassis.Cluster != nil {
		clusterNodeID = cfg.Chassis.Cluster.NodeID
	}
	rethToPhys := cfg.RethToPhysical()
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		// #6730: the SECURE-TUNNEL predicate, not a raw two-letter prefix.
		// This branch ends in an unconditional `continue`, so every name it
		// claims is skipped by the physical-interface handling below — and
		// `HasPrefix(ifName, "st")` claimed `start0`, `stx` and `st65536` too.
		// For those, XFRMIfNameAndID returns ("", 0) for every unit, so each
		// unit `continue`s and the trailing `continue` then drops the whole
		// interface: no addresses, no MTU, no DHCP, no networkd model at all.
		// Nothing downstream re-adds it — stripUnmanagedInterfaces runs
		// against this same `seen` set, so the NIC is brought DOWN.
		//
		// IsSecureTunnelIfName is the bounded predicate the xfrmi constructor
		// itself uses, so exactly the names that can become an xfrmi take this
		// branch and everything else reaches the ordinary handling.
		if config.IsSecureTunnelIfName(ifName) {
			mtu := ifCfg.MTU
			for unitNum, unit := range ifCfg.Units {
				// #6955: resolve the netdev through the AUTHORED
				// `bind-interface` string, not by reconstructing it from the
				// ref. pkg/routing/xfrm.go materialises the device under
				// exactly `LinuxIfName(bindInterface)`, so `bind-interface
				// st0` creates `st0` while the unit ref is `st0.0` — and the
				// reconstruction answered `st0.0`, a device that does not
				// exist. The lookup below then missed and `continue`d, so the
				// authored `family inet address` was never applied and the
				// tunnel came up with no IP and no connected prefix.
				//
				// `ok == false` means no configured VPN binds this ref (or its
				// if_id collides), in which case pkg/routing creates NO device
				// and there is nothing to address.
				unitName, ok := cfg.SecureTunnelUnitNetdev(fmt.Sprintf("%s.%d", ifName, unitNum))
				if !ok {
					continue
				}
				if _, err := result.cachedInterfaceByName(unitName); err != nil {
					continue
				}
				if seen[unitName] {
					continue
				}
				seen[unitName] = true
				unitMTU := mtu
				if unit.MTU > 0 && (unitMTU == 0 || unit.MTU < unitMTU) {
					unitMTU = unit.MTU
				}
				desc := ifCfg.Description
				if unit.Description != "" {
					desc = unit.Description
				}
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:             unitName,
					Addresses:        unit.Addresses,
					PrimaryAddress:   unit.PrimaryAddress,
					PreferredAddress: unit.PreferredAddress,
					DHCPv4:           unit.DHCP,
					DHCPv6:           unit.DHCPv6,
					DADDisable:       unit.DADDisable,
					MTU:              unitMTU,
					Description:      desc,
				})
			}
			continue
		}

		// Skip reth interfaces — no physical device exists; the physical
		// member interface inherits the reth's config below.
		if _, isReth := rethToPhys[ifName]; isReth {
			continue
		}

		// For physical members with a RedundantParent, merge the parent
		// reth's config (addresses, VLANs, redundancy group).
		effectiveCfg := ifCfg
		isVRRPReth := false
		if ifCfg.RedundantParent != "" {
			if rethCfg, ok := cfg.Interfaces.Interfaces[ifCfg.RedundantParent]; ok && rethCfg != nil {
				effectiveCfg = rethCfg
				isVRRPReth = rethCfg.RedundancyGroup > 0 && clusterNodeID >= 0
			}
		} else {
			// #6781: an interface with no `redundant-parent` is a member of no
			// redundant pair, and an interface that OWNS one was already skipped
			// above (the skip keys on RethToPhysical, i.e. on some port naming
			// it as their redundant-parent). So reaching here with
			// RedundancyGroup > 0 is exactly the shape #6781 is about:
			// `redundant-ether-options redundancy-group` on an interface that is
			// neither a member nor an owner.
			//
			// Treating it as a VRRP-backed reth REPLACED the operator's
			// configured address with a 169.254.<rg>.<node>/32 link-local below
			// and handed the real address to VRRP as a VIP. In VRRP mode that
			// demoted a plain L3 interface's address to one that exists only
			// while MASTER; under `no-reth-vrrp` the direct collector skipped
			// the interface too, so the address was stripped here and installed
			// by NOBODY, on both nodes. It also armed the RETH virtual-MAC
			// recovery search below for a MAC this interface can never carry.
			//
			// Commit now rejects the shape (validateRethRedundancyGroupStrict);
			// this keeps a tolerantly-loaded config that still carries it from
			// losing the address.
			isVRRPReth = false
		}

		linuxName := config.LinuxIfName(ifName)
		originalName := "" // kernel name before .link rename (for RETH recovery)
		physIface, err := result.cachedInterfaceByName(linuxName)
		if err != nil && isVRRPReth && cfg.Chassis.Cluster != nil {
			// Interface not found under its config name — it may exist
			// under its kernel name if the .link rename was lost. Search
			// by the expected RETH virtual MAC.
			rgID := effectiveCfg.RedundancyGroup
			expectedMAC := net.HardwareAddr{0x02, 0xbf, 0x72,
				byte(cfg.Chassis.Cluster.ClusterID), byte(rgID), byte(clusterNodeID)}
			physIface = findInterfaceByMAC(expectedMAC)
			if physIface != nil {
				slog.Info("found RETH member under kernel name",
					"config", linuxName, "actual", physIface.Name,
					"mac", expectedMAC)
				// Mark kernel name as seen so unmanaged detection skips it.
				seen[physIface.Name] = true
				// Use OriginalName= in .link for stable matching across
				// reboots (PCI name is stable, MAC alternates between
				// physical and virtual).
				originalName = physIface.Name
			}
		}
		// vSRX fabric member resolution: when a fabric interface (fab0, fab1)
		// has a LocalFabricMember set (vSRX fabric-options mode), look up the
		// member's Linux name to find the physical interface and rename it.
		if physIface == nil && strings.HasPrefix(ifName, "fab") && ifCfg.LocalFabricMember != "" {
			memberLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
			physIface, _ = result.cachedInterfaceByName(memberLinux)
			if physIface != nil {
				slog.Info("found vSRX fabric member interface",
					"fab", linuxName, "member", ifCfg.LocalFabricMember,
					"kernel", physIface.Name)
				seen[physIface.Name] = true
				originalName = physIface.Name
			}
		}
		// Fabric interface recovery: when a fabric interface (fab0, fab1)
		// isn't found by name, read the bootstrap .link file for its
		// OriginalName= (PCI kernel name) and look up the kernel interface
		// under that name. This handles the case where the .link rename
		// hasn't taken effect yet (e.g. no reboot since bootstrap).
		if physIface == nil && strings.HasPrefix(ifName, "fab") {
			origName := readOriginalNameFromLink(linuxName)
			if origName != "" {
				physIface, err = result.cachedInterfaceByName(origName)
				if physIface != nil {
					slog.Info("found fabric interface under kernel name",
						"config", linuxName, "actual", physIface.Name,
						"originalName", origName)
					seen[physIface.Name] = true
					originalName = origName
				}
			}
		}
		if physIface == nil {
			continue
		}
		// IPVLAN fabric: mark the parent interface as seen so unmanaged
		// detection doesn't bring it DOWN (IPVLAN needs parent UP for carrier).
		// Also add a ManagedInterfaces entry (no addresses, no .link) so the
		// parent gets a .network file that keeps it UP.
		if ifCfg.LocalFabricMember != "" {
			parentLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
			if !seen[parentLinux] {
				seen[parentLinux] = true
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:        parentLinux,
					Description: "fabric parent (IPVLAN host)",
				})
			}
		}
		mac := physIface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		// If this is a RETH member with a virtual MAC already programmed
		// (02:bf:72:...), use the permanent (factory) MAC for the .link
		// file so it matches on reboot before the daemon sets the virtual MAC.
		if isVRRPReth && isVirtualRethMAC(physIface.HardwareAddr) {
			// Recover original kernel name for stable .link OriginalName=
			// matching. More reliable than MACAddress= because the MAC
			// alternates between physical (boot) and virtual (daemon sets it).
			if originalName == "" {
				originalName = originalKernelNameFn(physIface.Name, result)
				if originalName == "" {
					originalName = readOriginalNameFromLink(linuxName)
				}
				if originalName != "" {
					slog.Info("recovered RETH original kernel name",
						"iface", linuxName, "originalName", originalName)
				}
			}
			// Use permanent MAC when available to avoid writing the virtual
			// MAC to the .link MACAddress field. If OriginalName is set,
			// generateLink uses it instead of MACAddress anyway.
			if permMAC := getPermAddr(physIface.Name, result); permMAC != "" {
				mac = permMAC
			}
		}

		// vSRX fabric members (LocalFabricMember set): the parent physical
		// interface (ge-0-0-0) keeps its name; fab0 is an IPVLAN overlay.
		// Don't write a .link file for the fab* name — linksetup already
		// handles ge-X-0-Y naming. Clear addresses since they go on the IPVLAN.
		if ifCfg.LocalFabricMember != "" {
			mac = ""
			originalName = ""
		}

		if effectiveCfg.VlanTagging {
			// VLAN parent: no addresses, just rename
			if !seen[linuxName] {
				seen[linuxName] = true
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:         linuxName,
					MACAddress:   mac,
					OriginalName: originalName,
					IsVLANParent: true,
					Disable:      ifCfg.Disable,
					Speed:        ifCfg.Speed,
					Duplex:       ifCfg.Duplex,
					MTU:          ifCfg.MTU,
					Description:  ifCfg.Description,
				})
			}
			// VLAN sub-interfaces get their own .network file
			for _, unit := range effectiveCfg.Units {
				if unit.VlanID > 0 {
					subName := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subName] {
						seen[subName] = true
						addrs := unit.Addresses
						if isVRRPReth {
							// Replace VIP addresses with a link-local base for VRRP.
							addrs = []string{fmt.Sprintf("169.254.%d.%d/32", effectiveCfg.RedundancyGroup, clusterNodeID+1)}
						}
						result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
							Name:             subName,
							Addresses:        addrs,
							PrimaryAddress:   unit.PrimaryAddress,
							PreferredAddress: unit.PreferredAddress,
							DHCPv4:           unit.DHCP,
							DHCPv6:           unit.DHCPv6,
							DADDisable:       unit.DADDisable,
							MTU:              unit.MTU,
							Description:      unit.Description,
							KeepAddresses:    isVRRPReth,
						})
					}
				}
			}
		} else {
			// Regular interface (non-VLAN)
			if !seen[linuxName] {
				seen[linuxName] = true
				// Collect addresses from all units (using effective config for RETH members)
				var addrs []string
				var dhcpv4, dhcpv6, dadDisable bool
				var primaryAddr, preferredAddr string
				unitMTU := 0
				for _, unit := range effectiveCfg.Units {
					addrs = append(addrs, unit.Addresses...)
					if unit.DHCP {
						dhcpv4 = true
					}
					if unit.DHCPv6 {
						dhcpv6 = true
					}
					if unit.DADDisable {
						dadDisable = true
					}
					if unit.MTU > 0 && (unitMTU == 0 || unit.MTU < unitMTU) {
						unitMTU = unit.MTU
					}
					if unit.PrimaryAddress != "" && primaryAddr == "" {
						primaryAddr = unit.PrimaryAddress
					}
					if unit.PreferredAddress != "" && preferredAddr == "" {
						preferredAddr = unit.PreferredAddress
					}
				}
				// Unit-level MTU (family inet/inet6) overrides interface-level MTU
				mtu := ifCfg.MTU
				if unitMTU > 0 && (mtu == 0 || unitMTU < mtu) {
					mtu = unitMTU
				}
				// VRRP-backed RETH: replace VIP addresses with a
				// link-local base; native VRRP manages the actual VIPs.
				if isVRRPReth {
					addrs = []string{fmt.Sprintf("169.254.%d.%d/32", effectiveCfg.RedundancyGroup, clusterNodeID+1)}
					primaryAddr = ""
					preferredAddr = ""
				}
				// Management interfaces (fxp*, fab*) are bound to vrf-mgmt.
				// Include VRF= in .network so networkctl reconfigure preserves binding.
				vrfName := ""
				// #7515: config.IsManagementIfName is the SSOT. If this drifts
				// from the daemon's management-VRF set, networkctl reconfigure
				// strips a binding the daemon just made (or preserves one it
				// never made).
				if config.IsManagementIfName(ifName) {
					vrfName = "vrf-mgmt"
				}
				result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
					Name:             linuxName,
					MACAddress:       mac,
					OriginalName:     originalName,
					Addresses:        addrs,
					PrimaryAddress:   primaryAddr,
					PreferredAddress: preferredAddr,
					DHCPv4:           dhcpv4,
					DHCPv6:           dhcpv6,
					Disable:          ifCfg.Disable,
					DADDisable:       dadDisable,
					Speed:            ifCfg.Speed,
					Duplex:           ifCfg.Duplex,
					MTU:              mtu,
					Description:      ifCfg.Description,
					KeepAddresses:    isVRRPReth,
					VRFName:          vrfName,
				})
			}
		}
	}
}

// buildFabricBondModels emits networkd bond + member entries for multi-member
// fabric interfaces (vSRX single-member IPVLAN fabric is handled elsewhere).
func buildFabricBondModels(cfg *config.Config, result *CompileResult, seen map[string]bool) {
	// Generate networkd .netdev + .network files for fabric bonds with multiple
	// members. This makes the bond persistent across reboots via systemd-networkd
	// (the routing package also creates the bond via netlink at runtime).
	// Skip vSRX-style fabric (LocalFabricMember set) — the daemon creates an
	// IPVLAN on the single local member; no bond needed.
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		if len(ifCfg.FabricMembers) <= 1 || ifCfg.LocalFabricMember != "" {
			continue
		}
		bondName := ifName
		if !seen[bondName] {
			seen[bondName] = true
			// Collect addresses from fabric interface units
			var addrs []string
			for _, unit := range ifCfg.Units {
				addrs = append(addrs, unit.Addresses...)
			}
			result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
				Name:        bondName,
				IsBond:      true,
				BondMode:    "active-backup",
				Addresses:   addrs,
				Description: ifCfg.Description,
				MTU:         ifCfg.MTU,
				VRFName:     "vrf-mgmt",
			})
		}
		// Member interfaces: .network with Bond= referencing the bond
		for _, member := range ifCfg.FabricMembers {
			memberName := config.LinuxIfName(member)
			if seen[memberName] {
				continue
			}
			seen[memberName] = true
			var mac string
			if iface, err := result.cachedInterfaceByName(memberName); err == nil {
				mac = iface.HardwareAddr.String()
			}
			result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
				Name:       memberName,
				MACAddress: mac,
				BondMaster: bondName,
			})
		}
	}
}

// buildBridgeDomainModels emits bridge .netdev/.network entries for each bridge
// domain and sets BridgeMaster on the VLAN sub-interfaces that belong to one.
func buildBridgeDomainModels(cfg *config.Config, result *CompileResult, seen map[string]bool) {
	// Bridge domains: generate bridge .netdev + .network entries and set
	// BridgeMaster on VLAN sub-interfaces that belong to a bridge domain.
	// Build vlanID → bridge device name map for bridge member assignment.
	vlanToBridge := make(map[int]string)
	for _, bd := range cfg.BridgeDomains {
		bridgeName := "br-" + bd.Name
		for _, vid := range bd.VlanIDs {
			vlanToBridge[vid] = bridgeName
		}
	}

	for _, bd := range cfg.BridgeDomains {
		bridgeName := "br-" + bd.Name
		if seen[bridgeName] {
			continue
		}
		seen[bridgeName] = true

		// Collect IRB addresses from the referenced interface unit
		var addrs []string
		if bd.RoutingInterface != "" {
			// Parse "irb.N" to get unit number
			parts := strings.SplitN(bd.RoutingInterface, ".", 2)
			if len(parts) == 2 {
				irbName := parts[0] // "irb"
				unitNum, _ := strconv.Atoi(parts[1])
				if irbCfg, ok := cfg.Interfaces.Interfaces[irbName]; ok && irbCfg != nil {
					if unit, ok := irbCfg.Units[unitNum]; ok {
						addrs = unit.Addresses
					}
				}
			}
		}

		result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
			Name:      bridgeName,
			IsBridge:  true,
			Addresses: addrs,
		})
	}

	// Set BridgeMaster on VLAN sub-interfaces that are bridge domain members.
	for i, mi := range result.ManagedInterfaces {
		if !isConfiguredVLANSubInterface(mi.Name, cfg) {
			continue
		}
		if idx := strings.IndexByte(mi.Name, '.'); idx >= 0 {
			suffix := mi.Name[idx+1:]
			if vid, err := strconv.Atoi(suffix); err == nil {
				if bridge, ok := vlanToBridge[vid]; ok {
					result.ManagedInterfaces[i].BridgeMaster = bridge
				}
			}
		}
	}
}

// stripUnmanagedInterfaces discovers every system interface and marks the
// unconfigured ones unmanaged: bring them down and remove non-link-local
// addresses so traffic cannot leak through an unconfigured path. Daemon-owned
// devices, the #1922 protected set, and (#1956) leave-alone unmapped NICs are
// skipped.
func stripUnmanagedInterfaces(cfg *config.Config, result *CompileResult, seen map[string]bool) {
	// Discover all system interfaces and mark unconfigured ones as unmanaged.
	// Unmanaged interfaces are brought down and have addresses removed to
	// prevent traffic leaking through unconfigured paths.
	//
	// Skip interfaces created by the daemon itself (VRFs, tunnels, bridges).
	daemonOwned := make(map[string]bool)
	daemonOwned["vrf-mgmt"] = true // implicit management VRF for fxp*/fab*
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType != "forwarding" {
			daemonOwned["vrf-"+ri.Name] = true
		}
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil {
			daemonOwned[ifc.Tunnel.Name] = true
		}
		// Per-unit tunnel interfaces
		for _, unit := range ifc.Units {
			if unit.Tunnel != nil {
				daemonOwned[unit.Tunnel.Name] = true
			}
		}
		if len(ifc.FabricMembers) > 0 {
			daemonOwned[name] = true
		}
		// IPVLAN fabric overlays (fab0, fab1) are daemon-created.
		if ifc.LocalFabricMember != "" {
			daemonOwned[config.LinuxIfName(name)] = true
		}
	}
	for _, bd := range cfg.BridgeDomains {
		daemonOwned["br-"+bd.Name] = true
	}

	// #1922 Item 4 protected set: the management lifeline / fxp0 / explicit
	// management-interface leaf are NEVER brought down or address-stripped by
	// the unmanaged strip, EVEN on an empty/absent/rolled-back config. The
	// set is resolved by the daemon (config-independent, lives in the
	// reconcile path) and merged into the skip map here. OQ-D resolution:
	// the interface is auto-EXEMPTED from the dataplane claim (skipped from
	// the unmanaged strip), while normal mgmt-zone policy still applies when
	// the operator assigns it to a zone in the config. nil resolver (unit
	// tests / non-daemon) leaves pre-#1922 behavior unchanged.
	if protectedInterfaceResolver != nil {
		for name := range protectedInterfaceResolver() {
			if name != "" {
				daemonOwned[name] = true
			}
		}
	}

	// #1956: in device-map mode with unmapped-interface-policy leave-alone
	// (the bare-metal default), NICs that are neither mapped nor protected
	// are INVISIBLE to xpf — never marked Unmanaged, never address-stripped,
	// never brought down. This is the F2 fix: a real host has NICs xpf must
	// not touch (BMC/IPMI shared NIC, storage fabric, the admin's own mgmt
	// path). manage-down reproduces today's claim-all for operators who DO
	// want xpf to own the whole box.
	leaveAloneUnmapped := false
	mappedLinuxNames := make(map[string]bool)
	if dm := cfg.Chassis.DeviceMap; dm.Active() {
		if dm.EffectiveUnmappedPolicy() == config.DeviceMapPolicyLeaveAlone {
			leaveAloneUnmapped = true
		}
		for _, e := range dm.Entries {
			mappedLinuxNames[config.LinuxIfName(e.LogicalName)] = true
		}
	}

	allIfaces, _ := net.Interfaces()
	for _, iface := range allIfaces {
		name := iface.Name
		// Skip loopback, already-managed, and daemon-created interfaces
		if name == "lo" || seen[name] || daemonOwned[name] {
			continue
		}
		// Skip VLAN sub-interfaces of managed parents
		if idx := strings.IndexByte(name, '.'); idx >= 0 {
			if seen[name[:idx]] {
				continue
			}
		}
		// #1956 leave-alone: skip any NIC that is not a mapped logical name
		// (mapped-but-unconfigured NICs still fall through to the normal
		// unmanaged handling so a mapped-but-not-in-a-zone NIC is brought
		// down as before; only genuinely UNMAPPED NICs are left alone).
		if leaveAloneUnmapped && !mappedLinuxNames[name] {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}

		// If this is a daemon-created bond/RETH that's no longer in config,
		// delete the device entirely rather than marking it unmanaged.
		nl, err := result.cachedLinkByIndex(iface.Index)
		if err != nil {
			continue
		}
		if _, isBond := nl.(*netlink.Bond); isBond {
			if err := netlink.LinkDel(nl); err == nil {
				slog.Info("deleted stale bond device", "name", name)
			} else {
				slog.Warn("failed to delete stale bond", "name", name, "err", err)
			}
			continue
		}

		seen[name] = true
		result.ManagedInterfaces = append(result.ManagedInterfaces, networkd.InterfaceConfig{
			Name:       name,
			MACAddress: mac,
			Unmanaged:  true,
		})

		// Bring down and remove all non-link-local addresses immediately.
		// The networkd .network file with ActivationPolicy=always-down
		// ensures it stays down across reboots.
		addrs, _ := netlink.AddrList(nl, netlink.FAMILY_ALL)
		for i := range addrs {
			if addrs[i].IP.IsLinkLocalUnicast() || addrs[i].IP.IsLinkLocalMulticast() {
				continue
			}
			if err := netlink.AddrDel(nl, &addrs[i]); err == nil {
				slog.Info("removed address from unmanaged interface",
					"addr", addrs[i].IPNet, "name", name)
			}
		}
		if err := netlink.LinkSetDown(nl); err == nil {
			slog.Info("brought down unmanaged interface", "name", name)
		}
	}
}

// applyTunnelHostInbound auto-adds HOST_INBOUND_GRE to any security zone
// whose interface carries a configured GRE tunnel's source IP. When a GRE
// tunnel is configured the outer encapsulated packets must reach the
// kernel for decapsulation; without this flag the zone's host-inbound
// policy blocks outer GRE (protocol 47) because it is not explicitly
// listed as a system-service.
//
// Extracted from compileZones as a pure, netlink-free seam (the rest of
// compileZones reconciles host interfaces via netlink and is not
// unit-testable). nil zone / interface map values are skipped: a nil
// *config.ZoneConfig or *config.InterfaceConfig slot is reachable on the
// tolerant/programmatic and HA-peer-sync config paths (#3499, sibling of
// #3492/#3496 — the nil-slot invariant the dataplane SSOT already
// defends, e.g. userspace/zones.go). Without the guards the zone.Interfaces
// and zone.HostInboundTraffic derefs panic the apply-path reconcile.
func applyTunnelHostInbound(dp DataPlane, cfg *config.Config, result *CompileResult) {
	autoFlags := make(map[string]uint32) // zone name → extra flags
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		tunnels := []*config.TunnelConfig{}
		if ifCfg.Tunnel != nil {
			tunnels = append(tunnels, ifCfg.Tunnel)
		}
		for _, unit := range ifCfg.Units {
			if unit.Tunnel != nil {
				tunnels = append(tunnels, unit.Tunnel)
			}
		}
		for _, tun := range tunnels {
			if tun.Source == "" {
				continue
			}
			srcIP := net.ParseIP(tun.Source)
			if srcIP == nil {
				continue
			}
			var flag uint32
			if tun.Mode == "gre" || tun.Mode == "" {
				flag = HostInboundGRE
			}
			if flag == 0 {
				continue
			}
			// Find which zone's interface carries this tunnel source IP.
			for zoneName, zone := range cfg.Security.Zones {
				if zone == nil {
					continue
				}
				for _, ifRef := range zone.Interfaces {
					_, cn, un, _ := resolveInterfaceRef(ifRef, cfg)
					ic, ok := cfg.Interfaces.Interfaces[cn]
					if !ok || ic == nil {
						continue
					}
					u, ok := ic.Units[un]
					if !ok {
						continue
					}
					for _, addr := range u.Addresses {
						ip, _, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if ip.Equal(srcIP) {
							autoFlags[zoneName] |= flag
						}
					}
				}
			}
		}
	}
	for zoneName, flags := range autoFlags {
		zid, ok := result.ZoneIDs[zoneName]
		if !ok {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		var existing uint32
		if zone.HostInboundTraffic != nil {
			for _, svc := range zone.HostInboundTraffic.SystemServices {
				if f, ok := HostInboundServiceFlags[svc]; ok {
					existing |= f
				}
			}
			for _, proto := range zone.HostInboundTraffic.Protocols {
				if f, ok := HostInboundProtocolFlags[proto]; ok {
					existing |= f
				}
			}
		}
		if existing&flags != flags {
			merged := existing | flags
			zc := ZoneConfig{HostInbound: merged}
			if zone.TCPRst {
				zc.TCPRst = 1
			}
			dp.SetZoneConfig(zid, zc)
			slog.Info("auto-added host-inbound for tunnel transport",
				"zone", zoneName, "flags", fmt.Sprintf("0x%x", flags))
		}
	}
}

func compileScreenProfiles(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	var maxScreenID uint32
	for name, profile := range cfg.Security.Screen {
		sid, ok := result.ScreenIDs[name]
		if !ok {
			continue
		}

		sc := buildScreenConfig(
			profile,
			cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie",
		)

		if err := dp.SetScreenConfig(uint32(sid), sc); err != nil {
			return fmt.Errorf("set screen config %s (id=%d): %w", name, sid, err)
		}
		if uint32(sid) > maxScreenID {
			maxScreenID = uint32(sid)
		}

		if !isValidationPass(dp) {
			slog.Info("screen profile compiled",
				"name", name, "id", sid,
				"flags", fmt.Sprintf("0x%x", sc.Flags),
				"syn_thresh", sc.SynFloodThresh,
				"icmp_thresh", sc.ICMPFloodThresh,
				"udp_thresh", sc.UDPFloodThresh)
		}
	}

	// Zero screen config entries above the highest used ID.
	dp.ZeroStaleScreenConfigs(maxScreenID)

	return nil
}

func buildScreenConfig(profile *config.ScreenProfile, synCookie bool) ScreenConfig {
	var sc ScreenConfig

	if profile == nil {
		return sc
	}

	if profile.TCP.Land {
		sc.Flags |= ScreenLandAttack
	}
	if profile.TCP.SynFin {
		sc.Flags |= ScreenTCPSynFin
	}
	if profile.TCP.NoFlag {
		sc.Flags |= ScreenTCPNoFlag
	}
	if profile.TCP.FinNoAck {
		sc.Flags |= ScreenTCPFinNoAck
	}
	if profile.TCP.WinNuke {
		sc.Flags |= ScreenWinNuke
	}
	if profile.TCP.SynFrag {
		sc.Flags |= ScreenSynFrag
	}
	if profile.IP.TearDrop {
		sc.Flags |= ScreenTearDrop
	}
	if profile.TCP.SynFlood != nil {
		// SYN-flood screening is armed whenever the operator configures
		// `tcp syn-flood`, even without an explicit attack-threshold. The
		// config compiler seeds the Junos default (200 SYN seg/s) at parse
		// time (defaultSynFloodAttackThreshold in pkg/config); this gate is
		// defensive so a SynFloodConfig that reaches the dataplane with a
		// zero/unset attack-threshold still arms the screen (and syn-cookie)
		// at the default rather than silently disabling protection (#3024).
		sc.Flags |= ScreenSynFlood
		thresh := profile.TCP.SynFlood.AttackThreshold
		if thresh <= 0 {
			thresh = defaultSynFloodAttackThreshold
		}
		sc.SynFloodThresh = uint32(thresh)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			sc.SynFloodSrcThresh = uint32(profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			sc.SynFloodDstThresh = uint32(profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			sc.SynFloodTimeout = uint32(profile.TCP.SynFlood.Timeout)
		}
		if synCookie {
			sc.Flags |= ScreenSynCookie
		}
	}
	if profile.ICMP.PingDeath {
		sc.Flags |= ScreenPingOfDeath
	}
	if profile.ICMP.FloodThreshold > 0 {
		sc.Flags |= ScreenICMPFlood
		sc.ICMPFloodThresh = uint32(profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		sc.Flags |= ScreenIPSourceRoute
	}
	if profile.UDP.FloodThreshold > 0 {
		sc.Flags |= ScreenUDPFlood
		sc.UDPFloodThresh = uint32(profile.UDP.FloodThreshold)
	}
	if profile.TCP.PortScanThreshold > 0 {
		sc.Flags |= ScreenPortScan
		sc.PortScanThresh = uint32(profile.TCP.PortScanThreshold)
	}
	if profile.IP.IPSweepThreshold > 0 {
		sc.Flags |= ScreenIPSweep
		sc.IPSweepThresh = uint32(profile.IP.IPSweepThreshold)
	}
	if profile.LimitSession.SourceIPBased > 0 {
		sc.Flags |= ScreenSessionLimitSrc
		sc.SessionLimitSrc = uint32(profile.LimitSession.SourceIPBased)
	}
	if profile.LimitSession.DestinationIPBased > 0 {
		sc.Flags |= ScreenSessionLimitDst
		sc.SessionLimitDst = uint32(profile.LimitSession.DestinationIPBased)
	}

	return sc
}

// validateZoneScreenReferences resolves EVERY security zone's `screen-profile`
// reference before any zone is programmed (#4960 / #6894 r5).
//
// WHY THIS IS SEPARATE FROM compileScreenProfiles. That phase compiles the
// profile SET and is already in the pre-pass table; it is not what fails here.
// What fails is a zone's reference TO a profile that the set does not contain,
// and that reference is resolved per zone, inside the mutating loop.
//
// TWO lookups resolve it, not one, and this checks BOTH because either aborts
// the compile:
//
//   - buildZoneConfig resolves against result.ScreenIDs (the COMPILED id map)
//     to fill ZoneConfig.ScreenProfileID, immediately before SetZoneConfig; and
//   - mapZoneInterface resolves against cfg.Security.Screen (the CONFIG map) to
//     build the per-interface screen flags, after several host mutations.
//
// They normally agree — assignScreenIDs derives one from the other — but they
// are distinct gates and a fix that hoisted only the first would still abort
// mid-loop on a VLAN sub-interface. Checking both keeps this sweep a faithful
// pre-image of what the loop enforces.
//
// PURE by construction: it takes no DataPlane and writes nothing. That is the
// property that makes it safe to run before the mutation point, and it is why
// the pre-pass can run it against the discarding shim as well.
//
// Zones are visited in SORTED order, deliberately. programZoneMaps ranges a Go
// map, so its abort order is unspecified; a config with two bad references
// would report whichever the runtime happened to reach first, differing run to
// run and between the pre-pass and the real pass. Sorting makes the reported
// offender deterministic and identical on both HA nodes.
func validateZoneScreenReferences(cfg *config.Config, result *CompileResult) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		zone := cfg.Security.Zones[name]
		// A nil zone slot is reachable on the tolerant / HA-peer-sync paths and
		// programZoneMaps skips it, so skip it here too: this sweep must reject
		// exactly what the loop rejects, never more.
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		if result != nil {
			if _, ok := result.ScreenIDs[zone.ScreenProfile]; !ok {
				return fmt.Errorf("screen profile %q not found for zone %q",
					zone.ScreenProfile, name)
			}
		}
		if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
			return fmt.Errorf("screen profile %q not found for zone %q",
				zone.ScreenProfile, name)
		}
	}
	return nil
}
