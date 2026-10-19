package daemon

import (
	"log/slog"
	"net/netip"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// frrHADemotionState is a render-time snapshot of which configured RETH RGs
// this node owns. It is deliberately derived from cluster state, not the
// combined rg_active state: cluster ownership changes before VRRP has finished
// removing the virtual addresses, and dynamic routing must stop on that edge.
type frrHADemotionState struct {
	active         map[int]bool
	rethInterfaces map[int]map[string]struct{}
	globalActive   bool
}

func newFRRHADemotionState(d *Daemon, cfg *config.Config) *frrHADemotionState {
	if d == nil || d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	state := &frrHADemotionState{
		active:         make(map[int]bool),
		rethInterfaces: make(map[int]map[string]struct{}),
	}
	owners := cfg.RethRGOwners()
	for name, rgID := range owners {
		state.active[rgID] = d.cluster.IsLocalPrimary(rgID)
		if state.rethInterfaces[rgID] == nil {
			state.rethInterfaces[rgID] = make(map[string]struct{})
		}
		addHAInterfaceName(cfg, state.rethInterfaces[rgID], name)
		// #15060: unit refs (reth0.80) belong to the same RG as the base;
		// otherwise they miss the set and follow RG0 instead of the owner.
		if ifc, ok := config.LookupInterface(cfg, name); ok {
			addHAInterfaceUnitNames(cfg, state.rethInterfaces[rgID], ifc)
		}
	}
	// A global/loopback peering has no data-RETH address from which to infer a
	// group. It follows RG0 when configured; clusters without RG0 retain the
	// established "primary for any group" ownership fallback.
	if primary, known := d.cluster.LocalGroupPrimary(0); known {
		state.globalActive = primary
	} else {
		state.globalActive = d.cluster.IsLocalPrimaryAny()
	}
	return state
}

// filterProtocols returns copies of protocol config with inactive-RG interface
// participation and peerings removed. Removing a neighbor from ApplyFull's
// managed section resets the BGP session and withdraws its advertisements;
// removing an IGP's RETH interface withdraws the corresponding adjacency and
// its originated routes. Config objects remain immutable across the render.
func (s *frrHADemotionState) filterProtocols(cfg *config.Config, protocols config.ProtocolsConfig, instanceInterfaces []string) config.ProtocolsConfig {
	if s == nil {
		return protocols
	}
	groups := s.groupsForInterfaces(cfg, instanceInterfaces)
	protocols.OSPF = s.filterOSPF(cfg, protocols.OSPF, groups)
	protocols.OSPFv3 = s.filterOSPFv3(cfg, protocols.OSPFv3, groups)
	protocols.RIP = s.filterRIP(cfg, protocols.RIP, groups)
	protocols.ISIS = s.filterISIS(cfg, protocols.ISIS, groups)
	if protocols.BGP != nil {
		protocols.BGP = s.filterBGP(cfg, protocols.BGP, groups)
	}
	return protocols
}

// filterStaticRoutes drops (or prunes next-hops of) static routes whose
// egress belongs to a redundancy group this node does not own (#15734).
//
// A static route's egress is attributed two ways:
//   - an explicit next-hop interface (operator-qualified, or the IPv6
//     next-hop interface inferred from the connected prefixes) names the
//     egress directly — but ONLY a RETH-attributed interface is RG-scoped
//     (#15783); a node-local interface exists on both nodes regardless of
//     RG0, so it never demotes a static hop;
//   - a next-hop ADDRESS inside an egress interface's connected prefix
//     (configured Addresses or vrrp-group VirtualAddresses, #15783)
//     attributes the route even when no interface was named — that is
//     how FRR itself decides the route is active (the zebra connected
//     route must exist), so it is the same fact the FIB build consumes.
//
// Routes with no attributable egress (next-table leaks, discard/reject)
// are kept: they do not depend on a RETH address this node may not hold.
//
// Why this exists: on a demoted node every static route used to stay in
// the FRR managed section forever. Zebra then marked each one inactive
// (its egress connected prefix is gone with the VIPs) and selected the
// cluster-mode blackhole default instead — so `show ipv6 route` read as
// a deliberate discard while the node was expected to fabric-redirect.
// Symmetrically, when only SOME RGs move (the per-RG failover the gate
// drives), the new owner must actually gain the WAN statics: with them
// filtered here, promotion re-renders them and zebra activates them the
// moment the VIPs land. Before this filter, the loss cluster's RG1/RG2
// split left node1 owning the LAN (RG2) with every WAN v6 static
// stranded inactive, so LAN->WAN IPv6 transit blackholed on the kernel
// default while neighbor recovery (NA) succeeded.
func (s *frrHADemotionState) filterStaticRoutes(cfg *config.Config, routes []*config.StaticRoute, v6NextHopInterfaces map[string]string, instanceInterfaces []string) []*config.StaticRoute {
	if s == nil || len(routes) == 0 {
		return routes
	}
	instanceGroups := s.groupsForInterfaces(cfg, instanceInterfaces)
	filtered := make([]*config.StaticRoute, 0, len(routes))
	for _, route := range routes {
		if route == nil {
			filtered = append(filtered, route)
			continue
		}
		if route.Discard || route.Reject || route.NextTable != "" || len(route.NextHops) == 0 {
			filtered = append(filtered, route)
			continue
		}
		kept := make([]config.NextHopEntry, 0, len(route.NextHops))
		for _, hop := range route.NextHops {
			if s.staticHopActive(cfg, hop, v6NextHopInterfaces, instanceGroups) {
				kept = append(kept, hop)
			}
		}
		if len(kept) == 0 {
			continue
		}
		if len(kept) == len(route.NextHops) {
			filtered = append(filtered, route)
			continue
		}
		pruned := *route
		pruned.NextHops = kept
		filtered = append(filtered, &pruned)
	}
	return filtered
}

// staticHopActive reports whether one static next-hop's egress is owned
// by an active RG (or is not RETH-attributable at all, #15783).
//
// The 'not RETH-attributable → active' contract binds THIS function;
// the shared inactiveInterface helper cannot express it for statics: its
// !matched fallthrough follows instance groups and then RG0 (globalActive),
// which is correct for dynamic PROTOCOL peerings/IGPs (a non-RETH peering
// has no data-RETH address and must follow cluster control ownership) but
// wrong for a static route whose egress is a node-local connected
// interface — those interfaces exist on BOTH nodes regardless of RG0.
// So statics resolve interface attribution STRICTLY: only an interface
// matched to a configured RETH RG (base/unit refs, canonicalised) is
// RG-scoped; anything else (plain ge/xe/lo, undeclared) stays active.
// instanceGroups/RG0 never demote a static hop.
//
// Address attribution mirrors that split: the RETH walk enumerates each
// unit's configured Addresses AND its vrrp-group VirtualAddresses'
// prefixes (#15783 — a next-hop inside a VIP subnet egresses via the RETH
// even when no configured host address covers it). The fallback scan then
// attributes a hop contained in a NON-RETH connected prefix to that
// node-local interface (active), so a RETH prefix lying outside this
// node's reachable ordering cannot swallow a plain-interface hop whose
// zebra connected route exists here.
func (s *frrHADemotionState) staticHopActive(cfg *config.Config, hop config.NextHopEntry, v6NextHopInterfaces map[string]string, instanceGroups []int) bool {
	iface := hop.Interface
	if iface == "" && v6NextHopInterfaces != nil {
		iface = v6NextHopInterfaces[hop.Address]
	}
	if iface != "" {
		return !s.staticInactiveInterface(cfg, iface)
	}
	addr, err := netip.ParseAddr(hop.Address)
	if err != nil {
		return true // unparseable: not attributable, keep (render validates)
	}
	rethAttribution := ""
	localAttribution := false
	if cfg == nil {
		return true
	}
	// Scan RETH-owned interfaces first (deterministic RG order so
	// overlapping prefixes resolve stably), then require that no
	// node-local (non-RETH) connected prefix claims the hop instead.
	owners := cfg.RethRGOwners()
	rgIDs := make([]int, 0, len(owners))
	byRG := make(map[int][]string)
	for name, rgID := range owners {
		if _, seen := byRG[rgID]; !seen {
			rgIDs = append(rgIDs, rgID)
		}
		byRG[rgID] = append(byRG[rgID], name)
	}
	sort.Ints(rgIDs)
	for _, rgID := range rgIDs {
		for _, name := range byRG[rgID] {
			ifc := cfg.Interfaces.Interfaces[name]
			if ifc == nil {
				continue
			}
			for _, unit := range ifc.Units {
				if unitAddressOrVRRPContains(unit, addr) {
					rethAttribution = name
					if s.active[rgID] {
						return true
					}
					// Inactive owner found; a later RETH owner could
					// still be active under an overlap, so keep scanning
					// RETH owners before consulting node-local prefixes.
					break
				}
			}
		}
	}
	// A hop in any non-RETH connected prefix (configured address or
	// vrrp-group virtual address of a plain interface) is node-local.
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if _, isRETH := owners[name]; isRETH {
			continue
		}
		for _, unit := range ifc.Units {
			if unitAddressOrVRRPContains(unit, addr) {
				localAttribution = true
				break
			}
		}
		if localAttribution {
			break
		}
	}
	if localAttribution {
		// #15783 node-local override: a hop also covered by a non-RETH
		// connected prefix resolves via that node-local connected route
		// on this node even when an inactive RG's RETH prefix covers it
		// too, so zebra can resolve it here; keep it.
		return true
	}
	if rethAttribution != "" {
		return false // claimed only by RETH owner(s), none active (active returned above)
	}
	return true // no prefix claims it: not RG-scoped
}

// unitAddressOrVRRPContains reports whether addr lies in any configured
// address prefix or vrrp-group virtual-address prefix of unit (#15783).
// Virtual addresses may be bare host literals (tolerant load before
// normalization); those contribute their host prefix. Prefix length is
// NOT inherited from a sibling unit address — that would invent a
// subnet the operator never configured.
func unitAddressOrVRRPContains(unit *config.InterfaceUnit, addr netip.Addr) bool {
	if unit == nil {
		return false
	}
	for _, cidr := range unit.Addresses {
		if prefixContainsAddr(cidr, addr) {
			return true
		}
	}
	for _, group := range unit.VRRPGroups {
		if group == nil {
			continue
		}
		for _, vip := range group.VirtualAddresses {
			if prefixContainsAddr(vip, addr) {
				return true
			}
		}
	}
	return false
}

// prefixContainsAddr parses value as a prefix (bare literals become host
// prefixes) and reports family-matching containment.
func prefixContainsAddr(value string, addr netip.Addr) bool {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Is4() == addr.Is4() && prefix.Masked().Contains(addr)
	}
	if host, err := netip.ParseAddr(value); err == nil {
		return host.Is4() == addr.Is4() && host == addr
	}
	return false
}

// staticInactiveInterface is the static-route-only interface test: true
// iff name is attributable to a configured RETH RG that is not locally
// active. Unmatched interfaces are node-local and never inactive here,
// REGARDLESS of RG0/globalActive or the route's routing-instance groups
// — the #15783 contract. (Dynamic protocols keep inactiveInterface.)
func (s *frrHADemotionState) staticInactiveInterface(cfg *config.Config, name string) bool {
	matched := false
	for rgID, interfaces := range s.rethInterfaces {
		if !haInterfaceRefsMatch(cfg, interfaces, []string{name}) {
			continue
		}
		matched = true
		if s.active[rgID] {
			return false
		}
	}
	return matched
}

func (s *frrHADemotionState) inactiveInterface(cfg *config.Config, name string, instanceGroups []int) bool {
	matched := false
	for rgID, interfaces := range s.rethInterfaces {
		if !haInterfaceRefsMatch(cfg, interfaces, []string{name}) {
			continue
		}
		matched = true
		if s.active[rgID] {
			return false
		}
	}
	if matched {
		return true
	}
	if len(instanceGroups) != 0 {
		return !anyHARGActive(s.active, instanceGroups)
	}
	return !s.globalActive
}

func (s *frrHADemotionState) filterOSPF(cfg *config.Config, source *config.OSPFConfig, instanceGroups []int) *config.OSPFConfig {
	if source == nil {
		return nil
	}
	filtered := *source
	filtered.Areas = make([]*config.OSPFArea, 0, len(source.Areas))
	for _, area := range source.Areas {
		if area == nil {
			filtered.Areas = append(filtered.Areas, nil)
			continue
		}
		copyArea := *area
		copyArea.Interfaces = nil
		for _, iface := range area.Interfaces {
			if iface == nil || !s.inactiveInterface(cfg, iface.Name, instanceGroups) {
				copyArea.Interfaces = append(copyArea.Interfaces, iface)
			}
		}
		if len(copyArea.Interfaces) != 0 || len(copyArea.VirtualLinks) != 0 {
			filtered.Areas = append(filtered.Areas, &copyArea)
		}
	}
	return &filtered
}

func (s *frrHADemotionState) filterOSPFv3(cfg *config.Config, source *config.OSPFv3Config, instanceGroups []int) *config.OSPFv3Config {
	if source == nil {
		return nil
	}
	filtered := *source
	filtered.Areas = make([]*config.OSPFv3Area, 0, len(source.Areas))
	for _, area := range source.Areas {
		if area == nil {
			filtered.Areas = append(filtered.Areas, nil)
			continue
		}
		copyArea := *area
		copyArea.Interfaces = nil
		for _, iface := range area.Interfaces {
			if iface == nil || !s.inactiveInterface(cfg, iface.Name, instanceGroups) {
				copyArea.Interfaces = append(copyArea.Interfaces, iface)
			}
		}
		if len(copyArea.Interfaces) != 0 {
			filtered.Areas = append(filtered.Areas, &copyArea)
		}
	}
	return &filtered
}

func (s *frrHADemotionState) filterRIP(cfg *config.Config, source *config.RIPConfig, instanceGroups []int) *config.RIPConfig {
	if source == nil {
		return nil
	}
	filtered := *source
	filtered.Interfaces = filterFRRHAInterfaceNames(cfg, s, source.Interfaces, instanceGroups)
	filtered.Passive = filterFRRHAInterfaceNames(cfg, s, source.Passive, instanceGroups)
	return &filtered
}

func (s *frrHADemotionState) filterISIS(cfg *config.Config, source *config.ISISConfig, instanceGroups []int) *config.ISISConfig {
	if source == nil {
		return nil
	}
	filtered := *source
	filtered.Interfaces = nil
	for _, iface := range source.Interfaces {
		if iface == nil || !s.inactiveInterface(cfg, iface.Name, instanceGroups) {
			filtered.Interfaces = append(filtered.Interfaces, iface)
		}
	}
	return &filtered
}

func filterFRRHAInterfaceNames(cfg *config.Config, state *frrHADemotionState, source []string, instanceGroups []int) []string {
	filtered := make([]string, 0, len(source))
	for _, name := range source {
		if !state.inactiveInterface(cfg, name, instanceGroups) {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func (s *frrHADemotionState) groupsForInterfaces(cfg *config.Config, names []string) []int {
	var groups []int
	for rgID, interfaces := range s.rethInterfaces {
		if len(names) == 0 {
			break
		}
		if haInterfaceRefsMatch(cfg, interfaces, names) {
			groups = append(groups, rgID)
		}
	}
	return groups
}

func (s *frrHADemotionState) filterBGP(cfg *config.Config, source *config.BGPConfig, instanceGroups []int) *config.BGPConfig {
	filtered := *source
	filtered.Neighbors = make([]*config.BGPNeighbor, 0, len(source.Neighbors))
	neighborGroups := s.globalBGPNeighborGroups(cfg, source)
	for _, neighbor := range source.Neighbors {
		if neighbor == nil {
			continue
		}
		groups := neighborGroups[neighbor.Address]
		if len(groups) != 0 {
			if anyHARGActiveMap(s.active, groups) {
				filtered.Neighbors = append(filtered.Neighbors, neighbor)
			}
			continue
		}
		if len(instanceGroups) != 0 {
			if anyHARGActive(s.active, instanceGroups) {
				filtered.Neighbors = append(filtered.Neighbors, neighbor)
			}
			continue
		}
		if s.globalActive {
			filtered.Neighbors = append(filtered.Neighbors, neighbor)
		}
	}
	return &filtered
}

func (s *frrHADemotionState) globalBGPNeighborGroups(cfg *config.Config, bgp *config.BGPConfig) map[string]map[int]struct{} {
	groups := make(map[string]map[int]struct{})
	owners := cfg.RethRGOwners()
	for rgID := range s.rethInterfaces {
		addresses := make(map[netip.Addr]struct{})
		var prefixes []netip.Prefix
		for name, owner := range owners {
			if owner != rgID {
				continue
			}
			iface := cfg.Interfaces.Interfaces[name]
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				for _, address := range unit.Addresses {
					addHALocalAddress(address, addresses, &prefixes)
				}
				for _, vrrpGroup := range unit.VRRPGroups {
					if vrrpGroup == nil {
						continue
					}
					for _, address := range vrrpGroup.VirtualAddresses {
						addHALocalAddress(address, addresses, &prefixes)
					}
				}
			}
		}
		for _, neighbor := range bgpNeighborsForRG(bgp, addresses, prefixes) {
			if groups[neighbor] == nil {
				groups[neighbor] = make(map[int]struct{})
			}
			groups[neighbor][rgID] = struct{}{}
		}
	}
	return groups
}

func anyHARGActive(active map[int]bool, groups []int) bool {
	for _, rgID := range groups {
		if active[rgID] {
			return true
		}
	}
	return false
}

func anyHARGActiveMap(active map[int]bool, groups map[int]struct{}) bool {
	for rgID := range groups {
		if active[rgID] {
			return true
		}
	}
	return false
}

// scheduleFRRHAReconcile applies the current HA-filtered FRR render off the
// cluster watcher. It re-reads config and ownership only after acquiring the
// shared apply semaphore, so queued edges coalesce naturally to latest state.
func (d *Daemon) scheduleFRRHAReconcile(reason string) {
	if d == nil || d.cluster == nil || d.frr == nil || d.store == nil || d.isResetting() {
		return
	}
	ctx := d.applyCancelCtx()
	go func() {
		if err := d.applySem.Acquire(ctx, 1); err != nil {
			return
		}
		defer d.applySem.Release(1)
		if d.isResetting() {
			return
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			return
		}
		err := d.applyFRRConfig(d.assembleFRRConfig(cfg, d.commitOverlayForConfig(cfg)))
		if err != nil {
			slog.Warn("HA routing reconcile did not fully converge; FRR retry remains armed",
				"reason", reason, "err", err)
		}
	}()
}
