package daemon

import (
	"log/slog"
	"net/netip"

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
