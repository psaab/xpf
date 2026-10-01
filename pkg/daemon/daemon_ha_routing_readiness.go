package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const haRoutingStatusTimeout = 2 * time.Second

type haRoutingRequirement struct {
	protocol    string
	routeProto  string
	routeFamily int
	tableID     int
	vrf         string
	interfaces  []string
	neighbors   []string
}

type haRoutingAdjacencies struct {
	ospf   map[string][]frr.OSPFNeighbor
	ospfV3 map[string][]frr.OSPFNeighbor
	isis   map[string][]frr.ISISAdjacency
	bgp    map[string][]frr.BGPPeerSummary
}

// dynamicRoutingReady requires evidence independently for every dynamic
// protocol/table that can serve the RG. A route learned by another protocol or
// in another table cannot make this RG's protocol ready.
func dynamicRoutingReady(requirements []haRoutingRequirement, routes []routing.LearnedRoute, adjacencies haRoutingAdjacencies) (bool, []string) {
	var reasons []string
	for _, requirement := range requirements {
		if hasLearnedRoute(requirement, routes) || hasEstablishedAdjacency(requirement, adjacencies) {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("%s routing not ready in table %d: no learned route or established adjacency", requirement.protocol, requirement.tableID))
	}
	return len(reasons) == 0, reasons
}

func hasLearnedRoute(requirement haRoutingRequirement, routes []routing.LearnedRoute) bool {
	for _, route := range routes {
		if route.TableID == requirement.tableID && route.Protocol == requirement.routeProto &&
			(requirement.routeFamily == 0 || route.Family == requirement.routeFamily) {
			return true
		}
	}
	return false
}

func hasEstablishedAdjacency(requirement haRoutingRequirement, status haRoutingAdjacencies) bool {
	switch requirement.protocol {
	case "ospf":
		for _, neighbor := range status.ospf[requirement.vrf] {
			if strings.HasPrefix(strings.ToLower(neighbor.State), "full") && hasName(requirement.interfaces, neighbor.Interface) {
				return true
			}
		}
	case "ospfv3":
		for _, neighbor := range status.ospfV3[requirement.vrf] {
			if strings.HasPrefix(strings.ToLower(neighbor.State), "full") && hasName(requirement.interfaces, neighbor.Interface) {
				return true
			}
		}
	case "isis":
		for _, adjacency := range status.isis[requirement.vrf] {
			if !adjacency.Malformed && strings.EqualFold(adjacency.State, "up") && hasName(requirement.interfaces, adjacency.Interface) {
				return true
			}
		}
	case "bgp":
		for _, peer := range status.bgp[requirement.vrf] {
			if strings.EqualFold(peer.State, "Established") && hasName(requirement.neighbors, peer.Neighbor) {
				return true
			}
		}
	}
	return false
}

func hasName(names []string, candidate string) bool {
	for _, name := range names {
		if name == candidate || config.LinuxIfName(name) == config.LinuxIfName(candidate) {
			return true
		}
	}
	return false
}

func (d *Daemon) haRoutingTransferReadiness(rgID int) (bool, []string) {
	if d == nil || d.store == nil {
		return true, nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || allowsDegradedRoutingTakeover(cfg, rgID) {
		return true, nil
	}
	requirements := haRoutingRequirementsForRG(cfg, rgID)
	if len(requirements) == 0 {
		return true, nil
	}

	tableIDs := make([]int, 0, len(requirements))
	seenTables := make(map[int]struct{}, len(requirements))
	for _, requirement := range requirements {
		if requirement.tableID <= 0 {
			continue
		}
		if _, ok := seenTables[requirement.tableID]; ok {
			continue
		}
		seenTables[requirement.tableID] = struct{}{}
		tableIDs = append(tableIDs, requirement.tableID)
	}
	sort.Ints(tableIDs)
	routes, routeErr := routing.ImportLearnedRoutes(tableIDs)
	if routeErr != nil {
		routes = nil
	}

	// Routes are sufficient evidence. Query FRR only for protocol requirements
	// that still lack a route, and bound every vtysh call so an explicit
	// failover cannot wait indefinitely on a wedged routing process.
	adjacencies := haRoutingAdjacencies{
		ospf:   make(map[string][]frr.OSPFNeighbor),
		ospfV3: make(map[string][]frr.OSPFNeighbor),
		isis:   make(map[string][]frr.ISISAdjacency),
		bgp:    make(map[string][]frr.BGPPeerSummary),
	}
	needed := make(map[string]map[string]struct{})
	for _, requirement := range requirements {
		if hasLearnedRoute(requirement, routes) {
			continue
		}
		if needed[requirement.vrf] == nil {
			needed[requirement.vrf] = make(map[string]struct{})
		}
		needed[requirement.vrf][requirement.protocol] = struct{}{}
	}
	var statusErrors []string
	if d.frr != nil && len(needed) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), haRoutingStatusTimeout)
		defer cancel()
		vrfs := make([]string, 0, len(needed))
		for vrf := range needed {
			vrfs = append(vrfs, vrf)
		}
		sort.Strings(vrfs)
		for _, vrf := range vrfs {
			for _, protocol := range []string{"bgp", "isis", "ospf", "ospfv3"} {
				if _, ok := needed[vrf][protocol]; !ok {
					continue
				}
				var statusErr error
				switch protocol {
				case "bgp":
					adjacencies.bgp[vrf], statusErr = d.frr.GetBGPSummaryVRF(ctx, vrf)
				case "isis":
					adjacencies.isis[vrf], statusErr = d.frr.GetISISAdjacencyVRF(ctx, vrf)
				case "ospf":
					adjacencies.ospf[vrf], statusErr = d.frr.GetOSPFNeighborsVRF(ctx, vrf)
				case "ospfv3":
					adjacencies.ospfV3[vrf], statusErr = d.frr.GetOSPFv3NeighborsVRF(ctx, vrf)
				}
				if statusErr != nil {
					statusErrors = append(statusErrors, fmt.Sprintf("%s status unavailable for routing-instance %q: %v", protocol, vrf, statusErr))
				}
			}
		}
	}
	ready, reasons := dynamicRoutingReady(requirements, routes, adjacencies)
	if ready {
		return true, nil
	}
	if routeErr != nil {
		reasons = append(reasons, "learned route status unavailable: "+routeErr.Error())
	}
	reasons = append(reasons, statusErrors...)
	return false, reasons
}

func allowsDegradedRoutingTakeover(cfg *config.Config, rgID int) bool {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg != nil && rg.ID == rgID {
			return rg.AllowDegradedRoutingTakeover
		}
	}
	return false
}

func haRoutingRequirementsForRG(cfg *config.Config, rgID int) []haRoutingRequirement {
	if cfg == nil || rgID < 0 {
		return nil
	}
	ifaces := make(map[string]struct{})
	localAddresses := make(map[netip.Addr]struct{})
	localPrefixes := make([]netip.Prefix, 0)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || ifc.RedundancyGroup != rgID {
			continue
		}
		addHAInterfaceName(cfg, ifaces, ifc.Name)
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, value := range unit.Addresses {
				addHALocalAddress(value, localAddresses, &localPrefixes)
			}
			for _, group := range unit.VRRPGroups {
				if group == nil {
					continue
				}
				for _, value := range group.VirtualAddresses {
					addHALocalAddress(value, localAddresses, &localPrefixes)
				}
			}
		}
	}
	if len(ifaces) == 0 {
		return nil
	}

	requirements := make(map[string]*haRoutingRequirement)
	add := func(protocol, routeProto string, routeFamily int, vrf string, tableID int, interfaces, neighbors []string) {
		key := protocol + "\x00" + vrf + "\x00" + strconv.Itoa(tableID)
		requirement := requirements[key]
		if requirement == nil {
			requirement = &haRoutingRequirement{
				protocol: protocol, routeProto: routeProto, routeFamily: routeFamily, tableID: tableID, vrf: vrf,
			}
			requirements[key] = requirement
		}
		requirement.interfaces = appendUnique(requirement.interfaces, interfaces...)
		requirement.neighbors = appendUnique(requirement.neighbors, neighbors...)
	}

	mainTable := int(unix.RT_TABLE_MAIN)
	if cfg.Protocols.OSPF != nil {
		interfaces := ospfInterfaceNames(cfg.Protocols.OSPF)
		if matched := matchingHAInterfaces(cfg, ifaces, interfaces); len(matched) > 0 {
			add("ospf", "ospf", netlink.FAMILY_V4, "", mainTable, matched, nil)
		}
	}
	if cfg.Protocols.OSPFv3 != nil {
		interfaces := ospfV3InterfaceNames(cfg.Protocols.OSPFv3)
		if matched := matchingHAInterfaces(cfg, ifaces, interfaces); len(matched) > 0 {
			add("ospfv3", "ospf", netlink.FAMILY_V6, "", mainTable, matched, nil)
		}
	}
	if cfg.Protocols.ISIS != nil {
		interfaces := isisInterfaceNames(cfg.Protocols.ISIS)
		if matched := matchingHAInterfaces(cfg, ifaces, interfaces); len(matched) > 0 {
			add("isis", "isis", 0, "", mainTable, matched, nil)
		}
	}
	if cfg.Protocols.RIP != nil {
		interfaces := matchingHAInterfaces(cfg, ifaces, cfg.Protocols.RIP.Interfaces)
		if len(interfaces) > 0 {
			add("rip", "rip", 0, "", mainTable, interfaces, nil)
		}
	}
	if cfg.Protocols.BGP != nil {
		neighbors := bgpNeighborsForRG(cfg.Protocols.BGP, localAddresses, localPrefixes)
		if len(neighbors) > 0 {
			add("bgp", "bgp", 0, "", mainTable, nil, neighbors)
		}
	}

	for _, instance := range cfg.RoutingInstances {
		if instance == nil || !haInterfaceRefsMatch(cfg, ifaces, instance.Interfaces) {
			continue
		}
		tableID := instance.TableID
		vrf := instance.Name
		if instance.OSPF != nil {
			interfaces := matchingHAInterfaces(cfg, ifaces, ospfInterfaceNames(instance.OSPF))
			if len(interfaces) > 0 {
				add("ospf", "ospf", netlink.FAMILY_V4, vrf, tableID, interfaces, nil)
			}
		}
		if instance.OSPFv3 != nil {
			interfaces := matchingHAInterfaces(cfg, ifaces, ospfV3InterfaceNames(instance.OSPFv3))
			if len(interfaces) > 0 {
				add("ospfv3", "ospf", netlink.FAMILY_V6, vrf, tableID, interfaces, nil)
			}
		}
		if instance.ISIS != nil {
			interfaces := matchingHAInterfaces(cfg, ifaces, isisInterfaceNames(instance.ISIS))
			if len(interfaces) > 0 {
				add("isis", "isis", 0, vrf, tableID, interfaces, nil)
			}
		}
		if instance.RIP != nil {
			interfaces := matchingHAInterfaces(cfg, ifaces, instance.RIP.Interfaces)
			if len(interfaces) > 0 {
				add("rip", "rip", 0, vrf, tableID, interfaces, nil)
			}
		}
		if instance.BGP != nil && len(instance.BGP.Neighbors) > 0 {
			neighbors := make([]string, 0, len(instance.BGP.Neighbors))
			for _, neighbor := range instance.BGP.Neighbors {
				if neighbor != nil {
					neighbors = appendUnique(neighbors, neighbor.Address)
				}
			}
			if len(neighbors) > 0 {
				add("bgp", "bgp", 0, vrf, tableID, nil, neighbors)
			}
		}
	}

	out := make([]haRoutingRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		out = append(out, *requirement)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tableID != out[j].tableID {
			return out[i].tableID < out[j].tableID
		}
		if out[i].vrf != out[j].vrf {
			return out[i].vrf < out[j].vrf
		}
		return out[i].protocol < out[j].protocol
	})
	return out
}

func addHAInterfaceName(cfg *config.Config, names map[string]struct{}, name string) {
	if name == "" {
		return
	}
	for _, candidate := range []string{name, config.LinuxIfName(name), cfg.ResolveKernelIfName(name), config.LinuxIfName(cfg.ResolveKernelIfName(name))} {
		if candidate != "" {
			names[candidate] = struct{}{}
		}
	}
}

func addHALocalAddress(value string, addresses map[netip.Addr]struct{}, prefixes *[]netip.Prefix) {
	if address, err := netip.ParseAddr(value); err == nil {
		addresses[address.Unmap()] = struct{}{}
		return
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addresses[prefix.Addr().Unmap()] = struct{}{}
		*prefixes = append(*prefixes, prefix.Masked())
	}
}

func ospfInterfaceNames(cfg *config.OSPFConfig) []string {
	var names []string
	if cfg == nil {
		return names
	}
	for _, area := range cfg.Areas {
		if area == nil {
			continue
		}
		for _, iface := range area.Interfaces {
			if iface != nil {
				names = appendUnique(names, iface.Name)
			}
		}
	}
	return names
}

func ospfV3InterfaceNames(cfg *config.OSPFv3Config) []string {
	var names []string
	if cfg == nil {
		return names
	}
	for _, area := range cfg.Areas {
		if area == nil {
			continue
		}
		for _, iface := range area.Interfaces {
			if iface != nil {
				names = appendUnique(names, iface.Name)
			}
		}
	}
	return names
}

func isisInterfaceNames(cfg *config.ISISConfig) []string {
	var names []string
	if cfg == nil {
		return names
	}
	for _, iface := range cfg.Interfaces {
		if iface != nil {
			names = appendUnique(names, iface.Name)
		}
	}
	return names
}

func matchingHAInterfaces(cfg *config.Config, rgInterfaces map[string]struct{}, configured []string) []string {
	var matched []string
	for _, name := range configured {
		if name == "" {
			continue
		}
		resolved := cfg.ResolveKernelIfName(name)
		if _, ok := rgInterfaces[name]; ok {
			matched = appendUnique(matched, resolved)
			continue
		}
		if _, ok := rgInterfaces[config.LinuxIfName(name)]; ok {
			matched = appendUnique(matched, resolved)
			continue
		}
		if _, ok := rgInterfaces[resolved]; ok {
			matched = appendUnique(matched, resolved)
		}
	}
	return matched
}

func haInterfaceRefsMatch(cfg *config.Config, rgInterfaces map[string]struct{}, refs []string) bool {
	for _, ref := range refs {
		resolved := cfg.ResolveKernelIfName(ref)
		if _, ok := rgInterfaces[ref]; ok {
			return true
		}
		if _, ok := rgInterfaces[config.LinuxIfName(ref)]; ok {
			return true
		}
		if _, ok := rgInterfaces[resolved]; ok {
			return true
		}
	}
	return false
}

func bgpNeighborsForRG(cfg *config.BGPConfig, addresses map[netip.Addr]struct{}, prefixes []netip.Prefix) []string {
	var neighbors []string
	if cfg == nil {
		return neighbors
	}
	for _, neighbor := range cfg.Neighbors {
		if neighbor == nil || neighbor.Address == "" {
			continue
		}
		if neighbor.LocalAddress != "" {
			local, err := netip.ParseAddr(neighbor.LocalAddress)
			if err != nil {
				continue
			}
			if _, ok := addresses[local.Unmap()]; !ok {
				continue
			}
		} else {
			peer, err := netip.ParseAddr(neighbor.Address)
			if err != nil {
				continue
			}
			localSubnet := false
			for _, prefix := range prefixes {
				if prefix.Contains(peer.Unmap()) {
					localSubnet = true
					break
				}
			}
			if !localSubnet {
				continue
			}
		}
		neighbors = appendUnique(neighbors, neighbor.Address)
	}
	return neighbors
}

func appendUnique(values []string, additions ...string) []string {
	for _, value := range additions {
		if value == "" {
			continue
		}
		found := false
		for _, existing := range values {
			if existing == value {
				found = true
				break
			}
		}
		if !found {
			values = append(values, value)
		}
	}
	return values
}
