package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// This realm tags only routes reconciled by xpf. RTPROT_STATIC is shared with
// operator-installed routes in table 999, so the tag lets startup cleanup reap
// its own stale routes without claiming or deleting those operator routes.
const mgmtStaticRouteRealm = 0x585046 // "XPF"

type mgmtStaticRouteTarget struct {
	family int
	route  netlink.Route
}

// applyMgmtVRFStaticRoutesTo installs management-scoped configuration routes
// and the system backup-router in table 999, then removes stale xpf-owned
// RTPROT_STATIC entries. Table 999 is dedicated to management interfaces; a
// global static is copied here only when every next-hop resolves to a
// management interface (explicitly, or through a connected table-999 route).
func (d *Daemon) applyMgmtVRFStaticRoutesTo(
	nlh mgmtRouteProgrammer,
	cfg *config.Config,
	mgmtSet map[string]bool,
) error {
	current := [2][]netlink.Route{}
	for i, family := range [...]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := nlh.RouteListFiltered(family, &netlink.Route{
			Table: mgmtVRFTableID,
		}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return fmt.Errorf("mgmt VRF static route inventory (family %d): %w", family, err)
		}
		current[i] = routes
	}

	desired := mgmtStaticRoutesDesired(nlh, cfg, mgmtSet, current)
	present := make(map[string]struct{}, len(desired))
	applied := make(map[string]struct{}, len(desired))
	for i, family := range [...]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, route := range current[i] {
			if route.Protocol != unix.RTPROT_STATIC {
				continue
			}
			key := mgmtStaticRouteKey(route, family)
			if _, wanted := desired[key]; wanted {
				present[key] = struct{}{}
				if route.Realm == mgmtStaticRouteRealm {
					applied[key] = struct{}{}
				}
			}
		}
	}

	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var errs []error
	for _, key := range keys {
		if _, exists := present[key]; exists {
			continue
		}
		target := desired[key]
		if err := nlh.RouteReplace(&target.route); err != nil {
			slog.Warn("mgmt VRF static route: replace failed",
				"destination", mgmtRouteDstKey(target.route.Dst, target.family),
				"table", mgmtVRFTableID, "err", err)
			errs = append(errs, fmt.Errorf("mgmt VRF static route replace %s: %w",
				mgmtRouteDstKey(target.route.Dst, target.family), err))
			continue
		}
		applied[key] = struct{}{}
	}

	for i, family := range [...]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, route := range current[i] {
			if route.Protocol != unix.RTPROT_STATIC || route.Realm != mgmtStaticRouteRealm {
				continue
			}
			key := mgmtStaticRouteKey(route, family)
			if _, keep := applied[key]; keep {
				continue
			}
			if err := nlh.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("mgmt VRF static route: stale route delete failed",
					"destination", mgmtRouteDstKey(route.Dst, family),
					"table", mgmtVRFTableID, "err", err)
				errs = append(errs, fmt.Errorf("mgmt VRF static route delete %s: %w",
					mgmtRouteDstKey(route.Dst, family), err))
			}
		}
	}
	return errors.Join(errs...)
}

func mgmtStaticRoutesDesired(
	nlh mgmtRouteProgrammer,
	cfg *config.Config,
	mgmtSet map[string]bool,
	current [2][]netlink.Route,
) map[string]mgmtStaticRouteTarget {
	desired := make(map[string]mgmtStaticRouteTarget)
	if cfg == nil || len(mgmtSet) == 0 {
		return desired
	}

	if route, family, ok := mgmtBackupRouterRoute(cfg.System.BackupRouter, cfg.System.BackupRouterDst); ok {
		mgmtAddStaticRoute(desired, route, family)
	}

	connected := [2][]netlink.Route{current[0], current[1]}
	inferredV6 := inferIPv6StaticNextHopInterfaces(cfg, nil)[""]
	exclusions := config.StaticRouteExclusions(cfg)
	allStatics := [][]*config.StaticRoute{
		cfg.RoutingOptions.StaticRoutes,
		cfg.RoutingOptions.Inet6StaticRoutes,
	}
	for _, routes := range allStatics {
		for _, static := range routes {
			if static == nil || exclusions[static] != "" || static.NoInstall ||
				static.NextTable != "" || static.Discard || static.Reject || len(static.NextHops) == 0 {
				continue
			}
			dst, family, ok := mgmtStaticRouteDestination(static.Destination)
			if !ok {
				continue
			}

			byPreference := make(map[int][]*netlink.NexthopInfo)
			routeScoped, routeAvailable := true, true
			for _, nextHop := range static.NextHops {
				if nextHop.Address == "" && nextHop.Interface == "" {
					routeScoped = false
					break
				}
				var gateway net.IP
				if nextHop.Address != "" {
					gateway = net.ParseIP(nextHop.Address)
					if gateway == nil || mgmtStaticIPFamily(gateway) != family {
						routeScoped = false
						break
					}
				}

				linkIndex := 0
				if nextHop.Interface != "" {
					linkName := cfg.ResolveKernelIfName(nextHop.Interface)
					if !config.IsManagementIfName(linkName) || !mgmtSet[linkName] {
						routeScoped = false
						break
					}
					link, err := nlh.LinkByName(linkName)
					if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
						slog.Warn("mgmt VRF static route: interface not available",
							"interface", linkName, "destination", static.Destination, "err", err)
						routeAvailable = false
						break
					}
					linkIndex = link.Attrs().Index
				} else {
					linkIndex, routeScoped = mgmtStaticConnectedLinkIndex(gateway, connected[mgmtStaticFamilyIndex(family)])
					if !routeScoped && family == netlink.FAMILY_V6 {
						if inferred := inferredV6[nextHop.Address]; inferred != "" {
							linkName := cfg.ResolveKernelIfName(inferred)
							if config.IsManagementIfName(linkName) && mgmtSet[linkName] {
								link, err := nlh.LinkByName(linkName)
								if err == nil && link != nil && link.Attrs() != nil && link.Attrs().Index > 0 {
									linkIndex, routeScoped = link.Attrs().Index, true
								}
							}
						}
					}
					if !routeScoped {
						break
					}
				}

				preference := static.Preference
				if nextHop.HasPreference {
					preference = nextHop.Preference
				}
				byPreference[preference] = append(byPreference[preference], &netlink.NexthopInfo{
					LinkIndex: linkIndex,
					Gw:        gateway,
				})
			}
			if !routeScoped || !routeAvailable {
				continue
			}
			preferences := make([]int, 0, len(byPreference))
			for preference := range byPreference {
				preferences = append(preferences, preference)
			}
			sort.Ints(preferences)
			for _, preference := range preferences {
				hops := byPreference[preference]
				sort.Slice(hops, func(i, j int) bool {
					if hops[i].LinkIndex != hops[j].LinkIndex {
						return hops[i].LinkIndex < hops[j].LinkIndex
					}
					return hops[i].Gw.String() < hops[j].Gw.String()
				})
				route := netlink.Route{
					Family:   family,
					Dst:      dst,
					Table:    mgmtVRFTableID,
					Type:     unix.RTN_UNICAST,
					Protocol: unix.RTPROT_STATIC,
					Realm:    mgmtStaticRouteRealm,
					Priority: preference,
				}
				if len(hops) == 1 {
					route.LinkIndex = hops[0].LinkIndex
					route.Gw = hops[0].Gw
				} else {
					route.MultiPath = hops
				}
				mgmtAddStaticRoute(desired, route, family)
			}
		}
	}
	return desired
}

// mgmtStaticRouteConnectedInventory snapshots table 999 for FRR's static-route
// exclusion. Config-only inference cannot see a DHCP address, but the static
// reconciler resolves an implicit gateway from the live connected routes there.
func mgmtStaticRouteConnectedInventory(mgmtSet map[string]bool) [2][]netlink.Route {
	var current [2][]netlink.Route
	if len(mgmtSet) == 0 {
		return current
	}
	for i, family := range [...]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Table: mgmtVRFTableID,
		}, netlink.RT_FILTER_TABLE)
		if err != nil {
			slog.Warn("mgmt VRF static route connected-route inventory failed",
				"family", family, "table", mgmtVRFTableID, "err", err)
			continue
		}
		current[i] = routes
	}
	return current
}

// mgmtStaticRoutesForFRR keeps routes owned by the management VRF out of FRR's
// default-table static route input. A configured management gateway is scoped
// by its explicit interface or by a unique management-connected prefix. A
// gateway learned on a DHCP management interface is scoped by its live
// table-999 connected route.

func mgmtStaticRoutesForFRR(
	cfg *config.Config,
	mgmtSet map[string]bool,
	inferredV6 map[string]string,
	current [2][]netlink.Route,
) ([]*config.StaticRoute, []*config.StaticRoute) {
	if cfg == nil {
		return nil, nil
	}
	if len(mgmtSet) == 0 {
		return cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes
	}
	exclusions := config.StaticRouteExclusions(cfg)
	return filterMgmtStaticRoutesForFRR(cfg, cfg.RoutingOptions.StaticRoutes, mgmtSet, exclusions, inferredV6, current),
		filterMgmtStaticRoutesForFRR(cfg, cfg.RoutingOptions.Inet6StaticRoutes, mgmtSet, exclusions, inferredV6, current)
}

func filterMgmtStaticRoutesForFRR(
	cfg *config.Config,
	routes []*config.StaticRoute,
	mgmtSet map[string]bool,
	exclusions map[*config.StaticRoute]string,
	inferredV6 map[string]string,
	current [2][]netlink.Route,
) []*config.StaticRoute {
	var filtered []*config.StaticRoute
	for i, route := range routes {
		if !mgmtStaticRouteIsManagementScoped(cfg, route, mgmtSet, exclusions, inferredV6, current) {
			if filtered != nil {
				filtered = append(filtered, route)
			}
			continue
		}
		if filtered == nil {
			filtered = make([]*config.StaticRoute, 0, len(routes)-1)
			filtered = append(filtered, routes[:i]...)
		}
	}
	if filtered == nil {
		return routes
	}
	return filtered
}

func mgmtStaticRouteIsManagementScoped(
	cfg *config.Config,
	route *config.StaticRoute,
	mgmtSet map[string]bool,
	exclusions map[*config.StaticRoute]string,
	inferredV6 map[string]string,
	current [2][]netlink.Route,
) bool {
	if route == nil || exclusions[route] != "" || route.NoInstall ||
		route.NextTable != "" || route.Discard || route.Reject || len(route.NextHops) == 0 {
		return false
	}
	_, family, ok := mgmtStaticRouteDestination(route.Destination)
	if !ok {
		return false
	}
	for _, nextHop := range route.NextHops {
		if nextHop.Address == "" && nextHop.Interface == "" {
			return false
		}
		if nextHop.Interface != "" {
			linkName := cfg.ResolveKernelIfName(nextHop.Interface)
			if !config.IsManagementIfName(linkName) || !mgmtSet[linkName] {
				return false
			}
			continue
		}
		gateway := net.ParseIP(nextHop.Address)
		if gateway == nil || mgmtStaticIPFamily(gateway) != family {
			return false
		}
		linkName, found := mgmtStaticConfigConnectedInterface(cfg, gateway, mgmtSet)
		if !found {
			if _, liveConnected := mgmtStaticConnectedLinkIndex(
				gateway, current[mgmtStaticFamilyIndex(family)]); liveConnected {
				continue
			}
		}
		if !found && family == netlink.FAMILY_V6 {
			linkName = cfg.ResolveKernelIfName(inferredV6[nextHop.Address])
			found = config.IsManagementIfName(linkName) && mgmtSet[linkName]
		}
		if !found || !config.IsManagementIfName(linkName) || !mgmtSet[linkName] {
			return false
		}
	}
	return true
}

func mgmtStaticConfigConnectedInterface(
	cfg *config.Config,
	gateway net.IP,
	mgmtSet map[string]bool,
) (string, bool) {
	bestBits, bestIf, ambiguous := -1, "", false
	for ifName, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		base := config.LinuxIfName(ifName)
		for unitNum, unit := range iface.Units {
			if unit == nil {
				continue
			}
			linkName := cfg.ResolveKernelIfName(config.LogicalUnitDeviceKey(base, unitNum, unit))
			if !config.IsManagementIfName(linkName) || !mgmtSet[linkName] {
				continue
			}
			consider := func(address string) {
				ip, prefix, err := net.ParseCIDR(address)
				if err != nil || ip == nil || mgmtStaticIPFamily(ip) != mgmtStaticIPFamily(gateway) ||
					!prefix.Contains(gateway) {
					return
				}
				bits, _ := prefix.Mask.Size()
				if bits > bestBits {
					bestBits, bestIf, ambiguous = bits, linkName, false
				} else if bits == bestBits && linkName != bestIf {
					ambiguous = true
				}
			}
			for _, address := range unit.Addresses {
				consider(address)
			}
			for _, group := range unit.VRRPGroups {
				if group == nil {
					continue
				}
				for _, address := range group.VirtualAddresses {
					consider(address)
				}
			}
		}
	}
	return bestIf, bestBits >= 0 && !ambiguous
}

func mgmtBackupRouterRoute(nextHop, destination string) (netlink.Route, int, bool) {
	gateway := net.ParseIP(strings.TrimSpace(nextHop))
	if gateway == nil || config.FRRAddrIsMapped(nextHop) {
		return netlink.Route{}, 0, false
	}
	family := mgmtStaticIPFamily(gateway)
	if destination == "" {
		destination = "0.0.0.0/0"
		if family == netlink.FAMILY_V6 {
			destination = "::/0"
		}
	}
	dst, dstFamily, ok := mgmtStaticRouteDestination(destination)
	if !ok || dstFamily != family {
		slog.Warn("mgmt VRF static route: invalid backup-router destination",
			"next_hop", nextHop, "destination", destination)
		return netlink.Route{}, 0, false
	}
	return netlink.Route{
		Family:   family,
		Dst:      dst,
		Gw:       gateway,
		Table:    mgmtVRFTableID,
		Type:     unix.RTN_UNICAST,
		Protocol: unix.RTPROT_STATIC,
		Realm:    mgmtStaticRouteRealm,
		Priority: 250,
	}, family, true
}

func mgmtStaticRouteDestination(value string) (*net.IPNet, int, bool) {
	value = strings.TrimSpace(value)
	if _, dst, err := net.ParseCIDR(value); err == nil {
		_, bits := dst.Mask.Size()
		if bits == 32 {
			return dst, netlink.FAMILY_V4, true
		}
		if bits == 128 {
			return dst, netlink.FAMILY_V6, true
		}
		return nil, 0, false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, 0, false
	}
	if config.FRRAddrFamily(value) == "v6" {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, netlink.FAMILY_V6, true
	}
	return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, netlink.FAMILY_V4, true
}

func mgmtStaticIPFamily(ip net.IP) int {
	if ip != nil && config.FRRAddrFamily(ip.String()) == "v6" {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func mgmtStaticFamilyIndex(family int) int {
	if family == netlink.FAMILY_V6 {
		return 1
	}
	return 0
}

func mgmtStaticConnectedLinkIndex(gateway net.IP, routes []netlink.Route) (int, bool) {
	linkIndex, found := 0, false
	for _, route := range routes {
		if route.Protocol != unix.RTPROT_KERNEL || route.Scope != netlink.SCOPE_LINK ||
			route.Dst == nil || route.Gw != nil || !route.Dst.Contains(gateway) {
			continue
		}
		if !found {
			linkIndex, found = route.LinkIndex, true
			continue
		}
		if route.LinkIndex != linkIndex {
			return 0, false
		}
	}
	return linkIndex, found
}

func mgmtAddStaticRoute(routes map[string]mgmtStaticRouteTarget, route netlink.Route, family int) {
	routes[mgmtStaticRouteKey(route, family)] = mgmtStaticRouteTarget{family: family, route: route}
}

func mgmtStaticRouteKey(route netlink.Route, family int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%s|%d|%d|%d", family, mgmtRouteDstKey(route.Dst, family),
		route.Priority, route.Type, route.Scope)
	if len(route.MultiPath) == 0 {
		fmt.Fprintf(&b, "|%d|%s", route.LinkIndex, route.Gw.String())
		return b.String()
	}
	legs := make([]string, 0, len(route.MultiPath))
	for _, hop := range route.MultiPath {
		if hop == nil {
			continue
		}
		legs = append(legs, fmt.Sprintf("%d|%s", hop.LinkIndex, hop.Gw.String()))
	}
	sort.Strings(legs)
	for _, leg := range legs {
		b.WriteByte('|')
		b.WriteString(leg)
	}
	return b.String()
}
