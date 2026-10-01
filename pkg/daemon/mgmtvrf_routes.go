package daemon

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// mgmtVRFNeedsOperatorInventory reports whether active management leases have
// routes whose precedence must be checked against operator statics. The
// inventory is needed for both a DHCP default and RFC 3442 classless routes.
func mgmtVRFNeedsOperatorInventory(leases []*dhcp.Lease, mgmtSet map[string]bool) bool {
	for _, lease := range leases {
		if mgmtSet[lease.Interface] &&
			(lease.Gateway.IsValid() || len(lease.ClasslessRoutes) > 0) {
			return true
		}
	}
	return false
}

func mgmtVRFNeedsControlFabricInventory(leases []*dhcp.Lease, mgmtSet map[string]bool) bool {
	for _, lease := range leases {
		if mgmtSet[lease.Interface] && len(lease.ClasslessRoutes) > 0 {
			return true
		}
	}
	return false
}

func mgmtVRFControlFabricInterfaces(cfg *config.Config, mgmtSet map[string]bool) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cluster := cfg.Chassis.Cluster
	configured := [...]string{
		cluster.ControlInterface,
		cluster.FabricInterface,
		cluster.Fabric1Interface,
	}
	seen := make(map[string]struct{}, len(configured))
	interfaces := make([]string, 0, len(configured))
	for _, name := range configured {
		if name == "" {
			continue
		}
		name = config.LinuxIfName(name)
		if name == "" || !mgmtSet[name] {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		interfaces = append(interfaces, name)
	}
	return interfaces
}

func mgmtVRFControlFabricLinkIndexes(
	nlh mgmtRouteProgrammer,
	interfaces []string,
) (map[int]string, error) {
	if len(interfaces) == 0 {
		return nil, nil
	}
	linkNames := make(map[int]string, len(interfaces))
	for _, name := range interfaces {
		link, err := nlh.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup %s: %w", name, err)
		}
		attrs := link.Attrs()
		if attrs == nil || attrs.Index <= 0 {
			return nil, fmt.Errorf("lookup %s: invalid link index", name)
		}
		linkNames[attrs.Index] = name
	}
	return linkNames, nil
}

// mgmtVRFRouteInventory keeps operator statics as the authority for DHCP
// precedence (#9943), while retaining management connected kernel prefixes as
// a classless-route fence (#11383). Connected routes on configured cluster
// control/fabric interfaces are returned separately for the non-overridable
// fence (#11362).
func mgmtVRFRouteInventory(
	nlh mgmtRouteReconciler,
	family int,
	controlFabricLinks map[int]string,
) ([]netlink.Route, []netlink.Route, []netip.Prefix, error) {
	routes, err := nlh.RouteListFiltered(family, &netlink.Route{
		Table: mgmtVRFTableID,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, nil, nil, err
	}
	operators := make([]netlink.Route, 0, len(routes))
	controlFabricConnected := make([]netlink.Route, 0, len(controlFabricLinks))
	connectedPrefixes := make([]netip.Prefix, 0)
	for _, route := range routes {
		if route.Protocol == unix.RTPROT_DHCP {
			continue
		}
		if route.Protocol == unix.RTPROT_KERNEL {
			if route.Scope == netlink.SCOPE_LINK && route.Dst != nil && route.Gw == nil {
				if prefix, ok := mgmtRoutePrefix(route, family); ok {
					connectedPrefixes = append(connectedPrefixes, prefix)
				}
				if _, protected := controlFabricLinks[route.LinkIndex]; protected &&
					route.Scope == netlink.SCOPE_LINK && route.Dst != nil && route.Gw == nil {
					controlFabricConnected = append(controlFabricConnected, route)
				}
			}
			continue
		}
		if route.Protocol != unix.RTPROT_STATIC {
			slog.Warn("SECURITY: ignoring non-static management-VRF route for "+
				"DHCP precedence (#9943)",
				"destination", mgmtRoutePrefixString(route, family),
				"protocol", route.Protocol, "table", mgmtVRFTableID)
			continue
		}
		operators = append(operators, route)
	}
	return operators, controlFabricConnected, connectedPrefixes, nil
}

func mgmtRoutePrefixString(route netlink.Route, family int) string {
	if prefix, ok := mgmtRoutePrefix(route, family); ok {
		return prefix.String()
	}
	return "<invalid>"
}

func mgmtRoutePrefix(route netlink.Route, family int) (netip.Prefix, bool) {
	if route.Dst == nil {
		if family == netlink.FAMILY_V6 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), true
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	addr, ok := netip.AddrFromSlice(route.Dst.IP)
	if !ok || (family == netlink.FAMILY_V4 && !addr.Is4()) ||
		(family == netlink.FAMILY_V6 && addr.Is4()) {
		return netip.Prefix{}, false
	}
	ones, bits := route.Dst.Mask.Size()
	if bits != addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}

// mgmtRouteCoveringPrefix returns the route that contains a learned prefix.
// Only a route at least as broad as the learned prefix can override it; a
// broader learned route does not override a more-specific route and remains
// necessary for uncovered addresses.
func mgmtRouteCoveringPrefix(
	learned netip.Prefix,
	routes []netlink.Route,
	family int,
) (netip.Prefix, netlink.Route, bool) {
	for _, route := range routes {
		prefix, ok := mgmtRoutePrefix(route, family)
		if !ok || prefix.Bits() > learned.Bits() ||
			prefix.Addr().BitLen() != learned.Addr().BitLen() ||
			!prefix.Contains(learned.Addr()) {
			continue
		}
		return prefix, route, true
	}
	return netip.Prefix{}, netlink.Route{}, false
}

func mgmtRouteCoveredByOperator(learned netip.Prefix, operators []netlink.Route, family int) string {
	if prefix, _, ok := mgmtRouteCoveringPrefix(learned, operators, family); ok {
		return prefix.String()
	}
	return ""
}
