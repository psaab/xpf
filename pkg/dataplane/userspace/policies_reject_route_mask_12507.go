package userspace

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// #12507: whole-snapshot refusals for static-route destinations and bind-less
// IPsec selectors whose zero-padded CIDR mask the userspace helper cannot parse.
//
// The helper reads route destinations and fence selectors with ipnet, which
// accepts at most two IPv4 and three IPv6 mask digits
// (config.CIDRMaskHelperRefusesPadding). A published route with a longer mask
// fails the snapshot closed (RouteDestinationUnparseable), and so does a fence
// row (InvalidBindlessSelector). The compiler writes helper-supported padding
// canonically and strict commit rejects the rest, so these arms fire only for a
// tolerantly loaded config: a boot load, an HA peer sync, or a rollback target.
//
// Each arm names exactly the rows the snapshot builder publishes, so a stamp
// is a refusal the helper really makes:
//
//   - a route excluded from the FIB (config.StaticRouteExclusions) never
//     reaches the helper and is not reported;
//   - every other refused route is published by buildRouteSnapshots after its
//     runtime filters (gateway resolution, the ip-monitoring overlay, the live
//     ip-rule mirror). The refusal is then a function of the config alone,
//     which is all PolicyContentRejectionReasons can see;
//   - a route-based VPN (bind-interface) has no fence row, so its selectors are
//     not reported. Its P-MECH inventory row degrades on its own; that is not a
//     whole-snapshot refusal.

// forEachHelperRefusedStaticRoute visits every static route the snapshot
// builder publishes whose destination mask the helper cannot parse. It walks
// the builder's own lists with the builder's exclusion verdict, and passes each
// list's base table and family as addRoutes receives them.
func forEachHelperRefusedStaticRoute(cfg *config.Config, exclusions map[*config.StaticRoute]string,
	visit func(table, family string, route *config.StaticRoute)) {
	if cfg == nil {
		return
	}
	walk := func(table, family string, routes []*config.StaticRoute) {
		for _, route := range routes {
			if route == nil || exclusions[route] != "" ||
				!config.CIDRMaskHelperRefusesPadding(route.Destination) {
				continue
			}
			visit(table, family, route)
		}
	}
	walk("inet.0", "inet", cfg.RoutingOptions.StaticRoutes)
	walk("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes)
	instances := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances = append(instances, ri)
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].Name < instances[j].Name })
	for _, ri := range instances {
		walk(ri.Name+".inet.0", "inet", ri.StaticRoutes)
		walk(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes)
	}
}

// configHasHelperRefusedStaticRoute is the allocation-free precondition for
// the builder's post-overlay pass and collectStaticRouteCIDRMaskRejections, so
// an ordinary config pays for neither the instance sort nor a second
// StaticRouteExclusions walk on every build.
func configHasHelperRefusedStaticRoute(cfg *config.Config) bool {
	refused := func(routes []*config.StaticRoute) bool {
		for _, route := range routes {
			if route != nil && config.CIDRMaskHelperRefusesPadding(route.Destination) {
				return true
			}
		}
		return false
	}
	if refused(cfg.RoutingOptions.StaticRoutes) || refused(cfg.RoutingOptions.Inet6StaticRoutes) {
		return true
	}
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && (refused(ri.StaticRoutes) || refused(ri.Inet6StaticRoutes)) {
			return true
		}
	}
	return false
}

func collectStaticRouteCIDRMaskRejections(cfg *config.Config) []string {
	if cfg == nil || !configHasHelperRefusedStaticRoute(cfg) {
		return nil
	}
	var reasons []string
	forEachHelperRefusedStaticRoute(cfg, config.StaticRouteExclusions(cfg),
		func(table, family string, route *config.StaticRoute) {
			tableName, _ := normalizeRouteSnapshotFamily(table, family, route.Destination)
			reasons = append(reasons, fmt.Sprintf(
				"static route %q in table %q has redundant leading-zero CIDR mask digits the userspace helper cannot parse; userspace publication is refused (#12507)",
				route.Destination, tableName))
		})
	return reasons
}

// configHasHelperRefusedSelector is the cheap precondition for
// collectBindlessSelectorCIDRMaskRejections: every fence row value comes from
// one of these four fields, and the row walk renders the swanctl config.
func configHasHelperRefusedSelector(cfg *config.Config) bool {
	for _, vpn := range cfg.Security.IPsec.VPNs {
		if vpn == nil {
			continue
		}
		if config.CIDRMaskHelperRefusesPadding(vpn.LocalID) || config.CIDRMaskHelperRefusesPadding(vpn.RemoteID) {
			return true
		}
		for _, ts := range vpn.TrafficSelectors {
			if ts != nil && (config.CIDRMaskHelperRefusesPadding(ts.LocalIP) ||
				config.CIDRMaskHelperRefusesPadding(ts.RemoteIP)) {
				return true
			}
		}
	}
	return false
}

func collectBindlessSelectorCIDRMaskRejections(cfg *config.Config) []string {
	if cfg == nil || !configHasHelperRefusedSelector(cfg) {
		return nil
	}
	var reasons []string
	forEachBindlessSelectorRow(cfg, nil, func(vpn string, row IpsecBindlessSelectorSnapshot) {
		for _, side := range [...]struct{ name, value string }{
			{"local_ts", row.LocalTS},
			{"remote_ts", row.RemoteTS},
		} {
			if config.CIDRMaskHelperRefusesPadding(side.value) {
				reasons = append(reasons, fmt.Sprintf(
					"IPsec VPN %q bind-less selector fence row %s %q has redundant leading-zero CIDR mask digits the userspace helper cannot parse; userspace publication is refused (#12507)",
					vpn, side.name, side.value))
			}
		}
	})
	return reasons
}
