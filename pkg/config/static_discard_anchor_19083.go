package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateStaticDiscardAnchorWarnings19083 names a pattern whose behaviour
// changes in a chassis cluster with #19083: a static route whose next hop is
// on no configured connected subnet and whose longest CONFIGURED covering
// route is a blackhole — a discard/reject static or a policy-less generate
// aggregate (FRR renders both as Null0/reject). In cluster mode staticd's
// next-hop tracking is bound to a map that refuses resolution through a
// blackhole next hop (pkg/frr cluster_static_nht_19083.go), so FRR no longer
// installs (or exports) such a static; the userspace helper already treats it
// as unresolved, and so does Junos (the next hop is not reachable). An
// operator who used the pattern to originate a blackhole for the prefix
// should configure that prefix as a discard route instead.
//
// It is a WARNING (#1960: never refuse a loadable config for a behaviour
// note), only in cluster mode, and only for the default routing table, the
// scope of the NHT binding. Routes learned at runtime (DHCP, BGP, IGPs) are
// invisible here: a learned more-specific route can still resolve the next
// hop, so the text says "configured".
func validateStaticDiscardAnchorWarnings19083(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	type covering struct {
		prefix    netip.Prefix
		what      string
		self      *StaticRoute
		blackhole bool
	}
	var routes []covering
	addStatic := func(list []*StaticRoute) {
		for _, sr := range list {
			if sr == nil {
				continue
			}
			p, err := netip.ParsePrefix(sr.Destination)
			if err != nil {
				continue
			}
			routes = append(routes, covering{prefix: p.Masked(), what: "static " + sr.Destination,
				self: sr, blackhole: sr.Discard || sr.Reject})
		}
	}
	addStatic(cfg.RoutingOptions.StaticRoutes)
	addStatic(cfg.RoutingOptions.Inet6StaticRoutes)
	for _, gr := range cfg.RoutingOptions.GenerateRoutes {
		if gr == nil || gr.Policy != "" { // #11456: a policy-bearing aggregate renders nothing
			continue
		}
		if p, err := netip.ParsePrefix(gr.Prefix); err == nil {
			routes = append(routes, covering{prefix: p.Masked(), what: "generate route " + gr.Prefix, blackhole: true})
		}
	}
	var connected []netip.Prefix
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, name := range ifNames {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, a := range unit.Addresses {
				if p, err := netip.ParsePrefix(a); err == nil {
					connected = append(connected, p.Masked())
				}
			}
		}
	}

	var out []string
	check := func(sr *StaticRoute) {
		if sr == nil || sr.Discard || sr.Reject || sr.NextTable != "" || sr.NoInstall {
			return
		}
		for _, hop := range sr.NextHops {
			if hop.Address == "" || hop.Interface != "" {
				continue
			}
			gw, err := netip.ParseAddr(hop.Address)
			if err != nil {
				continue
			}
			onLink := false
			for _, c := range connected {
				if c.Addr().Is4() == gw.Is4() && c.Contains(gw) {
					onLink = true
					break
				}
			}
			if onLink {
				continue
			}
			best, anyNonBlackhole, anchor := -1, false, ""
			for _, r := range routes {
				if r.self == sr || r.prefix.Addr().Is4() != gw.Is4() || !r.prefix.Contains(gw) {
					continue
				}
				switch bits := r.prefix.Bits(); {
				case bits > best:
					best, anyNonBlackhole, anchor = bits, !r.blackhole, r.what
				case bits == best:
					anyNonBlackhole = anyNonBlackhole || !r.blackhole
				}
			}
			if best < 0 || anyNonBlackhole {
				continue
			}
			out = append(out, fmt.Sprintf(
				"routing-options static route %s next-hop %s resolves only through the blackhole %s among configured routes; "+
					"in a chassis cluster xpf does not install or export a static whose next hop resolves through a blackhole (#19083), "+
					"and the dataplane already treats it as unresolved. To discard %s deliberately, configure it as a discard route.",
				sr.Destination, hop.Address, anchor, sr.Destination))
		}
	}
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		check(sr)
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		check(sr)
	}
	return out
}
