package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateIPsecRouteTrafficSelectorsStrict rejects installed static routes via
// an XFRM bind-interface when the route destination is not covered by any
// rendered remote traffic-selector child on that tunnel (#11422).
func validateIPsecRouteTrafficSelectorsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	vpnNames := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)

	if err := validateIPsecStaticRouteTrafficSelectors11422(cfg, vpnNames,
		cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes); err != nil {
		return err
	}
	for _, instance := range cfg.RoutingInstances {
		if instance == nil {
			continue
		}
		if err := validateIPsecStaticRouteTrafficSelectors11422(cfg, vpnNames,
			instance.StaticRoutes, instance.Inet6StaticRoutes); err != nil {
			return err
		}
	}
	return nil
}

func validateIPsecStaticRouteTrafficSelectors11422(
	cfg *Config,
	vpnNames []string,
	routeFamilies ...[]*StaticRoute,
) error {
	for _, routes := range routeFamilies {
		for _, route := range routes {
			if route == nil || route.NoInstall || route.NextTable != "" || route.Discard || route.Reject {
				continue
			}
			destination, ok := ipsecRouteDestinationPrefix11422(route.Destination)
			if !ok {
				continue
			}
			for _, nextHop := range route.NextHops {
				if nextHop.Interface == "" {
					continue
				}
				_, routeIfID := XFRMIfNameAndID(nextHop.Interface)
				if routeIfID == 0 {
					continue
				}

				var owner string
				covered := false
				for _, name := range vpnNames {
					vpn := cfg.Security.IPsec.VPNs[name]
					if vpn == nil || vpn.BindInterface == "" {
						continue
					}
					_, bindIfID := XFRMIfNameAndID(vpn.BindInterface)
					if bindIfID != routeIfID || !bindInterfaceOwnsRef(vpn.BindInterface, nextHop.Interface) {
						continue
					}
					if owner == "" {
						owner = name
					}
					if ipsecTSAddressSetsCoverPrefix11422(
						ModeledIPsecSelectorPairs11380(vpn), destination) {
						covered = true
						break
					}
				}
				if owner != "" && !covered {
					return fmt.Errorf(
						"static route %s via bind-interface %q is outside VPN %q's rendered remote traffic-selector union; XFRM will blackhole the routed traffic (#11422)",
						route.Destination, nextHop.Interface, owner)
				}
			}
		}
	}
	return nil
}

func ipsecRouteDestinationPrefix11422(destination string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(destination); err == nil && !prefix.Addr().Is4In6() {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(destination); err == nil && addr.Zone() == "" && !addr.Is4In6() {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

func ipsecTSAddressSetsCoverPrefix11422(
	children []ModeledIPsecSelectorPair11380,
	prefix netip.Prefix,
) bool {
	first := prefix.Masked().Addr()
	last := ipsecTSPrefixLast11380(prefix)
	cursor := first
	for {
		var furthest netip.Addr
		for _, child := range children {
			for _, candidate := range child.remote.ranges {
				if candidate.first.Is4() != cursor.Is4() ||
					candidate.first.Compare(cursor) > 0 || candidate.last.Compare(cursor) < 0 {
					continue
				}
				if !furthest.IsValid() || candidate.last.Compare(furthest) > 0 {
					furthest = candidate.last
				}
			}
		}
		if !furthest.IsValid() {
			return false
		}
		if furthest.Compare(last) >= 0 {
			return true
		}
		cursor = furthest.Next()
		if !cursor.IsValid() {
			return false
		}
	}
}
