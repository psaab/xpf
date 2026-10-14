package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
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

				// #12909: several VPNs may legitimately share one
				// bind-interface with provably disjoint selectors (#11380).
				// Each contributes its remote ranges to the XFRM policies on
				// that device, so a routed destination is coverable by their
				// UNION. Requiring one single VPN to cover the whole
				// destination falsely rejected aggregates split across
				// complementary VPNs on the same st0.X.
				var owners []string
				var union []ModeledIPsecSelectorPair11380
				for _, name := range vpnNames {
					vpn := cfg.Security.IPsec.VPNs[name]
					if vpn == nil || vpn.BindInterface == "" {
						continue
					}
					_, bindIfID := XFRMIfNameAndID(vpn.BindInterface)
					if bindIfID != routeIfID || !bindInterfaceOwnsRef(vpn.BindInterface, nextHop.Interface) {
						continue
					}
					owners = append(owners, name)
					union = append(union, ModeledIPsecSelectorPairs11380(vpn)...)
				}
				if len(owners) > 0 && !ipsecTSAddressSetsCoverPrefix11422(union, destination) {
					quoted := make([]string, len(owners))
					for i, name := range owners {
						quoted[i] = fmt.Sprintf("%q", name)
					}
					return fmt.Errorf(
						"static route %s via bind-interface %q is outside VPN %s's rendered remote traffic-selector union; XFRM will blackhole the routed traffic (#11422)",
						route.Destination, nextHop.Interface, strings.Join(quoted, ", "))
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
			for _, candidate := range child.Remote.Ranges {
				if candidate.First.Is4() != cursor.Is4() ||
					candidate.First.Compare(cursor) > 0 || candidate.Last.Compare(cursor) < 0 {
					continue
				}
				if !furthest.IsValid() || candidate.Last.Compare(furthest) > 0 {
					furthest = candidate.Last
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
