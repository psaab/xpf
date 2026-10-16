package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateIPv6UnitMTUStrict rejects an IPv6-bearing unit whose configured
// link MTU is below RFC 8200 §5's 1280-byte minimum (#13936). unit.MTU is
// the order-independent minimum of its inet and inet6 family MTUs, so an
// IPv4-only family mtu can lower the value ultimately written to the link.
// An explicit unit MTU overrides the interface MTU; absent both, the live
// MTU is unknown at commit and is not gated.
func validateIPv6UnitMTUStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || !interfaceUnitHasIPv6_13936(unit) {
				continue
			}
			mtu := unit.MTU
			if mtu <= 0 {
				mtu = ifc.MTU
			}
			if mtu > 0 && mtu < RALinkMTUMin {
				return fmt.Errorf("interfaces %s unit %d: effective mtu %d is below the IPv6 minimum %d (RFC 8200 §5); raise the interface or family mtu (#13936)",
					ifName, un, mtu, RALinkMTUMin)
			}
		}
	}
	return nil
}

func interfaceUnitHasIPv6_13936(unit *InterfaceUnit) bool {
	if unit.FamilyInet6 || unit.DHCPv6 || unit.DHCPv6Client != nil {
		return true
	}
	for _, raw := range unit.Addresses {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			return true
		}
	}
	return false
}
