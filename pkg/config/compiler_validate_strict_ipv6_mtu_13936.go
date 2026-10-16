package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateIPv6UnitMTUStrict rejects an IPv6-bearing unit whose effective
// link MTU is below RFC 8200 §5's 1280-byte minimum (#13936). Untagged units
// share the physical link: planPhysDesired writes the MTU of the lowest
// referenced, untagged, non-tunnel sibling when one has an MTU, otherwise
// the interface MTU. A tagged unit uses its own MTU, falling back to that
// effective parent MTU. If no configured value exists, the live MTU is
// unknown at commit and is not gated.
func validateIPv6UnitMTUStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	referenced := vlanUnitMTUReferencedUnits9837(cfg)
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

		parentMTU := ifc.MTU
		for _, un := range unitNums {
			sibling := ifc.Units[un]
			if sibling == nil || sibling.VlanID > 0 || sibling.Tunnel != nil ||
				sibling.MTU <= 0 || !referenced[ifName][un] {
				continue
			}
			parentMTU = sibling.MTU
			break
		}

		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || !interfaceUnitHasIPv6_13936(unit) {
				continue
			}
			mtu := unit.MTU
			if unit.VlanID > 0 {
				if mtu <= 0 {
					mtu = parentMTU
				}
			} else if referenced[ifName][un] || mtu <= 0 {
				// When this unit is actually planned, every untagged
				// sibling shares the selected parent MTU. Without a zone
				// reference, retain its explicit unit MTU as the
				// configured effective value checked by the commit gate.
				mtu = parentMTU
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
