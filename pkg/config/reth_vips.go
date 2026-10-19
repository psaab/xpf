package config

import (
	"fmt"
	"sort"
)

// RethVIPsForRG returns the VIPs (CIDR strings) per Linux interface name for
// RETH interfaces belonging to the given redundancy group. Used by direct
// VIP mode (when no-reth-vrrp is set) where the daemon manages VIPs without
// VRRP, by the VRRP collector, and by the cluster ip-monitor probe source
// resolution (#15038) — one derivation so the probe source can never drift
// from the installed set.
func (c *Config) RethVIPsForRG(rgID int) map[string][]string {
	if c == nil {
		return nil
	}
	rethToPhys := c.RethToPhysical()

	result := make(map[string][]string)
	// #6781: the same structural ownership predicate the VRRP-backed collector
	// uses. This replaces a `strings.HasPrefix(name, "reth")` filter whose
	// stated purpose — "skip fabric, control, and management interfaces that
	// default to RedundancyGroup 0" — is already served by the predicate (those
	// interfaces own no group), but which ALSO excluded a structurally valid
	// redundant pair whose owner is not spelled "reth*", leaving that group
	// with no VIPs installed at all.
	rgOwners := c.RethRGOwners()

	for _, name := range sortedRethIfNames(c) {
		ifc := c.Interfaces.Interfaces[name]
		// #6780: skip a present-but-nil interface — this is the direct
		// (no-reth-vrrp / private-rg-election) ownership mode's collector, and
		// it carried the same raw deref as the VRRP-mode one above.
		if ifc == nil {
			continue
		}
		if owns, ok := rgOwners[name]; !ok || owns != rgID {
			continue
		}

		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := LinuxIfName(physName)

		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.TaggingEnabled() {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				// #6780: nil unit derefs at len(unit.Addresses).
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				result[subIface] = append(result[subIface], unit.Addresses...)
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if unit == nil { // #6780
					continue
				}
				vips = append(vips, unit.Addresses...)
			}
			if len(vips) > 0 {
				result[linuxName] = append(result[linuxName], vips...)
			}
		}
	}
	return result
}

// sortedRethIfNames returns sorted interface names for deterministic iteration.
func sortedRethIfNames(c *Config) []string {
	names := make([]string, 0, len(c.Interfaces.Interfaces))
	for name := range c.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
