package config

import (
	"fmt"
	"sort"
)

// RethVIPsByRG returns, for every redundancy group, the VIPs (CIDR strings)
// per Linux interface name owned by that group. It is the ONE walk that
// builds the RETH sub-interface name and collects unit addresses (#17140):
// the direct VIP mode, the VRRP collector and the cluster ip-monitor probe
// source all derive from it, so they can never drift.
//
// The walk skips present-but-nil and disabled interfaces (#6780/#16590) and
// disabled or nil units (#16590), resolves RETH->physical via
// RethToPhysical, applies VLAN sub-interface naming when tagging is
// enabled, and canonically dedupes each sub-interface's VIPs (#11482) so
// alias spellings (e.g. 2001:db8:61::1/64 vs 2001:DB8:61:0::1/64) yield
// one entry — the direct path must not feed a duplicate to AddrAdd or to
// a GARP/NA burst.
func (c *Config) RethVIPsByRG() map[int]map[string][]string {
	if c == nil {
		return nil
	}
	rethToPhys := c.RethToPhysical()

	// #6781: the same structural ownership predicate the VRRP-backed collector
	// uses. This replaces a `strings.HasPrefix(name, "reth")` filter whose
	// stated purpose — "skip fabric, control, and management interfaces that
	// default to RedundancyGroup 0" — is already served by the predicate (those
	// interfaces own no group), but which ALSO excluded a structurally valid
	// redundant pair whose owner is not spelled "reth*", leaving that group
	// with no VIPs installed at all.
	rgOwners := c.RethRGOwners()

	result := make(map[int]map[string][]string)
	for _, name := range sortedRethIfNames(c) {
		ifc := c.Interfaces.Interfaces[name]
		// #6780: skip a present-but-nil interface — this is the direct
		// (no-reth-vrrp / private-rg-election) ownership mode's collector, and
		// it carried the same raw deref as the VRRP-mode one above.
		if ifc == nil {
			continue
		}
		if ifc.Disable {
			continue
		}
		rgID, ok := rgOwners[name]
		if !ok {
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

		rgMap := result[rgID]
		if ifc.TaggingEnabled() {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				// #16590 (#14575 residual): a disabled unit owns no address.
				if unit == nil || unit.Disable || len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				if rgMap == nil {
					rgMap = make(map[string][]string)
					result[rgID] = rgMap
				}
				rgMap[subIface] = append(rgMap[subIface], unit.Addresses...)
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if unit == nil || unit.Disable { // #6780 / #16590
					continue
				}
				vips = append(vips, unit.Addresses...)
			}
			if len(vips) > 0 {
				if rgMap == nil {
					rgMap = make(map[string][]string)
					result[rgID] = rgMap
				}
				rgMap[linuxName] = append(rgMap[linuxName], vips...)
			}
		}
	}
	// #11482 canonical dedupe, applied once here so every consumer sees the
	// same one-entry-per-VIP set. Dedupe after merging all interfaces/units
	// that can land on the same sub-interface.
	for _, rgMap := range result {
		for subIface, vips := range rgMap {
			rgMap[subIface] = DedupeVRRPVIPs(vips)
		}
	}
	return result
}

// RethVIPsForRG returns the VIPs (CIDR strings) per Linux interface name for
// RETH interfaces belonging to the given redundancy group. Used by direct
// VIP mode (when no-reth-vrrp is set) where the daemon manages VIPs without
// VRRP, by the VRRP collector, and by the cluster ip-monitor probe source
// resolution (#15038) — one derivation (RethVIPsByRG) so the probe source
// can never drift from the installed set.
func (c *Config) RethVIPsForRG(rgID int) map[string][]string {
	if c == nil {
		return nil
	}
	return c.RethVIPsByRG()[rgID]
}

// AddressIdentitiesByNetdev returns, per kernel netdev, the identity set
// (PrefixIdentity) of every address the config assigns to that netdev
// (#18573): every RETH VIP of every redundancy group, under the SAME
// netdev naming RethVIPsByRG installs them with, plus every unit address
// of every enabled non-RETH interface, resolved through the
// ResolveKernelIfName rule the interface address reconcile and the
// userspace snapshot agree on (#8994). Disabled interfaces and units
// contribute nothing (they own no address, #14575/#16590). Unparseable
// addresses are skipped.
//
// It is the "configured ownership" set: an xpf-stamped direct-mode VIP
// whose (netdev, identity) is absent here is a leftover that no
// redundancy group and no plain interface wants, so the direct-VIP
// reconcile deletes it and the userspace snapshot never publishes it.
// The predicate is config-only — it does not depend on which node owns
// which group — so a non-owner and an owner reach the same verdict.
func (c *Config) AddressIdentitiesByNetdev() map[string]map[string]bool {
	if c == nil {
		return nil
	}
	out := make(map[string]map[string]bool)
	add := func(netdev, addr string) {
		p, ok := ParseVRRPVIP(addr)
		if !ok || netdev == "" {
			return
		}
		if out[netdev] == nil {
			out[netdev] = make(map[string]bool)
		}
		out[netdev][PrefixIdentity(p)] = true
	}
	for _, perNetdev := range c.RethVIPsByRG() {
		for netdev, vips := range perNetdev {
			for _, vip := range vips {
				add(netdev, vip)
			}
		}
	}
	owners := c.RethRGOwners()
	tunMap := tunnelNameMapFn(c)
	for _, name := range sortedRethIfNames(c) {
		ifc := c.Interfaces.Interfaces[name]
		if ifc == nil || ifc.Disable {
			continue
		}
		if _, isReth := owners[name]; isReth {
			continue // RethVIPsByRG above is the RETH derivation
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil || unit.Disable || len(unit.Addresses) == 0 {
				continue
			}
			netdev := c.resolveKernelIfNameWith(fmt.Sprintf("%s.%d", name, unitNum), tunMap)
			for _, addr := range unit.Addresses {
				add(netdev, addr)
			}
		}
	}
	return out
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
