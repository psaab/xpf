package dataplane

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// unitCarriesStandaloneVRRP reports whether unit carries a standalone
// (generic, non-RETH) vrrp-group with at least one virtual address (#15061).
//
// pkg/vrrp.CollectInstances builds an instance from any unit's VRRPGroups
// regardless of redundant-parent / redundancy-group, and becomeMaster
// installs each VIP as a genuine kernel address (pkg/vrrp addVIPsLocked).
// Those VIPs are foreign to systemd-networkd: no Address= line renders
// them, so without KeepAddresses the generated .network carries no static
// keep and an ordinary networkctl reconfigure strips the VIP while the
// instance stays MASTER.
//
// A group with no virtual address installs nothing, so it owns no foreign
// address and must not widen the keep — mirroring the DHCP rule that a
// client owning no address on the interface does not widen it (#14594).
// Disabled units are excluded by the callers, which already skip them
// before consulting this predicate; CollectInstances also skips disabled
// interfaces/units (#16834), matching that handling.
func unitCarriesStandaloneVRRP(unit *config.InterfaceUnit) bool {
	if unit == nil {
		return false
	}
	for _, vg := range unit.VRRPGroups {
		if vg != nil && len(vg.VirtualAddresses) > 0 {
			return true
		}
	}
	return false
}

// unitStandaloneVRRPVIPs returns the canonicalised virtual addresses of
// unit's standalone vrrp-groups (#16833), in authored order, deduplicated.
// Canonicalisation via netlink.ParseAddr puts the keep set in the same key
// space planAddressReconcile uses for kernel addresses, so a VIP authored
// as 10.0.1.1/24 matches the kernel's 10.0.1.1/24. Unparseable entries are
// dropped: pkg/vrrp cannot install them either, so there is no foreign
// address to keep. The caller filters disabled units.
func unitStandaloneVRRPVIPs(unit *config.InterfaceUnit) []string {
	if unit == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, vg := range unit.VRRPGroups {
		if vg == nil {
			continue
		}
		for _, vip := range vg.VirtualAddresses {
			addr, err := netlink.ParseAddr(vip)
			if err != nil || addr == nil || addr.IPNet == nil {
				continue
			}
			key := addr.IPNet.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}

// interfaceCarriesStandaloneVRRP reports whether any unit of ifCfg carries
// a standalone vrrp-group (see unitCarriesStandaloneVRRP). Used for rows
// whose model merges every unit (the non-VLAN arm) and for VLAN parents,
// whose untagged units bind their instance to the parent device.
func interfaceCarriesStandaloneVRRP(ifCfg *config.InterfaceConfig) bool {
	if ifCfg == nil || ifCfg.Disable {
		return false
	}
	for _, unit := range ifCfg.Units {
		if unit != nil && !unit.Disable && unitCarriesStandaloneVRRP(unit) {
			return true
		}
	}
	return false
}

// interfaceUnitStandaloneVRRPVIPs returns the VIPs owned by an enabled unit
// on an enabled interface. VRRP collects no instance for either disabled
// scope, so a VIP present on the netdev is stale rather than foreign-owned.
func interfaceUnitStandaloneVRRPVIPs(ifCfg *config.InterfaceConfig, unit *config.InterfaceUnit) []string {
	if ifCfg == nil || ifCfg.Disable || unit == nil || unit.Disable {
		return nil
	}
	return unitStandaloneVRRPVIPs(unit)
}
