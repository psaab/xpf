package dataplane

import "github.com/psaab/xpf/pkg/config"

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
// before consulting this predicate (CollectInstances itself does not
// check Disable; the model arms mirror their existing disabled handling).
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

// interfaceCarriesStandaloneVRRP reports whether any unit of ifCfg carries
// a standalone vrrp-group (see unitCarriesStandaloneVRRP). Used for rows
// whose model merges every unit (the non-VLAN arm) and for VLAN parents,
// whose untagged units bind their instance to the parent device.
func interfaceCarriesStandaloneVRRP(ifCfg *config.InterfaceConfig) bool {
	if ifCfg == nil {
		return false
	}
	for _, unit := range ifCfg.Units {
		if unit != nil && !unit.Disable && unitCarriesStandaloneVRRP(unit) {
			return true
		}
	}
	return false
}
