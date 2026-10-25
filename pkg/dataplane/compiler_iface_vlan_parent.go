package dataplane

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// untaggedUnitAddresses returns the real addresses untagged units of a
// non-RETH VLAN parent carry on the parent device itself (#16795). A unit
// with no vlan-id has no sub-interface: planPhysDesired folds its addresses
// onto the parent plan and reconcileInterfaceAddresses installs them there,
// and its zone binds the parent, so the parent is the address owner.
// Without rendering them on the parent row, networkd.Apply's reconfigure
// tail stripped them as foreign on every apply whose files changed.
//
// It returns nil for anything else: a RETH member (its untagged unit's
// addresses are VIPs owned by VRRP, and the parent carries only the
// advert source via vlanParentVRRPSource), a disabled unit, a unit
// already holding a standalone vrrp-group (its addresses stay VIP-foreign
// exactly as on a non-VLAN row: the row keeps them via
// KeepAddresses/KeepForeignStatic but renders none of them), and any
// tagged unit (whose addresses belong to its sub-interface). Iteration is
// by ascending unit number so the rendered order is deterministic.
func untaggedUnitAddresses(ifCfg *config.InterfaceConfig, isVRRPReth bool) []string {
	if isVRRPReth || ifCfg == nil {
		return nil
	}
	nums := make([]int, 0, len(ifCfg.Units))
	for n := range ifCfg.Units {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	var out []string
	seen := make(map[string]bool)
	for _, n := range nums {
		unit := ifCfg.Units[n]
		if unit == nil || unit.Disable || unit.VlanID > 0 || unitCarriesStandaloneVRRP(unit) {
			continue
		}
		for _, a := range unit.Addresses {
			if seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// vlanParentVRRPSource returns the addresses a VLAN parent carries ITSELF
// (networkd.InterfaceConfig.VLANParentAddresses): the VRRP advert source of a
// VRRP-backed RETH that has an addressed unit with no vlan-id (#9721).
//
// A unit with no vlan-id has no sub-interface, so CollectRethInstances
// (pkg/vrrp) binds that unit's instance to the parent device. Every other device
// of a VRRP-backed RETH carries the 169.254.<rg>.<node+1>/32 source
// (buildInterfaceNetworkdModels). Without it on the parent the instance found no
// IPv4 source and sent no IPv4 advertisement, so both nodes could become MASTER
// for the unit's VIPs.
//
// It returns nil for anything else: a tagged-only parent, an untagged unit with
// no address (which builds no instance), or an interface that is not a
// VRRP-backed RETH member. isVRRPReth and clusterNodeID are the caller's, so the
// parent is rendered under the same rule as every other RETH device.
//
// Split out of compiler_iface.go, which sits at the 2000 LOC [REFACTOR] floor.
// It is a pure function of the config, like planPhysDesired.
func vlanParentVRRPSource(ifCfg *config.InterfaceConfig, isVRRPReth bool, clusterNodeID int) []string {
	if !isVRRPReth || ifCfg == nil {
		return nil
	}
	for _, unit := range ifCfg.Units {
		if unit != nil && !unit.Disable && unit.VlanID <= 0 && len(unit.Addresses) > 0 {
			return []string{fmt.Sprintf("169.254.%d.%d/32", ifCfg.RedundancyGroup, clusterNodeID+1)}
		}
	}
	return nil
}
