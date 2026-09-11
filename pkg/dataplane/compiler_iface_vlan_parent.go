package dataplane

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

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
		if unit != nil && unit.VlanID <= 0 && len(unit.Addresses) > 0 {
			return []string{fmt.Sprintf("169.254.%d.%d/32", ifCfg.RedundancyGroup, clusterNodeID+1)}
		}
	}
	return nil
}
