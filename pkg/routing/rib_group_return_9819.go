package routing

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RibGroupReturnRulePriority is the ip-rule priority of the #9819 rib-group
// return rules. A leaking instance gets destination-scoped lookup into each
// peer's table, but only for prefixes leaked by OTHER instances (#11062):
//
//	ip rule add pref 1500 to <peer-prefix> iif vrf-<instance> lookup <peer-table>
//	ip rule add pref 1500 to <peer-prefix> oif vrf-<instance> lookup <peer-table>
//
// Looking up the peer table avoids falling through to main's default route.
// The userspace FIB mirrors these rules as reverse NextTable routes between
// the source and peer tables.
const RibGroupReturnRulePriority = 1500

// The ordering is load-bearing: scoped return rules run after the kernel's
// l3mdev lookup and before the VRF miss terminator; the rib-group leak band
// stays below both. These priorities are checked at compile time.
const (
	_ = uint(RibGroupReturnRulePriority - 1001)
	_ = uint(vrfMissTerminatorPriority - RibGroupReturnRulePriority - 1)
	_ = uint(ribGroupLeakRulePriority - vrfMissTerminatorPriority - 1)
)

// ribGroupPeerReturnPrefix identifies a peer's leaked prefix and the table
// that owns its connected route.
type ribGroupPeerReturnPrefix struct {
	prefix  *net.IPNet
	tableID int
}

// addRibGroupReturnRules installs one iif/oif pair per peer prefix, restricted
// to families for which this instance successfully installed its own leak.
// It returns failures for Apply to aggregate; a failed return rule does not
// withdraw the forward leak.
func (rg *ribGroupManager) addRibGroupReturnRules(inst *config.RoutingInstanceConfig, peerPrefixes map[int][]ribGroupPeerReturnPrefix) []error {
	// applyVRFReconcile creates no VRF device for a forwarding instance or a
	// reserved name, so there is no VRF context to give a return path to.
	if inst.InstanceType == "forwarding" || config.IsReservedRoutingInstanceName(inst.Name) {
		return nil
	}
	return installDestinationScopedReturnRules(rg.ops, "rib-group", inst.Name, RibGroupReturnRulePriority, peerPrefixes)
}

// installDestinationScopedReturnRules installs `to <peer-prefix> iif|oif
// vrf-<instance> lookup <peer-table>`. Its Dst selector prevents an unrelated
// VRF miss from entering another VRF; the same rule is represented by a
// reverse NextTable route in the userspace FIB.
func installDestinationScopedReturnRules(ops ruleOps, kind, instName string, priority int, prefixes map[int][]ribGroupPeerReturnPrefix) []error {
	vrfName := "vrf-" + instName
	var errs []error
	seen := make(map[struct {
		family int
		prefix string
		table  int
	}]bool)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, peer := range prefixes[family] {
			if peer.prefix == nil || peer.tableID <= 0 {
				errs = append(errs, fmt.Errorf(
					"%s return rules instance %s family %d: refusing a peer prefix without a target table (#11062)",
					kind, instName, family))
				continue
			}
			key := struct {
				family int
				prefix string
				table  int
			}{family, peer.prefix.String(), peer.tableID}
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, selector := range []string{"iif", "oif"} {
				rule := netlink.NewRule()
				rule.Family = family
				rule.Priority = priority
				rule.Table = peer.tableID
				rule.Dst = peer.prefix
				if selector == "iif" {
					rule.IifName = vrfName
				} else {
					rule.OifName = vrfName
				}
				if err := ops.RuleAdd(rule); err != nil {
					errs = append(errs, fmt.Errorf(
						"add %s return rule to peer %s table %d %s %s family %d: %w",
						kind, peer.prefix, peer.tableID, selector, vrfName, family, err))
					continue
				}
				slog.Info(kind+" return rule added",
					"instance", instName, "to", peer.prefix.String(), "peerTable", peer.tableID,
					"selector", selector+" "+vrfName, "family", family, "pref", priority)
			}
		}
	}
	return errs
}
