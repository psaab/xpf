package routing

import (
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ribGroupReturnRulePriority is the ip-rule priority of the #9819 rib-group
// return rules. A routing instance whose interface routes leak into main gets,
// for each family its leak installs:
//
//	ip rule add pref 1500 iif vrf-<instance> lookup main
//	ip rule add pref 1500 oif vrf-<instance> lookup main
//
// The VRF miss terminator (vrfMissTerminatorPriority) ends every lookup that
// misses a VRF table. A leak source's table has no route to the hosts that use
// its leaked prefixes, because main is what reaches them. Measured in a network
// namespace with the terminator and nothing else:
//   - the lookup from main to a leaked address fails its reverse-path check
//     (EINVAL);
//   - the return lookup from the source's slave is unreachable.
//
// These rules restore both.
//
// They are the reliance #9819 asked to be named: a leak source's misses
// resolve in main. Main is also the only table they reach. `lookup main` is a
// table action, so a lookup that misses main too moves on to the terminator,
// and the rib-group band and every other instance's table stay out of reach.
// Before #9819 such a miss fell through the band as well.
//
// The rules sit after the kernel's l3mdev rule at 1000, so the source's own
// table is consulted first. A source with its own covering route, a default
// for example, never reaches them.
const ribGroupReturnRulePriority = 1500

// The ordering is load-bearing. At or below 1000 a return rule would pre-empt
// the source's own table. At or above the terminator it would never be reached.
// A terminator at or above the leak band would let the band see VRF misses
// again. All three are constants, so the order is checked at compile time.
const (
	_ = uint(ribGroupReturnRulePriority - 1001)
	_ = uint(vrfMissTerminatorPriority - ribGroupReturnRulePriority - 1)
	_ = uint(ribGroupLeakRulePriority - vrfMissTerminatorPriority - 1)
)

// addRibGroupReturnRules installs the return rules for one leak source, for
// each family in which at least one of its leak rules installed. It returns
// the failures for Apply to aggregate. A failed return rule does not withdraw
// the leak rules: the userspace FIB mirrors those and does not depend on a
// kernel return path.
func (rg *ribGroupManager) addRibGroupReturnRules(inst *config.RoutingInstanceConfig, installed map[int]bool) []error {
	// applyVRFReconcile creates no VRF device for a forwarding instance or a
	// reserved name, so there is no VRF context to give a return path to.
	if inst.InstanceType == "forwarding" || config.IsReservedRoutingInstanceName(inst.Name) {
		return nil
	}
	vrfName := "vrf-" + inst.Name
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if !installed[family] {
			continue
		}
		for _, selector := range []string{"iif", "oif"} {
			rule := netlink.NewRule()
			rule.Family = family
			rule.Priority = ribGroupReturnRulePriority
			rule.Table = mainTableID
			if selector == "iif" {
				rule.IifName = vrfName
			} else {
				rule.OifName = vrfName
			}
			if err := rg.ops.RuleAdd(rule); err != nil {
				errs = append(errs, fmt.Errorf(
					"add rib-group return rule %s %s lookup main instance %s family %d: %w",
					selector, vrfName, inst.Name, family, err))
				continue
			}
			slog.Info("rib-group return rule added",
				"instance", inst.Name, "selector", selector+" "+vrfName,
				"family", family, "pref", ribGroupReturnRulePriority)
		}
	}
	return errs
}
