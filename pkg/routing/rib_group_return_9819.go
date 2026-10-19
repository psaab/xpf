package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RibGroupReturnRulePriority is the LEGACY flat ip-rule priority of the
// pre-#14975 rib-group return rules. It is retained only so clear() and the
// userspace FIB mirror recognize rules installed by an older binary during
// an in-place upgrade. New installs use the per-prefix LPM priority from
// config.RibGroupReturnRulePriority:
//
//	ip rule add pref <derived> to <peer-prefix> iif vrf-<instance> lookup <peer-table>
//	ip rule add pref <derived> to <peer-prefix> oif vrf-<instance> lookup <peer-table>
//
// Looking up the peer table avoids falling through to main's default route.
// The userspace FIB mirrors these rules as reverse NextTable routes between
// the source and peer tables.
const RibGroupReturnRulePriority = config.LegacyRibGroupReturnRulePriority

// IsRibGroupReturnRulePriority reports whether priority belongs to a
// rib-group return rule: the legacy flat 1500 or any priority in the
// LPM-derived return window (1000, 2000). Kernel ip-rule priorities are
// per-family, so the derived window is shared by both families.
func IsRibGroupReturnRulePriority(priority int) bool {
	return priority > 1000 && priority < 2000
}

// ribGroupReturnRulePriorityFor returns the LPM-ordered priority for one
// peer prefix.
func ribGroupReturnRulePriorityFor(prefix *net.IPNet) int {
	if prefix == nil {
		return RibGroupReturnRulePriority
	}
	prefixLength, addressBits := prefix.Mask.Size()
	if addressBits == 0 {
		// Unparseable mask: fail closed to the legacy value, which is
		// still inside the return window and swept by clear().
		return RibGroupReturnRulePriority
	}
	return config.RibGroupReturnRulePriority(prefixLength, addressBits)
}

// The ordering is load-bearing: scoped return rules run after the kernel's
// l3mdev lookup (1000) and before the VRF miss terminator (2000); the
// rib-group leak band stays after both. Checked at compile time.
const (
	_ = uint(config.RibGroupReturnRulePriorityBase - 1001)
	_ = uint(vrfMissTerminatorPriority - (config.RibGroupReturnRulePriorityBase + config.RibGroupReturnRulePriorityWindow))
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
	return installDestinationScopedReturnRules(rg.ops, "rib-group", inst.Name, peerPrefixes)
}

// installDestinationScopedReturnRules installs `to <peer-prefix> iif|oif
// vrf-<instance> lookup <peer-table>` at the prefix's LPM-derived priority
// (#14975). Its Dst selector prevents an unrelated VRF miss from entering
// another VRF; the same rule is represented by a reverse NextTable route in
// the userspace FIB. A pre-existing identical rule (EEXIST, e.g. a survivor
// of a failed clear) counts as installed, mirroring next-table handling
// (#9810); every other add failure is aggregated.
func installDestinationScopedReturnRules(ops ruleOps, kind, instName string, prefixes map[int][]ribGroupPeerReturnPrefix) []error {
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
			priority := ribGroupReturnRulePriorityFor(peer.prefix)
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
					if errors.Is(err, unix.EEXIST) {
						continue
					}
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
