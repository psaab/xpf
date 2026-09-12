package routing

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// vrfMissTerminatorPriority is the ip-rule priority of the #9819 VRF miss
// terminator, installed once per address family:
//
//	ip rule add pref 2000 l3mdev unreachable
//
// The kernel's own l3mdev rule, at 1000, is a LOOKUP rule. A lookup that missed
// the VRF's table therefore continued down the rule list: into the rib-group
// leak band at 30000, and then into main at 32766. A VRF-context kernel lookup
// left its instance whenever its table had no covering route. That covers
// ingress on a slave the userspace dataplane does not adjudicate, plaintext
// from a VRF-bound tunnel, and any socket bound to a VRF.
//
// The terminator carries the SAME l3mdev selector as the kernel's rule, so it
// matches exactly the lookups that consulted a VRF table and missed, and ends
// them with ENETUNREACH. It is the rule form of the per-VRF
// `unreachable default metric 4278198272` route the kernel's VRF documentation
// recommends. The route form would put an entry in every VRF table, and FRR's
// zebra, systemd-networkd and the FBF harness all enumerate those tables. A rule
// is visible to none of them.
//
// Priorities between 1000 and this one are for VRF-context steering that must
// run after the VRF's own table and before the terminator. Today the only rules
// there are the rib-group return rules at ribGroupReturnRulePriority.
const vrfMissTerminatorPriority = 2000

// vrfMissTerminatorOps is the netlink surface the terminator needs. Production
// is dscpRuleOps, which embeds *netlink.Handle for RuleDel and adds the l3mdev
// install in rule_l3mdev_linux.go.
type vrfMissTerminatorOps interface {
	RuleDel(*netlink.Rule) error
	// RuleAddL3mdevUnreachable installs `pref <priority> l3mdev unreachable`
	// for one family. netlink v1.3.1's Rule has no l3mdev selector.
	RuleAddL3mdevUnreachable(family, priority int) error
}

// setVRFMissTerminator installs (present) or removes (!present) the terminator
// in both families, and aggregates the per-family failures.
//
// Install is idempotent through the kernel's own duplicate check. Under
// NLM_F_EXCL the kernel compares every field of the rule, the l3mdev flag and
// the action included, so EEXIST means this exact rule is already installed,
// not merely some rule at this priority.
//
// Removal deletes by priority and action and does not carry the l3mdev flag, so
// a box with no VRFs can still commit on a kernel built without l3mdev support.
// ENOENT is the desired end state, not a failure.
func setVRFMissTerminator(ops vrfMissTerminatorOps, present bool) error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if present {
			err := ops.RuleAddL3mdevUnreachable(family, vrfMissTerminatorPriority)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				errs = append(errs, fmt.Errorf("install VRF miss terminator (family %d, pref %d): %w",
					family, vrfMissTerminatorPriority, err))
			}
			continue
		}
		rule := netlink.NewRule()
		rule.Family = family
		rule.Priority = vrfMissTerminatorPriority
		rule.Type = nl.FR_ACT_UNREACHABLE
		if err := ops.RuleDel(rule); err != nil && !isRuleAlreadyGone(err) {
			errs = append(errs, fmt.Errorf("remove VRF miss terminator (family %d, pref %d): %w",
				family, vrfMissTerminatorPriority, err))
		}
	}
	return errors.Join(errs...)
}
