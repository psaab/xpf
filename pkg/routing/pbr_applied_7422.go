package routing

import (
	"net"
	"reflect"
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// pbr_applied_7422.go reports two different readback facts:
//
//   - band occupancy: even-priority slots in the PBR band, without claiming
//     their rules match the active config;
//   - observable mismatches: desired lookup slots whose netlink-visible rule
//     fields differ, are missing, or are occupied by an unexpected rule.
//
// Each PBR lookup rule uses the even offset of a two-priority pair; its
// unreachable shadow occupies the following odd offset. netlink v1.3.1 does
// not decode fib-rule action into Rule.Type, nor does RuleList expose FRA_DSCP.
// The occupancy count therefore cannot prove a rule was applied, and the
// mismatch check explicitly cannot verify the DSCP selector (or action). The
// priority-band SSOT is shared with the install side (#4479); rules outside it
// are not ours.
// PBRAppliedCount returns even-priority PBR-band occupancy across both address
// families and whether readback SUCCEEDED. It intentionally does not claim
// these rules match the desired config; use PBRAppliedStatus for the sampled
// observable mismatch count.
//
// The bool is not advisory. A failed RuleList is indistinguishable from "no
// rules installed" in the count alone, and reporting 0 against a non-zero
// desired count would look exactly like a total install failure. A caller that
// cannot read must omit both readback metrics rather than publish fabricated
// zeros. Both families must succeed.
func PBRAppliedCount(ops ruleOps) (count int, ok bool) {
	count, _, ok = PBRAppliedStatus(ops, nil)
	return
}

// PBRAppliedStatus returns PBR-band occupancy, the number of mismatched
// expected lookup slots, and whether both family readbacks succeeded.
//
// Desired PBR lookup rules are assigned even priorities in slice order, with
// one rule per two-priority pair. A mismatch is one for each missing or
// incorrect expected slot, plus each unexpected/duplicate in-band lookup rule.
// RuleList exposes all Rule fields except the fib-rule action, and netlink
// v1.3.1 does not expose FRA_DSCP at all; DSCP selectors and actions therefore
// cannot contribute to this mismatch signal. The exported metric help states
// this limit explicitly.
func PBRAppliedStatus(ops ruleOps, desired []PBRRule) (bandOccupancy, mismatched int, ok bool) {
	if ops == nil {
		return 0, 0, false
	}
	lo := uint32(config.PBRRulePriorityBase)
	hi := lo + uint32(config.PBRRuleWindow)
	expected := make([]netlink.Rule, len(desired))
	expectedOK := make([]bool, len(desired))
	for i := range desired {
		expected[i], expectedOK[i] = pbrExpectedLookupRule(desired[i], int(lo)+2*i)
	}

	type lookupKey struct {
		family   int
		priority int
	}
	type observedSlot struct {
		count   int
		matched bool
	}
	observed := make(map[lookupKey]observedSlot)
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := ops.RuleList(family)
		if err != nil {
			return 0, 0, false
		}
		for i := range rules {
			rule := rules[i]
			priority := rule.Priority
			if priority < int(lo) || priority >= int(hi) || (priority-int(lo))%2 != 0 {
				continue
			}
			bandOccupancy++
			key := lookupKey{family: family, priority: priority}
			slot := observed[key]
			index := (priority - int(lo)) / 2
			if slot.count == 0 {
				if index >= 0 && index < len(desired) &&
					desired[index].Family == family && expectedOK[index] {
					slot.matched = pbrNetlinkRuleMatches(expected[index], rule)
				}
			} else if !slot.matched {
				if index >= 0 && index < len(desired) &&
					desired[index].Family == family && expectedOK[index] &&
					pbrNetlinkRuleMatches(expected[index], rule) {
					slot.matched = true
				}
			}
			slot.count++
			observed[key] = slot
		}
	}

	seen := make([]bool, len(desired))
	for key, slot := range observed {
		index := (key.priority - int(lo)) / 2
		if index < 0 || index >= len(desired) || desired[index].Family != key.family {
			mismatched += slot.count
			continue
		}
		seen[index] = true
		if !slot.matched {
			mismatched++
		}
		mismatched += slot.count - 1
	}
	for _, present := range seen {
		if !present {
			mismatched++
		}
	}
	return bandOccupancy, mismatched, true
}

func pbrExpectedLookupRule(pbr PBRRule, priority int) (netlink.Rule, bool) {
	rule := netlink.NewRule()
	rule.Priority = priority
	rule.Family = pbr.Family
	rule.Table = pbr.TableID
	rule.IifName = pbr.IifName
	if pbr.Src != "" {
		_, src, err := net.ParseCIDR(pbr.Src)
		if err != nil {
			return netlink.Rule{}, false
		}
		rule.Src = src
	}
	if pbr.Dst != "" {
		_, dst, err := net.ParseCIDR(pbr.Dst)
		if err != nil {
			return netlink.Rule{}, false
		}
		rule.Dst = dst
	}
	if pbr.IPProto > 0 {
		rule.IPProto = pbr.IPProto
	}
	if pbr.Sport != nil {
		rule.Sport = netlink.NewRulePortRange(pbr.Sport.Lo, pbr.Sport.Hi)
	}
	if pbr.Dport != nil {
		rule.Dport = netlink.NewRulePortRange(pbr.Dport.Lo, pbr.Dport.Hi)
	}
	// DSCPSet cannot be represented in RuleList's readback; do not pretend the
	// desired DSCP value was checked. Type is likewise left at netlink's default
	// because RuleList does not decode the action.
	return *rule, true
}

func pbrNetlinkRuleMatches(expected, observed netlink.Rule) bool {
	// RuleList intentionally does not decode the fib-rule action into Type.
	// Normalize that single unreadable field before comparing every other
	// netlink-visible selector and routing attribute.
	expected.Type = observed.Type
	return reflect.DeepEqual(expected, observed)
}

// PBRAppliedStatusLive is the production entry point, reading through the
// live netlink handle. Split from PBRAppliedStatus so band and structural
// mismatch behavior can be exercised with an in-memory ruleOps fake.
func PBRAppliedStatusLive(desired []PBRRule) (int, int, bool) {
	return PBRAppliedStatus(netlinkRuleOps{}, desired)
}

// PBRAppliedCountLive is retained for callers that need only band occupancy.
func PBRAppliedCountLive() (int, bool) {
	count, _, ok := PBRAppliedStatusLive(nil)
	return count, ok
}

// netlinkRuleOps is the live implementation, listing through the package-level
// netlink functions. Only RuleList is reachable here; the mutating methods
// satisfy the interface and are never called on this path.
type netlinkRuleOps struct{}

func (netlinkRuleOps) RuleAdd(r *netlink.Rule) error { return netlink.RuleAdd(r) }
func (netlinkRuleOps) RuleDel(r *netlink.Rule) error { return netlink.RuleDel(r) }
func (netlinkRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	return netlink.RuleList(family)
}
func (netlinkRuleOps) RuleAddDSCP(r *netlink.Rule, dscp uint8) error {
	return dscpRuleOps{}.RuleAddDSCP(r, dscp)
}
