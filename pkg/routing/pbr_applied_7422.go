package routing

import (
	"net"
	"reflect"
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// pbr_applied_7422.go reports two different readback facts:
//
//   - band occupancy: even-priority slots in the PBR band, without claiming
//     their rules match the active config;
//   - observable mismatches: desired lookup slots whose netlink-visible rule
//     fields differ, are missing, or are occupied by an unexpected rule.
//
// Each PBR lookup rule uses the even offset of a two-priority pair; its
// unreachable shadow occupies the following odd offset. The live readback
// goes through RuleListFull (rule_dump_linux.go), which decodes the
// fib-rule action (Rule.Type) netlink v1.3.1's RuleList omits, so the
// mismatch check DOES verify the action: a lookup slot replaced by an
// unreachable rule at the same priority is a mismatch (#17078). The
// DSCP selector is carried too, but it is compared only when the
// desired rule declares one (PBRRule.DSCPSet): the fake-able
// PBRAppliedStatus path reads []netlink.Rule, which cannot represent
// a readback DSCP, so an undeclared desire must not be charged for a
// selector it never asked to check. The priority-band SSOT is shared
// with the install side (#4479); rules outside it are not ours.
//
// The bool is not advisory. A failed RuleList is indistinguishable from "no
// rules installed" in the count alone, and reporting 0 against a non-zero
// desired count would look exactly like a total install failure. A caller that
// cannot read must omit both readback metrics rather than publish fabricated
// zeros. Both families must succeed.

// PBRAppliedStatus returns PBR-band occupancy, the number of mismatched
//
// Desired PBR lookup rules are assigned even priorities in slice order, with
// one rule per two-priority pair. A mismatch is one for each missing or
// incorrect expected slot, plus each unexpected/duplicate in-band lookup rule.
// The comparison covers every netlink-visible field including the fib-rule
// action (Rule.Type, decoded by RuleListFull on the live path). The DSCP
// selector is compared only on the live path and only when the desired
// rule declares one (PBRRule.DSCPSet); the exported metric help states
// this limit explicitly.
func PBRAppliedStatus(ops ruleOps, desired []PBRRule) (bandOccupancy, mismatched int, ok bool) {
	if ops == nil {
		return 0, 0, false
	}
	lo := uint32(config.PBRRulePriorityBase)
	hi := lo + uint32(config.PBRRuleWindow)
	type observedSlot struct {
		expected   netlink.Rule
		expectedOK bool
		count      int
		matched    bool
	}
	slots := make([]observedSlot, len(desired))
	for index, pbr := range desired {
		slots[index].expected, slots[index].expectedOK =
			pbrExpectedLookupRule(pbr, int(lo)+2*index)
	}
	// When the ops can also return full rows, the DSCP sidecar joins
	// the comparison for slots whose desired rule declares a DSCP
	// selector; the RuleList projection alone cannot represent it.
	fullOps, hasFull := ops.(fullRuleOps)
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		var rows []RuleRow
		if hasFull {
			var err error
			rows, err = fullOps.RuleListFullRows(family)
			if err != nil {
				return 0, 0, false
			}
		} else {
			rules, err := ops.RuleList(family)
			if err != nil {
				return 0, 0, false
			}
			rows = make([]RuleRow, len(rules))
			for i := range rules {
				rows[i].Rule = rules[i]
			}
		}
		for i := range rows {
			rule := rows[i].Rule
			priority := rule.Priority
			if priority < int(lo) || priority >= int(hi) || (priority-int(lo))%2 != 0 {
				continue
			}
			bandOccupancy++
			index := (priority - int(lo)) / 2
			if index >= len(desired) || desired[index].Family != family {
				mismatched++
				continue
			}
			slot := &slots[index]
			slot.count++
			if slot.expectedOK && !slot.matched &&
				pbrNetlinkRuleMatches(slot.expected, rule) &&
				(!hasFull || !desired[index].DSCPSet ||
					(rows[i].DSCPSet && rows[i].DSCP == desired[index].DSCP)) {
				slot.matched = true
			}
		}
	}

	for _, slot := range slots {
		if slot.count == 0 || !slot.matched {
			mismatched++
		}
		if slot.count > 1 {
			mismatched += slot.count - 1
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
	// A PBR lookup rule is installed under RTN_UNICAST (rules.go
	// buildPBRRules); RuleListFull decodes the kernel action into
	// Type, so the expected action is part of the comparison. DSCPSet
	// cannot be represented in a netlink.Rule expectation; it is
	// compared from the RuleRow sidecar by PBRAppliedStatusLive.
	rule.Type = unix.RTN_UNICAST
	return *rule, true
}

func pbrNetlinkRuleMatches(expected, observed netlink.Rule) bool {
	// Every netlink-visible selector and routing attribute is
	// compared, including the fib-rule action: RuleListFull decodes
	// it into Type (#17078), so no field is normalised away.
	return reflect.DeepEqual(expected, observed)
}

// fullRuleOps is the ruleOps PBRAppliedStatus needs when the readback
// must also see each row's FRA_DSCP sidecar: RuleListFullRows returns
// the decoded rows, RuleList their netlink.Rule projection (what
// PBRAppliedStatus consumes). The live implementation satisfies it;
// in-memory fakes that only implement ruleOps take the projection-only
// path, where a declared DSCP desire is unchecked exactly as before.
type fullRuleOps interface {
	ruleOps
	RuleListFullRows(family int) ([]RuleRow, error)
}

// PBRAppliedStatusLive is the production entry point, reading through
// RuleListFull so the fib-rule action and the FRA_DSCP sidecar both
// reach the mismatch check. Split from PBRAppliedStatus so band and
// structural mismatch behavior can be exercised with an in-memory
// ruleOps fake.
func PBRAppliedStatusLive(desired []PBRRule) (int, int, bool) {
	return PBRAppliedStatus(netlinkFullRuleOps{}, desired)
}

// netlinkFullRuleOps is the live implementation, listing through
// RuleListFull. Only the list methods are reachable here; the mutating
// methods satisfy the interface and are never called on this path.
type netlinkFullRuleOps struct{}

func (netlinkFullRuleOps) RuleAdd(r *netlink.Rule) error { return netlink.RuleAdd(r) }
func (netlinkFullRuleOps) RuleDel(r *netlink.Rule) error { return netlink.RuleDel(r) }
func (netlinkFullRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	rows, err := RuleListFull(family)
	if err != nil {
		return nil, err
	}
	rules := make([]netlink.Rule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, row.Rule)
	}
	return rules, nil
}
func (netlinkFullRuleOps) RuleListFullRows(family int) ([]RuleRow, error) {
	return RuleListFull(family)
}
func (netlinkFullRuleOps) RuleAddDSCP(r *netlink.Rule, dscp uint8) error {
	return dscpRuleOps{}.RuleAddDSCP(r, dscp)
}
