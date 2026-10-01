package routing

import (
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// pbr_applied_7422.go answers "how many PBR ip rules are ACTUALLY in the
// kernel", as distinct from how many the config asks for.
//
// #7422 row 12: `xpf_pbr_rules_installed` is named for an applied fact and
// derived from a desired one — `routing.PBRBuildStats` is a pure function of
// the config, emitted before the dataplane gate. A rule the builder produced
// but the kernel refused is counted as installed, so the metric an operator
// alerts on cannot see the failure it exists to catch.
//
// The band, not a tag, is what identifies xpf's rules. PBR ip rules occupy
// [PBRRulePriorityBase, PBRRulePriorityBase+PBRRuleWindow) — 29000..29999 —
// and each lookup rule uses the even offset of a two-priority pair; its
// unreachable shadow occupies the following odd offset. netlink v1.3.1 does
// not decode the fib-rule action into Rule.Type, so count lookup slots by their
// stable priority-pair position. The band constant is the SSOT shared with the
// userspace FIB ingest (#4479). Rules outside the band (the kernel's own
// 0/32766/32767, next-table at 32000-32099, rib-group at 30000-30999, and
// legacy rules) are not ours and are not counted.

// PBRAppliedCount returns the number of PBR steering lookup rules present in
// the kernel, summed across both address families, and whether readback SUCCEEDED.
//
// The bool is not advisory. A failed RuleList is indistinguishable from "no
// rules installed" in the count alone, and reporting 0-applied against
// N-desired would look exactly like a total install failure — the loudest
// possible false alarm. A caller that cannot read must omit the metric rather
// than publish a fabricated zero.
//
// Both families must succeed. A partial read is a partial truth, and a metric
// that silently halves during an IPv6 hiccup is worse than an absent one.
func PBRAppliedCount(ops ruleOps) (count int, ok bool) {
	if ops == nil {
		return 0, false
	}
	lo := uint32(config.PBRRulePriorityBase)
	hi := lo + uint32(config.PBRRuleWindow)
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := ops.RuleList(family)
		if err != nil {
			return 0, false
		}
		for i := range rules {
			if p := rules[i].Priority; p >= int(lo) && p < int(hi) &&
				(p-int(lo))%2 == 0 {
				count++
			}
		}
	}
	return count, true
}

// PBRAppliedCountLive is the production entry point, reading through the live
// netlink handle. Split from PBRAppliedCount so the band arithmetic is
// exercised by tests against an in-memory ruleOps fake, the same seam
// NewManagerWithRuleOpsForTest uses.
func PBRAppliedCountLive() (int, bool) {
	return PBRAppliedCount(netlinkRuleOps{})
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
