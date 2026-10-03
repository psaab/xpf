package userspace

import (
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// ruleDSCPSelectorsFn reads selectors the netlink Rule type cannot represent.
// FRA_DSCP must be considered alongside RuleList: RuleList drops that attribute
// and reports Tos==0, which otherwise makes a scoped rule appear unconditional.
var ruleDSCPSelectorsFn = routing.RuleListDSCPSelectors

type ipRuleDSCPSelectorKey struct {
	priority int
	table    int
	dst      string
}

// routeLeakDSCPSelectors indexes the sidecar dump by the fields netlink.Rule
// can decode, allowing the route mirror to detect otherwise hidden selectors.
func routeLeakDSCPSelectors(family int) (map[ipRuleDSCPSelectorKey]routing.RuleDSCPSelector, error) {
	selectors, err := ruleDSCPSelectorsFn(family)
	if err != nil {
		// RuleList cannot expose FRA_DSCP. If the sidecar read fails, a
		// destination-only row cannot be proven unscoped; do not publish a
		// snapshot that may widen it into an unconditional NextTable leak.
		return nil, fmt.Errorf("route snapshot: list DSCP selectors for family %d: %w", family, err)
	}
	if len(selectors) == 0 {
		return nil, nil
	}

	rules := make(map[ipRuleDSCPSelectorKey]routing.RuleDSCPSelector, len(selectors))
	for _, selector := range selectors {
		key := ipRuleDSCPSelectorKey{
			priority: selector.Priority,
			table:    selector.Table,
			dst:      selector.Dst,
		}
		rules[key] = selector
	}
	return rules, nil
}

// ipRuleHasDSCPSelector logs and reports a rule whose DSCP selector cannot be
// preserved by the destination-only route snapshot.
func ipRuleHasDSCPSelector(
	family int,
	rule netlink.Rule,
	selectors map[ipRuleDSCPSelectorKey]routing.RuleDSCPSelector,
) bool {
	if rule.Dst == nil {
		return false
	}
	selector, ok := selectors[ipRuleDSCPSelectorKey{
		priority: rule.Priority,
		table:    rule.Table,
		dst:      rule.Dst.String(),
	}]
	if !ok {
		return false
	}
	slog.Warn("skipping ip-rule with an unsupported FRA_DSCP selector from the "+
		"userspace FIB mirror; a NextTable row would widen the match (#11685)",
		"family", family, "priority", rule.Priority, "table", rule.Table,
		"destination", rule.Dst.String(), "dscp", selector.DSCP)
	return true
}
