package routing

import (
	"net"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNextTableClearDeletesOwnedRulesAndPreservesForeign11453(t *testing.T) {
	ops := newFakeRuleOps()
	stale := []netlink.Rule{
		rule11453(t, 101, 101, "10.1.0.0/24", "", ""),
		rule11453(t, 102, 101, "10.2.0.0/24", "ge-0-0-0", ""),
		rule11453(t, legacyNextTableRulePriority+2, 7050, "10.9.0.0/24", "", ""),
		rule11453(t, nextTableRulePriority+1, 101, "10.3.0.0/24", "ge-0-0-0", ""),
		rule11453(t, previousNextTableRulePriority+1, 101, "10.4.0.0/24", "ge-0-0-0", ""),
	}
	foreign := []netlink.Rule{
		// The old [100,200) cleanup was priority-only; preserve a main-table
		// rule and a rule with a source selector in that legacy window.
		{Family: unix.AF_INET, Priority: 110, Table: 254},
		{Family: unix.AF_INET, Priority: 111, Table: 101, Src: mustPrefix11453(t, "192.0.2.0/24")},
		// Current and previous bands must also require an unreserved target
		// table and the complete destination+iif shape emitted by xpf.
		rule11453(t, nextTableRulePriority+2, 254, "10.5.0.0/24", "ge-0-0-0", ""),
		rule11453(t, nextTableRulePriority+3, 101, "10.6.0.0/24", "ge-0-0-0", "eth0"),
		rule11453(t, previousNextTableRulePriority+2, 254, "10.7.0.0/24", "ge-0-0-0", ""),
	}
	withProto := rule11453(t, nextTableRulePriority+4, 101, "10.8.0.0/24", "ge-0-0-0", "")
	withProto.IPProto = 6
	foreign = append(foreign, withProto)
	for i, table := range []int{
		0, int(unix.RT_TABLE_DEFAULT), mainTableID, int(unix.RT_TABLE_LOCAL),
		config.ManagementVRFTableID, config.ProbeTableBase,
		config.ProbeTableBase + config.ProbeTableCount - 1,
	} {
		foreign = append(foreign, rule11453(t, nextTableRulePriority+5+i, table,
			"10.10.0.0/24", "ge-0-0-0", ""))
	}
	ops.rules[unix.AF_INET] = append(ops.rules[unix.AF_INET], stale...)
	ops.rules[unix.AF_INET] = append(ops.rules[unix.AF_INET], foreign...)

	if err := (&nextTableManager{ops: ops}).Apply(nil, nil, testNextTableIifs); err != nil {
		t.Fatalf("empty next-table apply: %v", err)
	}
	assertRulesPresent11453(t, ops, "stale xpf next-table rule", stale, false)
	assertRulesPresent11453(t, ops, "foreign rule", foreign, true)
}

func TestRibGroupClearDeletesOwnedRulesAndPreservesForeign11453(t *testing.T) {
	ops := newFakeRuleOps()
	stale := []netlink.Rule{
		rule11453(t, ribGroupLeakRulePriority+1, 101, "10.1.0.0/24", "", ""),
		rule11453(t, ribGroupRulePriority, 101, "", "", ""),
		rule11453(t, RibGroupReturnRulePriority, 102, "10.2.0.0/24", "vrf-dmz", ""),
		rule11453(t, RibGroupReturnRulePriority, 102, "10.3.0.0/24", "", "vrf-dmz"),
	}
	foreign := []netlink.Rule{
		// A main-table lookalike is foreign: the #9819 installer emits
		// peer-table return rules, never Table==main.
		rule11453(t, RibGroupReturnRulePriority, 254, "10.4.0.0/24", "vrf-dmz", ""),
		// A current leak priority is not sufficient without the complete
		// xpf destination-only, non-reserved-table shape.
		rule11453(t, ribGroupLeakRulePriority+2, 254, "10.5.0.0/24", "", ""),
		rule11453(t, ribGroupLeakRulePriority+3, 101, "10.6.0.0/24", "", "eth0"),
		// Legacy blanket windows require a from-all shape; preserve rules
		// with a destination, source, or mark selector.
		rule11453(t, ribGroupRulePriority+1, 254, "192.0.2.0/24", "", ""),
		{Family: unix.AF_INET, Priority: ribGroupRulePriority + 2, Table: 101, Src: mustPrefix11453(t, "198.51.100.0/24")},
		{Family: unix.AF_INET, Priority: ribGroupRulePriority + 3, Table: 101, Mark: 1},
		{Family: unix.AF_INET, Priority: 250, Table: 254, Dst: mustPrefix11453(t, "203.0.113.0/24")},
		{Family: unix.AF_INET, Priority: 251, Table: 101, Mark: 1},
		// At 1500, a non-VRF selector or both selectors is not an xpf
		// return-rule shape and must survive.
		rule11453(t, RibGroupReturnRulePriority, 102, "10.7.0.0/24", "ge-0-0-0", ""),
		rule11453(t, RibGroupReturnRulePriority, 102, "10.8.0.0/24", "vrf-dmz", "eth0"),
	}
	ops.rules[unix.AF_INET] = append(ops.rules[unix.AF_INET], stale...)
	ops.rules[unix.AF_INET] = append(ops.rules[unix.AF_INET], foreign...)

	if err := (&ribGroupManager{ops: ops}).Apply(nil, nil, nil); err != nil {
		t.Fatalf("empty rib-group apply: %v", err)
	}
	assertRulesPresent11453(t, ops, "stale xpf rib-group rule", stale, false)
	assertRulesPresent11453(t, ops, "foreign rule", foreign, true)
}

func rule11453(t *testing.T, priority, table int, dst, iif, oif string) netlink.Rule {
	t.Helper()
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Priority = priority
	rule.Table = table
	rule.IifName = iif
	rule.OifName = oif
	if dst != "" {
		rule.Dst = mustPrefix11453(t, dst)
	}
	return *rule
}

func mustPrefix11453(t *testing.T, prefix string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", prefix, err)
	}
	return network
}

func assertRulesPresent11453(t *testing.T, ops *fakeRuleOps, description string, rules []netlink.Rule, wantPresent bool) {
	t.Helper()
	for _, want := range rules {
		found := false
		for _, have := range ops.rules[want.Family] {
			if reflect.DeepEqual(have, want) {
				found = true
				break
			}
		}
		if found != wantPresent {
			t.Errorf("%s %+v present=%v, want %v; remaining rules=%+v", description, want, found, wantPresent, ops.rules[want.Family])
		}
	}
}
