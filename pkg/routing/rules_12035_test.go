package routing

import (
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestRibGroupClearPreservesSelectorlessCharonRules12035(t *testing.T) {
	ops := newFakeRuleOps()
	foreign := make([]netlink.Rule, 0, 2)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		// strongSwan/charon's default from-all lookup rule has no FRA selectors.
		rule := netlink.NewRule()
		rule.Family = family
		rule.Priority = 220
		rule.Table = 220
		foreign = append(foreign, *rule)
		ops.rules[family] = append(ops.rules[family], *rule)
	}

	if err := (&ribGroupManager{ops: ops}).Apply(nil, nil, nil); err != nil {
		t.Fatalf("empty rib-group apply: %v", err)
	}
	assertRulesPresent11453(t, ops, "selector-less charon rule", foreign, true)
}

func TestPBRClearPreservesForeignRulesAndDeletesOwned12035(t *testing.T) {
	ops := newFakeRuleOps()
	foreign := make([]netlink.Rule, 0, 8)
	stale := make([]netlink.Rule, 0, 6)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, priority := range []int{pbrRulePriority + 4, config.LegacyPBRRulePriorityBase + 4} {
			mark := netlink.NewRule()
			mark.Family = family
			mark.Priority = priority
			mark.Table = 220
			mark.Mark = 7
			mark.Type = unix.RTN_UNICAST
			foreign = append(foreign, *mark)
			ops.rules[family] = append(ops.rules[family], *mark)

			oif := netlink.NewRule()
			oif.Family = family
			oif.Priority = priority + 1
			oif.Table = 220
			oif.OifName = "eth9"
			oif.Type = unix.RTN_UNICAST
			foreign = append(foreign, *oif)
			ops.rules[family] = append(ops.rules[family], *oif)
		}

		dst := mustPrefix11453(t, routePrefix12035(family))
		lookup := netlink.NewRule()
		lookup.Family = family
		lookup.Priority = pbrRulePriority + 10
		lookup.Table = 100123
		lookup.IifName = "ge-0-0-0"
		lookup.Dst = dst
		lookup.Type = unix.RTN_UNICAST
		stale = append(stale, *lookup)
		ops.rules[family] = append(ops.rules[family], *lookup)

		shadow := netlink.NewRule()
		shadow.Family = family
		shadow.Priority = pbrRulePriority + 11
		shadow.Table = -1
		shadow.IifName = "ge-0-0-0"
		shadow.Dst = dst
		shadow.Type = uint8(pbrTerminatorAction)
		stale = append(stale, *shadow)
		ops.rules[family] = append(ops.rules[family], *shadow)

		legacy := netlink.NewRule()
		legacy.Family = family
		legacy.Priority = config.LegacyPBRRulePriorityBase + 10
		legacy.Table = 100123
		legacy.IifName = "ge-0-0-0"
		legacy.Dst = dst
		legacy.Type = unix.RTN_UNICAST
		stale = append(stale, *legacy)
		ops.rules[family] = append(ops.rules[family], *legacy)
	}

	if err := (&pbrManager{ops: ops}).Apply(nil); err != nil {
		t.Fatalf("empty PBR apply: %v", err)
	}
	assertRulesPresent11453(t, ops, "foreign fwmark/oif PBR-band rule", foreign, true)
	assertRulesPresent11453(t, ops, "stale xpf PBR rule", stale, false)
}

// TestRuleClearOwnershipOnKernel12035 exercises the same ownership boundary
// against a private kernel rule table. The charon-like rule and foreign PBR
// rules must survive while stale xpf-shaped rules are removed.
func TestRuleClearOwnershipOnKernel12035(t *testing.T) {
	ops := privateRuleOps12035(t)
	var foreign []netlink.Rule
	stalePriorities := map[int][]int{}
	add := func(rule *netlink.Rule, keep bool) {
		t.Helper()
		if err := ops.RuleAdd(rule); err != nil {
			t.Fatalf("add rule %+v: %v", rule, err)
		}
		if keep {
			foreign = append(foreign, *rule)
		} else {
			stalePriorities[rule.Family] = append(stalePriorities[rule.Family], rule.Priority)
		}
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		charons := netlink.NewRule()
		charons.Family, charons.Priority, charons.Table = family, 220, 220
		charons.Type = unix.RTN_UNICAST
		add(charons, true)

		for _, priority := range []int{pbrRulePriority + 4, config.LegacyPBRRulePriorityBase + 4} {
			mark := netlink.NewRule()
			mark.Family, mark.Priority, mark.Table = family, priority, 220
			mark.Mark, mark.Type = 7, unix.RTN_UNICAST
			add(mark, true)

			oif := netlink.NewRule()
			oif.Family, oif.Priority, oif.Table = family, priority+1, 220
			oif.OifName, oif.Type = "lo", unix.RTN_UNICAST
			add(oif, true)
		}

		dst := mustPrefix11453(t, routePrefix12035(family))
		ribLeak := netlink.NewRule()
		ribLeak.Family, ribLeak.Priority, ribLeak.Table = family, ribGroupLeakRulePriority+10, 100123
		ribLeak.Dst, ribLeak.Type = dst, unix.RTN_UNICAST
		add(ribLeak, false)

		legacyBlanket := netlink.NewRule()
		legacyBlanket.Family, legacyBlanket.Priority, legacyBlanket.Table = family, ribGroupRulePriority, 100123
		legacyBlanket.Type = unix.RTN_UNICAST
		add(legacyBlanket, false)

		pbrLookup := netlink.NewRule()
		pbrLookup.Family, pbrLookup.Priority, pbrLookup.Table = family, pbrRulePriority+10, 100123
		pbrLookup.IifName, pbrLookup.Dst, pbrLookup.Type = "lo", dst, unix.RTN_UNICAST
		add(pbrLookup, false)

		pbrShadow := netlink.NewRule()
		pbrShadow.Family, pbrShadow.Priority, pbrShadow.Table = family, pbrRulePriority+11, -1
		pbrShadow.IifName, pbrShadow.Dst, pbrShadow.Type = "lo", dst, uint8(pbrTerminatorAction)
		add(pbrShadow, false)

		legacyPBR := netlink.NewRule()
		legacyPBR.Family, legacyPBR.Priority, legacyPBR.Table = family, config.LegacyPBRRulePriorityBase+10, 100123
		legacyPBR.IifName, legacyPBR.Dst, legacyPBR.Type = "lo", dst, unix.RTN_UNICAST
		add(legacyPBR, false)
	}

	if err := (&ribGroupManager{ops: ops}).Apply(nil, nil, nil); err != nil {
		t.Fatalf("rib-group apply: %v", err)
	}
	if err := (&pbrManager{ops: ops}).Apply(nil); err != nil {
		t.Fatalf("PBR apply: %v", err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := ops.RuleList(family)
		if err != nil {
			t.Fatalf("list family %d: %v", family, err)
		}
		byPriority := make(map[int]netlink.Rule, len(rules))
		for _, rule := range rules {
			byPriority[rule.Priority] = rule
		}
		for _, want := range foreign {
			if want.Family != family {
				continue
			}
			got, ok := byPriority[want.Priority]
			if !ok || got.Table != want.Table || got.Mark != want.Mark || got.OifName != want.OifName {
				t.Errorf("family %d foreign rule at priority %d did not survive: got=%+v present=%v", family, want.Priority, got, ok)
			}
		}
		for _, priority := range stalePriorities[family] {
			if rule, ok := byPriority[priority]; ok {
				t.Errorf("family %d stale xpf rule at priority %d survived: %+v", family, priority, rule)
			}
		}
	}
}

func privateRuleOps12035(t *testing.T) dscpRuleOps {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns (needs CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() {
		if err := netns.Set(orig); err != nil {
			t.Errorf("restore original netns: %v", err)
		}
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("open netlink handle in private netns: %v", err)
	}
	t.Cleanup(handle.Close)
	return dscpRuleOps{handle}
}

func routePrefix12035(family int) string {
	if family == unix.AF_INET6 {
		return "2001:db8:1203:5::/64"
	}
	return "192.0.2.0/24"
}
