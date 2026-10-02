package routing

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// #11319: PBR rules now precede destination leaks in both address families.
// Next-table and rib-group rules share a prefix-derived priority mapping so
// longest-prefix order is consistent across leak sources; admission caps are
// independent of priority assignment.
//
// These cells pin the PBR/shared-leak/main bands, installed priorities in both
// families, and a real kernel's first-match verdict for overlapping leaks.

// TestKernelBandOrderPBRFirst11319 pins the as-built RPDB order: PBR strictly
// before the shared leak range, every xpf band strictly before the kernel's
// main rule (32766) and after the VRF miss terminator (2000).
func TestKernelBandOrderPBRFirst11319(t *testing.T) {
	pbrLo, pbrHi := pbrRulePriority, pbrRulePriority+maxPBRRules
	leakLo := config.NextTableRulePriorityBase
	leakHi := leakLo + config.RouteLeakRulePriorityWindow

	if pbrLo != 29000 || pbrHi != 30000 {
		t.Errorf("PBR band = [%d,%d), want [29000,30000)", pbrLo, pbrHi)
	}
	if nextTableRulePriority != leakLo {
		t.Errorf("next-table priority base must be %d, got %d",
			leakLo, nextTableRulePriority)
	}
	if ribGroupLeakRulePriority != leakLo {
		t.Errorf("rib-group priority base must be %d, got %d",
			leakLo, ribGroupLeakRulePriority)
	}
	if pbrHi > leakLo {
		t.Errorf("PBR band end %d must sort before the shared leak range start %d", pbrHi, leakLo)
	}
	const kernelMainRule = 32766 // `32766: from all lookup main`, not RT_TABLE_MAIN
	if leakHi > kernelMainRule {
		t.Errorf("shared leak range end %d must sort before main %d", leakHi, kernelMainRule)
	}
	if vrfMissTerminatorPriority >= pbrLo {
		t.Errorf("VRF miss terminator %d must sort before the PBR band start %d",
			vrfMissTerminatorPriority, pbrLo)
	}
}

// TestKernelBandOrderAppliesInBothFamilies11319 installs rules through each
// Apply path and verifies every leak priority is derived from its destination
// prefix while PBR still precedes all leak rules in both families.

func TestKernelBandOrderAppliesInBothFamilies11319(t *testing.T) {
	ntOps := newFakeRuleOps()
	nt := &nextTableManager{ops: ntOps}
	if err := nt.Apply(
		[]*config.StaticRoute{
			{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
			{Destination: "2001:db8:20::/48", NextTable: "dmz-vr"},
		},
		[]*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}},
		testNextTableIifs,
	); err != nil {
		t.Fatalf("next-table Apply: %v", err)
	}

	rgOps := newFakeRuleOps()
	rg := &ribGroupManager{ops: rgOps}
	// Two leaking instances so the #11062 return rules install alongside the
	// leaks; the return rules sit at 1500 and must not be mistaken for band
	// members below.
	if err := rg.Apply(
		map[string]*config.RibGroup{"leak": {Name: "leak", ImportRibs: []string{"inet.0", "inet6.0"}}},
		[]*config.RoutingInstanceConfig{
			{Name: "a-vr", TableID: 101, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
			{Name: "b-vr", TableID: 102, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
		},
		map[string][]string{
			"a-vr": {"10.0.1.0/24", "2001:db8:1::/64"},
			"b-vr": {"10.0.2.0/24", "2001:db8:2::/64"},
		},
	); err != nil {
		t.Fatalf("rib-group Apply: %v", err)
	}

	pbrOps := newFakeRuleOps()
	pbr := &pbrManager{ops: pbrOps}
	if err := pbr.Apply([]PBRRule{
		{Family: unix.AF_INET, Dst: "10.9.0.0/16", TableID: 500, Instance: "pbr-vr", IifName: "ge-0-0-0"},
		{Family: unix.AF_INET6, Dst: "2001:db8:9::/48", TableID: 500, Instance: "pbr-vr", IifName: "ge-0-0-0"},
	}); err != nil {
		t.Fatalf("PBR Apply: %v", err)
	}

	inWindow := func(prio int) bool {
		return prio >= config.NextTableRulePriorityBase &&
			prio < config.NextTableRulePriorityBase+config.RouteLeakRulePriorityWindow
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		var ntPrios, rgPrios, pbrPrios []int
		var returnPrios []int
		for _, rule := range ntOps.rules[family] {
			ntPrios = append(ntPrios, rule.Priority)
			if rule.Dst == nil {
				t.Errorf("family %d: next-table rule has no destination: %+v", family, rule)
				continue
			}
			prefixLength, addressBits := rule.Dst.Mask.Size()
			want := config.RouteLeakRulePriority(prefixLength, addressBits, config.RouteLeakNextTable)
			if rule.Priority != want {
				t.Errorf("family %d: next-table %s priority = %d, want prefix-derived %d",
					family, rule.Dst, rule.Priority, want)
			}
			if !inWindow(rule.Priority) {
				t.Errorf("family %d: next-table priority %d outside shared leak range", family, rule.Priority)
			}
		}
		for _, rule := range rgOps.rules[family] {
			switch {
			case rule.Priority == RibGroupReturnRulePriority:
				returnPrios = append(returnPrios, rule.Priority)
			case inWindow(rule.Priority):
				rgPrios = append(rgPrios, rule.Priority)
				if rule.Dst == nil {
					t.Errorf("family %d: rib-group leak rule has no destination: %+v", family, rule)
					continue
				}
				prefixLength, addressBits := rule.Dst.Mask.Size()
				want := config.RouteLeakRulePriority(prefixLength, addressBits, config.RouteLeakRibGroup)
				if rule.Priority != want {
					t.Errorf("family %d: rib-group %s priority = %d, want prefix-derived %d",
						family, rule.Dst, rule.Priority, want)
				}
			default:
				t.Errorf("family %d: rib-group installed priority %d outside the shared leak range and return priority",
					family, rule.Priority)
			}
		}
		for _, rule := range pbrOps.rules[family] {
			pbrPrios = append(pbrPrios, rule.Priority)
		}
		if len(ntPrios) == 0 || len(rgPrios) == 0 || len(pbrPrios) == 0 {
			t.Fatalf("family %d: each rule kind must install at least one rule (nt=%v rg=%v pbr=%v)",
				family, ntPrios, rgPrios, pbrPrios)
		}
		for _, priority := range pbrPrios {
			if priority < pbrRulePriority || priority >= pbrRulePriority+maxPBRRules {
				t.Errorf("family %d: PBR priority %d outside [%d,%d)",
					family, priority, pbrRulePriority, pbrRulePriority+maxPBRRules)
			}
		}
		maxOf := func(priorities []int) int {
			max := priorities[0]
			for _, priority := range priorities[1:] {
				if priority > max {
					max = priority
				}
			}
			return max
		}
		minOf := func(priorities []int) int {
			min := priorities[0]
			for _, priority := range priorities[1:] {
				if priority < min {
					min = priority
				}
			}
			return min
		}
		allLeakPrios := append(append([]int(nil), ntPrios...), rgPrios...)
		if maxOf(pbrPrios) >= minOf(allLeakPrios) {
			t.Errorf("family %d: PBR priorities %v must sort before all leak priorities %v",
				family, pbrPrios, allLeakPrios)
		}
		// The #11062 return rules stay below every band: they are consulted
		// before PBR by design (peer-prefix-scoped, pre-terminator).
		for _, priority := range returnPrios {
			if priority >= minOf(pbrPrios) {
				t.Errorf("family %d: return priority %d must sort before the PBR band", family, priority)
			}
		}
	}
}

// TestClearSweepsLegacyBands11319 pins upgrade cleanup for the old next-table
// range at 100-199 and PBR range at 31000-31999. Both pre-#9420 global and
// #9420 ingress-scoped next-table generations remain deletable when their
// destination/table shape identifies them; foreign rules must survive.
func TestClearSweepsLegacyBands11319(t *testing.T) {
	const legacyNextTable = 100
	const legacyPBR = 31000

	t.Run("next-table sweeps stale 100-199", func(t *testing.T) {
		ops := newFakeRuleOps()
		seedCurrentLeakRule(ops, unix.AF_INET, legacyNextTable+5, 101, "10.100.0.0/24", "")
		seedCurrentLeakRule(ops, unix.AF_INET6, legacyNextTable+5, 101, "2001:db8:100::/64", "ge-0-0-0")
		seedRule(ops, unix.AF_INET, 0, 255)
		seedRule(ops, unix.AF_INET, 32766, 254)
		seedRule(ops, unix.AF_INET, 32767, 253)

		if err := (&nextTableManager{ops: ops}).Apply(nil, nil, testNextTableIifs); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if hasPriority(ops, unix.AF_INET, legacyNextTable+5) || hasPriority(ops, unix.AF_INET6, legacyNextTable+5) {
			t.Errorf("stale pre-#11319 next-table rules must be swept, v4=%v v6=%v",
				ops.rules[unix.AF_INET], ops.rules[unix.AF_INET6])
		}
		for _, prio := range []int{0, 32766, 32767} {
			if !hasPriority(ops, unix.AF_INET, prio) {
				t.Errorf("foreign prio %d must survive the sweep, v4=%v", prio, ops.rules[unix.AF_INET])
			}
		}
	})

	t.Run("PBR sweeps stale 31000-31999", func(t *testing.T) {
		ops := newFakeRuleOps()
		seedPBRRule(ops, unix.AF_INET, legacyPBR+5, 500)
		seedPBRRule(ops, unix.AF_INET6, legacyPBR+5, 500)
		seedRule(ops, unix.AF_INET, 0, 255)
		seedRule(ops, unix.AF_INET, 32766, 254)
		seedRule(ops, unix.AF_INET, 32767, 253)

		if err := (&pbrManager{ops: ops}).Apply(nil); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if hasPriority(ops, unix.AF_INET, legacyPBR+5) || hasPriority(ops, unix.AF_INET6, legacyPBR+5) {
			t.Errorf("stale pre-#11319 PBR rules must be swept, v4=%v v6=%v",
				ops.rules[unix.AF_INET], ops.rules[unix.AF_INET6])
		}
		for _, prio := range []int{0, 32766, 32767} {
			if !hasPriority(ops, unix.AF_INET, prio) {
				t.Errorf("foreign prio %d must survive the sweep, v4=%v", prio, ops.rules[unix.AF_INET])
			}
		}
	})
}

// TestPBRPrecedesLeakBandsOnRealKernel11319 is the kernel half: a broad
// next-table rule and a more-specific rib-group rule compete in both
// families, while PBR still precedes both.
//
// It is skipped when the environment cannot create a user+net namespace.
// Every verdict is scored against a control in the SAME run.
func TestPBRPrecedesLeakBandsOnRealKernel11319(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("unshare not available (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("iproute2 not available (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("iproute2 not available")
	}
	script := fmt.Sprintf(`set -e
ip link add duma type dummy
ip link add dumb type dummy
ip link set duma up; ip link set dumb up; ip link set lo up
ip addr add 10.10.0.2/24 dev duma
ip addr add 2001:db8:10::2/64 dev duma
ip addr add 10.20.0.2/24 dev dumb
ip addr add 2001:db8:20::2/64 dev dumb
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
ip route add 10.9.0.0/16 via 10.20.0.1 dev dumb table 200
ip -6 route add 2001:db8:9::/48 via 2001:db8:20::1 dev dumb table 200
ip route add 10.9.0.0/16 via 10.20.0.1 dev dumb table 300
ip -6 route add 2001:db8:9::/48 via 2001:db8:20::1 dev dumb table 300
ip route add 10.9.0.0/16 via 10.20.0.1 dev dumb table 500
ip -6 route add 2001:db8:9::/48 via 2001:db8:20::1 dev dumb table 500
g() { ip route get "$@" 2>&1 | head -1; }
g6() { ip -6 route get "$@" 2>&1 | head -1; }
echo "A_NO_RULE_V4=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "A_NO_RULE_V6=$(g6 2001:db8:9::1 from 2001:db8:10::77 iif duma)"
ip rule add to 10.9.0.0/16 iif duma table 200 pref %d
ip -6 rule add to 2001:db8:9::/48 iif duma table 200 pref %d
ip rule add to 10.9.0.0/24 table 300 pref %d
ip -6 rule add to 2001:db8:9::/64 table 300 pref %d
echo "B_LEAK_ONLY_V4=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "B_LEAK_ONLY_V6=$(g6 2001:db8:9::1 from 2001:db8:10::77 iif duma)"
ip rule add from 10.10.0.77 to 10.9.0.1 iif duma table 500 pref %d
ip -6 rule add from 2001:db8:10::77 to 2001:db8:9::1 iif duma table 500 pref %d
echo "C_PBR_VS_LEAK_V4=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "C_PBR_VS_LEAK_V6=$(g6 2001:db8:9::1 from 2001:db8:10::77 iif duma)"
echo "D_NONPBR_V4=$(g 10.9.0.2 from 10.10.0.99 iif duma)"
echo "D_NONPBR_V6=$(g6 2001:db8:9::2 from 2001:db8:10::99 iif duma)"
`,
		config.RouteLeakRulePriority(16, 32, config.RouteLeakNextTable),
		config.RouteLeakRulePriority(48, 128, config.RouteLeakNextTable),
		config.RouteLeakRulePriority(24, 32, config.RouteLeakRibGroup),
		config.RouteLeakRulePriority(64, 128, config.RouteLeakRibGroup),
		pbrRulePriority, pbrRulePriority,
	)
	out, err := exec.Command("unshare", "-rn", "bash", "-c", script).CombinedOutput()
	if err != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns setup failed: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			got[k] = v
		}
	}
	for _, k := range []string{
		"A_NO_RULE_V4", "A_NO_RULE_V6",
		"B_LEAK_ONLY_V4", "B_LEAK_ONLY_V6",
		"C_PBR_VS_LEAK_V4", "C_PBR_VS_LEAK_V6",
		"D_NONPBR_V4", "D_NONPBR_V6",
	} {
		if strings.TrimSpace(got[k]) == "" {
			t.Fatalf("missing or empty observation %s (full output: %q) — refusing to score a negative against nothing", k, out)
		}
	}
	noRoute := func(k string) bool {
		line := strings.ToLower(got[k])
		return strings.Contains(line, "unreachable") || strings.Contains(line, "no route")
	}

	// Controls: without any matching rule the destination has no route in the
	// main table, so every table-N verdict below comes from an installed rule,
	// not the topology.
	for _, k := range []string{"A_NO_RULE_V4", "A_NO_RULE_V6"} {
		if !noRoute(k) {
			t.Fatalf("A: %s must have no route with no rule installed, got %q", k, got[k])
		}
	}
	// The more-specific /24 and /64 rib-group rules have lower prefix-derived
	// priorities than the broad next-table rules, so table 300 wins in both
	// families.
	for _, k := range []string{"B_LEAK_ONLY_V4", "B_LEAK_ONLY_V6"} {
		if !strings.Contains(got[k], "table 300") {
			t.Fatalf("B: %s must resolve in the rib-group table 300, got %q", k, got[k])
		}
	}
	// The finding: PBR must win over both leak bands in both families,
	// matching the helper's PBR-first override.
	for _, k := range []string{"C_PBR_VS_LEAK_V4", "C_PBR_VS_LEAK_V6"} {
		if !strings.Contains(got[k], "table 500") {
			t.Fatalf("C: %s must resolve in the PBR table 500 (PBR ahead of the leak bands), got %q", k, got[k])
		}
	}
	// Negative controls: a packet outside the PBR from-selector must still
	// follow a leak rule — proving C is selector-driven, not a PBR rule
	// matching everything.
	for _, k := range []string{"D_NONPBR_V4", "D_NONPBR_V6"} {
		if strings.Contains(got[k], "table 500") {
			t.Fatalf("D: %s must NOT resolve in the PBR table 500 (outside the from-selector), got %q", k, got[k])
		}
		if !strings.Contains(got[k], "table 300") {
			t.Fatalf("D: %s must resolve in a leak table (300), got %q", k, got[k])
		}
	}
}
