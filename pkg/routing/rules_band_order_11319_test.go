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

// #11319: the kernel leak bands (next-table 100-199, rib-group 30000-30999)
// outranked PBR (31000-31999) in both families, while the helper applies the
// PBR override FIRST (userspace-dp/src/afxdp/forwarding/pbr.rs
// ingress_route_table_override runs before any FIB lookup, and leak rows are
// only consulted inside the resolved table) and never consults leak rows
// under an override table. Same packet, different table on the two planes.
// The helper is the Junos-faithful side (a firewall-filter routing-instance
// action steers before the route lookup), so the fix renumbers the kernel
// bands: PBR 29000-29999, rib-group leak 30000-30999 (unchanged), next-table
// 32000-32099 — all still before main (32766).
//
// These cells pin that order at three levels: the constants, the installed
// rules in both families, and a real kernel's first-match verdict.

// TestKernelBandOrderPBRFirst11319 pins the as-built RPDB order: PBR strictly
// before both leak bands, every xpf band strictly before the kernel's main
// rule (32766) and after the VRF miss terminator (2000).
//
// RED-on-revert: restoring PBRRulePriorityBase=31000 or
// NextTableRulePriorityBase=100 breaks the chain (PBR sorts after a leak
// band) and this fails.
func TestKernelBandOrderPBRFirst11319(t *testing.T) {
	pbrLo, pbrHi := pbrRulePriority, pbrRulePriority+maxPBRRules
	rgLo, rgHi := ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules
	ntLo, ntHi := nextTableRulePriority, nextTableRulePriority+maxNextTableRules

	// The exact as-built numbers. Band moves are cross-plane contracts: the
	// FBF steering harness (test/incus/test-fbf-steering.sh) matches the PBR
	// band by numeric pattern, and the userspace FIB ingest skips it by the
	// same SSOT — a silent retune breaks one of them, so retunes update here.
	if pbrLo != 29000 || pbrHi != 30000 {
		t.Errorf("PBR band = [%d,%d), want [29000,30000)", pbrLo, pbrHi)
	}
	if rgLo != 30000 || rgHi != 31000 {
		t.Errorf("rib-group leak band = [%d,%d), want [30000,31000)", rgLo, rgHi)
	}
	if ntLo != 32000 || ntHi != 32100 {
		t.Errorf("next-table band = [%d,%d), want [32000,32100)", ntLo, ntHi)
	}

	// The order itself: PBR first among the three (helper parity), then the
	// leak bands in ascending-priority order (the helper sorts leak rows by
	// rule_priority, so both planes agree leak-vs-leak too).
	if pbrHi > rgLo {
		t.Errorf("PBR band end %d must sort before the rib-group leak band start %d", pbrHi, rgLo)
	}
	if rgHi > ntLo {
		t.Errorf("rib-group leak band end %d must sort before the next-table band start %d", rgHi, ntLo)
	}
	// Every xpf band stays before main (a band at/after 32766 re-opens the
	// #3876 shadow-by-default no-op) and after the VRF miss terminator.
	const kernelMainRule = 32766 // `32766: from all lookup main`, not RT_TABLE_MAIN
	if ntHi > kernelMainRule {
		t.Errorf("next-table band end %d must sort before main %d", ntHi, kernelMainRule)
	}
	if vrfMissTerminatorPriority >= pbrLo {
		t.Errorf("VRF miss terminator %d must sort before the PBR band start %d",
			vrfMissTerminatorPriority, pbrLo)
	}
}

// TestKernelBandOrderAppliesInBothFamilies11319 installs one rule per band
// per family through the real Apply paths and asserts the installed
// priorities land in their band's window with PBR < rib-group < next-table
// in EACH family.
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

	inWindow := func(prio, lo, hi int) bool { return prio >= lo && prio < hi }
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		var ntPrios, rgPrios, pbrPrios []int
		var retPrios []int
		for _, r := range ntOps.rules[family] {
			ntPrios = append(ntPrios, r.Priority)
		}
		for _, r := range rgOps.rules[family] {
			switch {
			case r.Priority == RibGroupReturnRulePriority:
				retPrios = append(retPrios, r.Priority)
			case inWindow(r.Priority, ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules):
				rgPrios = append(rgPrios, r.Priority)
			default:
				t.Errorf("family %d: rib-group installed prio %d outside the leak band and the return prio",
					family, r.Priority)
			}
		}
		for _, r := range pbrOps.rules[family] {
			pbrPrios = append(pbrPrios, r.Priority)
		}
		if len(ntPrios) == 0 || len(rgPrios) == 0 || len(pbrPrios) == 0 {
			t.Fatalf("family %d: each band must install at least one rule (nt=%v rg=%v pbr=%v) — "+
				"without that the order below is vacuous", family, ntPrios, rgPrios, pbrPrios)
		}
		for _, p := range ntPrios {
			if !inWindow(p, nextTableRulePriority, nextTableRulePriority+maxNextTableRules) {
				t.Errorf("family %d: next-table prio %d outside [%d,%d)",
					family, p, nextTableRulePriority, nextTableRulePriority+maxNextTableRules)
			}
		}
		for _, p := range pbrPrios {
			if !inWindow(p, pbrRulePriority, pbrRulePriority+maxPBRRules) {
				t.Errorf("family %d: PBR prio %d outside [%d,%d)",
					family, p, pbrRulePriority, pbrRulePriority+maxPBRRules)
			}
		}
		maxOf := func(ps []int) int {
			m := ps[0]
			for _, p := range ps[1:] {
				if p > m {
					m = p
				}
			}
			return m
		}
		minOf := func(ps []int) int {
			m := ps[0]
			for _, p := range ps[1:] {
				if p < m {
					m = p
				}
			}
			return m
		}
		if maxOf(pbrPrios) >= minOf(rgPrios) {
			t.Errorf("family %d: PBR prios %v must all sort before rib-group prios %v (helper applies PBR first)",
				family, pbrPrios, rgPrios)
		}
		if maxOf(rgPrios) >= minOf(ntPrios) {
			t.Errorf("family %d: rib-group prios %v must all sort before next-table prios %v",
				family, rgPrios, ntPrios)
		}
		// The #11062 return rules stay below every band: they are consulted
		// before PBR by design (peer-prefix-scoped, pre-terminator).
		for _, p := range retPrios {
			if p >= minOf(pbrPrios) {
				t.Errorf("family %d: return prio %d must sort before the PBR band", family, p)
			}
		}
	}
}

// TestClearSweepsLegacyBands11319 pins the upgrade path: an in-place upgrade
// from a pre-#11319 binary leaves next-table rules at 100-199 and PBR rules
// at 31000-31999. A stale next-table rule at 100 would STILL outrank PBR —
// reintroducing the finding for those prefixes — so every Apply must sweep
// the legacy windows alongside the current ones (the rib-group clear()
// precedent for 33000/200). Foreign rules (the kernel's own 0/32766/32767)
// must survive.
//
// The legacy numbers are literals here on purpose: they name the bands the
// OLD binary installed, which no current constant describes.
func TestClearSweepsLegacyBands11319(t *testing.T) {
	const legacyNextTable = 100
	const legacyPBR = 31000

	t.Run("next-table sweeps stale 100-199", func(t *testing.T) {
		ops := newFakeRuleOps()
		seedRule(ops, unix.AF_INET, legacyNextTable+5, 101)
		seedRule(ops, unix.AF_INET6, legacyNextTable+5, 101)
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
		seedRule(ops, unix.AF_INET, legacyPBR+5, 500)
		seedRule(ops, unix.AF_INET6, legacyPBR+5, 500)
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

// TestPBRPrecedesLeakBandsOnRealKernel11319 is the kernel half: the A/B/C/D
// cells from the issue, executed in a private netns in BOTH families.
//
// Three rules cover the same destination — a next-table-shaped rule (to+iif),
// a rib-group-shaped rule (to), and a PBR-shaped rule (from+to+iif) — at the
// SSOT band priorities. The kernel's first-match verdict must be the PBR
// table, matching the helper (which evaluates the PBR override before any
// FIB lookup). Priorities are injected from the SSOT constants, so this cell
// REDs on the pre-fix numbering (PBR at 31000 sorts after the rib-group leak
// at 30000 and the verdict is the leak table, not the PBR table).
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
ip rule add to 10.9.0.0/16 table 300 pref %d
ip -6 rule add to 2001:db8:9::/48 table 300 pref %d
echo "B_LEAK_ONLY_V4=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "B_LEAK_ONLY_V6=$(g6 2001:db8:9::1 from 2001:db8:10::77 iif duma)"
ip rule add from 10.10.0.77 to 10.9.0.1 iif duma table 500 pref %d
ip -6 rule add from 2001:db8:10::77 to 2001:db8:9::1 iif duma table 500 pref %d
echo "C_PBR_VS_LEAK_V4=$(g 10.9.0.1 from 10.10.0.77 iif duma)"
echo "C_PBR_VS_LEAK_V6=$(g6 2001:db8:9::1 from 2001:db8:10::77 iif duma)"
echo "D_NONPBR_V4=$(g 10.9.0.2 from 10.10.0.99 iif duma)"
echo "D_NONPBR_V6=$(g6 2001:db8:9::2 from 2001:db8:10::99 iif duma)"
`,
		nextTableRulePriority, nextTableRulePriority,
		ribGroupLeakRulePriority, ribGroupLeakRulePriority,
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
	// Leak-vs-leak as-built order: rib-group (30000) precedes next-table
	// (32000), so the leak-only verdict is the rib-group table in both
	// families. (Pre-fix this was table 200: next-table sat at 100.)
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
