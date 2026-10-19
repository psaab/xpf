package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #14975 (D33-02): rib-group return rules must use longest-prefix priority
// inside the (1000,2000) window instead of flat 1500, tolerate EEXIST from a
// pre-existing identical rule, and still be swept by clear() in both the
// kernel manager and the userspace FIB mirror.

func returnPriority14975(t *testing.T, prefix string) int {
	t.Helper()
	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", prefix, err)
	}
	pl, bits := dst.Mask.Size()
	return config.RibGroupReturnRulePriority(pl, bits)
}

func TestRibGroupReturnLongestPrefixPriority14975(t *testing.T) {
	if got, want := returnPriority14975(t, "10.40.0.0/16"), returnPriority14975(t, "10.40.1.0/24"); !(want < got) {
		t.Errorf("v4 LPM: /24 priority %d must precede /16 %d", want, got)
	}
	if got, want := returnPriority14975(t, "10.0.0.0/8"), returnPriority14975(t, "10.40.0.0/16"); !(want < got) {
		t.Errorf("v4 LPM: /16 priority %d must precede /8 %d", want, got)
	}
	if got, want := returnPriority14975(t, "2001:db8::/32"), returnPriority14975(t, "2001:db8:40::/64"); !(want < got) {
		t.Errorf("v6 LPM: /64 priority %d must precede /32 %d", want, got)
	}
	// Whole band stays strictly between l3mdev (1000) and terminator (2000).
	for _, pfx := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.40.1.5/32", "::/0", "2001:db8::/32", "2001:db8:40::1/128"} {
		p := returnPriority14975(t, pfx)
		if p <= 1000 || p >= 2000 {
			t.Errorf("%s priority %d outside (1000,2000)", pfx, p)
		}
		if !IsRibGroupReturnRulePriority(p) {
			t.Errorf("%s priority %d not recognized by IsRibGroupReturnRulePriority", pfx, p)
		}
	}
	// Collision-free within each family (distinct prefix lengths).
	seen4 := map[int]string{}
	for _, pfx := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.40.0.0/16", "10.40.1.0/24", "10.40.1.128/25", "10.40.1.5/32"} {
		p := returnPriority14975(t, pfx)
		if other, dup := seen4[p]; dup {
			t.Errorf("v4 priority collision %d for %s and %s", p, pfx, other)
		}
		seen4[p] = pfx
	}
	seen6 := map[int]string{}
	for _, pfx := range []string{"::/0", "2001:db8::/32", "2001:db8:40::/64", "2001:db8:40::1/128"} {
		p := returnPriority14975(t, pfx)
		if other, dup := seen6[p]; dup {
			t.Errorf("v6 priority collision %d for %s and %s", p, pfx, other)
		}
		seen6[p] = pfx
	}
	// Legacy flat value stays recognized for upgrade cleanup / FIB compat.
	if RibGroupReturnRulePriority != 1500 {
		t.Errorf("legacy RibGroupReturnRulePriority = %d, want 1500", RibGroupReturnRulePriority)
	}
	if !IsRibGroupReturnRulePriority(1500) {
		t.Errorf("IsRibGroupReturnRulePriority(1500) = false, want true (legacy)")
	}
	for _, p := range []int{1000, 2000, 29000, 30000, 0, -1} {
		if IsRibGroupReturnRulePriority(p) {
			t.Errorf("IsRibGroupReturnRulePriority(%d) = true, want false", p)
		}
	}
}

// Apply-level: overlapping peer prefixes install distinct LPM priorities so
// the kernel first-match picks the narrower peer's table; clear() must sweep
// the derived band on re-apply and on zero-transition.
func TestRibGroupReturnRulesLPMApply14975(t *testing.T) {
	ribGroups := map[string]*config.RibGroup{
		"leak": {Name: "leak", ImportRibs: []string{"inet.0", "inet6.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "src", TableID: 200, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
		{Name: "broad", TableID: 300, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
		{Name: "narrow", TableID: 400, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
	}
	connected := map[string][]string{
		"src":    {"10.30.0.0/24", "2001:db8:30::/64"},
		"broad":  {"10.0.0.0/8", "2001:db8::/32"},
		"narrow": {"10.40.1.0/24", "2001:db8:40::/64"},
	}
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}
	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	type key struct {
		dst string
		tbl int
	}
	got := map[key]int{}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, r := range ops.rules[fam] {
			if r.Dst == nil || (r.IifName != "vrf-src" && r.OifName != "vrf-src") {
				continue
			}
			k := key{r.Dst.String(), r.Table}
			if prev, ok := got[k]; ok && prev != r.Priority {
				t.Errorf("inconsistent priority for %+v: %d vs %d", k, prev, r.Priority)
			}
			got[k] = r.Priority
		}
	}
	broadP, ok1 := got[key{"10.0.0.0/8", 300}]
	narrowP, ok2 := got[key{"10.40.1.0/24", 400}]
	if !ok1 || !ok2 {
		t.Fatalf("missing src v4 return rules: %v", got)
	}
	if !(narrowP < broadP) {
		t.Errorf("LPM violated: narrow /24 priority %d must precede broad /8 %d (flat-1500 defect)", narrowP, broadP)
	}
	if broadP == RibGroupReturnRulePriority && narrowP == RibGroupReturnRulePriority {
		t.Errorf("both overlapping return rules still at flat %d", RibGroupReturnRulePriority)
	}
	broad6, ok1 := got[key{"2001:db8::/32", 300}]
	narrow6, ok2 := got[key{"2001:db8:40::/64", 400}]
	if !ok1 || !ok2 {
		t.Fatalf("missing src v6 return rules: %v", got)
	}
	if !(narrow6 < broad6) {
		t.Errorf("v6 LPM violated: /64 priority %d must precede /32 %d", narrow6, broad6)
	}
	for k, p := range got {
		if !IsRibGroupReturnRulePriority(p) {
			t.Errorf("return rule %+v priority %d not in return band", k, p)
		}
	}
	// Control: non-overlapping peer still returns (src -> its own peers exist).
	if _, ok := got[key{"10.30.0.0/24", 200}]; ok {
		t.Errorf("src must not get a return rule to its own table: %v", got)
	}
	// Re-apply must not stack: clear() sweeps derived priorities.
	count := func() int {
		n := 0
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			n += len(ops.rules[fam])
		}
		return n
	}
	n1 := count()
	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if n2 := count(); n1 != n2 {
		t.Errorf("second Apply stacked rules: %d -> %d (clear did not sweep derived return priorities)", n1, n2)
	}
	if err := rg.Apply(nil, instances, connected); err != nil {
		t.Fatalf("zero Apply: %v", err)
	}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, r := range ops.rules[fam] {
			if r.Dst != nil && IsRibGroupReturnRulePriority(r.Priority) {
				t.Errorf("return rule survived zero-transition: %+v", r)
			}
		}
	}
}

// eexistReturnOps14975 fails the first return-rule-shaped add per
// (dst,table,iif,oif) with EEXIST, simulating a pre-existing identical rule
// left by a failed clear / concurrent apply, then succeeds.
type eexistReturnOps14975 struct {
	*fakeRuleOps
	seen map[string]bool
}

func (f *eexistReturnOps14975) RuleAdd(r *netlink.Rule) error {
	if r.Dst != nil && (r.IifName != "" || r.OifName != "") && IsRibGroupReturnRulePriority(r.Priority) {
		key := r.Dst.String() + "|" + r.IifName + "|" + r.OifName
		if f.seen == nil {
			f.seen = map[string]bool{}
		}
		if !f.seen[key] {
			f.seen[key] = true
			// Record it as present (the kernel already has it), then report EEXIST.
			f.fakeRuleOps.rules[r.Family] = append(f.fakeRuleOps.rules[r.Family], *r)
			return unix.EEXIST
		}
	}
	return f.fakeRuleOps.RuleAdd(r)
}
func (f *eexistReturnOps14975) RuleAddDSCP(r *netlink.Rule, dscp uint8) error {
	return f.fakeRuleOps.RuleAddDSCP(r, dscp)
}

func TestRibGroupReturnRulePreExistingEEXIST14975(t *testing.T) {
	ribGroups := map[string]*config.RibGroup{
		"leak": {Name: "leak", ImportRibs: []string{"inet.0", "inet6.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "src", TableID: 200, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
		{Name: "b", TableID: 300, InterfaceRoutesRibGroup: "leak", InterfaceRoutesRibGroupV6: "leak"},
	}
	connected := map[string][]string{
		"src": {"10.30.0.0/24"},
		"b":   {"10.40.0.0/24"},
	}
	base := newFakeRuleOps()
	ops := &eexistReturnOps14975{fakeRuleOps: base}
	rg := &ribGroupManager{ops: ops}
	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply with pre-existing (EEXIST) return rules must succeed, got: %v", err)
	}
	// The return rule is present exactly once per selector.
	found := 0
	for _, r := range base.rules[unix.AF_INET] {
		if r.Dst != nil && r.Dst.String() == "10.40.0.0/24" && (r.IifName == "vrf-src" || r.OifName == "vrf-src") {
			found++
		}
	}
	if found == 0 {
		t.Fatalf("expected src return rule to peer prefix present, rules=%v", base.rules[unix.AF_INET])
	}
}
