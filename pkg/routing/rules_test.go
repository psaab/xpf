package routing

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// testNextTableIifs is the #9420 ingress-scoping set used by next-table rule
// tests: one default-instance ingress interface, so each leak costs one rule.
var testNextTableIifs = []string{"ge-0-0-0"}

// fakeRuleOps is an in-memory ip-rule table implementing ruleOps. It
// records every RuleAdd/RuleDel so tests can assert exactly which
// policy-routing rules a domain manager programs — WITHOUT netlink.
// This is the seam the #1698 split introduced; before it, the rule
// reconcilers could not be exercised without a live kernel (see the
// "can't test actual ip rule creation without netlink" note in
// TestRibGroupNeedsLeak).
type fakeRuleOps struct {
	// rules holds the current rule set keyed by family, mirroring the
	// kernel's per-family rule list that RuleList returns.
	rules map[int][]netlink.Rule

	// listErr injects a per-family RuleList dump failure, simulating a
	// transient netlink error on one address family while the other
	// succeeds — the failure mode #2273 fixes. RuleList(family) returns
	// listErr[family] (and a nil slice) when present.
	listErr map[int]error

	// addErr, when non-nil, makes RuleAdd fail without recording the rule —
	// used to exercise the #3430 H3 add-failure aggregation in pbrManager.Apply.
	addErr error

	// addErrFamily injects a per-family RuleAdd failure, simulating a
	// transient netlink error on one address family while the other
	// succeeds. RuleAdd fails (without recording the rule) when
	// addErrFamily[r.Family] is non-nil. Used to exercise the #3731
	// next-table / rib-group add-failure aggregation with family isolation
	// (a v4 add can fail while the sibling v6 add still installs).
	addErrFamily map[int]error
	addErrType   map[uint8]error

	// delErr, when non-nil, makes RuleDel fail without removing the rule —
	// used to exercise the #3430 H3 clear-failure aggregation (a stale rule
	// that cannot be deleted must surface as a non-nil Apply error).
	delErr error

	adds int
	dels int
	delTypes []uint8

	// dscps records, per family and in add order, the DSCP each RuleAddDSCP
	// call carried. netlink.Rule cannot hold it (#7796).
	dscps map[int][]uint8
}

func newFakeRuleOps() *fakeRuleOps {
	return &fakeRuleOps{rules: map[int][]netlink.Rule{
		unix.AF_INET:  {},
		unix.AF_INET6: {},
	}}
}

func (f *fakeRuleOps) RuleAdd(r *netlink.Rule) error {
	if f.addErr != nil {
		return f.addErr
	}
	if f.addErrFamily != nil {
		if err := f.addErrFamily[r.Family]; err != nil {
			return err
		}
	}
	if f.addErrType != nil {
		if err := f.addErrType[r.Type]; err != nil {
			return err
		}
	}
	f.adds++
	f.rules[r.Family] = append(f.rules[r.Family], *r)
	return nil
}

// RuleAddDSCP records the rule AND the DSCP it was installed with. The DSCP
// must be recorded somewhere the assertions can see: netlink.Rule has no field
// for it (that is the whole of #7796), so a fake that dropped it would let every
// DSCP test pass while asserting nothing about the selector.
func (f *fakeRuleOps) RuleAddDSCP(r *netlink.Rule, dscp uint8) error {
	if err := f.RuleAdd(r); err != nil {
		return err
	}
	if f.dscps == nil {
		f.dscps = map[int][]uint8{}
	}
	f.dscps[r.Family] = append(f.dscps[r.Family], dscp)
	return nil
}

func (f *fakeRuleOps) RuleDel(r *netlink.Rule) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.delTypes = append(f.delTypes, r.Type)
	f.dels++
	list := f.rules[r.Family]
	out := list[:0:0]
	for _, e := range list {
		if e.Priority == r.Priority {
			continue
		}
		out = append(out, e)
	}
	f.rules[r.Family] = out
	return nil
}

func (f *fakeRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	if f.listErr != nil {
		if err := f.listErr[family]; err != nil {
			return nil, err
		}
	}
	return f.rules[family], nil
}

type typeCheckingRuleOps struct {
	*fakeRuleOps
}

func (f typeCheckingRuleOps) RuleDel(r *netlink.Rule) error {
	for _, existing := range f.rules[r.Family] {
		if existing.Priority == r.Priority && existing.Type == r.Type {
			return f.fakeRuleOps.RuleDel(r)
		}
	}
	return unix.ENOENT
}


// failList arms RuleList(family) to return err. Used to recreate the
// transient per-family netlink dump failure from #2273.
func (f *fakeRuleOps) failList(family int, err error) {
	if f.listErr == nil {
		f.listErr = map[int]error{}
	}
	f.listErr[family] = err
}

// failAdd arms RuleAdd(rule) to return err for rules in the given family
// (without recording them). Used to recreate a transient per-family netlink
// add failure so the #3731 aggregation can be exercised with one family
// failing while the sibling family still installs.
func (f *fakeRuleOps) failAdd(family int, err error) {
	if f.addErrFamily == nil {
		f.addErrFamily = map[int]error{}
	}
	f.addErrFamily[family] = err
}

// count returns the number of rules currently present for a family.
func (f *fakeRuleOps) count(family int) int { return len(f.rules[family]) }

// hasTable reports whether any rule in the family targets the table.
func (f *fakeRuleOps) hasTable(family, table int) bool {
	for _, r := range f.rules[family] {
		if r.Table == table {
			return true
		}
	}
	return false
}

// findDstRule returns the first rule in the family whose table and masked
// destination prefix match — the #3876 per-prefix leak rule shape.
func (f *fakeRuleOps) findDstRule(family, table int, dst string) (netlink.Rule, bool) {
	for _, r := range f.rules[family] {
		if r.Table == table && r.Dst != nil && r.Dst.String() == dst {
			return r, true
		}
	}
	return netlink.Rule{}, false
}

// TestRibGroupRulesApply_Fake exercises ribGroupManager over a fake
// ruleOps, asserting the #3876 PER-PREFIX leak rules are programmed for the
// source table. Each rule must carry a Dst (the connected prefix) and sit at
// a priority BEFORE the main table (< 32766) so a specific imported prefix
// wins over a main-table default route.
//
// RED-on-revert: reverting to the pre-#3876 `from all lookup <sourceTable>
// pref 33000` blanket rule makes this fail — the rule carries no Dst
// (findDstRule misses) and sits at 33000 > 32766 (shadowed by default).
func TestRibGroupRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name:       "dmz-leak",
			ImportRibs: []string{"dmz-vr.inet.0", "inet.0"},
		},
		"peer-leak": {
			Name:       "peer-leak",
			ImportRibs: []string{"peer-vr.inet.0", "inet.0"},
		},
		"self-only": {
			Name:       "self-only",
			ImportRibs: []string{"tunnel-vr.inet.0"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
		{Name: "dmz-vr", TableID: 101,
			InterfaceRoutesRibGroup:   "dmz-leak",
			InterfaceRoutesRibGroupV6: "dmz-leak"},
		{Name: "peer-vr", TableID: 102,
			InterfaceRoutesRibGroup:   "peer-leak",
			InterfaceRoutesRibGroupV6: "peer-leak"},
	}
	connected := map[string][]string{
		"dmz-vr":  {"10.0.30.0/24", "2001:db8:30::/64"},
		"peer-vr": {"10.0.40.0/24", "2001:db8:40::/64"},
		// tunnel-vr present but must not leak (self-only imports no main rib).
		"tunnel-vr": {"10.0.99.0/24"},
	}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// dmz-vr (table 101) leaks its connected prefixes into main → one
	// per-prefix rule per family, each with a Dst, each BEFORE main.
	v4, ok := ops.findDstRule(unix.AF_INET, 101, "10.0.30.0/24")
	if !ok {
		t.Fatalf("expected IPv4 per-prefix leak rule to 10.0.30.0/24 table 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if v4.Priority >= 32766 {
		t.Errorf("IPv4 leak rule pref %d must be BEFORE main (32766) so it wins over a default route (#3876)", v4.Priority)
	}
	if v4.Priority < ribGroupLeakRulePriority || v4.Priority >= ribGroupLeakRulePriority+maxRibGroupLeakRules {
		t.Errorf("IPv4 leak rule pref %d outside the #3876 window [%d,%d)", v4.Priority, ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules)
	}
	v6, ok := ops.findDstRule(unix.AF_INET6, 101, "2001:db8:30::/64")
	if !ok {
		t.Fatalf("expected IPv6 per-prefix leak rule to 2001:db8:30::/64 table 101, rules=%v", ops.rules[unix.AF_INET6])
	}
	if v6.Priority >= 32766 {
		t.Errorf("IPv6 leak rule pref %d must be BEFORE main (32766)", v6.Priority)
	}

	// tunnel-vr (self-only) must NOT produce a leak rule for table 100.
	if ops.hasTable(unix.AF_INET, 100) {
		t.Errorf("self-only should not leak table 100, rules=%v", ops.rules[unix.AF_INET])
	}
	// #11062: dmz-vr returns to the other leaking instance's prefix only, in
	// that peer's table; its own prefix and unrelated destinations do not
	// receive a return rule. The peer gets the reciprocal dmz-vr prefix.
	peerReturn, ok := ops.findDstRule(unix.AF_INET, 102, "10.0.40.0/24")
	if !ok || peerReturn.Priority != RibGroupReturnRulePriority ||
		(peerReturn.IifName != "vrf-dmz-vr" && peerReturn.OifName != "vrf-dmz-vr") {
		t.Errorf("missing dmz-vr return rule to peer table 102 scoped to 10.0.40.0/24: %+v", peerReturn)
	}
	for _, rule := range ops.rules[unix.AF_INET] {
		if rule.Priority == RibGroupReturnRulePriority &&
			(rule.IifName == "vrf-dmz-vr" || rule.OifName == "vrf-dmz-vr") &&
			(rule.Dst == nil || rule.Dst.String() != "10.0.40.0/24") {
			t.Errorf("dmz-vr return rule is not scoped to the other leaked prefix: %+v", rule)
		}
	}
	if got := rulesInWindow9819(ops, unix.AF_INET, ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules); got != 2 {
		t.Errorf("expected exactly 2 IPv4 leak rules, got %d", got)
	}
	if got := ops.count(unix.AF_INET); got != 6 {
		t.Errorf("expected 2 IPv4 leak rules and 4 peer-scoped return rules, got %d rules", got)
	}
	if got := ops.count(unix.AF_INET6); got != 6 {
		t.Errorf("expected 2 IPv6 leak rules and 4 peer-scoped return rules, got %d rules", got)
	}

	// Re-applying must clear the prior rules first (clear-then-add), so
	// the rule count stays stable rather than doubling.
	prevAdds := ops.adds
	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply (second): %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 6 {
		t.Errorf("after re-apply expected 2 IPv4 leak rules and 4 peer-scoped return rules, got %d rules", got)
	}
	if ops.dels == 0 {
		t.Error("expected re-apply to delete the prior rules (clear-then-add)")
	}
	if ops.adds <= prevAdds {
		t.Error("expected re-apply to re-add rules")
	}
}

// TestRibGroupUpgradeCleanupRemovesLegacyBlanket is the #3876 upgrade-cleanup
// guard. A pre-#3876 binary left an `ip rule from all lookup <sourceTable>
// pref 33000` blanket rule in the kernel. On the first apply after upgrade,
// clear() MUST remove that stale rule (its window is scanned) so the box is
// not left with the broken blanket rule alongside the new per-prefix rules.
//
// RED-on-revert: dropping the [33000,33100) (old-blanket) window from clear()
// leaves the seeded rule behind.
func TestRibGroupUpgradeCleanupRemovesLegacyBlanket(t *testing.T) {
	ops := newFakeRuleOps()
	// Seed a stale pre-#3876 blanket rule (from all lookup 101 pref 33000).
	seedRule(ops, unix.AF_INET, ribGroupRulePriority, 101)
	seedRule(ops, unix.AF_INET6, ribGroupRulePriority, 101)
	// And an even older legacy-window rule (pref 200).
	seedRule(ops, unix.AF_INET, 200, 101)

	rg := &ribGroupManager{ops: ops}
	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {Name: "dmz-leak", ImportRibs: []string{"inet.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}
	connected := map[string][]string{"dmz-vr": {"10.0.30.0/24"}}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The stale pref-33000 blanket rules and the pref-200 legacy rule must be gone.
	if hasPriority(ops, unix.AF_INET, ribGroupRulePriority) || hasPriority(ops, unix.AF_INET6, ribGroupRulePriority) {
		t.Errorf("upgrade cleanup must remove the stale pref-%d blanket rules, rules v4=%v v6=%v",
			ribGroupRulePriority, ops.rules[unix.AF_INET], ops.rules[unix.AF_INET6])
	}
	if hasPriority(ops, unix.AF_INET, 200) {
		t.Errorf("upgrade cleanup must remove the legacy pref-200 rule, rules=%v", ops.rules[unix.AF_INET])
	}
	// The new per-prefix rule must be installed in the #3876 window.
	if _, ok := ops.findDstRule(unix.AF_INET, 101, "10.0.30.0/24"); !ok {
		t.Errorf("expected the new per-prefix leak rule after upgrade, rules=%v", ops.rules[unix.AF_INET])
	}
}

// TestRibGroupRulesApply_UnknownRibNoLeak is the #2226 fail-on-revert
// guard. A rib-group whose ONLY import-rib names a rib that resolves to
// no real routing table (a typo / non-existent instance) must NOT install
// any leak rule for the source table. Before the fix, resolveRibTable
// returned a bare 0 for the unknown name; 0 != sourceTable(101) set
// needsLeak, and the applier installed `ip rule from all lookup 101` —
// a silent mis-leak of the source table into the main lookup. With the
// fix the unknown rib is skipped (ok=false) and no rule is programmed.
//
// Reverting either the resolveRibTable (int,bool) split or the
// needsLeak-loop ok guard makes this test fail (a phantom rule for
// table 101 appears).
func TestRibGroupRulesApply_UnknownRibNoLeak(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"typo-leak": {
			Name: "typo-leak",
			// Both names are undefined: a non-existent instance and pure
			// garbage. Neither resolves to a real table.
			ImportRibs: []string{"does-not-exist.inet.0", "garbage"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "typo-leak"},
	}
	// Even WITH connected prefixes available, an all-unknown rib-group must
	// leak nothing (it imports no main rib → leakV4/leakV6 stay false).
	connected := map[string][]string{"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"}}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("unknown import-rib must NOT install an IPv4 leak rule for table 101 (#2226), rules=%v", ops.rules[unix.AF_INET])
	}
	if ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("unknown import-rib must NOT install an IPv6 leak rule for table 101 (#2226), rules=%v", ops.rules[unix.AF_INET6])
	}
	// And specifically never a rule into table 0 (the old fallback target).
	if ops.hasTable(unix.AF_INET, 0) || ops.hasTable(unix.AF_INET6, 0) {
		t.Errorf("must never install a rule into table 0 from an unresolved rib (#2226)")
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 0 {
		t.Errorf("expected zero rules for an all-unknown rib-group, got %d (%v / %v)",
			got, ops.rules[unix.AF_INET], ops.rules[unix.AF_INET6])
	}
}

// TestRibGroupRulesApply_DefinedRibStillLeaks is the companion no-false-
// reject guard for #2226: a rib-group importing a DEFINED rib (another
// real instance's table, plus the main table) still leaks the source
// table correctly. This pins that the (int,bool) split did not break the
// happy path — only the unresolvable case changed.
func TestRibGroupRulesApply_DefinedRibStillLeaks(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name: "dmz-leak",
			// dmz-vr.inet.0 (self, table 101), tunnel-vr.inet.0 (defined,
			// table 100), inet.0 (main, 254). The defined non-self ribs
			// must drive the leak.
			ImportRibs: []string{"dmz-vr.inet.0", "tunnel-vr.inet.0", "inet.0"},
		},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100},
		{Name: "dmz-vr", TableID: 101,
			InterfaceRoutesRibGroup:   "dmz-leak",
			InterfaceRoutesRibGroupV6: "dmz-leak"},
	}
	connected := map[string][]string{
		"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"},
	}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The rib-group imports main (inet.0), so the per-prefix leak fires even
	// though it ALSO names a VRF→VRF target (tunnel-vr.inet.0) that Phase 1
	// does not install.
	if _, ok := ops.findDstRule(unix.AF_INET, 101, "10.0.30.0/24"); !ok {
		t.Errorf("defined import-rib must still leak table 101 (IPv4), rules=%v", ops.rules[unix.AF_INET])
	}
	if _, ok := ops.findDstRule(unix.AF_INET6, 101, "2001:db8:30::/64"); !ok {
		t.Errorf("defined import-rib must still leak table 101 (IPv6), rules=%v", ops.rules[unix.AF_INET6])
	}
}

// TestRibGroupApplyAggregatesAddErrors is the #3731 fail-on-revert guard for
// the rib-group reconciler. Each leaked table programs a v4 THEN a v6 ip rule;
// a RuleAdd failure on either (or both) must be aggregated and returned rather
// than logged-and-swallowed with Apply reporting nil (the pre-fix clearErr-only
// return). The subtests pin v4-only, v6-only, and both-family failures — the
// sibling family that DID install stays installed (forward progress) while
// Apply still surfaces the error.
//
// Reverting ribGroupManager.Apply to the log-only branches + `return clearErr`
// makes every subtest go RED (Apply returns nil).
func TestRibGroupApplyAggregatesAddErrors(t *testing.T) {
	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {Name: "dmz-leak", ImportRibs: []string{"inet.0"}}, // imports main
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101,
			InterfaceRoutesRibGroup:   "dmz-leak",
			InterfaceRoutesRibGroupV6: "dmz-leak"},
	}
	// One v4 + one v6 connected prefix → one v4 leak rule + one v6 leak rule.
	connected := map[string][]string{
		"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"},
	}

	t.Run("v4-only", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.failAdd(unix.AF_INET, errors.New("netlink EPERM on v4"))
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances, connected); err == nil {
			t.Fatal("Apply must return non-nil when the v4 leak rule fails (#3731)")
		}
		if ops.hasTable(unix.AF_INET, 101) {
			t.Errorf("failed v4 leak rule must not be recorded, rules=%v", ops.rules[unix.AF_INET])
		}
		if !ops.hasTable(unix.AF_INET6, 101) {
			t.Errorf("sibling v6 leak rule must still install (forward progress), rules=%v", ops.rules[unix.AF_INET6])
		}
	})

	t.Run("v6-only", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.failAdd(unix.AF_INET6, errors.New("netlink EPERM on v6"))
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances, connected); err == nil {
			t.Fatal("Apply must return non-nil when the v6 leak rule fails (#3731)")
		}
		if !ops.hasTable(unix.AF_INET, 101) {
			t.Errorf("sibling v4 leak rule must still install (forward progress), rules=%v", ops.rules[unix.AF_INET])
		}
		if ops.hasTable(unix.AF_INET6, 101) {
			t.Errorf("failed v6 leak rule must not be recorded, rules=%v", ops.rules[unix.AF_INET6])
		}
	})

	t.Run("both-family", func(t *testing.T) {
		ops := newFakeRuleOps()
		ops.addErr = errors.New("netlink ENOBUFS")
		rg := &ribGroupManager{ops: ops}
		if err := rg.Apply(ribGroups, instances, connected); err == nil {
			t.Fatal("Apply must return non-nil when both leak rules fail (#3731)")
		}
		if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
			t.Errorf("no leak rule should be recorded, v4=%d v6=%d",
				ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
		}
	})
}

// TestNextTableRulesApply_Fake exercises nextTableManager over a fake,
// asserting a next-table directive becomes an ip rule pointing at the
// target instance's table.
func TestNextTableRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}

	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
		{Destination: "10.99.0.0/16", NextTable: "unknown-vr"}, // skipped
		{Destination: "10.0.0.0/8"},                            // no next-table, skipped
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	if err := nt.Apply(routes, instances, testNextTableIifs); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("expected IPv4 next-table rule for table 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 101) {
		t.Errorf("expected IPv6 next-table rule for table 101, rules=%v", ops.rules[unix.AF_INET6])
	}
	if got := ops.count(unix.AF_INET); got != 1 {
		t.Errorf("expected 1 IPv4 rule (unknown-vr skipped), got %d", got)
	}
	if got := ops.count(unix.AF_INET6); got != 1 {
		t.Errorf("expected 1 IPv6 rule, got %d", got)
	}
}

// TestNextTableApplyAggregatesAddErrors is the #3731 fail-on-revert guard for
// the next-table reconciler. A per-rule RuleAdd failure after the up-front
// clear() must be aggregated and returned — not logged-and-swallowed with Apply
// still reporting nil (the pre-fix clearErr-only return). Before the fix a
// transient netlink add error left the inter-VRF leak DOWN while Apply told the
// daemon apply loop "success".
//
// Reverting nextTableManager.Apply to `continue` + `return clearErr` makes this
// test go RED (Apply returns nil).
func TestNextTableApplyAggregatesAddErrors(t *testing.T) {
	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	// Both-family failure: every RuleAdd fails, no rule recorded, Apply
	// surfaces the aggregated error.
	ops := newFakeRuleOps()
	ops.addErr = errors.New("netlink ENOBUFS")
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(routes, instances, testNextTableIifs); err == nil {
		t.Fatal("Apply must return a non-nil error when RuleAdd fails (#3731)")
	}
	if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
		t.Errorf("no rule should have been recorded, v4=%d v6=%d",
			ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
	}

	// Single-family failure: forward progress preserved — the v4 add fails
	// (error aggregated) while the sibling v6 rule still installs, and Apply
	// still returns the aggregated error rather than swallowing it.
	ops2 := newFakeRuleOps()
	ops2.failAdd(unix.AF_INET, errors.New("netlink EPERM on v4"))
	nt2 := &nextTableManager{ops: ops2}
	if err := nt2.Apply(routes, instances, testNextTableIifs); err == nil {
		t.Fatal("Apply must return non-nil when the v4 add fails (#3731)")
	}
	if ops2.count(unix.AF_INET) != 0 {
		t.Errorf("failed v4 rule must not be recorded, got %d", ops2.count(unix.AF_INET))
	}
	if ops2.count(unix.AF_INET6) != 1 {
		t.Errorf("sibling v6 rule must still install (forward progress), got %d", ops2.count(unix.AF_INET6))
	}
}

// TestNextTableApplyIdempotentReapply pins that the #3731 aggregation does not
// regress the clean path: a first apply returns nil, and re-applying the same
// config (clear-then-add) still returns nil with a stable rule set. The
// re-apply cannot EEXIST because clear() removes the prior in-window rules
// before they are re-added — an already-present rule is handled as success, not
// an error (matching the #3430 PBR path, which likewise clears then re-adds).
func TestNextTableApplyIdempotentReapply(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "dmz-vr"},
		{Destination: "2001:db8::/32", NextTable: "dmz-vr"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	if err := nt.Apply(routes, instances, testNextTableIifs); err != nil {
		t.Fatalf("clean Apply must return nil, got %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 2 {
		t.Fatalf("expected 2 rules after clean apply, got %d", got)
	}
	if err := nt.Apply(routes, instances, testNextTableIifs); err != nil {
		t.Fatalf("idempotent re-apply must return nil, got %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 2 {
		t.Fatalf("re-apply must keep a stable rule set, got %d", got)
	}
}

// TestNextTableRulesPriorityCap exercises the #1706 hard cap: programming
// more next-table routes than the clear() window (100 priorities) must
// stop at the boundary so every programmed rule stays inside the range
// clear() scans — otherwise rules at prio >= 200 leak permanently. The
// boundary case (exactly 100 routes) programs the full set; one over
// triggers the cap.
func TestNextTableRulesPriorityCap(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			// Distinct /24 destinations, all pointing at the same table.
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	// Exactly at the window size: all admitted, none beyond range.
	t.Run("at-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		if err := nt.Apply(mkRoutes(config.NextTableRuleWindow), instances, testNextTableIifs); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != config.NextTableRuleWindow {
			t.Fatalf("expected all %d routes programmed at the limit, got %d", config.NextTableRuleWindow, total)
		}
		assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+config.NextTableRuleWindow)
	})

	// One over the window: cap fires, only 100 admitted, none out of range,
	// and Apply surfaces a degraded error naming the cap (#6467) rather than a
	// silent Warn — mirroring the rib-group/PBR over-limit subtests.
	t.Run("over-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		nt := &nextTableManager{ops: ops}
		over := config.NextTableRuleWindow + 50
		if err := nt.Apply(mkRoutes(over), instances, testNextTableIifs); err == nil {
			t.Fatal("over-limit Apply must return a degraded error naming the cap (#6467)")
		}
		total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != config.NextTableRuleWindow {
			t.Fatalf("expected cap to hold at %d programmed rules, got %d", config.NextTableRuleWindow, total)
		}
		assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+config.NextTableRuleWindow)

		// Re-apply must leave no residue: every programmed rule is inside
		// clear()'s window, so clear-then-add keeps the count stable. A
		// leaked rule at prio >= the window top would survive clear() and grow
		// the set. The degraded error still surfaces on every over-limit apply.
		if err := nt.Apply(mkRoutes(over), instances, testNextTableIifs); err == nil {
			t.Fatal("re-apply over-limit must still surface the degraded error (#6467)")
		}
		total = ops.count(unix.AF_INET) + ops.count(unix.AF_INET6)
		if total != config.NextTableRuleWindow {
			t.Fatalf("re-apply leaked rules: expected %d, got %d", config.NextTableRuleWindow, total)
		}
	})
}

// TestRibGroupRulesPriorityCap exercises the #3876 hard cap for the
// per-prefix rib-group leak. One rule is programmed per connected prefix, and
// the total is bounded by maxRibGroupLeakRules; prefixes beyond the window
// must be dropped (with a degraded Apply error) and every programmed rule
// must stay inside the window clear() scans so nothing leaks across applies.
func TestRibGroupRulesPriorityCap(t *testing.T) {
	// One instance leaking into main, with n distinct v4 connected prefixes.
	mkConfig := func(n int) (map[string]*config.RibGroup, []*config.RoutingInstanceConfig, map[string][]string) {
		ribGroups := map[string]*config.RibGroup{
			"leak": {Name: "leak", ImportRibs: []string{"inet.0"}},
		}
		instances := []*config.RoutingInstanceConfig{
			{Name: "leak-vr", TableID: 1000, InterfaceRoutesRibGroup: "leak"},
		}
		prefixes := make([]string, 0, n)
		for i := 0; i < n; i++ {
			prefixes = append(prefixes, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		}
		return ribGroups, instances, map[string][]string{"leak-vr": prefixes}
	}

	t.Run("at-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		rg := &ribGroupManager{ops: ops}
		ribGroups, instances, connected := mkConfig(maxRibGroupLeakRules)
		if err := rg.Apply(ribGroups, instances, connected); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		// A single source has no peer prefix, so only forward leak rules apply.
		if got := ops.count(unix.AF_INET); got != maxRibGroupLeakRules {
			t.Fatalf("expected %d leak rules and no return rules without peers, got %d", maxRibGroupLeakRules, got)
		}
		assertRibGroupRulesInClearedWindows9819(t, ops)
	})

	t.Run("over-limit", func(t *testing.T) {
		ops := newFakeRuleOps()
		rg := &ribGroupManager{ops: ops}
		ribGroups, instances, connected := mkConfig(maxRibGroupLeakRules + 25)
		// Over-limit must surface a degraded Apply error (not swallowed).
		if err := rg.Apply(ribGroups, instances, connected); err == nil {
			t.Fatal("over-limit Apply must return a degraded error naming the cap")
		}
		if got := rulesInWindow9819(ops, unix.AF_INET, ribGroupLeakRulePriority, ribGroupLeakRulePriority+maxRibGroupLeakRules); got != maxRibGroupLeakRules {
			t.Fatalf("expected cap to hold at %d leak rules, got %d", maxRibGroupLeakRules, got)
		}
		if got := ops.count(unix.AF_INET); got != maxRibGroupLeakRules {
			t.Fatalf("expected %d leak rules and no return rules without peers, got %d", maxRibGroupLeakRules, got)
		}
		assertRibGroupRulesInClearedWindows9819(t, ops)
		// The rule beyond the window (pref ribGroupLeakRulePriority+1000) must be absent.
		if hasPriority(ops, unix.AF_INET, ribGroupLeakRulePriority+maxRibGroupLeakRules) {
			t.Errorf("a rule leaked beyond the cleared window (slot %d present)",
				ribGroupLeakRulePriority+maxRibGroupLeakRules)
		}

		// Re-apply must not leak: all programmed rules are inside the
		// cleared window, so the count stays capped.
		if err := rg.Apply(ribGroups, instances, connected); err == nil {
			t.Fatal("re-apply over-limit must still surface the degraded error")
		}
		if got := ops.count(unix.AF_INET); got != maxRibGroupLeakRules {
			t.Fatalf("re-apply leaked rib-group rules: expected %d, got %d",
				maxRibGroupLeakRules, got)
		}
	})
}

// hasPriority reports whether any rule in the family was programmed at
// the exact priority.
func hasPriority(ops *fakeRuleOps, family, prio int) bool {
	for _, r := range ops.rules[family] {
		if r.Priority == prio {
			return true
		}
	}
	return false
}

// assertAllRulesInRange fails the test if any programmed rule in either
// family has a priority outside [lo, hi) — i.e. a rule clear() would not
// remove. This is the invariant the #1706 priority caps guarantee.
func assertAllRulesInRange(t *testing.T, ops *fakeRuleOps, lo, hi int) {
	t.Helper()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, r := range ops.rules[family] {
			if r.Priority < lo || r.Priority >= hi {
				t.Errorf("rule priority %d outside cleared window [%d,%d) — would leak",
					r.Priority, lo, hi)
			}
		}
	}
}

// TestPBRRulesApply_Fake verifies each PBR lookup is followed by an
// unreachable rule with the same selectors, family, and ingress interface.
func TestPBRRulesApply_Fake(t *testing.T) {
	ops := newFakeRuleOps()
	p := &pbrManager{ops: typeCheckingRuleOps{fakeRuleOps: ops}}

	rules := []PBRRule{
		{
			Family: unix.AF_INET, DSCP: 46, DSCPSet: true,
			Src: "10.1.0.0/16", IPProto: 6,
			Sport: &PBRPortRange{Lo: 1000, Hi: 2000},
			Dport: &PBRPortRange{Lo: 443, Hi: 443},
			TableID: 100, Instance: "vr-a", IifName: "ge-0-0-0",
		},
		{Family: unix.AF_INET6, Src: "2001:db8::/32", TableID: 100, Instance: "vr-a", IifName: "ge-0-0-0"},
		{Family: unix.AF_INET, Dst: "10.5.0.0/16", TableID: 101, Instance: "vr-b", IifName: "ge-0-0-1"},
	}

	if err := p.Apply(rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !ops.hasTable(unix.AF_INET, 100) || !ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("expected IPv4 PBR lookup rules for tables 100 and 101, rules=%v", ops.rules[unix.AF_INET])
	}
	if !ops.hasTable(unix.AF_INET6, 100) {
		t.Errorf("expected IPv6 PBR lookup rule for table 100, rules=%v", ops.rules[unix.AF_INET6])
	}
	if got := ops.count(unix.AF_INET); got != 4 {
		t.Fatalf("expected 2 IPv4 lookup/shadow pairs, got %d rules", got)
	}
	if got := ops.count(unix.AF_INET6); got != 2 {
		t.Fatalf("expected 1 IPv6 lookup/shadow pair, got %d rules", got)
	}

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		entries := ops.rules[family]
		for i := 0; i < len(entries); i += 2 {
			terminator, lookup := entries[i], entries[i+1]
			if lookup.Type != unix.RTN_UNICAST || terminator.Type != pbrTerminatorAction {
				t.Errorf("family %d pair actions = (lookup %d, shadow %d), want (unicast,unreachable)",
					family, lookup.Type, terminator.Type)
			}
			if terminator.Priority != lookup.Priority+1 {
				t.Errorf("family %d priorities = (%d,%d), want adjacent lookup/shadow pair",
					family, lookup.Priority, terminator.Priority)
			}
			if lookup.Family != terminator.Family || lookup.IifName != terminator.IifName ||
				!reflect.DeepEqual(lookup.Src, terminator.Src) ||
				!reflect.DeepEqual(lookup.Dst, terminator.Dst) ||
				lookup.IPProto != terminator.IPProto ||
				!reflect.DeepEqual(lookup.Sport, terminator.Sport) ||
				!reflect.DeepEqual(lookup.Dport, terminator.Dport) {
				t.Errorf("family %d terminator selectors differ from lookup: lookup=%+v terminator=%+v",
					family, lookup, terminator)
			}
			if terminator.Table != -1 {
				t.Errorf("family %d unreachable rule table = %d, want no lookup table", family, terminator.Table)
			}
		}
	}
	if got := ops.dscps[unix.AF_INET]; len(got) != 2 || got[0] != 46 || got[1] != 46 {
		t.Errorf("DSCP must qualify both the lookup and shadow, got %v", got)
	}

	// Reconcile the same desired state twice: clear must remove both members of
	// every pair before they are re-added, without duplicate priorities.
	if err := p.Apply(rules); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if ops.count(unix.AF_INET) != 4 || ops.count(unix.AF_INET6) != 2 {
		t.Errorf("re-Apply duplicated or lost PBR pairs: v4=%d v6=%d",
			ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
	}

	// Empty rule set clears both lookup and unreachable rules.
	ops.delTypes = nil
	if err := p.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if ops.count(unix.AF_INET) != 0 || ops.count(unix.AF_INET6) != 0 {
		t.Errorf("expected all PBR rules cleared, v4=%d v6=%d",
			ops.count(unix.AF_INET), ops.count(unix.AF_INET6))
	}
	wantDeleteTypes := []uint8{
		pbrTerminatorAction, unix.RTN_UNICAST,
		pbrTerminatorAction, unix.RTN_UNICAST,
		pbrTerminatorAction, unix.RTN_UNICAST,
	}
	if !reflect.DeepEqual(ops.delTypes, wantDeleteTypes) {
		t.Errorf("clear delete actions = %v, want lookup/shadow actions %v",
			ops.delTypes, wantDeleteTypes)
	}
}

// The pre-#11394 implementation used one lookup per priority. An odd-priority
// stale lookup must still be deleted after the current pair layout is deployed.
func TestPBRClearFallsBackToLegacyLookupAction(t *testing.T) {
	ops := newFakeRuleOps()
	rule := &netlink.Rule{
		Family: unix.AF_INET, Priority: pbrRulePriority + 1,
		Table: 100, Type: unix.RTN_UNICAST,
	}
	if err := ops.RuleAdd(rule); err != nil {
		t.Fatalf("seed legacy-layout PBR rule: %v", err)
	}
	p := &pbrManager{ops: typeCheckingRuleOps{fakeRuleOps: ops}}
	if err := p.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Errorf("legacy unicast rule at odd priority was not deleted, %d rules remain", got)
	}
}

// TestPBRApplyScopesRuleToIif verifies pbrManager.Apply stamps the ingress
// interface onto both installed rules (FRA_IIFNAME, #5117): the PBR lookup and
// its unreachable shadow are scoped to that interface, and a rule with no
// IifName is REFUSED (never installed globally).
func TestPBRApplyScopesRuleToIif(t *testing.T) {
	t.Run("iif is programmed onto the rule", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		rules := []PBRRule{
			{Family: unix.AF_INET, Src: "10.0.1.0/24", TableID: 101, Instance: "ATT", IifName: "ge-0-0-0"},
		}
		if err := p.Apply(rules); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if ops.count(unix.AF_INET) != 2 {
			t.Fatalf("expected one installed lookup/shadow pair, got %d rules", ops.count(unix.AF_INET))
		}
		for _, r := range ops.rules[unix.AF_INET] {
			if got := r.IifName; got != "ge-0-0-0" {
				t.Errorf("installed rule IifName = %q, want %q (must scope both rules to ingress)", got, "ge-0-0-0")
			}
		}
	})

	t.Run("empty iif is refused, not installed globally", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		rules := []PBRRule{
			{Family: unix.AF_INET, Src: "10.0.1.0/24", TableID: 101, Instance: "ATT"}, // no IifName
		}
		err := p.Apply(rules)
		if err == nil {
			t.Fatal("Apply must return non-nil for a rule with no ingress interface (#5117 fail-closed)")
		}
		if ops.count(unix.AF_INET) != 0 {
			t.Errorf("no global iif-less rule may be installed, got %d", ops.count(unix.AF_INET))
		}
	})
}

// TestPBRApplyAggregatesAddErrors verifies that pbrManager.Apply surfaces a
// RuleAdd failure (#3430 H3) instead of swallowing it and reporting success
// after the up-front clear already removed the previously-working steering.
func TestPBRApplyAggregatesAddErrors(t *testing.T) {
	ops := newFakeRuleOps()
	ops.addErr = errors.New("netlink EPERM")
	p := &pbrManager{ops: ops}

	rules := []PBRRule{
		{Family: unix.AF_INET, DSCP: 46, DSCPSet: true, TableID: 100, Instance: "vr-a", IifName: "ge-0-0-0"},
	}
	err := p.Apply(rules)
	if err == nil {
		t.Fatal("Apply must return a non-nil error when RuleAdd fails (#3430 H3)")
	}
	if ops.count(unix.AF_INET) != 0 {
		t.Errorf("no rule should have been recorded, got %d", ops.count(unix.AF_INET))
	}
}

func TestPBRApplyRollsBackTerminatorWhenLookupFails(t *testing.T) {
	ops := newFakeRuleOps()
	ops.addErrType = map[uint8]error{
		unix.RTN_UNICAST: errors.New("lookup add failed"),
	}
	p := &pbrManager{ops: ops}
	err := p.Apply([]PBRRule{{
		Family: unix.AF_INET, Src: "10.0.1.0/24", TableID: 101,
		Instance: "vr", IifName: "ge-0-0-0",
	}})
	if err == nil {
		t.Fatal("a failed PBR lookup add must be surfaced")
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Errorf("the unreachable shadow must be rolled back when its lookup fails, got %d rules", got)
	}
}

// TestPBRApplyCapBoundary pins the apply-side priority-window cap: exactly
// maxPBRSteeringRules lookup/shadow pairs install cleanly, and one more
// triggers the overflow error (#11394).
func TestPBRApplyCapBoundary(t *testing.T) {
	mk := func(n int) []PBRRule {
		out := make([]PBRRule, n)
		for i := range out {
			out[i] = PBRRule{Family: unix.AF_INET, Src: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), TableID: 100, Instance: "vr", IifName: "ge-0-0-0"}
		}
		return out
	}

	t.Run("exactly at cap", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		if err := p.Apply(mk(maxPBRSteeringRules)); err != nil {
			t.Fatalf("exactly %d steering rules must apply without error, got %v", maxPBRSteeringRules, err)
		}
		if got, want := ops.count(unix.AF_INET), 2*maxPBRSteeringRules; got != want {
			t.Errorf("expected %d lookup/shadow rules installed, got %d", want, got)
		}
		assertAllRulesInRange(t, ops, pbrRulePriority, pbrRulePriority+maxPBRRules)
	})

	t.Run("one over cap", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		err := p.Apply(mk(maxPBRSteeringRules + 1))
		if err == nil {
			t.Fatal("exceeding the steering-rule cap must return a non-nil error")
		}
		if got, want := ops.count(unix.AF_INET), 2*maxPBRSteeringRules; got != want {
			t.Errorf("expected %d rules installed at the cap, got %d", want, got)
		}
		assertAllRulesInRange(t, ops, pbrRulePriority, pbrRulePriority+maxPBRRules)
	})
}

// TestPBRApplyClearDelFailureSurfaced verifies that a RuleDel failure during
// the up-front clear is surfaced (#3430 H3 second leg): a stale PBR rule that
// cannot be removed leaves the kernel in a divergent state, so Apply must
// return non-nil rather than reporting success because the new adds worked.
func TestPBRApplyClearDelFailureSurfaced(t *testing.T) {
	ops := newFakeRuleOps()
	// Seed a stale rule inside the PBR window so clear() tries to delete it.
	seedRule(ops, unix.AF_INET, pbrRulePriority+5, 100)
	ops.delErr = errors.New("netlink EBUSY")
	p := &pbrManager{ops: ops}

	// New desired rule set; its adds succeed, but the stale rule cannot be
	// cleared. Pre-fix the clear() RuleDel failure was debug-logged only and
	// Apply returned nil.
	rules := []PBRRule{
		{Family: unix.AF_INET, Src: "10.7.0.0/16", TableID: 101, Instance: "vr-b", IifName: "ge-0-0-0"},
	}
	if err := p.Apply(rules); err == nil {
		t.Fatal("Apply must return non-nil when a stale rule cannot be cleared (#3430 H3)")
	}
}

// TestNextTableRibGroupClearDelFailureSurfaced is the #5118 fail-on-revert
// guard. Both nextTableManager.clear and ribGroupManager.clear used to only
// debug-log a RuleDel failure, so errors.Join returned nil and Apply reported
// SUCCESS while a stale route-leak rule remained in the kernel. That rule is
// an active cross-VRF forwarding instruction that PRECEDES the main table, so
// the swallowed delete leaves a silent inter-VRF route leak that survives a
// "successful" commit. When RuleDel returns a REAL failure (the rule EXISTS
// but cannot be removed, e.g. EBUSY), Apply MUST return non-nil.
//
// Reverting either clear() to the pre-#5118 debug-log-only form makes Apply
// return nil despite the un-deletable rule, so this test fails.
func TestNextTableRibGroupClearDelFailureSurfaced(t *testing.T) {
	cases := []struct {
		name string
		prio int
		run  func(ops *fakeRuleOps) error
	}{
		{
			name: "next-table",
			prio: nextTableRulePriority + 3,
			run: func(ops *fakeRuleOps) error {
				// nil routes → no re-adds; the only activity is clear().
				return (&nextTableManager{ops: ops}).Apply(nil, nil, testNextTableIifs)
			},
		},
		{
			name: "rib-group",
			prio: ribGroupLeakRulePriority + 3,
			run: func(ops *fakeRuleOps) error {
				// Empty rib-groups → early return after clear(); no re-adds.
				return (&ribGroupManager{ops: ops}).Apply(nil, nil, nil)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeRuleOps()
			// A stale rule inside the managed window clear() scans.
			seedRule(ops, unix.AF_INET, c.prio, 100)
			// RuleDel returns a REAL failure: the rule exists but cannot be
			// removed, so it lingers as an active route-leak instruction.
			ops.delErr = errors.New("netlink EBUSY")
			if err := c.run(ops); err == nil {
				t.Fatalf("%s: Apply must return non-nil when a stale route-leak "+
					"rule cannot be cleared (#5118) — got nil", c.name)
			}
		})
	}
}

// TestNextTableRibGroupClearDelNotFoundIdempotent verifies the #5118 ENOENT
// carve-out: a RuleDel that fails because the rule is ALREADY GONE (ENOENT /
// no such rule — it vanished between the RuleList dump and the delete, or an
// idempotent re-clear removed it) is NOT a failure. Deleting an already-absent
// rule reaches the desired end-state, so Apply MUST return nil rather than
// spuriously failing the apply on a benign no-op delete.
func TestNextTableRibGroupClearDelNotFoundIdempotent(t *testing.T) {
	cases := []struct {
		name string
		prio int
		run  func(ops *fakeRuleOps) error
	}{
		{
			name: "next-table",
			prio: nextTableRulePriority + 4,
			run: func(ops *fakeRuleOps) error {
				return (&nextTableManager{ops: ops}).Apply(nil, nil, testNextTableIifs)
			},
		},
		{
			name: "rib-group",
			prio: ribGroupLeakRulePriority + 4,
			run: func(ops *fakeRuleOps) error {
				return (&ribGroupManager{ops: ops}).Apply(nil, nil, nil)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeRuleOps()
			seedRule(ops, unix.AF_INET, c.prio, 100)
			// RuleDel reports the rule is already absent — the delete's goal
			// (rule gone) is met, so this must NOT surface as an apply error.
			ops.delErr = unix.ENOENT
			if err := c.run(ops); err != nil {
				t.Fatalf("%s: Apply must return nil when a stale rule is already "+
					"absent (ENOENT) — got %v", c.name, err)
			}
		})
	}
}

// seedRule inserts a rule at the given family/priority/table directly into
// the fake's backing store (bypassing RuleAdd accounting) so a clear() can
// be exercised against pre-existing kernel rules.
func seedRule(ops *fakeRuleOps, family, prio, table int) {
	ops.rules[family] = append(ops.rules[family], netlink.Rule{
		Family:   family,
		Priority: prio,
		Table:    table,
	})
}

// TestRulesClearListErrorSurfaced is the #2273 fail-on-revert guard. When
// RuleList(AF_INET) fails transiently while RuleList(AF_INET6) succeeds,
// clear() (via Apply) must:
//
//  1. return a non-nil error naming the failing family (so the daemon
//     apply loop observes it instead of a silent self-healing-orphan
//     window), and
//  2. still best-effort delete the rules it COULD list — the AF_INET6
//     rule in the managed window is removed.
//
// The AF_INET rule in the window is left in place because its family's
// dump failed (the orphan this PR makes observable). Reverting clear() to
// `continue` + `return nil` makes assertion (1) fail for all three
// managers, and reverting the Apply wiring (returning bare nil) also fails
// (1) — this is the regression pin.
func TestRulesClearListErrorSurfaced(t *testing.T) {
	injErr := errors.New("netlink: transient EBUSY on AF_INET dump")

	type tc struct {
		name string
		// run pre-seeds rules, arms the AF_INET list failure, runs Apply
		// with a desired config that produces ZERO new rules (so the only
		// activity is the clear), and returns the Apply error.
		run func(ops *fakeRuleOps) error
		// inetPrio / inet6Prio are managed-window priorities for each
		// domain so the seeded rules fall inside clear()'s scan range.
		inetPrio  int
		inet6Prio int
	}

	cases := []tc{
		{
			name:      "next-table",
			inetPrio:  nextTableRulePriority + 1,
			inet6Prio: nextTableRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				nt := &nextTableManager{ops: ops}
				// No routes carry a next-table directive → no re-adds; the
				// only work clear() does is delete-in-window.
				return nt.Apply(nil, nil, testNextTableIifs)
			},
		},
		{
			name:      "rib-group",
			inetPrio:  ribGroupRulePriority + 1,
			inet6Prio: ribGroupRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				rg := &ribGroupManager{ops: ops}
				// Empty rib-groups → early return after clear; no re-adds.
				return rg.Apply(nil, nil, nil)
			},
		},
		{
			name:      "pbr",
			inetPrio:  pbrRulePriority + 1,
			inet6Prio: pbrRulePriority + 2,
			run: func(ops *fakeRuleOps) error {
				p := &pbrManager{ops: ops}
				// Empty PBR set → early return after clear; no re-adds.
				return p.Apply(nil)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeRuleOps()
			// One managed-window rule per family.
			seedRule(ops, unix.AF_INET, c.inetPrio, 100)
			seedRule(ops, unix.AF_INET6, c.inet6Prio, 101)
			// AF_INET dump fails transiently; AF_INET6 succeeds.
			ops.failList(unix.AF_INET, injErr)

			err := c.run(ops)
			if err == nil {
				t.Fatalf("%s: Apply must return an error when RuleList(AF_INET) fails (#2273) — got nil", c.name)
			}
			if !errors.Is(err, injErr) {
				t.Errorf("%s: returned error must wrap the injected list failure, got %v", c.name, err)
			}

			// Best-effort delete preserved: the family that DID list is
			// cleaned. The AF_INET6 window rule must be gone.
			if got := ops.count(unix.AF_INET6); got != 0 {
				t.Errorf("%s: AF_INET6 window rule must still be deleted despite the AF_INET list failure, count=%d rules=%v",
					c.name, got, ops.rules[unix.AF_INET6])
			}
			// The AF_INET window rule could not be listed, so it survives
			// (the orphan this PR makes observable, not silent).
			if got := ops.count(unix.AF_INET); got != 1 {
				t.Errorf("%s: AF_INET window rule should remain (its dump failed), count=%d", c.name, got)
			}
		})
	}
}

// TestPBRApplyRoutesDSCPThroughRuleAddDSCP7796 binds the WIRING, not the encoder.
//
// The encoder is proven against the kernel in rule_dscp_kernel_7796_test.go, but
// those cells SKIP without CAP_NET_ADMIN and they call RuleAddDSCP directly. If
// the pbr applier went on calling plain RuleAdd for a DSCP rule, every one of
// them would still pass while the shipped path emitted no DSCP selector at all —
// a rule matching EVERY DSCP, which is the #3430 H2 over-match wearing the #7796
// fix as a disguise.
//
// FAIL-ON-REVERT: change the applier's `if pbr.DSCPSet` branch back to
// p.ops.RuleAdd(rule) and this cell reds while the kernel cells stay green.
func TestPBRApplyRoutesDSCPThroughRuleAddDSCP7796(t *testing.T) {
	ops := newFakeRuleOps()
	p := &pbrManager{ops: ops}

	rules := []PBRRule{
		// A DSCP rule and a DSCP-LESS rule in the same apply: the applier has to
		// send each down the right path, so a build that routes everything one
		// way fails whichever way it picks.
		{Family: unix.AF_INET, DSCP: 46, DSCPSet: true, TableID: 100, Instance: "vr-a", IifName: "ge-0-0-0"},
		{Family: unix.AF_INET, DSCP: 0, DSCPSet: true, TableID: 101, Instance: "vr-b", IifName: "ge-0-0-1"},
		{Family: unix.AF_INET, Dst: "10.5.0.0/16", TableID: 102, Instance: "vr-c", IifName: "ge-0-0-2"},
	}
	if err := p.Apply(rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got := ops.dscps[unix.AF_INET]
	wantDSCPs := []uint8{46, 46, 0, 0}
	if len(got) != len(wantDSCPs) {
		t.Fatalf("RuleAddDSCP called %d times, want %d (lookup and unreachable rule per DSCPSet PBR); recorded=%v", len(got), len(wantDSCPs), got)
	}
	for i, want := range wantDSCPs {
		if got[i] != want {
			t.Errorf("RuleAddDSCP call %d used DSCP %d, want %d", i, got[i], want)
		}
	}
	// The DSCP-less lookup and shadow must NOT have gone through the DSCP path.
	if total := ops.count(unix.AF_INET); total != 6 {
		t.Errorf("expected 6 installed IPv4 rules (three lookup/shadow pairs), got %d", total)
	}
}
