package routing

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// STEP-0 RED cells for #9810 (routing side: SYN-LO0-02 loopback,
// LEAD-O4 PBR, SYN-C-LEAK-05 fault atomicity, SYN-WIN-01 agreement).

// TestDefaultInstanceIngressIfacesExcludesLoopback_9810 pins that loopback
// never enters the #9420 scoping set: neither `lo0` units (which resolve to
// the nonexistent `lo0`/`lo0.N` and install detached) nor a literal `lo`
// unit (which collapses to kernel `lo` — the live #9420 cross-VRF hijack).
func TestDefaultInstanceIngressIfacesExcludesLoopback_9810(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"lo0": {Name: "lo0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			5: {Number: 5},
		}},
		"lo": {Name: "lo", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}

	got := DefaultInstanceIngressIfaces(cfg)
	if strings.Join(got, ",") != "ge-0-0-0" {
		t.Fatalf("loopback must be excluded from the scoping set, got %v", got)
	}
	for _, iif := range got {
		if iif == "lo" || iif == "lo0" || strings.HasPrefix(iif, "lo0.") || strings.HasPrefix(iif, "lo.") {
			t.Errorf("scoping set carries loopback ingress %q", iif)
		}
	}
}

// pbr9810AttachConfig attaches filter as the input filter on the given
// (interface, unit, family) hooks.
func pbr9810AttachConfig(filter *config.FirewallFilter, instances []*config.RoutingInstanceConfig, hooks ...pbr9810Hook) *config.Config {
	cfg := &config.Config{RoutingInstances: instances}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for _, h := range hooks {
		ifc := cfg.Interfaces.Interfaces[h.ifName]
		if ifc == nil {
			ifc = &config.InterfaceConfig{Name: h.ifName, Units: map[int]*config.InterfaceUnit{}}
			cfg.Interfaces.Interfaces[h.ifName] = ifc
		}
		unit := ifc.Units[h.unit]
		if unit == nil {
			unit = &config.InterfaceUnit{Number: h.unit}
			ifc.Units[h.unit] = unit
		}
		if h.v6 {
			if cfg.Firewall.FiltersInet6 == nil {
				cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{}
			}
			cfg.Firewall.FiltersInet6[filter.Name] = filter
			unit.FilterInputV6 = filter.Name
		} else {
			if cfg.Firewall.FiltersInet == nil {
				cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{}
			}
			cfg.Firewall.FiltersInet[filter.Name] = filter
			unit.FilterInputV4 = filter.Name
		}
	}
	return cfg
}

type pbr9810Hook struct {
	ifName string
	unit   int
	v6     bool
}

// TestBuildPBRRulesDropsLoopbackAttachments_9810 pins LEAD-O4: an input
// filter carrying a `then routing-instance` term but attached on loopback
// builds NO rule (it would install detached on the nonexistent `lo0`) and
// reports the drop LOUD as a degraded build — never silently.
func TestBuildPBRRulesDropsLoopbackAttachments_9810(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	mkFilter := func() *config.FirewallFilter {
		return &config.FirewallFilter{Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "t", SourceAddresses: []string{"10.0.1.0/24"}, RoutingInstance: "ATT"},
		}}
	}
	mkPlainFilter := func() *config.FirewallFilter {
		return &config.FirewallFilter{Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "t", SourceAddresses: []string{"10.0.1.0/24"}, Action: "accept"},
		}}
	}

	t.Run("lo0 v4", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkFilter(), instances, pbr9810Hook{"lo0", 0, false})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("lo0 attachment must build no PBR rule, got %v", rules)
		}
		if err == nil || !strings.Contains(err.Error(), "lo0") {
			t.Fatalf("the drop must be loud and name lo0, got %v", err)
		}
	})

	t.Run("lo0 v6", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkFilter(), instances, pbr9810Hook{"lo0", 0, true})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("lo0 attachment must build no PBR rule, got %v", rules)
		}
		if err == nil || !strings.Contains(err.Error(), "lo0") {
			t.Fatalf("the drop must be loud and name lo0, got %v", err)
		}
	})

	t.Run("lo0 non-zero unit", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkFilter(), instances, pbr9810Hook{"lo0", 5, false})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("lo0.5 attachment must build no PBR rule, got %v", rules)
		}
		if err == nil {
			t.Fatal("the lo0.5 drop must be loud, got nil error")
		}
	})

	t.Run("bare lo", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkFilter(), instances, pbr9810Hook{"lo", 0, false})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("lo attachment must build no PBR rule, got %v", rules)
		}
		if err == nil {
			t.Fatal("the lo drop must be loud, got nil error")
		}
	})

	t.Run("mixed loopback and real", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkFilter(), instances,
			pbr9810Hook{"lo0", 0, false}, pbr9810Hook{"ge-0/0/0", 0, false})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 1 || rules[0].IifName != "ge-0-0-0" {
			t.Fatalf("only the real attachment must build a rule, got %v", rules)
		}
		if err == nil || !strings.Contains(err.Error(), "lo0") {
			t.Fatalf("the lo0 drop must still be loud, got %v", err)
		}
	})

	t.Run("non-PBR lo0 v4 stays silent", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkPlainFilter(), instances, pbr9810Hook{"lo0", 0, false})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("a non-PBR filter builds no rule anywhere, got %v", rules)
		}
		if err != nil {
			t.Fatalf("an ordinary lo0 accept filter must not report degraded PBR, got %v", err)
		}
	})

	t.Run("non-PBR lo0 v6 stays silent", func(t *testing.T) {
		cfg := pbr9810AttachConfig(mkPlainFilter(), instances, pbr9810Hook{"lo0", 0, true})
		rules, err := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Fatalf("a non-PBR filter builds no rule anywhere, got %v", rules)
		}
		if err != nil {
			t.Fatalf("an ordinary lo0 accept filter must not report degraded PBR, got %v", err)
		}
	})
}

// TestPBRClearScansTheWindowConstant_9810 is the SYN-C-NET-06 lockstep pin.
// It CANNOT redden (install cap and cleanup bound agree at 1000 today); it
// exists so a future PBRRuleWindow change that updates one side but not the
// other fails here instead of leaving stale rules or deleting live ones.
func TestPBRClearScansTheWindowConstant_9810(t *testing.T) {
	ops := newFakeRuleOps()
	edge := pbrRulePriority + maxPBRRules
	seed := func(prio int) {
		if err := ops.RuleAdd(&netlink.Rule{Family: unix.AF_INET, Priority: prio, Table: 100}); err != nil {
			t.Fatalf("seed prio %d: %v", prio, err)
		}
	}
	seed(pbrRulePriority)
	seed(edge - 1)
	seed(edge)

	if err := (&pbrManager{ops: ops}).clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	prios := map[int]bool{}
	for _, r := range ops.rules[unix.AF_INET] {
		prios[r.Priority] = true
	}
	if prios[pbrRulePriority] || prios[edge-1] {
		t.Errorf("rules inside [base, base+window) must be cleared, left %v", prios)
	}
	if !prios[edge] {
		t.Errorf("rule at base+window must survive the clear, left %v", prios)
	}
}

// failNthAddOps9810 fails exactly the n-th RuleAdd (1-based), recording every
// other call in the embedded fake.
type failNthAddOps9810 struct {
	*fakeRuleOps
	n     int
	count int
	err   error
}

func (f *failNthAddOps9810) RuleAdd(r *netlink.Rule) error {
	f.count++
	if f.count == f.n {
		return f.err
	}
	return f.fakeRuleOps.RuleAdd(r)
}

// TestNextTableInstallIsFaultAtomic_9810 pins SYN-C-LEAK-05: a netlink fault
// on one ingress interface of a leak must not leave the leak installed on a
// subset of its interfaces. The partial install is rolled back, the priority
// is not consumed, and the next leak installs in its place.
func TestNextTableInstallIsFaultAtomic_9810(t *testing.T) {
	inner := newFakeRuleOps()
	ops := &failNthAddOps9810{fakeRuleOps: inner, n: 2, err: errors.New("netlink: transient EBUSY")}
	nt := &nextTableManager{ops: ops}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	routes := []*config.StaticRoute{
		{Destination: "10.11.0.0/16", NextTable: "dmz-vr"},
		{Destination: "10.12.0.0/16", NextTable: "dmz-vr"},
	}
	iifs := []string{"ge-0-0-0", "ge-0-0-1"}

	err := nt.Apply(routes, instances, iifs)
	if err == nil || !strings.Contains(err.Error(), "10.11.0.0/16") {
		t.Fatalf("the fault must surface naming the failed leak, got %v", err)
	}
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil && r.Dst.String() == "10.11.0.0/16" {
			t.Fatalf("failed leak left installed on %q: %+v (must roll back)", r.IifName, r)
		}
	}
	var bPrios []int
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil && r.Dst.String() == "10.12.0.0/16" {
			bPrios = append(bPrios, r.Priority)
		}
	}
	if len(bPrios) != 2 || bPrios[0] != 100 || bPrios[1] != 101 {
		t.Fatalf("the next leak must reuse the failed prio (100,101), got %v", bPrios)
	}
}

// TestNextTableRuleAddEEXISTCountsAsInstalled_9810 pins the LEAK-05
// sub-decision: EEXIST means the desired rule content is already in the
// kernel (stale survivor of a failed clear), so it counts as installed —
// not as a rollback trigger. Rolling back on EEXIST would delete good
// siblings and reduce coverage to the single stale rule. 50 EEXIST leaks
// consume the full 100-slot reservation, so the 51st overflows — while no
// EEXIST failure itself surfaces (an added++-less treatment would admit all
// 51 silently, and a non-silent one would join 100 EEXIST errors).
func TestNextTableRuleAddEEXISTCountsAsInstalled_9810(t *testing.T) {
	ops := newFakeRuleOps()
	ops.failAdd(unix.AF_INET, unix.EEXIST)
	nt := &nextTableManager{ops: ops}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	var routes []*config.StaticRoute
	for i := range 51 {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.0.0/16", i), NextTable: "dmz-vr",
		})
	}
	err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"})
	if err == nil || !strings.Contains(err.Error(), "rule limit") {
		t.Fatalf("the 51st leak must overflow the EEXIST-consumed window, got %v", err)
	}
	if !strings.Contains(err.Error(), "1 next-table route(s)") {
		t.Errorf("overflow must report exactly the 1 dropped tail leak, got %q", err)
	}
	if strings.Contains(err.Error(), unix.EEXIST.Error()) {
		t.Errorf("converged EEXIST content must stay silent, got %q", err)
	}
}

// TestNextTableApplierAgreesWithExclusions_9810 is the SYN-WIN-01 money cell:
// with N=4 and L=30 the kernel installs 25 leaks while the shared verdict
// publishes all 30. The installed set and the published set must be IDENTICAL.
func TestNextTableApplierAgreesWithExclusions_9810(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("ge-0/0/%d", i)
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < 30; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "blue",
			})
	}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	applyErr := nt.Apply(cfg.RoutingOptions.StaticRoutes, cfg.RoutingInstances,
		DefaultInstanceIngressIfaces(cfg))
	if applyErr == nil {
		t.Fatal("30 leaks over 4 ingress interfaces must overflow the 100-slot window")
	}

	installed := map[string]bool{}
	for _, r := range ops.rules[unix.AF_INET] {
		if r.Dst != nil {
			installed[r.Dst.String()] = true
		}
	}
	excl := config.StaticRouteExclusions(cfg)
	published := map[string]bool{}
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if excl[sr] == "" {
			published[sr.Destination] = true
		}
	}
	if len(installed) != len(published) {
		t.Fatalf("installed %d leaks but published %d: kernel/FIB split (#9810)",
			len(installed), len(published))
	}
	for dst := range installed {
		if !published[dst] {
			t.Fatalf("installed leak %s is not published", dst)
		}
	}
	for dst := range published {
		if !installed[dst] {
			t.Fatalf("published leak %s is not installed", dst)
		}
	}
}

// TestNextTableOverflowAfterAddFailure_9810 is the GPT-1 regression: admission
// is independent of install/rollback accounting. Leak 1 faults and rolls back
// cleanly, freeing its slots — but its reservation is still consumed, so the
// verdict-excluded 51st leak must NOT install (pre-fix the freed cursor
// admitted it, and live-rule ingestion published it too). Every installed leak
// must be a verdict-admitted one; the faulted leak under-installs (reported,
// healed by #9693 retry) rather than shifting the tail in.
func TestNextTableOverflowAfterAddFailure_9810(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := range 51 {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.0.0/16", i), NextTable: "blue",
			})
	}
	inner := newFakeRuleOps()
	ops := &failNthAddOps9810{fakeRuleOps: inner, n: 2, err: errors.New("netlink: transient EBUSY")}
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(cfg.RoutingOptions.StaticRoutes, cfg.RoutingInstances,
		DefaultInstanceIngressIfaces(cfg))
	if err == nil || !strings.Contains(err.Error(), "rule limit") {
		t.Fatalf("the 51st leak must overflow despite the earlier rollback, got %v", err)
	}
	excl := config.StaticRouteExclusions(cfg)
	tail := cfg.RoutingOptions.StaticRoutes[50]
	if excl[tail] == "" {
		t.Fatal("fixture premise: the verdict must exclude the 51st leak")
	}
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil && r.Dst.String() == tail.Destination {
			t.Fatalf("verdict-excluded tail leak %s installed (GPT-1)", tail.Destination)
		}
	}
	installed := map[string]bool{}
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil {
			installed[r.Dst.String()] = true
		}
	}
	for i, sr := range cfg.RoutingOptions.StaticRoutes {
		if installed[sr.Destination] && excl[sr] != "" {
			t.Fatalf("installed leak %d (%s) is verdict-excluded: %q", i, sr.Destination, excl[sr])
		}
	}
	if len(installed) != 49 {
		t.Fatalf("want the 49 surviving admitted leaks installed (faulted leak 1 rolled back), got %d", len(installed))
	}
}

// TestNextTableOverflowAfterFailedRollback_9810 pins that the GPT-1 admission
// fix also holds when the rollback itself fails: the orphan stays, the
// reservation is still consumed, and the verdict-excluded tail still does not
// install.
func TestNextTableOverflowAfterFailedRollback_9810(t *testing.T) {
	inner := newFakeRuleOps()
	inner.delErr = errors.New("netlink: transient EBUSY on delete")
	ops := &failNthAddOps9810{fakeRuleOps: inner, n: 2, err: errors.New("netlink: transient EBUSY on add")}
	nt := &nextTableManager{ops: ops}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	var routes []*config.StaticRoute
	for i := range 51 {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.0.0/16", i), NextTable: "dmz-vr",
		})
	}
	err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"})
	if err == nil || !strings.Contains(err.Error(), "rule limit") {
		t.Fatalf("the 51st leak must overflow despite the failed rollback, got %v", err)
	}
	if !strings.Contains(err.Error(), "roll back") {
		t.Errorf("the failed rollback must surface, got %q", err)
	}
	seen := map[string]int{}
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil {
			seen[r.Dst.String()]++
		}
	}
	if seen["10.50.0.0/16"] != 0 {
		t.Fatal("verdict-excluded tail leak installed despite failed rollback (GPT-1)")
	}
	if seen["10.0.0.0/16"] != 1 {
		t.Fatalf("the un-rolled-back orphan must remain exactly once, got %d", seen["10.0.0.0/16"])
	}
}

// failNthDelOps9810 fails exactly the n-th RuleDel (1-based), delegating every
// other call to the embedded ops.
type failNthDelOps9810 struct {
	ruleOps
	n     int
	count int
	err   error
}

func (f *failNthDelOps9810) RuleDel(r *netlink.Rule) error {
	f.count++
	if f.count == f.n {
		return f.err
	}
	return f.ruleOps.RuleDel(r)
}

// TestNextTableRollbackSurvivorsPackAndGap_9810 pins the most contentious
// cursor logic: rollback survivors sit at ARBITRARY positions, so the scalar
// cursor is approximate — the next leak packs at a priority the orphan still
// holds (duplicate priorities, kernel-permitted) and skips a freed slot (gap
// waste). Both are transient: the joined error plus the #9693 retry heals.
// Fidelity note (SPARK-F6): the fake deletes by priority only while prod
// netlink deletes by full rule identity, so this cell pins the PRIO LAYOUT
// (dup at 101, gap at 100), not del precision.
func TestNextTableRollbackSurvivorsPackAndGap_9810(t *testing.T) {
	inner := newFakeRuleOps()
	addOps := &failNthAddOps9810{fakeRuleOps: inner, n: 3, err: errors.New("netlink: transient EBUSY on add")}
	ops := &failNthDelOps9810{ruleOps: addOps, n: 2, err: errors.New("netlink: transient EBUSY on delete")}
	nt := &nextTableManager{ops: ops}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	routes := []*config.StaticRoute{
		{Destination: "10.21.0.0/16", NextTable: "dmz-vr"},
		{Destination: "10.22.0.0/16", NextTable: "dmz-vr"},
	}
	err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-2"})
	if err == nil || !strings.Contains(err.Error(), "roll back") {
		t.Fatalf("the failed rollback del must surface, got %v", err)
	}
	byPrio := map[int][]string{}
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil {
			byPrio[r.Priority] = append(byPrio[r.Priority], r.Dst.String())
		}
	}
	if len(byPrio[100]) != 0 {
		t.Errorf("prio 100 was rolled back and skipped: gap waste pinned, got %v", byPrio[100])
	}
	if dsts := byPrio[101]; len(dsts) != 2 {
		t.Fatalf("prio 101 must pack the orphan and the next leak (dup), got %v", dsts)
	} else if !((dsts[0] == "10.21.0.0/16") != (dsts[1] == "10.21.0.0/16")) {
		t.Fatalf("prio 101 must hold exactly one orphan + one next-leak rule, got %v", dsts)
	}
}

// scriptOps9810 returns scripted errors for the first len(script) RuleAdds and
// succeeds thereafter; all other ops delegate to the embedded fake.
type scriptOps9810 struct {
	*fakeRuleOps
	script []error
	count  int
}

func (s *scriptOps9810) RuleAdd(r *netlink.Rule) error {
	s.count++
	if s.count <= len(s.script) && s.script[s.count-1] != nil {
		return s.script[s.count-1]
	}
	return s.fakeRuleOps.RuleAdd(r)
}

// TestNextTableEEXISTAdvancesInstallCursor_9810 pins that EEXIST-occupied slots
// advance the install cursor: the next leak programs past them rather than
// packing onto converged content.
func TestNextTableEEXISTAdvancesInstallCursor_9810(t *testing.T) {
	inner := newFakeRuleOps()
	ops := &scriptOps9810{fakeRuleOps: inner, script: []error{unix.EEXIST, unix.EEXIST}}
	nt := &nextTableManager{ops: ops}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
	routes := []*config.StaticRoute{
		{Destination: "10.23.0.0/16", NextTable: "dmz-vr"},
		{Destination: "10.24.0.0/16", NextTable: "dmz-vr"},
	}
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("EEXIST content is converged and must not fail the apply, got %v", err)
	}
	var prios []int
	for _, r := range inner.rules[unix.AF_INET] {
		if r.Dst != nil && r.Dst.String() == "10.24.0.0/16" {
			prios = append(prios, r.Priority)
		}
	}
	if len(prios) != 2 || prios[0] != 102 || prios[1] != 103 {
		t.Fatalf("the leak after an EEXIST leak must program past it (102,103), got %v", prios)
	}
}
