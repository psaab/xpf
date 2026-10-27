package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// #17971 RED cells for the dynamic main-table carve-out leg. The salvaged
// mechanism enumerates slot-0 main exceptions from the live main-table dump
// (ImportLearnedRoutes rows injected through the mainRoutes seam) instead of
// only from configured statics. These cells pin: (a) learned unicast and
// terminal rows more specific than an admitted leak mint carve-outs in both
// families, (b) rows that cannot win the merged-walk LPM mint nothing,
// (c) churn refresh converges the band without touching leak rules,
// (d) a failed dump leaves the installed band untouched, and (e) the
// production Manager wiring exposes the refresh.

func learnedRow17971(tableID, family int, destination string, nextHops []string, discard, reject bool) LearnedRoute {
	return LearnedRoute{
		TableID:     tableID,
		Family:      family,
		Destination: destination,
		NextHops:    nextHops,
		Discard:     discard,
		Reject:      reject,
		Protocol:    "bgp",
	}
}

func carveoutKeys17971(ops *fakeRuleOps) map[string]bool {
	out := map[string]bool{}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, rule := range ops.rules[family] {
			if isNextTableMainCarveoutShape(rule) {
				out[rule.Dst.String()+"|"+rule.IifName] = true
			}
		}
	}
	return out
}

func TestNextTableDynamicCarveoutsFromLearnedMain17971(t *testing.T) {
	learned := []LearnedRoute{
		// More specific than the admitted leaks: must mint.
		learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "10.2.0.0/16", nil, true, false),
		learnedRow17971(mainTableID, unix.AF_INET, "10.3.0.0/16", nil, false, true),
		learnedRow17971(mainTableID, unix.AF_INET6, "2001:db8:1::/48", []string{"2001:db8::1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET6, "2001:db8:2::/48", nil, true, false),
		// Must NOT mint: equal/broader than the leak, outside the leak,
		// another table, family-mismatched, nexthop-less unicast, default,
		// and malformed rows.
		learnedRow17971(mainTableID, unix.AF_INET, "10.0.0.0/8", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "10.0.0.0/7", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "192.0.2.0/24", []string{"192.0.2.1"}, false, false),
		learnedRow17971(100, unix.AF_INET, "10.4.0.0/16", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET6, "10.5.0.0/16", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "10.6.0.0/16", nil, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "0.0.0.0/0", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET, "not-a-cidr", []string{"192.0.2.1"}, false, false),
		// Duplicate of an admitted row: deduped.
		learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.9"}, false, false),
	}
	admitted := []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextTable: "red"},
		{Destination: "2001:db8::/32", NextTable: "red"},
	}
	got := nextTableDynamicCarveoutRules(learned, admitted, []string{"xwan", "xwan2"})
	want := map[string]bool{}
	for _, prefix := range []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "2001:db8:1::/48", "2001:db8:2::/48"} {
		for _, iif := range []string{"xwan", "xwan2"} {
			want[prefix+"|"+iif] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("dynamic carve-outs = %d rules, want %d: %+v", len(got), len(want), got)
	}
	for _, rule := range got {
		key := rule.Dst.String() + "|" + rule.IifName
		if !want[key] {
			t.Errorf("unexpected dynamic carve-out: %+v", rule)
			continue
		}
		delete(want, key)
		prefixLen, addressBits := rule.Dst.Mask.Size()
		if rule.Table != mainTableID ||
			rule.Priority != config.RouteLeakNextTableCarveoutPriority(prefixLen, addressBits) ||
			rule.SuppressPrefixlen != prefixLen-1 {
			t.Errorf("malformed dynamic carve-out: %+v", rule)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing dynamic carve-outs: %v", want)
	}
	// No ingress interfaces: fail-closed, no unscoped exceptions.
	if got := nextTableDynamicCarveoutRules(learned, admitted, nil); len(got) != 0 {
		t.Errorf("no-iif dynamic carve-outs = %+v, want none", got)
	}
}

func TestNextTableDynamicCarveoutApplyAndRefresh17971(t *testing.T) {
	routes := []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextTable: "red"},
		{Destination: "2001:db8::/32", NextTable: "red"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	iifs := []string{"xwan"}
	ops := newFakeRuleOps()
	learned := []LearnedRoute{
		learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.1"}, false, false),
		learnedRow17971(mainTableID, unix.AF_INET6, "2001:db8:1::/48", nil, false, true),
	}
	nt := &nextTableManager{ops: ops, mainRoutes: func() ([]LearnedRoute, error) {
		return append([]LearnedRoute(nil), learned...), nil
	}}
	if err := nt.Apply(routes, instances, iifs); err != nil {
		t.Fatalf("Apply with dynamic carve-outs: %v", err)
	}
	got := carveoutKeys17971(ops)
	if !got["10.1.0.0/16|xwan"] || !got["2001:db8:1::/48|xwan"] || len(got) != 2 {
		t.Fatalf("carve-outs after Apply = %v, want the two learned exceptions", got)
	}
	leakRules := 0
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		leakRules += ops.count(family)
	}

	// Churn: the v4 learned route withdraws and a v6 one appears. Refresh
	// must converge ONLY the carve-out band.
	learned = []LearnedRoute{
		learnedRow17971(mainTableID, unix.AF_INET6, "2001:db8:1::/48", nil, false, true),
		learnedRow17971(mainTableID, unix.AF_INET6, "2001:db8:2::/48", []string{"2001:db8::2"}, false, false),
	}
	if err := nt.RefreshCarveouts(routes, instances, iifs); err != nil {
		t.Fatalf("RefreshCarveouts: %v", err)
	}
	got = carveoutKeys17971(ops)
	if got["10.1.0.0/16|xwan"] {
		t.Errorf("withdrawn learned route kept its carve-out: %v", got)
	}
	if !got["2001:db8:1::/48|xwan"] || !got["2001:db8:2::/48|xwan"] || len(got) != 2 {
		t.Errorf("carve-outs after refresh = %v, want the two live v6 exceptions", got)
	}
	total := 0
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		total += ops.count(family)
	}
	if total != leakRules {
		t.Errorf("refresh changed total rule count %d -> %d; leak lookups/shadows must be untouched", leakRules, total)
	}
}

func TestNextTableDynamicCarveoutDumpFailureKeepsBand17971(t *testing.T) {
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	ops := newFakeRuleOps()
	fail := false
	nt := &nextTableManager{ops: ops, mainRoutes: func() ([]LearnedRoute, error) {
		if fail {
			return nil, errors.New("injected main-table dump failure")
		}
		return []LearnedRoute{
			learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.1"}, false, false),
		}, nil
	}}
	if err := nt.Apply(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	before := carveoutKeys17971(ops)
	if !before["10.1.0.0/16|xwan"] {
		t.Fatalf("carve-outs after Apply = %v, want the learned exception", before)
	}
	fail = true
	err := nt.RefreshCarveouts(routes, instances, []string{"xwan"})
	if err == nil || !strings.Contains(err.Error(), "dump failed") {
		t.Fatalf("RefreshCarveouts with failing dump = %v, want a dump-failure error", err)
	}
	if after := carveoutKeys17971(ops); !after["10.1.0.0/16|xwan"] || len(after) != len(before) {
		t.Errorf("failed dump mutated the installed band: before %v, after %v", before, after)
	}
	// A failing dump on the commit path must also surface, not silently
	// install a statics-only subset.
	if err := nt.Apply(routes, instances, []string{"xwan"}); err == nil {
		t.Error("Apply with failing dump returned nil, want the dump failure surfaced")
	}
}

func TestNextTableDynamicCarveoutDedupesStatic17971(t *testing.T) {
	routes := []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextTable: "red"},
		{Destination: "10.1.0.0/16", Discard: true},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops, mainRoutes: func() ([]LearnedRoute, error) {
		return []LearnedRoute{
			learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.1"}, false, false),
		}, nil
	}}
	if err := nt.Apply(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	count := 0
	for _, rule := range ops.rules[unix.AF_INET] {
		if isNextTableMainCarveoutShape(rule) && rule.Dst.String() == "10.1.0.0/16" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("static+learned same-prefix carve-outs = %d, want exactly 1", count)
	}
}

func TestManagerRefreshNextTableCarveouts17971(t *testing.T) {
	ops := newFakeRuleOps()
	m := &Manager{nextTbl: &nextTableManager{ops: ops, mainRoutes: func() ([]LearnedRoute, error) {
		return []LearnedRoute{
			learnedRow17971(mainTableID, unix.AF_INET, "10.1.0.0/16", []string{"192.0.2.1"}, false, false),
		}, nil
	}}}
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	if err := m.RefreshNextTableCarveouts(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("Manager.RefreshNextTableCarveouts: %v", err)
	}
	if got := carveoutKeys17971(ops); !got["10.1.0.0/16|xwan"] || len(got) != 1 {
		t.Fatalf("carve-outs via Manager = %v, want the learned exception only", got)
	}
	// Refresh on a manager whose dump seam is unwired keeps statics only.
	ops2 := newFakeRuleOps()
	m2 := &Manager{nextTbl: &nextTableManager{ops: ops2}}
	if err := m2.RefreshNextTableCarveouts(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("RefreshNextTableCarveouts without dump seam: %v", err)
	}
	if got := carveoutKeys17971(ops2); len(got) != 0 {
		t.Fatalf("carve-outs without dump seam = %v, want none", got)
	}
}
