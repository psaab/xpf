package routing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// pbr15271Config builds a config with an inet filter attached on ge-0/0/0.0
// and an inet6 filter attached on ge-0/0/1.0, mirroring the acceptance probe
// shape: an oversized steer4 term plus a small steer6 term.
func pbr15271Config(inetFilter, inet6Filter *config.FirewallFilter, instances []*config.RoutingInstanceConfig) *config.Config {
	cfg := &config.Config{RoutingInstances: instances}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{inetFilter.Name: inetFilter}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{inet6Filter.Name: inet6Filter}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, FilterInputV4: inetFilter.Name}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0, FilterInputV6: inet6Filter.Name}}},
	}
	return cfg
}

func pbr15271Srcs(n int, base string) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("%s.%d.0/24", base, i))
	}
	return out
}

// TestBuildPBRRulesOversizedTermDoesNotKillLaterBuilds15271 is the #15271
// B21-02 acceptance probe: a single over-budget inet term must be skipped
// WITHOUT killing the rest of the build. The inet6 build must still yield
// its one rule, and the degraded error must be exactly the one steer4 error.
//
// FAIL-ON-REVERT: pre-fix buildPBRFromFilter returned overflowed=true for
// ANY single over-budget term, BuildPBRRules latched the shared flag and
// skipped the whole inet6 build — 0 rules, and the surviving leg is lost.
func TestBuildPBRRulesOversizedTermDoesNotKillLaterBuilds15271(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	// 26 dsts > 500-rule cap even alone (26 src x 26 dst = 676 > 500... use
	// src x dst product clearly over budget: 26x26=676).
	bigSrcs := pbr15271Srcs(26, "10.1")
	bigDsts := make([]string, 0, 26)
	for i := range 26 {
		bigDsts = append(bigDsts, fmt.Sprintf("192.168.%d.0/24", i))
	}
	inetFilter := &config.FirewallFilter{
		Name: "steer4",
		Terms: []*config.FirewallFilterTerm{
			{Name: "oversized", SourceAddresses: bigSrcs, DestAddresses: bigDsts, RoutingInstance: "ATT"},
		},
	}
	inet6Filter := &config.FirewallFilter{
		Name: "steer6",
		Terms: []*config.FirewallFilterTerm{
			{Name: "small6", DestAddresses: []string{"2001:db8::/32"}, RoutingInstance: "ATT"},
		},
	}
	cfg := pbr15271Config(inetFilter, inet6Filter, instances)

	rules, err := BuildPBRRules(cfg)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want exactly 1 IPv6 rule (oversized v4 term skipped, v6 build survives), got %+v", len(rules), rules)
	}
	if rules[0].Family != unix.AF_INET6 {
		t.Errorf("surviving rule family = %d, want AF_INET6", rules[0].Family)
	}
	if rules[0].Dst != "2001:db8::/32" {
		t.Errorf("surviving rule Dst = %q, want 2001:db8::/32", rules[0].Dst)
	}
	if err == nil {
		t.Fatal("expected exactly one steer4 degraded error, got nil")
	}
	if !strings.Contains(err.Error(), "term oversized") {
		t.Errorf("error must name the oversized steer4 term, got: %v", err)
	}
	// Exactly one degraded entry: the steer4 overflow. The v6 term built.
	_, degraded := PBRBuildRulesAndStats(cfg)
	if degraded != 1 {
		t.Errorf("degraded = %d, want 1 (only the oversized steer4 term)", degraded)
	}
}

// TestBuildPBRRulesLaterFittingTermStillBuilt15271 pins the same-filter leg:
// an over-budget term followed by a small fitting term in the SAME filter —
// the small term must still build (disjoint addresses so it is not shadowed
// by the dropped preceding terminating term).
func TestBuildPBRRulesLaterFittingTermStillBuilt15271(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	bigSrcs := pbr15271Srcs(26, "10.2")
	bigDsts := make([]string, 0, 26)
	for i := range 26 {
		bigDsts = append(bigDsts, fmt.Sprintf("198.51.%d.0/24", i))
	}
	filter := &config.FirewallFilter{
		Name: "mix15271",
		Terms: []*config.FirewallFilterTerm{
			{Name: "oversized", SourceAddresses: bigSrcs, DestAddresses: bigDsts, RoutingInstance: "ATT"},
			{Name: "small", DestAddresses: []string{"203.0.113.0/24"}, RoutingInstance: "ATT"},
		},
	}
	rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
	if len(rules) != 1 || rules[0].Dst != "203.0.113.0/24" {
		t.Fatalf("rules = %+v, want exactly the small term's rule", rules)
	}
	if err == nil || !strings.Contains(err.Error(), "term oversized") {
		t.Errorf("error must name the oversized term, got: %v", err)
	}
	_, degraded := PBRBuildRulesAndStats(pbrTestConfig("inet", filter, instances, nil))
	if degraded != 1 {
		t.Errorf("degraded = %d, want 1", degraded)
	}
}

// TestBuildPBRRulesSkippedBigTermLeavesRoomForLaterTerms15271 pins the
// room-remains leg at scale: "fill" builds 484 rules leaving 16, "cross"
// (400) cannot fit and is skipped, and the small later terms in both
// families still fit in the room cross left. Only cross is degraded.
// FAIL-ON-REVERT: pre-fix the cross overflow latched the shared flag, so
// later/later6 were silently lost (484 rules, degraded still 1 — the loss
// was invisible, which is the B21-02 undercount).
func TestBuildPBRRulesSkippedBigTermLeavesRoomForLaterTerms15271(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	mk := func(base string, n int) ([]string, []string) {
		srcs := make([]string, 0, n)
		dsts := make([]string, 0, n)
		for i := range n {
			srcs = append(srcs, fmt.Sprintf("%s.%d.0/24", base, i))
			dsts = append(dsts, fmt.Sprintf("%s.%d.0/24", base, 100+i))
		}
		return srcs, dsts
	}
	fillSrcs, fillDsts := mk("10.10", 22)   // 484 rules, leaves 16
	crossSrcs, crossDsts := mk("10.20", 20) // 400 > remaining 16
	inetFilter := &config.FirewallFilter{
		Name: "fill4",
		Terms: []*config.FirewallFilterTerm{
			{Name: "fill", SourceAddresses: fillSrcs, DestAddresses: fillDsts, RoutingInstance: "ATT"},
			{Name: "cross", SourceAddresses: crossSrcs, DestAddresses: crossDsts, RoutingInstance: "ATT"},
			{Name: "later", DestAddresses: []string{"203.0.113.0/24"}, RoutingInstance: "ATT"},
		},
	}
	inet6Filter := &config.FirewallFilter{
		Name: "later6f",
		Terms: []*config.FirewallFilterTerm{
			{Name: "later6", DestAddresses: []string{"2001:db8:1::/48"}, RoutingInstance: "ATT"},
		},
	}
	cfg := pbr15271Config(inetFilter, inet6Filter, instances)

	rules, err := BuildPBRRules(cfg)
	if len(rules) != 486 {
		t.Fatalf("rules = %d, want 484 fill + later + later6 (486)", len(rules))
	}
	if err == nil {
		t.Fatal("expected degraded error on window exhaustion")
	}
	for _, name := range []string{"term cross"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error must name skipped %s, got: %v", name, err)
		}
	}
	for _, name := range []string{"term later", "term later6"} {
		if strings.Contains(err.Error(), name) {
			t.Errorf("built term %s must not be reported skipped, got: %v", name, err)
		}
	}
	_, degraded := PBRBuildRulesAndStats(cfg)
	if degraded != 1 {
		t.Errorf("degraded = %d, want 1 (only cross; later/later6 fit in the room cross left)", degraded)
	}
}

// TestBuildPBRRulesExactExhaustionAccountsEverySkippedTerm15271 pins the
// genuine-exhaustion leg of the fix direction: when the running total hits
// the budget exactly, every term left unbuilt — later terms in the same
// filter and the whole other family — is named/counted, not only a term
// that crossed. fill (484) + exact (16) lands exactly on the 500 cap; the
// next inet term and the inet6 term cannot build and must each degrade.
// FAIL-ON-REVERT: pre-fix the exact-fit build returned overflowed=false and
// the later terms were attempted with budget 0 — actually also erroring;
// the distinguishing pre-fix loss is covered by the probes above. This
// cell pins that exact exhaustion neither crashes nor silently drops.
func TestBuildPBRRulesExactExhaustionAccountsEverySkippedTerm15271(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	fillSrcs := pbr15271Srcs(22, "10.30")
	fillDsts := make([]string, 0, 22)
	for i := range 22 {
		fillDsts = append(fillDsts, fmt.Sprintf("172.30.%d.0/24", i))
	}
	exactSrcs := pbr15271Srcs(4, "10.31")
	exactDsts := make([]string, 0, 4)
	for i := range 4 {
		exactDsts = append(exactDsts, fmt.Sprintf("172.31.%d.0/24", i))
	}
	inetFilter := &config.FirewallFilter{
		Name: "exact4",
		Terms: []*config.FirewallFilterTerm{
			{Name: "fill", SourceAddresses: fillSrcs, DestAddresses: fillDsts, RoutingInstance: "ATT"},
			{Name: "exact", SourceAddresses: exactSrcs, DestAddresses: exactDsts, RoutingInstance: "ATT"},
			{Name: "later", DestAddresses: []string{"203.0.113.0/24"}, RoutingInstance: "ATT"},
		},
	}
	inet6Filter := &config.FirewallFilter{
		Name: "later6f",
		Terms: []*config.FirewallFilterTerm{
			{Name: "later6", DestAddresses: []string{"2001:db8:1::/48"}, RoutingInstance: "ATT"},
		},
	}
	cfg := pbr15271Config(inetFilter, inet6Filter, instances)
	rules, err := BuildPBRRules(cfg)
	if len(rules) != maxPBRSteeringRules {
		t.Fatalf("rules = %d, want exactly the %d cap", len(rules), maxPBRSteeringRules)
	}
	if err == nil {
		t.Fatal("expected degraded errors for the unbuilt later terms")
	}
	for _, name := range []string{"term later", "term later6"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error must name unbuilt %s, got: %v", name, err)
		}
	}
	_, degraded := PBRBuildRulesAndStats(cfg)
	if degraded != 2 {
		t.Errorf("degraded = %d, want 2 (later, later6)", degraded)
	}
	// Determinism: repeated builds give identical rule count and degraded.
	rules2, degraded2 := PBRBuildRulesAndStats(cfg)
	if len(rules2) != len(rules) || degraded2 != degraded {
		t.Errorf("rebuild mismatch: %d/%d vs %d/%d", len(rules2), degraded2, len(rules), degraded)
	}
}
