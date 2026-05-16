package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestCompleteFromTree_PlaceholderWithChildrenDescends(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "10.0.0.1"}, "", nil)
	if !contains(cands, "exact") || !contains(cands, "longer") || !contains(cands, "orlonger") {
		t.Fatalf("expected destination modifiers after placeholder, got %v", cands)
	}
	if contains(cands, "summary") {
		t.Fatalf("unexpected sibling completions after destination placeholder: %v", cands)
	}
}

func TestCompleteFromTree_PlaceholderWithoutChildrenStaysLevel(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"ping", "8.8.8.8"}, "", nil)
	if !contains(cands, "count") || !contains(cands, "source") || !contains(cands, "size") {
		t.Fatalf("expected ping option completions after host placeholder, got %v", cands)
	}
}

func TestCompleteFromTree_RequestFailoverSupportsNodeAfterRGValue(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
				},
			},
		},
	}

	cands := CompleteFromTree(
		OperationalTree,
		[]string{"request", "chassis", "cluster", "failover", "redundancy-group", "1"},
		"",
		cfg,
	)
	if !contains(cands, "node") {
		t.Fatalf("expected 'node' completion after redundancy-group value, got %v", cands)
	}
}

func TestCompleteFromTree_ShowRouteTableDynamicNames(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "blue"},
		},
	}

	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", cfg)
	if !contains(cands, "inet.0") || !contains(cands, "inet6.0") {
		t.Fatalf("expected default table names, got %v", cands)
	}
	if !contains(cands, "blue.inet.0") || !contains(cands, "blue.inet6.0") {
		t.Fatalf("expected per-instance table names, got %v", cands)
	}
}

func TestCompleteFromTree_UniquePrefixWordsDescend(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"sh", "sec"}, "", nil)
	if !contains(cands, "flow") || !contains(cands, "nat") {
		t.Fatalf("expected security subtree completions after unique prefixes, got %v", cands)
	}
}

func TestCompleteFromTree_AmbiguousLastConsumedPrefixReturnsMatches(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "s"}, "", nil)
	if !contains(cands, "security") || !contains(cands, "services") || !contains(cands, "system") {
		t.Fatalf("expected ambiguous show subtree matches, got %v", cands)
	}
}

func TestLookupDesc_ResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"show", "sec"}, "flow", false); got != "Show security flow information" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Show security flow information")
	}
}

func TestLookupDesc_ConfigModeResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"com"}, "confirmed", true); got != "Automatically rollback if not confirmed" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Automatically rollback if not confirmed")
	}
}

// #1319: typed-leaf `?` completion surfaces placeholder + ValueExamples
// through the real config-mode set tree.

func containsCand(cands []Candidate, name string) (Candidate, bool) {
	for _, c := range cands {
		if c.Name == name {
			return c, true
		}
	}
	return Candidate{}, false
}

func TestSchedulers_TypedLeaf_QuestionHelpShowsPlaceholderAndExamples(t *testing.T) {
	// After `sched transmit-rate`, `?` should show the rate placeholder
	// plus example values.
	cands := CompleteFromTreeWithDesc(
		ConfigTopLevel,
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
		"",
		nil,
	)
	if _, ok := containsCand(cands, "<rate>"); !ok {
		t.Fatalf("expected <rate> placeholder in `?` candidates, got %+v", cands)
	}
	if _, ok := containsCand(cands, "1g"); !ok {
		t.Fatalf("expected 1g example in `?` candidates, got %+v", cands)
	}
}

func TestSchedulers_TypedLeaf_AfterValueShowsModifiers(t *testing.T) {
	// After `sched transmit-rate 1g`, the value is consumed and `?`
	// should surface the `exact` modifier child.
	cands := CompleteFromTreeWithDesc(
		ConfigTopLevel,
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate", "1g"},
		"",
		nil,
	)
	if _, ok := containsCand(cands, "exact"); !ok {
		t.Fatalf("expected `exact` modifier after consumed rate, got %+v", cands)
	}
}

func TestSchedulers_TypedLeaf_PriorityEnumExamples(t *testing.T) {
	cands := CompleteFromTreeWithDesc(
		ConfigTopLevel,
		[]string{"set", "class-of-service", "schedulers", "be", "priority"},
		"",
		nil,
	)
	for _, want := range []string{"strict-high", "low", "high"} {
		if _, ok := containsCand(cands, want); !ok {
			t.Fatalf("expected enum example %q for priority, got %+v", want, cands)
		}
	}
}
