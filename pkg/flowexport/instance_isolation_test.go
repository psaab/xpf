package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2462 — sampling-instance identity is a first-class runtime object.
//
// Before #2462 the resolver merged EVERY sampling instance into one global
// export policy: collectVersionCollectors walked all instances into one
// collector slice, samplingRate() returned the first-nonzero InputRate in Go
// map order, and one sampleCounter was shared by the whole family. Flows from
// instance A exported to instance B's collectors and the effective rate
// depended on map iteration order. These tests assert each instance resolves
// to its OWN ExportConfig(s) — own collectors, own rate, own 1-in-N counter —
// and that instances are isolated and deterministically ordered.

// twoInstanceV9 builds two sampling instances with DIFFERENT rates and
// DIFFERENT collectors, disambiguated by address family (instance "alpha"
// serves inet, instance "bravo" serves inet6) so the combination is supported
// (family is the per-flow attribution selector).
func twoInstanceV9() *config.ForwardingOptionsConfig {
	return &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"alpha": {
					Name:      "alpha",
					InputRate: 2,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9},
						},
					},
				},
				"bravo": {
					Name:      "bravo",
					InputRate: 3,
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.2", Port: 2055, Version: config.FlowServerVersion9},
						},
					},
				},
			},
		},
	}
}

// v9OnlySvc is a v9-only global stanza with NO templates defined. The
// instance-isolation tests use flow-servers that reference no template, so the
// resolver places them in the default ("") group with the built-in timeout
// defaults — these tests assert per-instance collector/rate/counter isolation,
// not template resolution (that is covered by template_group_test.go).
func v9OnlySvc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{},
			},
		},
	}
}

// TestInstanceIsolation is the headline #2462 fail-on-revert test: two
// instances with different rates and different collectors resolve to TWO
// independent ExportConfigs, each carrying ONLY its own collector, its own
// rate, and its own (distinct) sampleCounter. Restore the merged-collector /
// first-nonzero-rate behavior and the collectors cross over and the rates
// collapse, failing the assertions below.
func TestInstanceIsolation(t *testing.T) {
	groups := ResolveV9TemplateGroups(v9OnlySvc(), twoInstanceV9())
	if len(groups) != 2 {
		t.Fatalf("two instances must yield two independent ExportConfigs, got %d", len(groups))
	}

	var alpha, bravo *ExportConfig
	for _, ec := range groups {
		switch ec.InstanceName {
		case "alpha":
			alpha = ec
		case "bravo":
			bravo = ec
		}
	}
	if alpha == nil || bravo == nil {
		t.Fatalf("both instances must resolve: alpha=%v bravo=%v", alpha, bravo)
	}

	// Each instance holds ONLY its own collector — no cross-contamination.
	if len(alpha.Collectors) != 1 || alpha.Collectors[0].Address != "10.0.0.1:2055" {
		t.Errorf("alpha collectors = %v, want only 10.0.0.1:2055", collectorAddrs(alpha))
	}
	if len(bravo.Collectors) != 1 || bravo.Collectors[0].Address != "10.0.0.2:2055" {
		t.Errorf("bravo collectors = %v, want only 10.0.0.2:2055", collectorAddrs(bravo))
	}

	// Each instance keeps its OWN rate (not the first-map-entry global rate).
	if alpha.SamplingRate != 2 {
		t.Errorf("alpha SamplingRate = %d, want 2 (its own InputRate)", alpha.SamplingRate)
	}
	if bravo.SamplingRate != 3 {
		t.Errorf("bravo SamplingRate = %d, want 3 (its own InputRate)", bravo.SamplingRate)
	}

	// Each instance has its OWN family scope.
	if !alpha.ServesInet || alpha.ServesInet6 {
		t.Errorf("alpha must serve inet only: inet=%v inet6=%v", alpha.ServesInet, alpha.ServesInet6)
	}
	if bravo.ServesInet || !bravo.ServesInet6 {
		t.Errorf("bravo must serve inet6 only: inet=%v inet6=%v", bravo.ServesInet, bravo.ServesInet6)
	}

	// The 1-in-N counters are INDEPENDENT (distinct pointers): advancing
	// alpha's counter must not move bravo's cadence.
	if alpha.counter() == bravo.counter() {
		t.Fatal("each instance must own a distinct sampleCounter; a shared counter " +
			"is the merged-policy defect this fix removes")
	}
}

// TestInstanceCounterIndependence proves 1-in-N is per-instance: with alpha at
// rate 2 and bravo at rate 3, alpha's modulo cadence is unaffected by bravo's
// sampling and vice versa. A shared counter (the old behavior) would interleave
// the two cadences and change which calls export.
func TestInstanceCounterIndependence(t *testing.T) {
	groups := ResolveV9TemplateGroups(v9OnlySvc(), twoInstanceV9())
	var alpha, bravo *ExportConfig
	for _, ec := range groups {
		switch ec.InstanceName {
		case "alpha":
			alpha = ec
		case "bravo":
			bravo = ec
		}
	}
	if alpha == nil || bravo == nil {
		t.Fatalf("both instances must resolve")
	}

	// Drive bravo several times; this must NOT perturb alpha's own counter.
	for i := 0; i < 5; i++ {
		bravo.ShouldExport(0, 0, true)
	}
	// alpha rate 2: first call -> counter 1 -> 1%2 != 0 -> drop; second -> 2%2 == 0 -> export.
	if alpha.ShouldExport(0, 0, false) {
		t.Fatal("alpha first call must drop (1%2 != 0); bravo's sampling must not advance alpha's counter")
	}
	if !alpha.ShouldExport(0, 0, false) {
		t.Fatal("alpha second call must export (2%2 == 0)")
	}
}

// TestInstanceTemplateGroupsShareInstanceCounter proves the per-INSTANCE
// counter is still shared across that instance's template groups (the #2461
// invariant, now scoped to one instance): two collectors in one instance
// referencing two templates share one counter, but a second instance gets its
// own.
func TestInstanceTemplateGroupsShareInstanceCounter(t *testing.T) {
	svc := twoTemplateV9Svc()
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"alpha": {
					Name:      "alpha",
					InputRate: 2,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "fast"},
							{Address: "10.0.0.2", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "slow"},
						},
					},
				},
				"bravo": {
					Name:      "bravo",
					InputRate: 2,
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.3", Port: 2055, Version: config.FlowServerVersion9},
						},
					},
				},
			},
		},
	}
	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) != 3 {
		t.Fatalf("alpha (2 templates) + bravo (1) must yield 3 groups, got %d", len(groups))
	}

	// Collect alpha's two template groups and bravo's group.
	var alphaGroups []*ExportConfig
	var bravoGroup *ExportConfig
	for _, ec := range groups {
		if ec.InstanceName == "alpha" {
			alphaGroups = append(alphaGroups, ec)
		} else if ec.InstanceName == "bravo" {
			bravoGroup = ec
		}
	}
	if len(alphaGroups) != 2 || bravoGroup == nil {
		t.Fatalf("want 2 alpha groups + 1 bravo group, got alpha=%d bravo=%v", len(alphaGroups), bravoGroup)
	}
	// alpha's two template groups share ONE counter.
	if alphaGroups[0].counter() != alphaGroups[1].counter() {
		t.Error("alpha's template groups must share the instance counter (#2461 within instance)")
	}
	// bravo's counter is distinct from alpha's.
	if bravoGroup.counter() == alphaGroups[0].counter() {
		t.Error("bravo must own a counter distinct from alpha (#2462)")
	}
}

// TestInstanceResolutionDeterministic proves resolving the same multi-instance
// config repeatedly yields identical instance ordering and per-instance
// collector ordering. Restore Go-map iteration order over instances and this
// flakes (the determinism half of #2462).
func TestInstanceResolutionDeterministic(t *testing.T) {
	fo := twoInstanceV9()
	var prev []string
	for i := 0; i < 50; i++ {
		groups := ResolveV9TemplateGroups(v9OnlySvc(), fo)
		var order []string
		for _, ec := range groups {
			order = append(order, ec.InstanceName)
			for _, c := range ec.Collectors {
				order = append(order, c.Address)
			}
		}
		if prev == nil {
			prev = order
			continue
		}
		if len(order) != len(prev) {
			t.Fatalf("resolve %d shape changed: %v vs %v", i, order, prev)
		}
		for j := range order {
			if order[j] != prev[j] {
				t.Fatalf("resolve %d nondeterministic at %d: %v vs %v", i, j, order, prev)
			}
		}
	}
	// Expected stable order: alpha before bravo (lexical instance order).
	want := []string{"alpha", "10.0.0.1:2055", "bravo", "10.0.0.2:2055"}
	if len(prev) != len(want) {
		t.Fatalf("order = %v, want %v", prev, want)
	}
	for i := range want {
		if prev[i] != want[i] {
			t.Fatalf("deterministic order = %v, want %v", prev, want)
		}
	}
}

// TestSingleInstanceNoRegression is the anti-over-gate guard: a single
// instance must resolve exactly as before (one group, its collectors, its
// rate), the common case the issue stresses must be unaffected.
func TestSingleInstanceNoRegression(t *testing.T) {
	fo := samplingFO(
		&config.FlowServer{Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9},
		&config.FlowServer{Address: "10.0.0.2", Port: 2055, Version: config.FlowServerVersion9},
	)
	groups := ResolveV9TemplateGroups(v9OnlySvc(), fo)
	if len(groups) != 1 {
		t.Fatalf("single instance must yield ONE group, got %d", len(groups))
	}
	g := groups[0]
	if g.InstanceName != "s" {
		t.Errorf("InstanceName = %q, want s", g.InstanceName)
	}
	if g.SamplingRate != 100 {
		t.Errorf("SamplingRate = %d, want 100 (samplingFO InputRate)", g.SamplingRate)
	}
	if len(g.Collectors) != 2 {
		t.Errorf("single instance group must hold both collectors, got %d", len(g.Collectors))
	}
	// samplingFO configures FamilyInet only.
	if !g.ServesInet || g.ServesInet6 {
		t.Errorf("samplingFO is inet-only: inet=%v inet6=%v", g.ServesInet, g.ServesInet6)
	}
	if !g.ServesFamily(false) || g.ServesFamily(true) {
		t.Error("inet-only instance must serve v4 but not v6 flows")
	}
}

// TestServesFamilyAttribution proves the per-family attribution: an inet-only
// instance does not claim IPv6 flows, an inet6-only instance does not claim
// IPv4 flows. This is the control-plane mechanism that keeps two
// family-disjoint instances isolated.
func TestServesFamilyAttribution(t *testing.T) {
	groups := ResolveV9TemplateGroups(v9OnlySvc(), twoInstanceV9())
	for _, ec := range groups {
		switch ec.InstanceName {
		case "alpha": // inet only
			if !ec.ServesFamily(false) || ec.ServesFamily(true) {
				t.Errorf("alpha (inet) must serve v4 only: v4=%v v6=%v", ec.ServesFamily(false), ec.ServesFamily(true))
			}
		case "bravo": // inet6 only
			if ec.ServesFamily(false) || !ec.ServesFamily(true) {
				t.Errorf("bravo (inet6) must serve v6 only: v4=%v v6=%v", ec.ServesFamily(false), ec.ServesFamily(true))
			}
		}
	}
}
