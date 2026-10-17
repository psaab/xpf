package flowexport

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #2461 — per-flow-server template binding.
//
// Before #2461 BuildExportConfig / BuildIPFIXExportConfig built ONE export
// config from the FIRST Go-map-iteration template and broadcast it to every
// collector, silently ignoring the per-flow-server `version9 { template ... }`
// / `version-ipfix { template ... }` reference. These tests assert the
// resolver now emits one ExportConfig per referenced template, so each
// collector's exporter carries the template (timeouts / export-extensions) it
// actually requested, in a deterministic order.

// twoTemplateV9Svc defines two distinct NetFlow v9 templates with
// observably different parameters (timeouts + the flow-dir extension).
func twoTemplateV9Svc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"fast": {
						Name:                "fast",
						FlowActiveTimeout:   30,
						FlowInactiveTimeout: 10,
						TemplateRefreshRate: 20,
						ExportExtensions:    []string{"flow-dir"},
					},
					"slow": {
						Name:                "slow",
						FlowActiveTimeout:   300,
						FlowInactiveTimeout: 90,
						TemplateRefreshRate: 120,
						// no flow-dir
					},
				},
			},
		},
	}
}

// twoTemplateIPFIXSvc is the IPFIX equivalent.
func twoTemplateIPFIXSvc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{
					"fast": {Name: "fast", FlowActiveTimeout: 30, TemplateRefreshRate: 20},
					"slow": {Name: "slow", FlowActiveTimeout: 300, TemplateRefreshRate: 120},
				},
			},
		},
	}
}

// twoCollectorV9 returns sampling with two collectors referencing two
// distinct v9 templates.
func twoCollectorV9() *config.ForwardingOptionsConfig {
	return samplingFO(
		&config.FlowServer{Address: "10.0.0.1", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "fast"},
		&config.FlowServer{Address: "10.0.0.2", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "slow"},
	)
}

// findGroupForCollector returns the ExportConfig group whose collector list
// contains the given address, or nil.
func findGroupForCollector(groups []*ExportConfig, addr string) *ExportConfig {
	for _, ec := range groups {
		for _, c := range ec.Collectors {
			if c.Address == addr {
				return ec
			}
		}
	}
	return nil
}

// TestV9PerServerTemplateBinding is the headline #2461 fail-on-revert test:
// two collectors referencing two different templates each get an export
// config carrying the template they referenced. Restore the old `break //
// use first template` and a single config (the first map entry) is broadcast
// to BOTH collectors — this test fails because the two groups would collapse
// or carry identical (first-map-entry) parameters.
func TestV9PerServerTemplateBinding(t *testing.T) {
	groups := ResolveV9TemplateGroups(twoTemplateV9Svc(), twoCollectorV9())
	if len(groups) != 2 {
		t.Fatalf("expected 2 template groups, got %d", len(groups))
	}

	fast := findGroupForCollector(groups, "10.0.0.1:2055")
	slow := findGroupForCollector(groups, "10.0.0.2:2055")
	if fast == nil || slow == nil {
		t.Fatalf("both collectors must be present: fast=%v slow=%v", fast, slow)
	}

	// The 10.0.0.1 collector requested "fast": 30/10/20s, flow-dir ON.
	if fast.TemplateName != "fast" {
		t.Errorf("collector 10.0.0.1 group TemplateName = %q, want fast", fast.TemplateName)
	}
	if fast.FlowActiveTimeout != 30*time.Second {
		t.Errorf("fast FlowActiveTimeout = %v, want 30s", fast.FlowActiveTimeout)
	}
	if fast.FlowInactiveTimeout != 10*time.Second {
		t.Errorf("fast FlowInactiveTimeout = %v, want 10s", fast.FlowInactiveTimeout)
	}
	if fast.TemplateRefreshRate != 20*time.Second {
		t.Errorf("fast TemplateRefreshRate = %v, want 20s", fast.TemplateRefreshRate)
	}
	if !fast.V9TemplateOpts.IncludeFlowDir {
		t.Error("fast template requested flow-dir; IncludeFlowDir must be true")
	}

	// The 10.0.0.2 collector requested "slow": 300/90/120s, flow-dir OFF.
	if slow.TemplateName != "slow" {
		t.Errorf("collector 10.0.0.2 group TemplateName = %q, want slow", slow.TemplateName)
	}
	if slow.FlowActiveTimeout != 300*time.Second {
		t.Errorf("slow FlowActiveTimeout = %v, want 300s", slow.FlowActiveTimeout)
	}
	if slow.FlowInactiveTimeout != 90*time.Second {
		t.Errorf("slow FlowInactiveTimeout = %v, want 90s", slow.FlowInactiveTimeout)
	}
	if slow.TemplateRefreshRate != 120*time.Second {
		t.Errorf("slow TemplateRefreshRate = %v, want 120s", slow.TemplateRefreshRate)
	}
	if slow.V9TemplateOpts.IncludeFlowDir {
		t.Error("slow template did NOT request flow-dir; IncludeFlowDir must be false")
	}

	// Each group has exactly its one collector (no cross-contamination).
	if len(fast.Collectors) != 1 || len(slow.Collectors) != 1 {
		t.Fatalf("each group must hold exactly its referenced collector: fast=%d slow=%d",
			len(fast.Collectors), len(slow.Collectors))
	}
}

// TestIPFIXPerServerTemplateBinding mirrors the v9 test for IPFIX.
func TestIPFIXPerServerTemplateBinding(t *testing.T) {
	fo := samplingFO(
		&config.FlowServer{Address: "10.0.0.1", Port: 4739, Version: config.FlowServerVersionIPFIX, VersionIPFIXTemplate: "fast"},
		&config.FlowServer{Address: "10.0.0.2", Port: 4739, Version: config.FlowServerVersionIPFIX, VersionIPFIXTemplate: "slow"},
	)
	groups := ResolveIPFIXTemplateGroups(twoTemplateIPFIXSvc(), fo)
	if len(groups) != 2 {
		t.Fatalf("expected 2 template groups, got %d", len(groups))
	}

	fast := findGroupForCollector(groups, "10.0.0.1:4739")
	slow := findGroupForCollector(groups, "10.0.0.2:4739")
	if fast == nil || slow == nil {
		t.Fatalf("both collectors must be present: fast=%v slow=%v", fast, slow)
	}
	if fast.TemplateName != "fast" || fast.FlowActiveTimeout != 30*time.Second || fast.TemplateRefreshRate != 20*time.Second {
		t.Errorf("fast group mis-resolved: name=%q active=%v refresh=%v",
			fast.TemplateName, fast.FlowActiveTimeout, fast.TemplateRefreshRate)
	}
	if slow.TemplateName != "slow" || slow.FlowActiveTimeout != 300*time.Second || slow.TemplateRefreshRate != 120*time.Second {
		t.Errorf("slow group mis-resolved: name=%q active=%v refresh=%v",
			slow.TemplateName, slow.FlowActiveTimeout, slow.TemplateRefreshRate)
	}
}

// TestSingleTemplateNoReferenceUnchanged is the no-regression guard: a
// single configured template with collectors that reference none must yield
// exactly one default group carrying that template's parameters — the common
// pre-#2461 single-template case. (Anti-over-gate concern from the issue.)
func TestSingleTemplateNoReferenceUnchanged(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"only": {Name: "only", FlowActiveTimeout: 45, ExportExtensions: []string{"flow-dir"}},
				},
			},
		},
	}
	fo := samplingFO(
		&config.FlowServer{Address: "10.0.0.1", Port: 2055},
		&config.FlowServer{Address: "10.0.0.2", Port: 2055},
	)
	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) != 1 {
		t.Fatalf("a single template with no per-server reference must yield ONE group, got %d", len(groups))
	}
	g := groups[0]
	if g.TemplateName != "" {
		t.Errorf("default group TemplateName = %q, want empty", g.TemplateName)
	}
	if len(g.Collectors) != 2 {
		t.Errorf("default group must hold both unreferenced collectors, got %d", len(g.Collectors))
	}
	// Unreferenced collectors inherit the lone template's parameters.
	if g.FlowActiveTimeout != 45*time.Second {
		t.Errorf("default group FlowActiveTimeout = %v, want 45s (the lone template)", g.FlowActiveTimeout)
	}
	if !g.V9TemplateOpts.IncludeFlowDir {
		t.Error("default group must inherit the lone template's flow-dir extension")
	}
	// BuildExportConfig (singular) returns this same group — backward compat.
	if ec := BuildExportConfig(svc, fo); ec == nil || len(ec.Collectors) != 2 {
		t.Errorf("BuildExportConfig must still return the aggregate single-group config")
	}
}

// TestTemplateGroupsAreDeterministic proves the grouping is stable across
// repeated resolves — group order (by template name) and per-group collector
// order (by address) are identical every time, killing the map-iteration
// nondeterminism (#2461). Restore Go-map iteration order and this flakes.
func TestTemplateGroupsAreDeterministic(t *testing.T) {
	// Three collectors across two templates, addresses intentionally out of
	// sorted order so a stable sort is observable.
	svc := twoTemplateV9Svc()
	fo := samplingFO(
		&config.FlowServer{Address: "10.0.0.9", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "slow"},
		&config.FlowServer{Address: "10.0.0.3", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "fast"},
		&config.FlowServer{Address: "10.0.0.7", Port: 2055, Version: config.FlowServerVersion9, Version9Template: "fast"},
	)

	var prev []string
	for i := 0; i < 20; i++ {
		groups := ResolveV9TemplateGroups(svc, fo)
		var order []string
		for _, ec := range groups {
			order = append(order, ec.TemplateName)
			for _, c := range ec.Collectors {
				order = append(order, c.Address)
			}
		}
		if prev == nil {
			prev = order
			continue
		}
		if len(order) != len(prev) {
			t.Fatalf("resolve %d produced a different shape: %v vs %v", i, order, prev)
		}
		for j := range order {
			if order[j] != prev[j] {
				t.Fatalf("resolve %d nondeterministic at %d: %v vs %v", i, j, order, prev)
			}
		}
	}
	// Expected stable order: group "fast" (10.0.0.3, 10.0.0.7) then "slow"
	// (10.0.0.9) — template name asc, address asc.
	want := []string{"fast", "10.0.0.3:2055", "10.0.0.7:2055", "slow", "10.0.0.9:2055"}
	if len(prev) != len(want) {
		t.Fatalf("order shape = %v, want %v", prev, want)
	}
	for i := range want {
		if prev[i] != want[i] {
			t.Fatalf("deterministic order = %v, want %v", prev, want)
		}
	}
}

// TestSharedSamplingCounterAcrossGroups proves all groups of a family share
// one 1-in-N counter: with rate 2 and one record offered per group, the
// shared counter advances across groups rather than each group counting from
// zero (which would corrupt the global cadence). The resolver wires the same
// *atomic.Uint64 into every group.
func TestSharedSamplingCounterAcrossGroups(t *testing.T) {
	groups := ResolveV9TemplateGroups(twoTemplateV9Svc(), twoCollectorV9())
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d", len(groups))
	}
	// Rate 2 was set by samplingFO (InputRate 100); override to 2 for clarity.
	for _, g := range groups {
		g.SamplingRate = 2
	}
	// First call on group 0: counter 1 -> 1%2 != 0 -> false.
	if groups[0].ShouldExport(0, 0, false) {
		t.Fatal("first sampled call must be dropped (1%2 != 0)")
	}
	// Next call on group 1 must see the SHARED counter at 2 -> true,
	// not a fresh per-group counter at 1 (which would drop).
	if !groups[1].ShouldExport(0, 0, false) {
		t.Fatal("second call on the OTHER group must see the shared counter (2%2 == 0); " +
			"a per-group counter would wrongly drop it")
	}
}
