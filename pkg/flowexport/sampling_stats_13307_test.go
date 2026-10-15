package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShouldExportCounters_13307 pins #13307 (D6-07): ShouldExport's
// zone-filter and 1-in-N sampling decisions were entirely silent — no
// counter distinguished "nothing to export" from "100% zone-filtered"
// (e.g. the #11433 fail-closed empty SamplingZones map) or "sampled out".
// FAIL-ON-REVERT: without the SamplingStats counters this test fails.
func TestShouldExportCounters_13307(t *testing.T) {
	ec := &ExportConfig{
		SamplingZones: map[uint16]SamplingDir{2: {Input: true}},
		SamplingRate:  2,
	}
	if ec.ShouldExport(1, 1) {
		t.Fatal("zone-filtered session exported")
	}
	if ec.ShouldExport(2, 9) {
		t.Fatal("first eligible session must be sampled out at rate 2")
	}
	if !ec.ShouldExport(2, 9) {
		t.Fatal("second eligible session must be sampled in at rate 2")
	}
	evaluated, selected, zoneFiltered := ec.SamplingStats()
	if evaluated != 2 || selected != 1 || zoneFiltered != 1 {
		t.Fatalf("SamplingStats = (evaluated=%d selected=%d zoneFiltered=%d), want (2 1 1)",
			evaluated, selected, zoneFiltered)
	}
	if evaluated+zoneFiltered != 3 || selected > evaluated {
		t.Fatalf("sampling conservation failed: evaluated=%d selected=%d zoneFiltered=%d",
			evaluated, selected, zoneFiltered)
	}
	open := &ExportConfig{}
	for range 3 {
		if !open.ShouldExport(1, 2) {
			t.Fatal("unrestricted config must export")
		}
	}
	if ev, sel, zf := open.SamplingStats(); ev != 3 || sel != 3 || zf != 0 {
		t.Fatalf("open SamplingStats = (%d %d %d), want (3 3 0)", ev, sel, zf)
	}
	closed := &ExportConfig{SamplingZones: map[uint16]SamplingDir{}}
	if closed.ShouldExport(1, 1) {
		t.Fatal("empty non-nil SamplingZones must fail closed")
	}
	if _, _, zf := closed.SamplingStats(); zf != 1 {
		t.Fatalf("empty-map drop zoneFiltered = %d, want 1", zf)
	}
}

// TestExcludedFlowServersCounted_13307 pins config-level exclusion telemetry.
// FAIL-ON-REVERT: the second fixture yields no ExportConfig, but the excluded
// stanza must still be counted by the active-config statistic.
func TestExcludedFlowServersCounted_13307(t *testing.T) {
	mixed := twoInstanceV9()
	mixed.Sampling.Instances["alpha"].FamilyInet.FlowServers = append(
		mixed.Sampling.Instances["alpha"].FamilyInet.FlowServers,
		&config.FlowServer{Address: "10.0.0.3", Port: 0, Version: config.FlowServerVersion9},
	)
	if got := CountExcludedFlowServers(v9OnlySvc(), mixed, config.FlowServerVersion9); got != 1 {
		t.Fatalf("mixed config excluded flow servers = %d, want 1", got)
	}
	if groups := ResolveV9TemplateGroups(v9OnlySvc(), mixed); len(groups) != 2 {
		t.Fatalf("mixed config groups = %d, want 2", len(groups))
	}

	allExcluded := twoInstanceV9()
	allExcluded.Sampling.Instances["alpha"].FamilyInet.FlowServers[0].Port = 0
	allExcluded.Sampling.Instances["bravo"].FamilyInet6.FlowServers[0].Port = 0
	if groups := ResolveV9TemplateGroups(v9OnlySvc(), allExcluded); len(groups) != 0 {
		t.Fatalf("fully excluded config produced %d exporter groups, want none", len(groups))
	}
	if got := CountExcludedFlowServers(v9OnlySvc(), allExcluded, config.FlowServerVersion9); got != 2 {
		t.Fatalf("fully excluded config count = %d, want 2 with no surviving groups", got)
	}
}
