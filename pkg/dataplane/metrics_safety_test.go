package dataplane

import "testing"

func TestSafetyTelemetrySnapshots13302(t *testing.T) {
	m := New()
	if got := m.DetachDebt(); len(got) != 0 {
		t.Fatalf("initial detach debt = %v, want empty", got)
	}
	m.SetDetachDebtForTest(22)
	m.SetDetachDebtForTest(11)
	if got := m.DetachDebt(); len(got) != 2 || got[0] != 11 || got[1] != 22 {
		t.Fatalf("detach debt snapshot = %v, want sorted [11 22]", got)
	}
	if got := m.HostDivergence(); len(got) != 0 {
		t.Fatalf("initial host divergence = %v, want empty", got)
	}
	m.recordHostDivergence(&CompileResult{hostMutations: map[string]bool{"LinkSetMTU": true, "RouteReplace": true}})
	if got := m.HostDivergence(); len(got) != 2 || got[0] != "LinkSetMTU" || got[1] != "RouteReplace" {
		t.Fatalf("host divergence snapshot = %v, want sorted mutation classes", got)
	}
	report, seen := m.ArmCoverageSnapshot()
	if seen || report.Ran {
		t.Fatalf("unknown coverage snapshot ran=%v seen=%v, want both false", report.Ran, seen)
	}
	m.armCoverage.mu.Lock()
	m.armCoverage.report = ArmCoverageReport{
		Surfaces:  []SurfaceCoverage{{Kind: CoverageUncovered}},
		Uncovered: 1,
		Ran:       true,
	}
	m.armCoverage.seen = true
	m.armCoverage.mu.Unlock()
	report, seen = m.ArmCoverageSnapshot()
	if !seen || !report.Ran || report.Uncovered != 1 || len(report.Surfaces) != 1 {
		t.Fatalf("snapshot=%+v seen=%v, want one uncovered surface", report, seen)
	}
	report.Surfaces[0].Kind = CoverageDirect
	next, _ := m.ArmCoverageSnapshot()
	if next.Surfaces[0].Kind != CoverageUncovered {
		t.Fatalf("mutating snapshot changed published proof: %+v", next.Surfaces[0])
	}
}
