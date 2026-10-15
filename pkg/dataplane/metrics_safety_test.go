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
	if _, ran, seen := m.SurfaceCoverage(); seen || ran {
		t.Fatalf("unknown coverage snapshot ran=%v seen=%v, want both false", ran, seen)
	}
	m.ProveArmCoverage(&CompileResult{})
	if surfaces, ran, seen := m.SurfaceCoverage(); !seen || !ran || len(surfaces) != 0 {
		t.Fatalf("completed empty proof surfaces=%v ran=%v seen=%v", surfaces, ran, seen)
	}
}
