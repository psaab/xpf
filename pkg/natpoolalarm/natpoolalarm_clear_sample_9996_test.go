package natpoolalarm

import (
	"strings"
	"testing"
)

// #9996: threshold-driven CLEARED lines must carry the fresh sub-threshold
// clearing sample, not the stale held pct from raise/hold time. Without the
// fix, clear() emits st.pct (the last held value), so a line that clears at
// 65% reports 95% — a CLEARED line at/above the clear threshold,
// self-contradicting.
func TestThresholdClearCarriesClearingSample9996(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false) // capacity 100; 1 used == 1%

	// Raise at 85%: the raise line carries the raising sample.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 85)))
	m.evaluate()
	lines := rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0].msg, raisedTag) {
		t.Fatalf("expected 1 raise line, got %+v", lines)
	}
	if !strings.Contains(lines[0].msg, "utilization=85%") {
		t.Fatalf("raise line must carry the raising sample, got %q", lines[0].msg)
	}

	// Hold at 95%: silent refresh of the held pct, no syslog.
	rec.reset()
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 95)))
	m.evaluate()
	if len(rec.snapshot()) != 0 {
		t.Fatalf("hold tick must emit nothing, got %+v", rec.snapshot())
	}
	if a := m.ActiveAlarms(); len(a) != 1 || a[0].CurrentPct != 95 {
		t.Fatalf("hold must refresh the registry pct to 95, got %+v", a)
	}

	// Clear at 65%: the CLEARED line must carry the fresh clearing sample.
	rec.reset()
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 65)))
	m.evaluate()
	lines = rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0].msg, clearedTag) {
		t.Fatalf("expected 1 clear line, got %+v", lines)
	}
	if !strings.Contains(lines[0].msg, "utilization=65%") {
		t.Fatalf("CLEARED line must carry the clearing sample (65%%), got %q", lines[0].msg)
	}
	if strings.Contains(lines[0].msg, "utilization=95%") {
		t.Fatalf("CLEARED line must not report the stale held pct, got %q", lines[0].msg)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("alarm should be cleared")
	}
}

// #9996: config-driven (unsampled) clears have no fresh sample to report, so
// they keep emitting the held pct — and must NOT fabricate a sample. Pin the
// clearAll path: raise at 85, then nil config clears with utilization=85%.
func TestUnsampledClearKeepsHeldPct9996(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 85)))
	m.evaluate() // raise
	rec.reset()

	// Nil config → clearAll → unsampled clear of the active alarm.
	vb.set(View{Config: nil, Pools: map[string]PoolStatus{}, HelperCoherent: true, Available: true})
	m.evaluate()
	lines := rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0].msg, clearedTag) {
		t.Fatalf("expected 1 unsampled clear line, got %+v", lines)
	}
	if !strings.Contains(lines[0].msg, "utilization=85%") {
		t.Fatalf("unsampled clear must keep the held pct (85%%), got %q", lines[0].msg)
	}
	if !strings.Contains(lines[0].msg, `reason="alarm config unavailable"`) {
		t.Fatalf("unsampled clear must keep its reason, got %q", lines[0].msg)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("alarm should be cleared")
	}
}
