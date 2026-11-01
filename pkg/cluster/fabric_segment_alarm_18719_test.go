package cluster

import (
	"strings"
	"testing"
)

// #18719: the fabric-segment watcher's alarm reaches `show chassis cluster
// status`, above every redundancy-group block, and nothing renders when the
// watcher reports nothing or is not wired.
func TestFormatStatusRendersFabricSegmentAlarms18719(t *testing.T) {
	m := NewManager(0, 1)
	if got := m.FormatStatus(); strings.Contains(got, "fabric link") {
		t.Fatalf("an unwired watcher must render nothing:\n%s", got)
	}
	m.SetFabricSegmentAlarmsFn(func() []string { return nil })
	if got := m.FormatStatus(); strings.Contains(got, "Warning: fabric link") {
		t.Fatalf("a quiet watcher must render nothing:\n%s", got)
	}
	line := "fabric link fab0 (ge-0-0-0) received 3 frame(s) from source MAC(s) that are neither peer's fabric MAC (18:e8:29:2c:13:7a), last 2s ago: ..."
	m.SetFabricSegmentAlarmsFn(func() []string { return []string{line} })
	got := m.FormatStatus()
	idx := strings.Index(got, "Warning: "+line)
	if idx < 0 {
		t.Fatalf("the raised alarm is not rendered:\n%s", got)
	}
	if rg := strings.Index(got, "Redundancy group:"); rg >= 0 && rg < idx {
		t.Fatalf("the alarm must sit above every redundancy-group block (#4009 awk contract):\n%s", got)
	}
	if hdr := strings.Index(got, "Monitor-failures"); hdr >= 0 && hdr < idx {
		t.Fatalf("the alarm must sit above the node table header:\n%s", got)
	}
}
