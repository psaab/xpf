package flowexport

import (
	"testing"
	"time"
)

// #15655 V17-02: a long-lived flow must emit an interim (active) export
// record when its age since last export reaches FlowActiveTimeout, and an
// idle flow's final record must be emitted when inactivity reaches
// FlowInactiveTimeout — via the actual exporter behaviour, not config parsing.
// This test drives the exporter tracking API that the daemon session-open /
// periodic paths use.

func TestActiveTimeoutEmitsInterim15655(t *testing.T) {
	cfg := &ExportConfig{
		FlowActiveTimeout:   60 * time.Second,
		FlowInactiveTimeout: 15 * time.Second,
	}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	if e.tracker == nil {
		t.Fatal("tracker not wired from ExportConfig timeouts")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	e.TrackFlowOpen(key, start)
	e.TouchFlow(key, start.Add(30*time.Second), 100, 10000)
	// Still active at +61s with recent traffic: interim record due.
	e.TouchFlow(key, start.Add(61*time.Second), 200, 20000)
	due := e.CollectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 {
		t.Fatalf("active timeout: want 1 interim export, got %d (%v)", len(due), due)
	}
	if due[0].EndTime.Sub(due[0].StartTime) < 60*time.Second {
		t.Fatalf("interim record duration too short: %v", due[0])
	}
	if due[0].Packets != 200 {
		t.Fatalf("interim packets = %d, want delta 200", due[0].Packets)
	}
	// Not due again immediately after export (window reset).
	if due2 := e.CollectDueExports(start.Add(62 * time.Second)); len(due2) != 0 {
		t.Fatalf("interim exported twice without new window: %v", due2)
	}
	// Idle: no Touch after interim; at lastActivity(61s)+15s the inactive
	// timer fires a final record and forgets the flow.
	idle := e.CollectDueExports(start.Add(61*time.Second + 16*time.Second))
	if len(idle) != 1 {
		t.Fatalf("inactive timeout: want 1 final export, got %d (%v)", len(idle), idle)
	}
	if e.tracker.Len() != 0 {
		t.Fatalf("inactive flow still tracked: len=%d", e.tracker.Len())
	}
	// IPFIX exporter shares the same enforcement.
	ie, err := NewIPFIXExporter(cfg)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	ie.TrackFlowOpen(key, start)
	if due := ie.CollectDueExports(start.Add(61 * time.Second)); len(due) != 1 {
		t.Fatalf("ipfix active timeout: want 1 interim, got %v", due)
	}
}
