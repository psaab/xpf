package flowexport

import "testing"

func TestRejectedFlowStateBound17815(t *testing.T) {
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer e.Close()

	keyAt := func(i int) FlowKey {
		return FlowKey{
			SrcIP: "192.0.2.1", DstIP: "198.51.100.2",
			SrcPort: uint16(i + 1), DstPort: 443, Protocol: 6,
		}
	}
	first := keyAt(0)
	for i := range rejectedFlowsMax {
		e.MarkFlowRejectedAtOpen(keyAt(i))
	}
	if got := len(e.RejectedKeys()); got != rejectedFlowsMax {
		t.Fatalf("rejected keys at cap = %d, want %d", got, rejectedFlowsMax)
	}
	if !e.HasFlowState(first) {
		t.Fatal("first rejected key must have state before cap eviction")
	}

	// Re-seeing a decided key must not clear the retained set at capacity.
	e.MarkFlowRejectedAtOpen(first)
	if got := len(e.RejectedKeys()); got != rejectedFlowsMax || !e.HasFlowState(first) {
		t.Fatalf("duplicate at cap changed state: size=%d first=%t, want %d/true", got, e.HasFlowState(first), rejectedFlowsMax)
	}

	newKey := keyAt(rejectedFlowsMax)
	e.MarkFlowRejectedAtOpen(newKey)
	if got := len(e.RejectedKeys()); got != 1 {
		t.Fatalf("rejected keys after cap+1 = %d, want 1 after clear-at-cap", got)
	}
	if e.HasFlowState(first) {
		t.Fatal("old rejected key must be evicted when the hard cap is reached")
	}
	if !e.HasFlowState(newKey) {
		t.Fatal("the key triggering clear-at-cap must remain remembered")
	}
}
