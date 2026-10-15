package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #13305 (D6-04): a clock-skewed Created stamp (after close time) is clamped
// to EndTime; that clamp must be counted, not silently folded into a
// zero-duration flow. Both exporters must expose it.
func TestFlowExportClockSkewClampedCounted13305(t *testing.T) {
	end := time.Unix(1_700_000_000, 0)
	rec := logging.EventRecord{Time: end, Type: "SESSION_CLOSE", Created: 1_700_000_500, Protocol: "TCP"}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}

	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.ExportSessionClose(rec, evt)
	if got := e.ClockSkewClamped(); got != 1 {
		t.Fatalf("NetFlow ClockSkewClamped = %d, want 1", got)
	}
	if got := e.EstimatedDurations(); got != 0 {
		t.Fatalf("NetFlow EstimatedDurations = %d, want 0 (skew is not missing)", got)
	}

	ie, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	ie.ExportSessionClose(rec, evt)
	if got := ie.ClockSkewClamped(); got != 1 {
		t.Fatalf("IPFIX ClockSkewClamped = %d, want 1", got)
	}
	if got := ie.EstimatedDurations(); got != 0 {
		t.Fatalf("IPFIX EstimatedDurations = %d, want 0 (skew is not missing)", got)
	}
}

// #13305: flowStartTime must distinguish skew-clamped from measured/missing.
func TestFlowStartTimeReportsClockSkew13305(t *testing.T) {
	end := time.Unix(1_700_000_000, 0)
	_, missing, clamped := flowStartTime(logging.EventRecord{Time: end, Created: 1_700_000_500})
	if missing || !clamped {
		t.Fatalf("skewed: missing=%v clamped=%v, want false/true", missing, clamped)
	}
	_, missing, clamped = flowStartTime(logging.EventRecord{Time: end, Created: 0})
	if !missing || clamped {
		t.Fatalf("missing: missing=%v clamped=%v, want true/false", missing, clamped)
	}
	_, missing, clamped = flowStartTime(logging.EventRecord{Time: end, Created: 1_699_999_000})
	if missing || clamped {
		t.Fatalf("measured: missing=%v clamped=%v, want false/false", missing, clamped)
	}
}
