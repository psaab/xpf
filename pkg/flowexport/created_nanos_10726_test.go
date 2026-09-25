package flowexport

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// TestFlowStartTimeClampsUntrustedCreatedNanos10726 guards the exporter edge
// even when an EventRecord did not come through logging's wire decoder. Before
// the clamp, time.Unix normalized 1,000,000,000 nanos into the following second.
func TestFlowStartTimeClampsUntrustedCreatedNanos10726(t *testing.T) {
	const created = uint32(1_700_000_000)
	rec := logging.EventRecord{
		Time:         time.Unix(int64(created)+2, 0),
		Created:      created,
		CreatedNanos: 1_000_000_000,
	}
	before := logging.InvalidCreatedNanos()
	got, estimated := flowStartTime(rec, 6)
	if estimated {
		t.Fatal("real Created timestamp must not use the packet estimate")
	}
	want := time.Unix(int64(created), 999_999_999)
	if !got.Equal(want) {
		t.Fatalf("flow StartTime = %v, want clamped %v", got, want)
	}
	if after := logging.InvalidCreatedNanos(); after < before+1 {
		t.Fatalf("invalid CreatedNanos counter = %d, want at least %d", after, before+1)
	}
}
