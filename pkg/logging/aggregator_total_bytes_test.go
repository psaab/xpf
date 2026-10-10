package logging

import (
	"testing"
	"time"
)

// TestSessionAggregator_TotalBytes_AsymmetricClose (#12150): the aggregate
// ranks and reports TOTAL (forward+reverse) bytes. A 100-byte forward / 900-byte
// reverse close must count as 1000, not 100, and rank above a smaller
// bidirectional flow.
func TestSessionAggregator_TotalBytes_AsymmetricClose(t *testing.T) {
	agg := NewSessionAggregator(time.Hour, 10)
	var logged []string
	agg.SetLogFunc(func(_ int, msg string) {
		logged = append(logged, msg)
	})

	// Server-heavy flow: 100 fwd + 900 rev = 1000 total.
	agg.Add(EventRecord{
		Type:            "SESSION_CLOSE",
		SrcAddr:         "10.0.1.5:1234",
		DstAddr:         "10.0.2.1:80",
		SessionBytes:    100,
		RevSessionBytes: 900,
	})
	// Smaller bidirectional flow: 200 fwd + 200 rev = 400 total.
	agg.Add(EventRecord{
		Type:            "SESSION_CLOSE",
		SrcAddr:         "10.0.1.6:1234",
		DstAddr:         "10.0.2.2:80",
		SessionBytes:    200,
		RevSessionBytes: 200,
	})

	agg.flushAndLog()
	want := []string{
		`RT_FLOW_SESSION_AGGREGATE top-source="10.0.1.5" sessions=1 bytes=1000`,
		`RT_FLOW_SESSION_AGGREGATE top-source="10.0.1.6" sessions=1 bytes=400`,
		`RT_FLOW_SESSION_AGGREGATE top-destination="10.0.2.1" sessions=1 bytes=1000`,
		`RT_FLOW_SESSION_AGGREGATE top-destination="10.0.2.2" sessions=1 bytes=400`,
	}
	if len(logged) != len(want) {
		t.Fatalf("expected %d aggregate log lines, got %d: %q", len(want), len(logged), logged)
	}
	for i := range want {
		if logged[i] != want[i] {
			t.Errorf("aggregate log line %d = %q, want %q", i, logged[i], want[i])
		}
	}
}

// TestSessionAggregator_TotalBytesSaturates ensures directional sums and
// per-key accumulations saturate instead of wrapping to small reportable values.
func TestSessionAggregator_TotalBytesSaturates(t *testing.T) {
	const maxUint64 = ^uint64(0)
	agg := NewSessionAggregator(time.Hour, 10)
	rec := EventRecord{
		Type:            "SESSION_CLOSE",
		SrcAddr:         "10.0.1.5:1234",
		DstAddr:         "10.0.2.1:80",
		SessionBytes:    maxUint64,
		RevSessionBytes: 1,
	}
	agg.Add(rec)
	agg.Add(rec)

	topSrc, _ := agg.Flush()
	if len(topSrc) != 1 {
		t.Fatalf("expected one source entry, got %d", len(topSrc))
	}
	if topSrc[0].Sessions != 2 {
		t.Errorf("expected 2 sessions, got %d", topSrc[0].Sessions)
	}
	if topSrc[0].Bytes != maxUint64 {
		t.Errorf("expected saturated total %d, got %d", maxUint64, topSrc[0].Bytes)
	}
}
