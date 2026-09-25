package cluster

import (
	"strings"
	"testing"
)

// TestMalformedSessionRecordWarningsAreBounded10724 drives both production
// receive arms. The old unconditional Warn emitted 20,000 lines for these
// frames; each family now emits one diagnostic while every dropped record is
// still counted.
func TestMalformedSessionRecordWarningsAreBounded10724(t *testing.T) {
	const framesPerFamily = 10_000
	logBuf := captureSlog(t)
	ss := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})

	for range framesPerFamily {
		ss.handleMessage(nil, syncMsgSessionV4, nil)
		ss.handleMessage(nil, syncMsgSessionV6, nil)
	}

	if got, want := ss.stats.MalformedRecordsDropped.Load(), uint64(2*framesPerFamily); got != want {
		t.Fatalf("MalformedRecordsDropped = %d, want %d", got, want)
	}
	logs := logBuf.String()
	if got := strings.Count(logs, "dropping malformed v4 session record"); got != 1 {
		t.Fatalf("%d malformed v4 frames emitted %d Warn lines, want exactly 1", framesPerFamily, got)
	}
	if got := strings.Count(logs, "dropping malformed v6 session record"); got != 1 {
		t.Fatalf("%d malformed v6 frames emitted %d Warn lines, want exactly 1", framesPerFamily, got)
	}
	if !strings.Contains(logs, "dropped_total=1") {
		t.Fatal("first sampled warning omitted the dropped-total diagnostic")
	}
}
