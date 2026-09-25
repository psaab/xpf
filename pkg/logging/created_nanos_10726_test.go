package logging

import (
	"encoding/binary"
	"testing"
)

// TestCreatedNanosRangeCheckedInBothDecodePaths10726 pins the SESSION_CLOSE
// wire range and clamp at both producer-facing decode boundaries. A malformed
// remainder must not become a second carry when a consumer calls time.Unix.
func TestCreatedNanosRangeCheckedInBothDecodePaths10726(t *testing.T) {
	frame := rawTimedFrame(eventTypeSessionClose, 1_700_000_000_000_000_000)
	binary.LittleEndian.PutUint32(frame[44:48], 1_000_000_000)
	before := InvalidCreatedNanos()

	decoded, ok := DecodeRawEventRecord(frame)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected valid-sized SESSION_CLOSE frame")
	}
	if decoded.CreatedNanos != maxCreatedNanos {
		t.Fatalf("decoded CreatedNanos = %d, want clamped %d", decoded.CreatedNanos, maxCreatedNanos)
	}

	reader := NewEventReader(nil, NewEventBuffer(4))
	var live EventRecord
	var fired bool
	reader.AddCallback(func(rec EventRecord, _ []byte) {
		live = rec
		fired = true
	})
	if !reader.ProcessRawEvent(frame) {
		t.Fatal("ProcessRawEvent rejected valid-sized SESSION_CLOSE frame")
	}
	if !fired {
		t.Fatal("live event callback did not receive SESSION_CLOSE")
	}
	if live.CreatedNanos != maxCreatedNanos {
		t.Fatalf("live CreatedNanos = %d, want clamped %d", live.CreatedNanos, maxCreatedNanos)
	}
	if got := InvalidCreatedNanos(); got < before+2 {
		t.Fatalf("invalid CreatedNanos counter = %d, want at least %d after both decode paths", got, before+2)
	}
}

func TestCreatedNanosAcceptsLastValidNanosecond10726(t *testing.T) {
	before := InvalidCreatedNanos()
	if got := ClampCreatedNanos(maxCreatedNanos); got != maxCreatedNanos {
		t.Fatalf("last valid CreatedNanos = %d, want %d", got, maxCreatedNanos)
	}
	if got := InvalidCreatedNanos(); got != before {
		t.Fatalf("valid CreatedNanos incremented invalid counter: before=%d after=%d", before, got)
	}
}
