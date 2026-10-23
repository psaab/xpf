package logging

import (
	"encoding/binary"
	"testing"
)

// #16303: a production-shaped SESSION_CREATE frame stamps its resolved
// egress ifindex at [148:152]; both decoders must surface it so the
// daemon can select output-only sampled flows at open.
func TestSessionOpenEgressIfindexDecodes16303(t *testing.T) {
	data := make([]byte, rawEventSessionPolicyGenerationSize)
	copy(data, rawSessionFrame(eventTypeSessionOpen, 1))
	binary.LittleEndian.PutUint32(data[rawEventEgressOffset:rawEventEgressOffset+4], 37)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected SESSION_OPEN frame")
	}
	if rec.EgressIfindex != 37 {
		t.Fatalf("DecodeRawEventRecord EgressIfindex = %d, want 37", rec.EgressIfindex)
	}

	reader := NewEventReader(nil, NewEventBuffer(4))
	reader.SetIfNames(map[uint32]string{37: "ge-0/0/2.0"})
	var live EventRecord
	reader.AddCallback(func(r EventRecord, _ []byte) { live = r })
	if !reader.ProcessRawEvent(data) {
		t.Fatal("ProcessRawEvent rejected SESSION_OPEN frame")
	}
	if live.EgressIfindex != 37 || live.EgressIface != "ge-0/0/2.0" {
		t.Fatalf("live open egress = (%d,%q), want (37,ge-0/0/2.0)", live.EgressIfindex, live.EgressIface)
	}
}
