package logging

import (
	"encoding/binary"
	"testing"
)

// #17065: logEvent and DecodeRawEventRecord must consume the single
// mapRawEvent mapper. This table runs every golden frame shape through
// both entry points and asserts equality on ALL wire-derived fields.
// Live-only enrichments are excluded by construction: names come from
// an empty reader (InZoneName/OutZoneName render the numeric fallback
// on the live path only, PolicyName likewise unless the mapper itself
// stamps the stamped-deny name, AppName/IngressIface/EgressIface are
// live resolutions), EventSeq/ElapsedTime are live post-steps, and the
// live SessionID ordinal fallback fires only when the mapper left 0.
// Wire-derived PolicyName (stamped POLICY_DENY) IS compared: both
// entry points must stamp it identically.

// frame17065 returns a golden frame of the given length/type. It reuses
// goldenFrame16127 (distinctive value in every fixed slot) and sets the
// event type byte; for POLICY_DENY it also stamps the GEN1 generation
// marker so the stamped-deny rules are exercised.
func frame17065(length int, family, eventType uint8, stampedDeny bool) []byte {
	data := goldenFrame16127(length, family)
	if len(data) > 55 {
		data[52] = eventType
	}
	if stampedDeny && len(data) >= rawEventWireSize {
		// GEN1 marker at [140:144]; generation rides [56:64] (already
		// 111 in the golden frame). policyDenyConfigGeneration requires
		// the marker plus POLICY_DENY type.
		binary.LittleEndian.PutUint32(data[policyConfigGenerationMarkerOffset:policyConfigGenerationMarkerOffset+4], policyConfigGenerationMarker)
	}
	return data
}

func TestMapRawEventParity17065(t *testing.T) {
	cases := []struct {
		name        string
		length      int
		family      uint8
		eventType   uint8
		stampedDeny bool
	}{
		{"open-144-v4", rawEventWireSize, addrFamilyInet, eventTypeSessionOpen, false},
		{"open-152-v4", rawEventExtSize, addrFamilyInet, eventTypeSessionOpen, false},
		{"open-160-v4", rawEventSessionIDSize, addrFamilyInet, eventTypeSessionOpen, false},
		{"open-168-v4-stamped", rawEventSessionPolicyGenerationSize, addrFamilyInet, eventTypeSessionOpen, false},
		{"open-160-v6", rawEventSessionIDSize, addrFamilyInet6, eventTypeSessionOpen, false},
		{"close-144-v4", rawEventWireSize, addrFamilyInet, eventTypeSessionClose, false},
		{"close-152-v4", rawEventExtSize, addrFamilyInet, eventTypeSessionClose, false},
		{"close-160-v4", rawEventSessionIDSize, addrFamilyInet, eventTypeSessionClose, false},
		{"close-160-v6", rawEventSessionIDSize, addrFamilyInet6, eventTypeSessionClose, false},
		{"deny-144-v4", rawEventWireSize, addrFamilyInet, eventTypePolicyDeny, false},
		{"deny-144-v4-stamped", rawEventWireSize, addrFamilyInet, eventTypePolicyDeny, true},
		{"screen-144-v4", rawEventWireSize, addrFamilyInet, eventTypeScreenDrop, false},
		{"filter-144-v4", rawEventWireSize, addrFamilyInet, eventTypeFilterLog, false},
		{"filter-152-v4", rawEventFilterLogGenerationSize, addrFamilyInet, eventTypeFilterLog, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := frame17065(tc.length, tc.family, tc.eventType, tc.stampedDeny)
			decoded, ok := DecodeRawEventRecord(frame)
			if !ok {
				t.Fatalf("DecodeRawEventRecord rejected %s frame", tc.name)
			}
			if !ValidRawEvent(frame) {
				t.Fatalf("ValidRawEvent rejected %s frame DecodeRawEventRecord accepted", tc.name)
			}
			live, ok := decodeLive16127(t, frame)
			if !ok {
				t.Fatalf("live ProcessRawEvent rejected %s frame", tc.name)
			}
			assertWireFields17065(t, live, decoded)
		})
	}
}

// assertWireFields17065 compares every wire-derived EventRecord field.
// Any field either entry point derives from the frame bytes belongs
// here; adding a wire field to one mapper without the other (the
// pre-#17065 hand-mapped pair) flips this RED.
func assertWireFields17065(t *testing.T, live, decoded EventRecord) {
	t.Helper()
	if !live.Time.Equal(decoded.Time) {
		t.Fatalf("Time live %v != decoded %v", live.Time, decoded.Time)
	}
	if live.Type != decoded.Type || live.SrcAddr != decoded.SrcAddr || live.DstAddr != decoded.DstAddr ||
		live.Protocol != decoded.Protocol || live.ProtocolNum != decoded.ProtocolNum ||
		live.Action != decoded.Action || live.PolicyID != decoded.PolicyID ||
		live.RuleID != decoded.RuleID || live.TermID != decoded.TermID ||
		live.Reason != decoded.Reason || live.OwnerRGID != decoded.OwnerRGID ||
		live.InZone != decoded.InZone || live.OutZone != decoded.OutZone ||
		live.ScreenCheck != decoded.ScreenCheck ||
		live.SessionPkts != decoded.SessionPkts || live.SessionBytes != decoded.SessionBytes ||
		live.NATSrcAddr != decoded.NATSrcAddr || live.NATDstAddr != decoded.NATDstAddr ||
		live.Created != decoded.Created || live.CreatedNanos != decoded.CreatedNanos ||
		live.RevSessionPkts != decoded.RevSessionPkts || live.RevSessionBytes != decoded.RevSessionBytes ||
		live.IngressIfindex != decoded.IngressIfindex || live.CloseReason != decoded.CloseReason ||
		live.TOS != decoded.TOS || live.TCPControlBits != decoded.TCPControlBits ||
		live.EgressIfindex != decoded.EgressIfindex {
		t.Fatalf("wire fields diverge:\nlive:    %+v\ndecoded: %+v", live, decoded)
	}
	// PolicyName: the mapper stamps it only for a stamped POLICY_DENY;
	// the live path additionally resolves it via the reader. Compare
	// only where the decoded (reader-free) value is set — both must
	// agree there — and require the live value to match when the frame
	// is a stamped deny (the mapper's rule, not the reader's).
	if decoded.PolicyName != "" && live.PolicyName != decoded.PolicyName {
		t.Fatalf("PolicyName live %q != decoded %q", live.PolicyName, decoded.PolicyName)
	}
	// SessionID: an extended session frame carries the wire id on both
	// paths; otherwise the decoder leaves 0 and the live ordinal
	// fallback (EventSeq) applies — that fallback is live-only by
	// design and must equal EventSeq exactly.
	if decoded.SessionID != 0 {
		if live.SessionID != decoded.SessionID {
			t.Fatalf("SessionID live %#x != decoded %#x", live.SessionID, decoded.SessionID)
		}
	} else if live.SessionID != live.EventSeq {
		t.Fatalf("live SessionID fallback %#x != EventSeq %#x (decoded left 0)", live.SessionID, live.EventSeq)
	}
	if live.EventSeq == 0 {
		t.Fatal("live EventSeq must be stamped (live-only post-step)")
	}
	if decoded.EventSeq != 0 || decoded.ElapsedTime != 0 {
		t.Fatalf("decoded record carries live-only enrichment: EventSeq %d ElapsedTime %d", decoded.EventSeq, decoded.ElapsedTime)
	}
}

// TestValidRawEvent17065 pins the cheap gate: it agrees with
// DecodeRawEventRecord's accept/reject verdict on short, unknown-family,
// and valid frames, and allocates nothing.
func TestValidRawEvent17065(t *testing.T) {
	valid := goldenFrame16127(rawEventWireSize, addrFamilyInet)
	if !ValidRawEvent(valid) {
		t.Fatal("ValidRawEvent rejected a valid 144-byte frame")
	}
	for _, n := range []int{0, 55, 111, rawEventWireSize - 1} {
		if ValidRawEvent(goldenFrame16127(n, addrFamilyInet)) {
			t.Fatalf("ValidRawEvent accepted a %d-byte short frame", n)
		}
	}
	badFam := goldenFrame16127(rawEventWireSize, addrFamilyInet)
	badFam[55] = 99
	if ValidRawEvent(badFam) {
		t.Fatal("ValidRawEvent accepted an unknown-family frame")
	}
	if _, ok := DecodeRawEventRecord(badFam); ok {
		t.Fatal("DecodeRawEventRecord accepted an unknown-family frame (gate/verdict drift)")
	}
	if got := testing.AllocsPerRun(100, func() {
		if !ValidRawEvent(valid) {
			t.Fatal("ValidRawEvent flipped inside alloc run")
		}
	}); got != 0 {
		t.Fatalf("ValidRawEvent allocs = %v, want 0", got)
	}
}

// BenchmarkValidRawEvent17065 is the event-stream gate benchmark
// (#17065 acceptance): with the raw callback installed the stream now
// pays only this predicate per frame instead of a full decode. It must
// stay at 0 allocs/op.
func BenchmarkValidRawEvent17065(b *testing.B) {
	frame := goldenFrame16127(rawEventSessionIDSize, addrFamilyInet)
	b.ReportAllocs()
	for b.Loop() {
		if !ValidRawEvent(frame) {
			b.Fatal("benchmark frame stopped validating")
		}
	}
}
