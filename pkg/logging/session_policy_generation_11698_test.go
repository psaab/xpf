package logging

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func sessionPolicyGenerationFrame(eventType uint8, policyID uint32, generation uint64) []byte {
	frame := make([]byte, rawEventSessionPolicyGenerationSize)
	frame[52] = eventType
	frame[53] = 6
	frame[55] = addrFamilyInet
	frame[rawEventLogSyslogOffset] = 1
	if eventType == eventTypeSessionClose {
		binary.LittleEndian.PutUint32(frame[rawEventPolicyCloseOffset:rawEventPolicyCloseOffset+4], policyID)
	} else {
		binary.LittleEndian.PutUint32(frame[44:48], policyID)
	}
	binary.LittleEndian.PutUint32(frame[policyConfigGenerationMarkerOffset:policyConfigGenerationMarkerOffset+4], policyConfigGenerationMarker)
	binary.LittleEndian.PutUint64(frame[rawEventSessionPolicyGenerationOffset:rawEventSessionPolicyGenerationOffset+8], generation)
	return frame
}

func TestSessionPolicyNameRequiresMatchingGeneration11698(t *testing.T) {
	const (
		policyID    = uint32(77)
		generationA = uint64(41)
		generationB = uint64(42)
	)
	for _, eventType := range []uint8{eventTypeSessionOpen, eventTypeSessionClose} {
		t.Run(eventTypeName(eventType), func(t *testing.T) {
			frame := sessionPolicyGenerationFrame(eventType, policyID, generationA)
			reader := NewEventReader(nil, NewEventBuffer(4))
			reader.SetPolicyNamesForGeneration(generationB, map[uint32]string{policyID: "policy-B"})
			if !reader.ProcessRawEvent(frame) {
				t.Fatal("ProcessRawEvent rejected stamped session frame")
			}
			got := reader.buffer.Latest(1)[0]
			if got.PolicyName != dataplane.UnattributedPolicyName {
				t.Errorf("generation-%d frame resolved under generation-%d as %q, want %q", generationA, generationB, got.PolicyName, dataplane.UnattributedPolicyName)
			}
			if got.PolicyID != policyID {
				t.Errorf("numeric policy ID = %d, want %d", got.PolicyID, policyID)
			}

			sameGeneration := NewEventReader(nil, NewEventBuffer(4))
			sameGeneration.SetPolicyNamesForGeneration(generationA, map[uint32]string{policyID: "policy-A"})
			if !sameGeneration.ProcessRawEvent(frame) {
				t.Fatal("ProcessRawEvent rejected same-generation session frame")
			}
			same := sameGeneration.buffer.Latest(1)[0]
			if same.PolicyName != "policy-A" || same.PolicyID != policyID {
				t.Errorf("same-generation record = (%q, %d), want (policy-A, %d)", same.PolicyName, same.PolicyID, policyID)
			}
			legacyFrame := append([]byte(nil), frame[:rawEventSessionPolicyGenerationOffset]...)
			clear(legacyFrame[policyConfigGenerationMarkerOffset : policyConfigGenerationMarkerOffset+4])
			legacy := NewEventReader(nil, NewEventBuffer(4))
			legacy.SetPolicyNamesForGeneration(generationB, map[uint32]string{policyID: "policy-B"})
			if !legacy.ProcessRawEvent(legacyFrame) {
				t.Fatal("ProcessRawEvent rejected an unstamped legacy session frame")
			}
			if got := legacy.buffer.Latest(1)[0].PolicyName; got != "policy-B" {
				t.Errorf("unstamped legacy frame resolved as %q, want current policy name", got)
			}
		})
	}
}
