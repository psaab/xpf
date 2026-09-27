package logging

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestPolicyDenyNameRequiresMatchingGeneration10978(t *testing.T) {
	const (
		policyID    = uint32(77)
		generationA = uint64(41)
		generationB = uint64(42)
	)
	frame := rawPolicyDenyFrame(policyID)
	binary.LittleEndian.PutUint64(frame[56:64], generationA)
	binary.LittleEndian.PutUint32(
		frame[policyDenyGenerationMarkerOff:policyDenyGenerationMarkerOff+4],
		policyDenyGenerationMarker,
	)

	if got, ok := policyDenyConfigGeneration(frame); !ok || got != generationA {
		t.Fatalf("frame generation = %d, stamped = %v; want generation %d", got, ok, generationA)
	}

	buffer := NewEventBuffer(4)
	reader := NewEventReader(nil, buffer)
	reader.SetPolicyNamesForGeneration(generationA, map[uint32]string{policyID: "policy-A"})
	if !reader.ProcessRawEvent(frame) {
		t.Fatal("ProcessRawEvent rejected stamped POLICY_DENY")
	}
	if got := buffer.Latest(1)[0].PolicyName; got != "policy-A" {
		t.Fatalf("matching-generation PolicyName = %q, want policy-A", got)
	}

	reader.SetPolicyNamesForGeneration(generationB, map[uint32]string{policyID: "policy-B"})
	if !reader.ProcessRawEvent(frame) {
		t.Fatal("ProcessRawEvent rejected queued-generation POLICY_DENY")
	}
	if got := buffer.Latest(1)[0].PolicyName; got != dataplane.UnattributedPolicyName {
		t.Fatalf("stale-generation PolicyName = %q, want %q", got, dataplane.UnattributedPolicyName)
	}

	decoded, ok := DecodeRawEventRecord(frame)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected stamped POLICY_DENY")
	}
	if decoded.PolicyName != dataplane.UnattributedPolicyName {
		t.Fatalf("decode-only PolicyName = %q, want %q", decoded.PolicyName, dataplane.UnattributedPolicyName)
	}

	legacyReader := NewEventReader(nil, NewEventBuffer(4))
	legacyReader.SetPolicyNames(map[uint32]string{policyID: "unversioned"})
	if !legacyReader.ProcessRawEvent(frame) {
		t.Fatal("ProcessRawEvent rejected stamped POLICY_DENY with an unversioned map")
	}
	if got := legacyReader.buffer.Latest(1)[0].PolicyName; got != dataplane.UnattributedPolicyName {
		t.Fatalf("unversioned map attributed stamped deny to %q, want %q",
			got, dataplane.UnattributedPolicyName)
	}
	if decoded.RuleID != policyID || decoded.TermID != 0 {
		t.Fatalf("stamped deny rule/term = %d/%d, want policy ID/zero %d/0",
			decoded.RuleID, decoded.TermID, policyID)
	}
}
