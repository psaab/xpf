package nfqueue

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestCapturePipelineRedispatchesFollowerAfterCompletion13232 is the
// regression for #13232 (D5-01): a follower frame queued behind an
// in-flight head on the same flow must be dispatched when the head's
// reinject completion resolves in Poll, without waiting for unrelated
// handoff traffic. On the unfixed pipeline Poll/resolveCompletion never
// re-ran eligibleLocked, so the follower stayed stranded in flow.frames
// with no verdict.
func TestCapturePipelineRedispatchesFollowerAfterCompletion13232(t *testing.T) {
	const markerHex = "00112233445566778899aabbccddeeff"
	ledger := NewD11AttestationLedger()
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error { return nil })
	armer.SetEnvironmentGate(func() bool { return true })
	if err := armer.Arm("attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, markerHex); err != nil {
		t.Fatalf("arm: %v", err)
	}
	minter := new(d11AttestLeaseMinter11016)
	submitter := new(pipelineTestSubmitter)
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		Submitter:     submitter,
		LeaseMinter:   minter,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Attestation: &D11AttestationConfig{
			Armer:            armer,
			Ledger:           ledger,
			OriginValid:      func(CaptureOrigin) bool { return true },
			AuthorityCurrent: func() bool { return true },
		},
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}

	marked := func(id uint32) *Packet {
		pkt := pipelineTestPacket(77, 2, 2, 7, id)
		payload := make([]byte, 20+8+32)
		payload[0] = 0x45
		payload[9] = 1
		payload[20] = 8
		marker, _ := hex.DecodeString(markerHex)
		copy(payload[20+8+16:20+8+32], marker)
		pkt.payload = payload
		return pkt
	}
	f1 := d11IngressFrame11016(CaptureHookForward, "same-flow", 101)
	f1.Packet = marked(101)
	f2 := d11IngressFrame11016(CaptureHookForward, "same-flow", 102)
	f2.Packet = marked(102)
	if err := p.Enqueue(f1); err != nil {
		t.Fatalf("Enqueue f1: %v", err)
	}
	if err := p.Enqueue(f2); err != nil {
		t.Fatalf("Enqueue f2: %v", err)
	}
	if got := p.Drain(10); got != 2 {
		t.Fatalf("Drain(10) = %d, want 2", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted after Drain = %d, want 1 (head only)", len(submitter.submitted))
	}

	complete := func(frame AdjudicatedFrame) {
		submitter.drain = []ReinjectCompletion{{
			RequestID:    frame.Lease.RequestID,
			PermitEpoch:  frame.Lease.PermitEpoch,
			QueueEpoch:   frame.Lease.QueueEpoch,
			QueueNumber:  frame.Lease.QueueNumber,
			Family:       1,
			Hook:         1,
			OwnedIfindex: 7,
			Outcome:      CompletionWritten,
		}}
		submitter.drain[0].BytesWritten = 60
		p.Poll(time.Now())
	}

	complete(submitter.submitted[0])
	// No new handoff traffic: Poll alone must have dispatched f2.
	if len(submitter.submitted) != 2 {
		t.Fatalf("submitted after f1 Poll = %d, want 2 (follower re-dispatched)", len(submitter.submitted))
	}
	complete(submitter.submitted[1])

	p.mu.Lock()
	_, flowExists := p.flows["same-flow"]
	queued := 0
	if flow := p.flows["same-flow"]; flow != nil {
		queued = len(flow.frames)
	}
	p.mu.Unlock()
	if flowExists || queued != 0 {
		t.Fatalf("flow not drained: exists=%v queued=%d", flowExists, queued)
	}
	if len(sink.verdicts) != 2 {
		t.Fatalf("sink verdicts = %d, want 2 (both frames terminal)", len(sink.verdicts))
	}
}

// TestCapturePipelineRedispatchesFollowerAfterAdmissionRefusal13232 covers
// the synchronous path: when applyAdmission refuses the head frame, the
// follower promoted to flow head must be dispatched in the same call,
// not stranded until unrelated traffic arrives.
