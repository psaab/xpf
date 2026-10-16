package nfqueue

import (
	"fmt"
	"testing"
)

// capEnforcingSubmitter13550 mimics SocketReinjectSubmitter's hard wire cap:
// any batch above reinjectMaxFrames is rejected whole.
type capEnforcingSubmitter13550 struct{ pipelineTestSubmitter }

func (s *capEnforcingSubmitter13550) SubmitAdjudicated(frames []AdjudicatedFrame) ([]ReinjectAdmission, error) {
	if len(frames) > reinjectMaxFrames {
		return nil, fmt.Errorf("nfqueue: reinject batch %d exceeds cap %d", len(frames), reinjectMaxFrames)
	}
	return s.pipelineTestSubmitter.SubmitAdjudicated(frames)
}

// TestCombinedBatchOverWireCapIsChunked13550: eligibleLocked caps per owner
// (64), so two owners produce a 128-frame combined submission. The socket
// submitter hard-rejects >64, which retired the whole batch. Chunking must
// adjudicate every frame.
func TestCombinedBatchOverWireCapIsChunked13550(t *testing.T) {
	var registry OriginRegistry
	if err := registry.Register(77, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(78, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-b", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	sink := new(pipelineTestSink)
	submitter := new(capEnforcingSubmitter13550)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: &registry, Phase: PipelineEnforcing, Sink: sink,
		Submitter: submitter, LeaseMinter: &queueScopedMinter{},
		ZoneEvaluator: passZoneEvaluator9506{}, ZoneSnapshot: passZoneSnapshot9506{},
		HandoffCap: 256, BatchCap: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, q := range []uint16{77, 78} {
		for i := range 64 {
			total++
			frame := CaptureFrame{
				Packet:     pipelineTestPacket(q, 2, 2, 7, uint32(total)),
				FlowKey:    fmt.Sprintf("flow-%d-%d", q, i),
				Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1, FIBGeneration: 1,
				QueueNumber: q, QueueEpoch: uint64(q - 67),
			}
			if err := p.Enqueue(frame); err != nil {
				t.Fatalf("Enqueue %d: %v", total, err)
			}
		}
	}
	if got := p.Drain(256); got != total {
		t.Fatalf("Drain = %d, want %d", got, total)
	}
	if len(submitter.submitted) != total {
		t.Fatalf("submitted = %d, want %d (combined batch over wire cap must be chunked, not dropped)", len(submitter.submitted), total)
	}
	if stats := p.Stats(); stats.Uncertain != 0 {
		t.Fatalf("Uncertain = %d, want 0 (chunked submissions admitted cleanly)", stats.Uncertain)
	}
}

// TestEarlyCompletionThenRefusalCountsUncertainAndRetires13550: a completion
// arriving before the admission refusal means the worker may already have
// acted; refusal must count Uncertain and retire the flow (dropping queued
// followers), mirroring admissionFailedState, not just Refused.
func TestEarlyCompletionThenRefusalCountsUncertainAndRetires13550(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9)
	frame := CaptureFrame{
		Packet:    pipelineTestPacket(77, 2, 2, 7, 11),
		FlowKey:   "early-refusal",
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner", STN: "st0", OwnedIfindex: 7},
		originSet: true,
	}
	follower := CaptureFrame{
		Packet:  pipelineTestPacket(77, 2, 2, 7, 12),
		FlowKey: "early-refusal",
		origin:  frame.origin, originSet: true,
	}
	lease := ReinjectLease{RequestID: 7, PermitEpoch: 9, QueueEpoch: 4, QueueNumber: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	early := ReinjectCompletion{RequestID: 7, PermitEpoch: 9, QueueNumber: 77, QueueEpoch: 4, Family: 1, Hook: 1, OwnedIfindex: 7, Outcome: CompletionWritten}
	item := &pendingReinject{frame: frame, lease: lease, admissionPending: true, earlyCompletion: &early, ledger: ledger, ledgerKey: key}
	p.mu.Lock()
	if !ledger.RecordEarlyCompletion(key, early) {
		t.Fatal("RecordEarlyCompletion failed")
	}
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame, follower}, pending: item}
	p.pending[lease.RequestID] = item
	p.mu.Unlock()

	family, hook := d11OriginWire(frame.origin)
	if got := p.applyAdmission(item, ReinjectAdmission{
		RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch, QueueNumber: lease.QueueNumber,
		QueueEpoch: lease.QueueEpoch, Family: family, Hook: hook, OwnedIfindex: 7, Admitted: false,
	}); got != nil {
		t.Fatalf("applyAdmission refusal returned %v, want nil (not an uncertain-cancel item)", got)
	}
	stats := p.Stats()
	if stats.Refused != 1 || stats.Uncertain != 1 {
		t.Fatalf("stats = %+v, want Refused=1 and Uncertain=1 for early completion before refusal", stats)
	}
	p.mu.Lock()
	flowPresent := p.flows[frame.FlowKey] != nil
	p.mu.Unlock()
	if flowPresent {
		t.Fatalf("flow entry remains after uncertain refusal; queued follower could poison future packets")
	}
	// Both head (refusal) and follower (retire) must be terminal DROP.
	if len(sink.verdicts) != 2 {
		t.Fatalf("sink verdicts = %d, want 2 (head + retired follower)", len(sink.verdicts))
	}
	for _, v := range sink.verdicts {
		if v.v != VerdictDrop {
			t.Fatalf("verdict = %v, want DROP", v.v)
		}
	}
}
