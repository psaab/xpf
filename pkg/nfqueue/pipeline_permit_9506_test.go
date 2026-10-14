package nfqueue

import (
	"errors"
	"testing"
	"time"
)

// #9506 S9.5 FORWARD permit join regressions. The enforcing pipeline's
// zone-PASS FORWARD arm must SUBMIT to the Rust D13/D14 worker adjudication
// (deny-only suppression is only for INPUT hooks and missing authority), a
// Written completion must account a reinject and terminally DROP the held
// original, and every refusal/uncertain arm stays a fail-closed DROP.

func TestEnforcingZonePassSubmitsForwardPermit9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := new(pipelineTestSubmitter)
	minter := &pipelineTestMinter{}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Submitter:     submitter,
		LeaseMinter:   minter,
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 5), FlowKey: "permit-forward",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted %d batches-frames, want 1: %+v", len(submitter.submitted), submitter.submitted)
	}
	frame := submitter.submitted[0]
	if frame.Flags != ReinjectSubmitFlagForward {
		t.Fatalf("submitted flags=%#x, want ReinjectSubmitFlagForward (%#x)", frame.Flags, ReinjectSubmitFlagForward)
	}
	if frame.Lease.RequestID == 0 || frame.Lease.QueueNumber != 77 {
		t.Fatalf("submitted lease=%+v, want minted lease on queue 77", frame.Lease)
	}
	stats := p.Stats()
	if stats.Adjudicated != 1 || stats.V1PermitSuppressed != 0 || stats.ZoneGateDrops != 0 {
		t.Fatalf("stats=%+v, want one adjudicated submit and no suppression", stats)
	}
	if sink.calls != 0 {
		t.Fatalf("sink saw %d verdicts before the completion, want 0 (frame is pending)", sink.calls)
	}

	// The worker adjudicated and wrote the frame to the adjudicated TUN:
	// the completion is Written with the exact held-original byte count.
	family, hook, wireErr := originWire(frame.Origin)
	if wireErr != nil {
		t.Fatal(wireErr)
	}
	submitter.drain = []ReinjectCompletion{{
		RequestID: frame.Lease.RequestID, PermitEpoch: frame.Lease.PermitEpoch,
		QueueNumber: frame.Lease.QueueNumber, QueueEpoch: frame.Lease.QueueEpoch,
		Family: family, Hook: hook, OwnedIfindex: frame.Origin.OwnedIfindex,
		Outcome: CompletionWritten, BytesWritten: uint32(len(frame.Frame.Packet.Payload())),
	}}
	if resolved := p.Poll(time.Now()); resolved != 1 {
		t.Fatalf("Poll resolved %d, want 1", resolved)
	}
	stats = p.Stats()
	if stats.Written != 1 || stats.Reinjected != 1 || stats.Dropped != 1 || stats.Accepted != 0 {
		t.Fatalf("stats=%+v, want one Written reinject and one terminal DROP of the original", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop || sink.verdicts[0].id != 5 {
		t.Fatalf("verdicts=%+v, want exactly one DROP of the held original", sink.verdicts)
	}
}

func TestEnforcingPermitAdmissionRefusedDrops9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := new(pipelineTestSubmitter)
	submitter.admit = []ReinjectAdmission{{
		RequestID: 1, PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1,
		Family: 1, Hook: 1, OwnedIfindex: 7,
		Admitted: false, Reason: "queue full", ReasonCode: 2,
	}}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Submitter:     submitter,
		LeaseMinter:   &pipelineTestMinter{},
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 6), FlowKey: "permit-refused",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	stats := p.Stats()
	if stats.Refused != 1 || stats.V1PermitSuppressed != 0 {
		t.Fatalf("stats=%+v, want one admission refusal and no suppression", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one fail-closed DROP", sink.verdicts)
	}
}

func TestEnforcingPermitTransportErrorIsUncertainDrop9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := &errorSubmitter9506{}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Submitter:     submitter,
		LeaseMinter:   &pipelineTestMinter{},
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 7), FlowKey: "permit-transport",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	stats := p.Stats()
	if stats.Uncertain != 1 {
		t.Fatalf("stats=%+v, want one uncertain transport failure", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one fail-closed DROP", sink.verdicts)
	}
}

func TestEnforcingInputHookZonePassStaysSuppressed9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := new(pipelineTestSubmitter)
	var registry OriginRegistry
	if err := registry.Register(78, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookInput, Owner: "owner-a", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      &registry,
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Submitter:     submitter,
		LeaseMinter:   &pipelineTestMinter{},
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(78, 2, 1, 7, 8), FlowKey: "input-suppressed",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 78, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	if len(submitter.submitted) != 0 {
		t.Fatalf("INPUT-hook frame was submitted for forwarding: %+v", submitter.submitted)
	}
	stats := p.Stats()
	if stats.V1PermitSuppressed != 1 || stats.Adjudicated != 0 {
		t.Fatalf("stats=%+v, want one D12a-residual suppression and no submit", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}

func TestEnforcingPermitCompletionWouldPermitStaysFailClosed9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := new(pipelineTestSubmitter)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		Submitter:     submitter,
		LeaseMinter:   &pipelineTestMinter{},
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 9), FlowKey: "would-permit-fallback",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("want one submitted frame")
	}
	frame := submitter.submitted[0]
	family, hook, wireErr := originWire(frame.Origin)
	if wireErr != nil {
		t.Fatal(wireErr)
	}
	// Defensive fallback: a WouldPermit completion (for example from a Rust
	// build that did not arm the write) must not become an ACCEPT.
	submitter.drain = []ReinjectCompletion{{
		RequestID: frame.Lease.RequestID, PermitEpoch: frame.Lease.PermitEpoch,
		QueueNumber: frame.Lease.QueueNumber, QueueEpoch: frame.Lease.QueueEpoch,
		Family: family, Hook: hook, OwnedIfindex: frame.Origin.OwnedIfindex,
		Outcome: CompletionWouldPermit,
	}}
	if resolved := p.Poll(time.Now()); resolved != 1 {
		t.Fatalf("Poll resolved %d, want 1", resolved)
	}
	stats := p.Stats()
	if stats.V1PermitSuppressed != 1 || stats.Written != 0 || stats.Accepted != 0 {
		t.Fatalf("stats=%+v, want one suppressed would-permit and no permit accounting", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}

type errorSubmitter9506 struct{}

func (s *errorSubmitter9506) SubmitAdjudicated([]AdjudicatedFrame) ([]ReinjectAdmission, error) {
	return nil, errors.New("submit socket closed")
}

func (s *errorSubmitter9506) DrainReinjectCompletions(uint32) ([]ReinjectCompletion, error) {
	return nil, nil
}

func (s *errorSubmitter9506) CancelReinject(ids []uint64, _ uint64, _ []ReinjectQueueScope) ([]uint64, error) {
	return ids, nil
}
