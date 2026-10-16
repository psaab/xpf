package nfqueue

import (
	"testing"
	"time"
)

// Regression for #14208: during D11Draining a selector-matching frame must
// never fall back to the ordinary FORWARD arm, and CancelForD11Drain must
// close the whole Rust permit even when pending work covers only a subset
// of queues.

const d11SelectorHex14208 = "0102030405060708090a0b0c0d0e0f10"

func d11MarkerPayload14208() []byte {
	var selector [16]byte
	for i := range selector {
		selector[i] = byte(i + 1)
	}
	payload := make([]byte, 20+8+32)
	payload[0] = 0x45
	payload[9] = 1
	payload[20] = 8
	copy(payload[20+8+16:], selector[:])
	return payload
}

// cancelRecordingSubmitter records every CancelReinject call so the drain
// test can assert the permit-wide close fence is issued. Other seam methods
// delegate to pipelineTestSubmitter.
type cancelRecordingSubmitter14208 struct {
	pipelineTestSubmitter
	cancels []struct {
		ids    []uint64
		permit uint64
		scopes []ReinjectQueueScope
	}
}

func (s *cancelRecordingSubmitter14208) CancelReinject(ids []uint64, permit uint64, scopes []ReinjectQueueScope) ([]uint64, error) {
	s.cancels = append(s.cancels, struct {
		ids    []uint64
		permit uint64
		scopes []ReinjectQueueScope
	}{append([]uint64(nil), ids...), permit, append([]ReinjectQueueScope(nil), scopes...)})
	return s.pipelineTestSubmitter.CancelReinject(ids, permit, scopes)
}

// d11DrainMinter14208 mints ordinary leases on the frame's own queue (so a
// queue-78 frame gets a queue-78 lease) and also satisfies the attest
// minter contract. Permit epochs mirror production: ordinary leases use
// the S4 permit epoch 1, attest leases use the armed D11 epoch.
type d11DrainMinter14208 struct{ next uint64 }

func (m *d11DrainMinter14208) MintLease(frame CaptureFrame) (ReinjectLease, error) {
	m.next++
	queue := frame.Packet.QueueID()
	return ReinjectLease{
		PermitEpoch: 1, QueueNumber: queue,
		QueueEpoch: uint64(queue), RequestID: m.next,
	}, nil
}

func (m *d11DrainMinter14208) MintLeaseForAttest(frame CaptureFrame, _ string, permitEpoch uint64) (ReinjectLease, error) {
	m.next++
	queue := frame.Packet.QueueID()
	return ReinjectLease{
		PermitEpoch: permitEpoch, QueueNumber: queue,
		QueueEpoch: uint64(queue), RequestID: m.next,
	}, nil
}

func d11DrainFrame14208(queue uint16, id uint32, payload []byte, flow string) CaptureFrame {
	pkt := pipelineTestPacket(queue, 2, 2, 7, id)
	if payload != nil {
		pkt.payload = payload
	}
	return CaptureFrame{
		Packet: pkt, FlowKey: flow,
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: queue, QueueEpoch: uint64(queue),
		origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		originSet: true, phase: PipelineEnforcing,
	}
}

func newD11DrainPipeline14208(t *testing.T, armer *D11AttestationArmer, ledger *D11AttestationLedger, submitter ReinjectSubmitter, minter LeaseMinter, sink *pipelineTestSink) *CapturePipeline {
	t.Helper()
	reg := pipelineTestRegistry(t)
	if err := reg.Register(78, CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookForward,
		Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
	}); err != nil {
		t.Fatalf("Register(78): %v", err)
	}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: reg, Phase: PipelineEnforcing,
		Sink: sink, Submitter: submitter, LeaseMinter: minter,
		Attestation: &D11AttestationConfig{
			Armer: armer, Ledger: ledger,
			OriginValid:      func(CaptureOrigin) bool { return true },
			AuthorityCurrent: func() bool { return true },
		},
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		HandoffCap:    8, BatchCap: 8, AckDeadline: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	return p
}

func TestD11DrainingSelectorFrameDeniedNotForwarded14208(t *testing.T) {
	ledger := NewD11AttestationLedger()
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error { return nil })
	armer.SetEnvironmentGate(func() bool { return true })
	if err := armer.Arm("attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, d11SelectorHex14208); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	submitter := new(pipelineTestSubmitter)
	minter := new(d11DrainMinter14208)
	sink := new(pipelineTestSink)
	p := newD11DrainPipeline14208(t, armer, ledger, submitter, minter, sink)

	if !armer.BeginDrain() {
		t.Fatal("BeginDrain failed")
	}
	if err := p.CancelForD11Drain(9); err != nil {
		t.Fatalf("CancelForD11Drain: %v", err)
	}

	marked := d11DrainFrame14208(78, 301, d11MarkerPayload14208(), "d11-drain-marked")
	ordinary := d11DrainFrame14208(78, 302, nil, "d11-drain-ordinary")
	p.mu.Lock()
	p.flows[marked.FlowKey] = &flowState{frames: []CaptureFrame{marked}}
	p.flows[ordinary.FlowKey] = &flowState{frames: []CaptureFrame{ordinary}}
	p.mu.Unlock()

	p.dispatchEligible()

	// The draining selector frame must be terminal DROP with no FORWARD
	// admission; the non-marker frame keeps the ordinary FORWARD arm.
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted = %d (%+v), want exactly 1 ordinary FORWARD admission", len(submitter.submitted), submitter.submitted)
	}
	if submitter.submitted[0].Flags&ReinjectSubmitFlagForward == 0 {
		t.Fatalf("ordinary frame lost FORWARD flag: flags=%d", submitter.submitted[0].Flags)
	}
	if submitter.submitted[0].Frame.Packet.id == marked.Packet.id {
		t.Fatal("draining selector frame was admitted on the ordinary FORWARD arm")
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop || sink.verdicts[0].id != marked.Packet.id {
		t.Fatalf("sink verdicts = %+v, want selector frame DROP only", sink.verdicts)
	}
	if stats := p.Stats(); stats.Adjudicated != 1 {
		t.Fatalf("Adjudicated = %d, want 1 (ordinary frame only)", stats.Adjudicated)
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Failures) != 1 || snapshot.Failures[0].Reason != "D11 authority is draining" {
		t.Fatalf("ledger failures = %+v, want one draining refusal", snapshot.Failures)
	}
}

func TestD11DrainingBeforeCancelLatchSelectorFrameDenied14208(t *testing.T) {
	ledger := NewD11AttestationLedger()
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error { return nil })
	armer.SetEnvironmentGate(func() bool { return true })
	if err := armer.Arm("attest-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 9, d11SelectorHex14208); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	submitter := new(pipelineTestSubmitter)
	minter := new(d11DrainMinter14208)
	sink := new(pipelineTestSink)
	p := newD11DrainPipeline14208(t, armer, ledger, submitter, minter, sink)

	// BeginDrain without CancelForD11Drain: d11RevokedPermitEpoch is not
	// yet latched, so attestSubmit proceeds to validation/lease minting.
	// The marker frame must still be refused (attestLease requires
	// D11Armed), never forwarded.
	if !armer.BeginDrain() {
		t.Fatal("BeginDrain failed")
	}
	marked := d11DrainFrame14208(77, 401, d11MarkerPayload14208(), "d11-prelatch-marked")
	p.mu.Lock()
	p.flows[marked.FlowKey] = &flowState{frames: []CaptureFrame{marked}}
	p.mu.Unlock()

	p.dispatchEligible()

	if len(submitter.submitted) != 0 {
		t.Fatalf("submitted = %+v, want no admission before the cancel latch", submitter.submitted)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("sink verdicts = %+v, want selector frame DROP", sink.verdicts)
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Failures) != 1 {
		t.Fatalf("ledger failures = %+v, want one refusal", snapshot.Failures)
	}
}

func TestCancelForD11DrainClosesPermitBeyondPendingQueues14208(t *testing.T) {
	ledger := NewD11AttestationLedger()
	ledger.Begin("node-a", "attest-cccccccccccccccccccccccccccccccc", 9)
	submitter := new(cancelRecordingSubmitter14208)
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: sink, Submitter: submitter,
		Attestation: &D11AttestationConfig{Ledger: ledger},
		HandoffCap:  8, BatchCap: 8,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	// One pending lease on queue 77 only: the scoped fence tombstones
	// queue 77, so the permit-wide close must be issued as a second
	// fence with an empty queue-scope set.
	frame := d11DrainFrame14208(77, 501, nil, "d11-drain-pending")
	lease := ReinjectLease{RequestID: 51, PermitEpoch: 9, QueueNumber: 77, QueueEpoch: 77}
	key, err := ledger.Reserve(frame, lease)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	pending := &pendingReinject{frame: frame, lease: lease, ledger: ledger, ledgerKey: key}
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
	p.pending[lease.RequestID] = pending
	p.mu.Unlock()

	if err := p.CancelForD11Drain(9); err != nil {
		t.Fatalf("CancelForD11Drain: %v", err)
	}
	if len(submitter.cancels) != 2 {
		t.Fatalf("cancel calls = %+v, want scoped fence + permit-wide close", submitter.cancels)
	}
	scoped := submitter.cancels[0]
	if scoped.permit != 9 || len(scoped.ids) != 1 || scoped.ids[0] != lease.RequestID ||
		len(scoped.scopes) != 1 || scoped.scopes[0] != (ReinjectQueueScope{QueueNumber: 77, QueueEpoch: 77}) {
		t.Fatalf("scoped cancel = %+v, want pending IDs + queue-77 scope under epoch 9", scoped)
	}
	closeFence := submitter.cancels[1]
	if closeFence.permit != 9 || len(closeFence.ids) != 0 || len(closeFence.scopes) != 0 {
		t.Fatalf("permit close = %+v, want epoch 9 with empty IDs and scopes", closeFence)
	}
	// No-pending case must still issue the single closing fence (this is
	// what the empty-scope wire form already did before #14208).
	submitter.cancels = nil
	p2, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing,
		Sink: new(pipelineTestSink), Submitter: submitter,
		Attestation: &D11AttestationConfig{Ledger: ledger},
		HandoffCap:  8, BatchCap: 8,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline p2: %v", err)
	}
	if err := p2.CancelForD11Drain(9); err != nil {
		t.Fatalf("CancelForD11Drain p2: %v", err)
	}
	if len(submitter.cancels) != 1 || submitter.cancels[0].permit != 9 ||
		len(submitter.cancels[0].scopes) != 0 {
		t.Fatalf("no-pending cancels = %+v, want one empty-scope epoch-9 fence", submitter.cancels)
	}
}
