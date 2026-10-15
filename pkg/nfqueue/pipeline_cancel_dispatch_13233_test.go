package nfqueue

import "testing"

// Regression for #13233 (D5-02): a scoped Cancel that unblocks queued
// frames must dispatch them through the phase-partitioned path used by
// consumeFrames. PipelineShadow is observation-only and must always
// VerdictAccept; an armed D11 PipelineEnforcing frame must enter
// attestation instead of the V1 submitEligible arm (which drops it via
// V1PermitSuppressed when there is no ordinary lease minter).

func TestScopedCancelDispatchesShadowFrameAccept13233(t *testing.T) {
	reg := pipelineTestRegistry(t)
	if err := reg.Register(78, CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookForward,
		Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
	}); err != nil {
		t.Fatalf("Register(78): %v", err)
	}
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      reg,
		Phase:         PipelineShadow,
		Sink:          sink,
		Submitter:     new(pipelineTestSubmitter),
		ZoneEvaluator: d11FixedZoneEvaluator11017{evaluation: ZoneEvaluation{Decision: ZoneDrop, Reason: ZoneReasonUnzoned}},
		ZoneSnapshot:  d11CurrentZoneSnapshot11017{current: true},
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	frame := CaptureFrame{
		Packet:    pipelineTestPacket(78, 2, 2, 7, 202),
		FlowKey:   "shadow-flow",
		phase:     PipelineShadow,
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7},
		originSet: true,
	}
	p.mu.Lock()
	p.flows["shadow-flow"] = &flowState{frames: []CaptureFrame{frame}}
	p.mu.Unlock()

	if err := p.Cancel(1, 77, 1); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictAccept {
		t.Fatalf("scoped Cancel on shadow frame verdicts=%+v stats=%+v, want one VerdictAccept",
			sink.verdicts, p.Stats())
	}
	if stats := p.Stats(); stats.Accepted != 1 || stats.Dropped != 0 || stats.ZoneGateDrops != 0 {
		t.Fatalf("scoped Cancel on shadow frame stats=%+v, want Accepted=1 Dropped=0 ZoneGateDrops=0", stats)
	}
}

func TestScopedCancelDispatchesArmedD11FrameToAttestation13233(t *testing.T) {
	ledger := NewD11AttestationLedger()
	armer := NewD11AttestationArmer("node-a", ledger, func(string, uint64) error { return nil })
	armer.SetEnvironmentGate(func() bool { return true })
	selectorHex := "0102030405060708090a0b0c0d0e0f10"
	if err := armer.Arm("attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, selectorHex); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	reg := pipelineTestRegistry(t)
	sink := new(pipelineTestSink)
	submitter := new(pipelineTestSubmitter)
	minter := new(d11AttestLeaseMinter11016)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:    reg,
		Phase:       PipelineEnforcing,
		Sink:        sink,
		Submitter:   submitter,
		LeaseMinter: minter,
		Attestation: &D11AttestationConfig{
			Armer:    armer,
			Ledger:   ledger,
			OriginValid: func(CaptureOrigin) bool { return true },
			AuthorityCurrent: func() bool { return true },
		},
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	// ICMP echo-request carrying the armed marker selector, as in
	// TestD11MarkerMatchesRejectsMalformedAndWrongSelectors10484.
	var selector [16]byte
	for i := range selector {
		selector[i] = byte(i + 1)
	}
	payload := make([]byte, 20+8+32)
	payload[0] = 0x45
	payload[9] = 1
	payload[20] = 8
	copy(payload[20+8+16:], selector[:])

	pkt := pipelineTestPacket(77, 2, 2, 7, 203)
	pkt.payload = payload
	frame := CaptureFrame{
		Packet:    pkt,
		FlowKey:   "d11-flow",
		phase:     PipelineEnforcing,
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
		origin:    CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7},
		originSet: true,
	}
	p.mu.Lock()
	p.flows["d11-flow"] = &flowState{frames: []CaptureFrame{frame}}
	p.mu.Unlock()

	if err := p.Cancel(1, 77, 1); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("scoped Cancel submitted=%+v verdicts=%+v stats=%+v, want one attestation admission",
			submitter.submitted, sink.verdicts, p.Stats())
	}
	snapshot := ledger.Snapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].AdmissionCode == "" {
		t.Fatalf("scoped Cancel did not record D11 attestation admission: snapshot=%+v", snapshot)
	}
	if stats := p.Stats(); stats.V1PermitSuppressed != 0 {
		t.Fatalf("scoped Cancel diverted armed D11 frame to V1 suppression: stats=%+v", stats)
	}
	if len(sink.verdicts) != 0 {
		t.Fatalf("attested frame must stay pending for completion, got verdicts=%+v", sink.verdicts)
	}
}
