package nfqueue

import "testing"

type stampingZoneSnapshot9506 struct {
	splitAuthorityZoneSnapshot9506
	authority ZoneSnapshotPacketAuthority
}

func (s stampingZoneSnapshot9506) PacketAuthority() ZoneSnapshotPacketAuthority {
	return s.authority
}

// A receive loop's copy of the shared generations can lag the accepted
// authority. Enqueue replaces it with the accepted packet authority, including
// the P-MECH half that the Rust gate compares against its inventory.
func TestCapturePipelineEnqueueStampsAcceptedPacketAuthority9506(t *testing.T) {
	authority := ZoneSnapshotPacketAuthority{
		ConfigGeneration: 9, FIBGeneration: 7,
		PMechInventoryGeneration: 11, PMechInventoryFIBGeneration: 7,
		PMechPolicyIdentity: [32]byte{0: 0xab, 31: 0xcd},
	}
	newPipeline := func() *CapturePipeline {
		p, err := NewCapturePipeline(CapturePipelineConfig{
			Registry:      pipelineTestRegistry(t),
			Phase:         PipelineEnforcing,
			Sink:          new(pipelineTestSink),
			ZoneEvaluator: DefaultZoneEvaluator{},
			ZoneSnapshot:  stampingZoneSnapshot9506{authority: authority},
			HandoffCap:    1,
			BatchCap:      1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	lagging := func(id uint32) CaptureFrame {
		return CaptureFrame{
			Packet: pipelineTestPacket(77, 2, 2, 7, id), FlowKey: "lagging-authority",
			Generation: 4, SnapshotGeneration: 4, ConfigGeneration: 8,
			FIBGeneration: 6, QueueNumber: 77, QueueEpoch: 1,
		}
	}

	p := newPipeline()
	if err := p.Enqueue(lagging(1)); err != nil {
		t.Fatal(err)
	}
	frame := <-p.handoff
	if frame.ConfigGeneration != authority.ConfigGeneration ||
		frame.FIBGeneration != authority.FIBGeneration ||
		frame.PMechInventoryGeneration != authority.PMechInventoryGeneration ||
		frame.PMechInventoryFIBGeneration != authority.PMechInventoryFIBGeneration ||
		frame.PMechPolicyIdentity != authority.PMechPolicyIdentity {
		t.Fatalf("enqueued frame authority=(%d,%d,%d,%d,%x), want %+v",
			frame.ConfigGeneration, frame.FIBGeneration, frame.PMechInventoryGeneration,
			frame.PMechInventoryFIBGeneration, frame.PMechPolicyIdentity, authority)
	}

	// End to end, the stamped frame passes the generation gate that the
	// lagging copy would have failed.
	p = newPipeline()
	if err := p.Enqueue(lagging(2)); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	if stats := p.Stats(); stats.ZoneGateDrops != 0 || stats.V1PermitSuppressed != 1 {
		t.Fatalf("stats=%+v, want the stamped frame to reach V1 suppression", stats)
	}
}

// The encoder is the last Go fence before Rust: a frame without an armed
// CLOCK_MONOTONIC deadline is refused rather than written with a zero or
// foreign-clock deadline.
func TestEncodeSubmitBatchRefusesUnarmedDeadline9506(t *testing.T) {
	valid := AdjudicatedFrame{
		Frame: CaptureFrame{
			Packet: pipelineTestPacket(9, 2, 2, 42, 0), FlowKey: "flow-a",
			SnapshotGeneration: 13, ConfigGeneration: 17, FIBGeneration: 19,
		},
		Origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner", STN: "stn", OwnedIfindex: 42,
		},
		Lease:           ReinjectLease{RequestID: 1, PermitEpoch: 7, QueueNumber: 9, QueueEpoch: 11},
		ZoneID:          23,
		IfID:            29,
		DeadlineMonoNS:  0x0102030405060708,
		DeadlineClockID: reinjectDeadlineClockMonotonic,
	}
	if _, err := encodeSubmitBatch([]AdjudicatedFrame{valid}); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*AdjudicatedFrame)
	}{
		{"zero deadline", func(f *AdjudicatedFrame) { f.DeadlineMonoNS = 0 }},
		{"unset clock", func(f *AdjudicatedFrame) { f.DeadlineClockID = 0 }},
		{"foreign clock", func(f *AdjudicatedFrame) { f.DeadlineClockID = reinjectDeadlineClockMonotonic + 1 }},
	} {
		frame := valid
		tc.mutate(&frame)
		payload, err := encodeSubmitBatch([]AdjudicatedFrame{frame})
		if err == nil || payload != nil {
			t.Fatalf("%s: encoded %d bytes err=%v, want a refusal", tc.name, len(payload), err)
		}
	}
}
