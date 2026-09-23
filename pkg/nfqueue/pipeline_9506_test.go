package nfqueue

import (
	"errors"
	"testing"
	"time"
)

func pipelineTestPacket(queue uint16, family uint8, hook uint8, ifindex uint32, id uint32) *Packet {
	q := &Queue{id: int(queue), fd: -1}
	return &Packet{
		q: q, id: id, queueID: queue, payload: []byte{0x45, byte(id)},
		nfgenFamily: family, hook: hook, indevIfindex: ifindex,
		recvTime: time.Now(),
	}
}

type pipelineTestSink struct {
	verdicts []struct {
		id uint32
		v  Verdict
	}
	err   error
	calls int
}

func (s *pipelineTestSink) Verdict(pkt *Packet, v Verdict) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.verdicts = append(s.verdicts, struct {
		id uint32
		v  Verdict
	}{pkt.id, v})
	return nil
}

type pipelineTestMinter struct {
	next uint64
}

func (m *pipelineTestMinter) MintLease(CaptureFrame) (ReinjectLease, error) {
	m.next++
	return ReinjectLease{PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1, RequestID: m.next}, nil
}

type queueScopedMinter struct {
	next uint64
}

func (m *queueScopedMinter) MintLease(frame CaptureFrame) (ReinjectLease, error) {
	m.next++
	queue := frame.Packet.QueueID()
	epoch := uint64(queue - 67)
	return ReinjectLease{
		PermitEpoch: 1,
		QueueNumber: queue,
		QueueEpoch:  epoch,
		RequestID:   m.next,
	}, nil
}

type pipelineTestSubmitter struct {
	submitted []AdjudicatedFrame
	admit     []ReinjectAdmission
	drain     []ReinjectCompletion
	cancelled []uint64
}

func (s *pipelineTestSubmitter) SubmitAdjudicated(frames []AdjudicatedFrame) ([]ReinjectAdmission, error) {
	s.submitted = append(s.submitted, frames...)
	if s.admit != nil {
		return s.admit, nil
	}
	out := make([]ReinjectAdmission, 0, len(frames))
	for _, f := range frames {
		family, hook, err := originWire(f.Origin)
		if err != nil {
			return nil, err
		}
		out = append(out, ReinjectAdmission{
			RequestID: f.Lease.RequestID, PermitEpoch: f.Lease.PermitEpoch,
			QueueNumber: f.Lease.QueueNumber, QueueEpoch: f.Lease.QueueEpoch,
			Family: family, Hook: hook, OwnedIfindex: f.Origin.OwnedIfindex,
			Admitted: true,
		})
	}
	return out, nil
}

func (s *pipelineTestSubmitter) DrainReinjectCompletions(uint32) ([]ReinjectCompletion, error) {
	out := append([]ReinjectCompletion(nil), s.drain...)
	s.drain = nil
	return out, nil
}

func (s *pipelineTestSubmitter) CancelReinject(ids []uint64, permit uint64, scopes []ReinjectQueueScope) ([]uint64, error) {
	s.cancelled = append(s.cancelled, ids...)
	return ids, nil
}

func pipelineTestRegistry(t *testing.T) *OriginRegistry {
	t.Helper()
	var registry OriginRegistry
	if err := registry.Register(77, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	return &registry
}

type passZoneSnapshot9506 struct{}

func (passZoneSnapshot9506) ResolveSTN(string) ZoneResolution {
	return ZoneResolution{ZoneID: 1, IfID: 7, Reason: ZoneReasonZoned}
}
func (passZoneSnapshot9506) Generations() (uint64, uint32) { return 1, 1 }
func (passZoneSnapshot9506) Current() bool                 { return true }

type splitAuthorityZoneSnapshot9506 struct{}

func (splitAuthorityZoneSnapshot9506) ResolveSTN(string) ZoneResolution {
	return ZoneResolution{ZoneID: 1, IfID: 7, Reason: ZoneReasonZoned}
}
func (splitAuthorityZoneSnapshot9506) Generations() (uint64, uint32) { return 4, 4 }
func (splitAuthorityZoneSnapshot9506) AcceptedGenerations() (uint64, uint32) {
	return 9, 7
}
func (splitAuthorityZoneSnapshot9506) QueueEpoch(queue uint16) uint64 {
	if queue == 77 {
		return 1
	}
	return 0
}
func (splitAuthorityZoneSnapshot9506) Current() bool { return true }
func (splitAuthorityZoneSnapshot9506) ValidateOrigin(CaptureOrigin) ZoneReason {
	return ZoneReasonZoned
}

type zeroAcceptedAuthorityZoneSnapshot9506 struct {
	splitAuthorityZoneSnapshot9506
}

func (zeroAcceptedAuthorityZoneSnapshot9506) AcceptedGenerations() (uint64, uint32) {
	return 0, 7
}

func TestCapturePipelineZeroQueueEpochDropsUnknownGeneration10485(t *testing.T) {
	sink := new(pipelineTestSink)
	var denyReasons []IpsecInnerReason
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: DefaultZoneEvaluator{},
		ZoneSnapshot:  splitAuthorityZoneSnapshot9506{},
		DenyEvents: DenyEventSinkFunc(func(event IpsecInnerDeny) bool {
			denyReasons = append(denyReasons, event.Reason)
			return true
		}),
		HandoffCap: 2,
		BatchCap:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 3), FlowKey: "zero-queue-epoch",
		Generation: 4, SnapshotGeneration: 4, ConfigGeneration: 9,
		FIBGeneration: 7, QueueNumber: 77, QueueEpoch: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	stats := p.Stats()
	if stats.ZoneGateUnavailable != 1 || stats.ZoneGateDrops != 1 ||
		stats.ZoneGateStale != 0 || stats.V1PermitSuppressed != 0 {
		t.Fatalf("stats=%+v, want one unknown-generation drop", stats)
	}
	if len(denyReasons) != 1 || denyReasons[0] != ReasonMissingGeneration {
		t.Fatalf("deny reasons=%v, want [ReasonMissingGeneration]", denyReasons)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}

func TestCapturePipelineZeroAcceptedAuthorityDropsUnknownGeneration10485(t *testing.T) {
	sink := new(pipelineTestSink)
	var denyReasons []IpsecInnerReason
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: DefaultZoneEvaluator{},
		ZoneSnapshot:  zeroAcceptedAuthorityZoneSnapshot9506{},
		DenyEvents: DenyEventSinkFunc(func(event IpsecInnerDeny) bool {
			denyReasons = append(denyReasons, event.Reason)
			return true
		}),
		HandoffCap: 2,
		BatchCap:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 4), FlowKey: "zero-accepted-authority",
		Generation: 4, SnapshotGeneration: 4, ConfigGeneration: 9,
		FIBGeneration: 7, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	stats := p.Stats()
	if stats.ZoneGateUnavailable != 1 || stats.ZoneGateDrops != 1 ||
		stats.ZoneGateStale != 0 || stats.V1PermitSuppressed != 0 {
		t.Fatalf("stats=%+v, want one unknown-generation drop", stats)
	}
	if len(denyReasons) != 1 || denyReasons[0] != ReasonMissingGeneration {
		t.Fatalf("deny reasons=%v, want [ReasonMissingGeneration]", denyReasons)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}
func TestCapturePipelineAcceptedAuthorityCanAdvanceFromCapture9506(t *testing.T) {
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: DefaultZoneEvaluator{},
		ZoneSnapshot:  splitAuthorityZoneSnapshot9506{},
		HandoffCap:    2,
		BatchCap:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "split-authority",
		Generation: 4, SnapshotGeneration: 4, ConfigGeneration: 9,
		FIBGeneration: 7, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	stats := p.Stats()
	if stats.ZoneGateDrops != 0 || stats.V1PermitSuppressed != 1 {
		t.Fatalf("stats=%+v, want accepted split authority and one V1 suppression", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal V1 DROP", sink.verdicts)
	}

	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 2), FlowKey: "stale-capture",
		Generation: 5, SnapshotGeneration: 5, ConfigGeneration: 9,
		FIBGeneration: 7, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("stale Drain=%d, want one frame", got)
	}
	stats = p.Stats()
	if stats.ZoneGateDrops != 1 || stats.ZoneGateStale != 1 {
		t.Fatalf("stale stats=%+v, want one stale gate drop", stats)
	}
}

type passZoneEvaluator9506 struct{}

func (passZoneEvaluator9506) Evaluate(CaptureOrigin, ZoneSnapshotRef) ZoneEvaluation {
	return ZoneEvaluation{Decision: ZonePass, ZoneID: 1, IfID: 7, Reason: ZoneReasonZoned}
}

func TestCapturePipelineRoutineV1SuppressionHasNoDenyEvent9506(t *testing.T) {
	sink := new(pipelineTestSink)
	denyEvents := 0
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineEnforcing,
		Sink:          sink,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		DenyEvents: DenyEventSinkFunc(func(IpsecInnerDeny) bool {
			denyEvents++
			return true
		}),
		HandoffCap: 2,
		BatchCap:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "routine-v1",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1,
		FIBGeneration: 1, QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one frame", got)
	}
	if stats := p.Stats(); stats.V1PermitSuppressed != 1 {
		t.Fatalf("stats=%+v, want one routine suppression", stats)
	}
	if denyEvents != 0 {
		t.Fatalf("routine suppression emitted %d deny events, want none", denyEvents)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}

func TestCapturePipelineOwnerHomogeneousPartition9506(t *testing.T) {
	origin := func(owner string) CaptureOrigin {
		return CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: owner, STN: "st0", OwnedIfindex: 7}
	}
	frames := []CaptureFrame{
		{FlowKey: "a", origin: origin("worker-a"), originSet: true},
		{FlowKey: "b", origin: origin("worker-b"), originSet: true},
		{FlowKey: "c", origin: origin("worker-a"), originSet: true},
	}
	parts := PartitionOwnerBatches(frames)
	if len(parts) != 2 {
		t.Fatalf("partitions=%d, want 2", len(parts))
	}
	for owner, batch := range parts {
		if len(batch) == 0 {
			t.Fatalf("owner %q has empty batch", owner)
		}
		for _, frame := range batch {
			if frame.origin.Owner != owner {
				t.Fatalf("owner %q batch contains %q", owner, frame.origin.Owner)
			}
		}
	}
	if got := len(DispatchWorkers(parts)); got != 2 {
		t.Fatalf("dispatch workers=%d, want 2 (mixed batch may not use one worker)", got)
	}
}

func TestCapturePipelineBoundedHandoff9506(t *testing.T) {
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:   pipelineTestRegistry(t),
		Phase:      PipelineShadow,
		Sink:       new(pipelineTestSink),
		HandoffCap: 1,
		BatchCap:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "a"}
	if err := p.Enqueue(frame); err != nil {
		t.Fatalf("first Enqueue: %v", err)
	}
	if err := p.Enqueue(frame); !errors.Is(err, ErrHandoffFull) {
		t.Fatalf("second Enqueue=%v, want ErrHandoffFull", err)
	}
	if got := p.Stats().HandoffRefusals; got != 1 {
		t.Fatalf("handoff refusals=%d, want 1", got)
	}
}

func TestCapturePipelineShadowAndQuarantine9506(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phase PipelinePhase
		want  Verdict
	}{
		{"shadow", PipelineShadow, VerdictAccept},
		{"quarantine", PipelineQuarantine, VerdictDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := new(pipelineTestSink)
			p, err := NewCapturePipeline(CapturePipelineConfig{
				Registry: pipelineTestRegistry(t), Phase: tc.phase, Sink: sink, HandoffCap: 2, BatchCap: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Enqueue(CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "a"}); err != nil {
				t.Fatal(err)
			}
			if n := p.Drain(2); n != 1 || len(sink.verdicts) != 1 || sink.verdicts[0].v != tc.want {
				t.Fatalf("Drain n=%d verdicts=%+v, want %v", n, sink.verdicts, tc.want)
			}
		})
	}
}

func TestCapturePipelineScopedCancelKeepsOtherQueueLive9506(t *testing.T) {
	sink := new(pipelineTestSink)
	var registry OriginRegistry
	for _, queue := range []uint16{77, 78} {
		if err := registry.Register(queue, CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		}); err != nil {
			t.Fatal(err)
		}
	}
	submitter := new(pipelineTestSubmitter)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: &registry, Phase: PipelineEnforcing, Sink: sink,
		LeaseMinter: &queueScopedMinter{}, Submitter: submitter,
		HandoffCap: 4, BatchCap: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, queue := range []uint16{77, 78} {
		if err := p.Enqueue(CaptureFrame{
			Packet:  pipelineTestPacket(queue, 2, 2, 7, uint32(queue)),
			FlowKey: "same-flow",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.Drain(4); got != 2 {
		t.Fatalf("Drain=%d, want 2", got)
	}
	if len(submitter.submitted) != 0 || len(submitter.cancelled) != 0 {
		t.Fatalf("fail-closed gate submitted=%+v cancelled=%v, want no reinject activity", submitter.submitted, submitter.cancelled)
	}
	stats := p.Stats()
	if stats.ZoneGateUnavailable != 2 || stats.ZoneGateDrops != 2 {
		t.Fatalf("stats=%+v, want two unavailable zone-gate drops", stats)
	}
	if len(sink.verdicts) != 2 {
		t.Fatalf("verdicts=%+v, want both frames terminal", sink.verdicts)
	}
	for _, verdict := range sink.verdicts {
		if verdict.v != VerdictDrop {
			t.Fatalf("verdicts=%+v, want only DROP", sink.verdicts)
		}
	}
	if err := p.Cancel(1, 77, 10); err != nil {
		t.Fatalf("scoped Cancel: %v", err)
	}
	if len(sink.verdicts) != 2 {
		t.Fatalf("scoped cancel changed terminal verdicts=%+v", sink.verdicts)
	}
}

func TestCapturePipelineFragmentCompletionOneClass9506(t *testing.T) {
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineQuarantine, Sink: sink,
		HandoffCap: 8, BatchCap: 8, FragmentSlots: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := FragmentKey{Version: 4, Tunnel: 1, VRF: 1, Generation: 1, ID: 5}
	for i, frag := range []Fragment{{Offset: 0, More: true, Data: []byte("ab")}, {Offset: 2, More: false, Data: []byte("cd")}} {
		if err := p.Enqueue(CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, uint32(i+1)), FlowKey: "frag", FragmentKey: &key, Fragment: &frag}); err != nil {
			t.Fatalf("Enqueue fragment %d: %v", i, err)
		}
	}
	if n := p.Drain(8); n != 2 || len(sink.verdicts) != 2 {
		t.Fatalf("fragment Drain n=%d verdicts=%+v, want two original verdicts", n, sink.verdicts)
	}
	for _, verdict := range sink.verdicts {
		if verdict.v != VerdictDrop {
			t.Fatalf("fragment verdict=%v, want one class DROP", verdict.v)
		}
	}
}

func TestCapturePipelineAdmittedEchoMismatchCancelsUncertain9506(t *testing.T) {
	sink := new(pipelineTestSink)
	submitter := &pipelineTestSubmitter{
		admit: []ReinjectAdmission{{
			RequestID: 1, PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 99,
			Family: reinjectOriginInet, Hook: reinjectOriginForward,
			OwnedIfindex: 7, Admitted: true,
		}},
	}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:    pipelineTestRegistry(t),
		Phase:       PipelineEnforcing,
		Sink:        sink,
		LeaseMinter: &pipelineTestMinter{},
		Submitter:   submitter,
		HandoffCap:  2,
		BatchCap:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "echo-mismatch",
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(1); got != 1 {
		t.Fatalf("Drain=%d, want one terminal frame", got)
	}
	if len(submitter.submitted) != 0 || len(submitter.cancelled) != 0 {
		t.Fatalf("fail-closed gate submitted=%+v cancelled=%v, want no reinject activity", submitter.submitted, submitter.cancelled)
	}
	stats := p.Stats()
	if stats.ZoneGateUnavailable != 1 || stats.ZoneGateDrops != 1 {
		t.Fatalf("stats=%+v, want one unavailable zone-gate drop", stats)
	}
	if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
	}
}

func TestCapturePipelineExtendedCompletionOutcomes9506(t *testing.T) {
	tests := []struct {
		name           string
		outcome        CompletionOutcome
		wantStale      uint64
		wantRefused    uint64
		wantUncertain  uint64
		wantSuppressed uint64
		wantNotify     bool
	}{
		{name: "fenced is stale", outcome: CompletionFenced, wantStale: 1},
		{name: "denied is refused", outcome: CompletionDenied, wantRefused: 1},
		{name: "accepted is uncertain", outcome: CompletionAccepted, wantUncertain: 1, wantNotify: true},
		{name: "would reinject is uncertain", outcome: CompletionWouldReinject, wantUncertain: 1, wantNotify: true},
		{name: "would permit is suppressed", outcome: CompletionWouldPermit, wantSuppressed: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := new(pipelineTestSink)
			uncertainCalls := 0
			p, err := NewCapturePipeline(CapturePipelineConfig{
				Registry:    pipelineTestRegistry(t),
				Phase:       PipelineEnforcing,
				Sink:        sink,
				OnUncertain: func(string) { uncertainCalls++ },
			})
			if err != nil {
				t.Fatal(err)
			}
			frame := CaptureFrame{
				Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "extended-outcome",
				origin: CaptureOrigin{
					Family: CaptureFamilyInet, Hook: CaptureHookForward,
					OwnedIfindex: 7,
				}, originSet: true,
			}
			pending := &pendingReinject{
				frame:    frame,
				lease:    ReinjectLease{PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1, RequestID: 1},
				deadline: time.Now().Add(time.Second),
			}
			p.mu.Lock()
			p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
			p.pending[pending.lease.RequestID] = pending
			p.mu.Unlock()
			if !p.resolveCompletion(ReinjectCompletion{
				RequestID: 1, PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1,
				Family: 1, Hook: 1, OwnedIfindex: 7, Outcome: tc.outcome,
			}) {
				t.Fatal("resolveCompletion returned false")
			}
			stats := p.Stats()
			if stats.Stale != tc.wantStale || stats.Refused != tc.wantRefused ||
				stats.Uncertain != tc.wantUncertain || stats.V1PermitSuppressed != tc.wantSuppressed {
				t.Fatalf("stats=%+v, want stale=%d refused=%d uncertain=%d suppressed=%d",
					stats, tc.wantStale, tc.wantRefused, tc.wantUncertain, tc.wantSuppressed)
			}
			wantCalls := 0
			if tc.wantNotify {
				wantCalls = 1
			}
			if uncertainCalls != wantCalls {
				t.Fatalf("uncertain callback count=%d, want %d", uncertainCalls, wantCalls)
			}
			if len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
				t.Fatalf("verdicts=%+v, want one terminal DROP", sink.verdicts)
			}
		})
	}
}

func TestCapturePipelineDispositionCounters10478(t *testing.T) {
	type completionCase struct {
		name    string
		outcome CompletionOutcome
		want    func(PipelineStats) uint64
	}
	cases := []completionCase{
		{name: "written", outcome: CompletionWritten, want: func(s PipelineStats) uint64 { return s.Written }},
		{name: "stale", outcome: CompletionStale, want: func(s PipelineStats) uint64 { return s.Stale }},
		{name: "cancelled", outcome: CompletionCancelled, want: func(s PipelineStats) uint64 { return s.Cancelled }},
		{name: "refused", outcome: CompletionRefused, want: func(s PipelineStats) uint64 { return s.Refused }},
		{name: "uncertain", outcome: CompletionUncertain, want: func(s PipelineStats) uint64 { return s.Uncertain }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := new(pipelineTestSink)
			p, err := NewCapturePipeline(CapturePipelineConfig{
				Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: sink,
			})
			if err != nil {
				t.Fatal(err)
			}
			frame := CaptureFrame{
				Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "disposition",
				origin: CaptureOrigin{
					Family: CaptureFamilyInet, Hook: CaptureHookForward,
					OwnedIfindex: 7,
				}, originSet: true,
			}
			pending := &pendingReinject{
				frame:    frame,
				lease:    ReinjectLease{PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1, RequestID: 1},
				deadline: time.Now().Add(time.Second),
			}
			p.mu.Lock()
			p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
			p.pending[pending.lease.RequestID] = pending
			p.mu.Unlock()
			completion := ReinjectCompletion{
				RequestID: 1, PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1,
				Family: 1, Hook: 1, OwnedIfindex: 7, Outcome: tc.outcome,
			}
			if tc.outcome == CompletionWritten {
				completion.BytesWritten = uint32(len(frame.Packet.Payload()))
			}
			if !p.resolveCompletion(completion) {
				t.Fatal("resolveCompletion returned false")
			}
			if got := tc.want(p.Stats()); got != 1 {
				t.Fatalf("stats=%+v, want %s=1", p.Stats(), tc.name)
			}
		})
	}

	t.Run("late completion", func(t *testing.T) {
		ledger := NewD11AttestationLedger()
		ledger.Begin("node-a", "attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
		p, err := NewCapturePipeline(CapturePipelineConfig{
			Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: new(pipelineTestSink),
			Attestation: &D11AttestationConfig{Ledger: ledger},
		})
		if err != nil {
			t.Fatal(err)
		}
		if p.resolveCompletion(ReinjectCompletion{RequestID: 99}) {
			t.Fatal("unknown completion unexpectedly resolved")
		}
		if got := p.Stats().LateCompletions; got != 1 {
			t.Fatalf("LateCompletions=%d, want 1", got)
		}
		failures := ledger.Snapshot().Failures
		if len(failures) != 1 || failures[0].Reason != "unmatched late completion request_id=99" {
			t.Fatalf("late ledger failures=%+v", failures)
		}
	})

	t.Run("ack timeout", func(t *testing.T) {
		p, err := NewCapturePipeline(CapturePipelineConfig{
			Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: new(pipelineTestSink),
		})
		if err != nil {
			t.Fatal(err)
		}
		frame := CaptureFrame{
			Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "timeout",
		}
		pending := &pendingReinject{
			frame:    frame,
			lease:    ReinjectLease{PermitEpoch: 1, QueueNumber: 77, QueueEpoch: 1, RequestID: 1},
			deadline: time.Now().Add(-time.Second),
		}
		p.mu.Lock()
		p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}, pending: pending}
		p.pending[pending.lease.RequestID] = pending
		p.mu.Unlock()
		if got := p.Poll(time.Now()); got != 1 {
			t.Fatalf("Poll=%d, want one timeout resolution", got)
		}
		stats := p.Stats()
		if stats.Timeouts != 1 || stats.Uncertain != 1 {
			t.Fatalf("stats=%+v, want Timeouts=1 Uncertain=1", stats)
		}
	})
}
