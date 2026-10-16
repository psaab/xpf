package nfqueue

import (
	"sync"
	"testing"
	"time"
)

type blockedTerminalSink13975 struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu       sync.Mutex
	verdicts []uint32
}

func (s *blockedTerminalSink13975) Verdict(pkt *Packet, _ Verdict) error {
	s.mu.Lock()
	s.verdicts = append(s.verdicts, pkt.id)
	s.mu.Unlock()
	if pkt.id == 1 {
		s.once.Do(func() {
			close(s.started)
			<-s.release
		})
	}
	return nil
}

// TestTimeoutRetirementPreventsConcurrentFollowerDispatch13975 holds the
// timed-out head's terminal sink between finishFrame and retireFlow. Drain
// races in that gap; its same-key follower must remain fenced until retirement
// removes the flow, rather than becoming an orphaned pending request.
func TestTimeoutRetirementPreventsConcurrentFollowerDispatch13975(t *testing.T) {
	var registry OriginRegistry
	if err := registry.Register(77, CaptureOrigin{Family: CaptureFamilyInet, Hook: CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	sink := &blockedTerminalSink13975{started: make(chan struct{}), release: make(chan struct{})}
	submitter := new(pipelineTestSubmitter)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: &registry, Phase: PipelineEnforcing, Sink: sink,
		Submitter: submitter, LeaseMinter: &pipelineTestMinter{},
		ZoneEvaluator: passZoneEvaluator9506{}, ZoneSnapshot: passZoneSnapshot9506{},
		HandoffCap: 8, BatchCap: 4, AckDeadline: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{1, 2} {
		if err := p.Enqueue(CaptureFrame{
			Packet: pipelineTestPacket(77, 2, 2, 7, id), FlowKey: "concurrent-retire",
			Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1, FIBGeneration: 1,
			QueueNumber: 77, QueueEpoch: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.Drain(8); got != 2 {
		t.Fatalf("initial Drain = %d, want 2", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("initial submitted = %d, want 1", len(submitter.submitted))
	}
	p.mu.Lock()
	head := p.pending[submitter.submitted[0].Lease.RequestID]
	if head == nil {
		p.mu.Unlock()
		t.Fatal("missing admitted head")
	}
	head.deadlineMonoNS = 1
	head.deadlineArmed = true
	p.mu.Unlock()

	pollDone := make(chan int, 1)
	go func() { pollDone <- p.Poll(time.Now()) }()
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("timeout path did not reach blocked terminal sink")
	}
	// The old head has left flow.frames, but its uncertain transition is not
	// complete. A concurrent Drain must not submit the queued follower.
	if err := p.Enqueue(CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 3), FlowKey: "concurrent-retire",
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1, FIBGeneration: 1,
		QueueNumber: 77, QueueEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.Drain(8); got != 1 {
		t.Fatalf("racing Drain = %d, want 1", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted during retirement = %d, want 1 (follower must remain fenced)", len(submitter.submitted))
	}
	close(sink.release)
	select {
	case got := <-pollDone:
		if got != 1 {
			t.Fatalf("Poll resolved = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Poll did not finish after releasing terminal sink")
	}
	p.mu.Lock()
	flowCount, pendingCount := len(p.flows), len(p.pending)
	p.mu.Unlock()
	if flowCount != 0 || pendingCount != 0 {
		t.Fatalf("after retirement flows=%d pending=%d, want both zero", flowCount, pendingCount)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.verdicts) != 3 {
		t.Fatalf("terminal verdicts=%v, want head and both queued followers dropped", sink.verdicts)
	}
}
