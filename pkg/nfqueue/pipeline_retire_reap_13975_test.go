package nfqueue

import (
	"testing"
	"time"
)

// drainErrSubmitter13975 fails completion drains, driving Poll's
// failPending path (helper-restart class uncertainty).
type drainErrSubmitter13975 struct {
	pipelineTestSubmitter

	cancelErr error
}

func (s *drainErrSubmitter13975) DrainReinjectCompletions(uint32) ([]ReinjectCompletion, error) {
	return nil, errDrain13975
}

func (s *drainErrSubmitter13975) CancelReinject(ids []uint64, permit uint64, scopes []ReinjectQueueScope) ([]uint64, error) {
	s.cancelled = append(s.cancelled, ids...)
	return ids, s.cancelErr
}

var errDrain13975 = drainErr13975{}

type drainErr13975 struct{}

func (drainErr13975) Error() string { return "completion drain error" }

func setupRetirePipeline13975(t *testing.T, submitter ReinjectSubmitter) (*CapturePipeline, *pipelineTestSink) {
	t.Helper()
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: sink,
		Submitter: submitter, LeaseMinter: &pipelineTestMinter{},
		ZoneEvaluator: passZoneEvaluator9506{}, ZoneSnapshot: passZoneSnapshot9506{},
		HandoffCap: 16, BatchCap: 8, AckDeadline: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, sink
}

func enqueue13975(t *testing.T, p *CapturePipeline, flowKey string, id uint32) {
	t.Helper()
	frame := CaptureFrame{
		Packet:     pipelineTestPacket(77, 2, 2, 7, id),
		FlowKey: flowKey, QueueNumber: 77, QueueEpoch: 1,
		Generation: 1, SnapshotGeneration: 1, ConfigGeneration: 1, FIBGeneration: 1,
	}
	if err := p.Enqueue(frame); err != nil {
		t.Fatalf("Enqueue %d: %v", id, err)
	}
}

// TestRetiredFlowReapedAfterAckTimeoutWithFollower13975: head admitted,
// follower queued, head's ack deadline expires. Followers DROP once, the
// retired entry is reaped, and a later same-key packet is submitted
// fresh instead of being dropped into the tombstone forever.
func TestRetiredFlowReapedAfterAckTimeoutWithFollower13975(t *testing.T) {
	submitter := new(pipelineTestSubmitter)
	p, _ := setupRetirePipeline13975(t, submitter)
	enqueue13975(t, p, "retire-timeout", 1)
	enqueue13975(t, p, "retire-timeout", 2)
	if got := p.Drain(8); got != 2 {
		t.Fatalf("Drain = %d, want 2", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted = %d, want 1 (only the head)", len(submitter.submitted))
	}
	// Hold the follower queued behind the admitted head; expire the head.
	p.mu.Lock()
	head := p.pending[submitter.submitted[0].Lease.RequestID]
	if head == nil {
		p.mu.Unlock()
		t.Fatal("no pending head after admission")
	}
	head.deadlineMonoNS = 1
	head.deadlineArmed = true
	p.mu.Unlock()
	if resolved := p.Poll(time.Now()); resolved != 1 {
		t.Fatalf("Poll resolved = %d, want 1", resolved)
	}
	assertFlowsReaped13975(t, p)
	// Follower and head both terminal DROP exactly once each.
	assertVerdicts13975(t, p, 2)
	// A later packet of the same key starts a fresh flow.
	enqueue13975(t, p, "retire-timeout", 3)
	if got := p.Drain(8); got != 1 {
		t.Fatalf("Drain later = %d, want 1", got)
	}
	if len(submitter.submitted) != 2 {
		t.Fatalf("submitted = %d, want 2 (later packet re-submitted after retire)", len(submitter.submitted))
	}
}

// TestRetiredFlowReapedAfterDrainError13975 covers failPending: a
// completion-drain error retires every pending flow at once.
func TestRetiredFlowReapedAfterDrainError13975(t *testing.T) {
	submitter := new(drainErrSubmitter13975)
	p, _ := setupRetirePipeline13975(t, submitter)
	enqueue13975(t, p, "retire-drain", 1)
	enqueue13975(t, p, "retire-drain", 2)
	if got := p.Drain(8); got != 2 {
		t.Fatalf("Drain = %d, want 2", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted = %d, want 1", len(submitter.submitted))
	}
	// Drain already consumed; Poll hits the drain error -> failPending.
	p.Poll(time.Now())
	assertFlowsReaped13975(t, p)
	assertVerdicts13975(t, p, 2)
	enqueue13975(t, p, "retire-drain", 3)
	if got := p.Drain(8); got != 1 {
		t.Fatalf("Drain later = %d, want 1", got)
	}
	if len(submitter.submitted) != 2 {
		t.Fatalf("submitted = %d, want 2 after drain-error retire", len(submitter.submitted))
	}
}

// TestRetiredFlowReapedAfterSinkError13975 covers finishFrame's sink
// error branch: the uncertain head still retires its followers once.
func TestRetiredFlowReapedAfterSinkError13975(t *testing.T) {
	submitter := new(pipelineTestSubmitter)
	p, sink := setupRetirePipeline13975(t, submitter)
	enqueue13975(t, p, "retire-sink", 1)
	enqueue13975(t, p, "retire-sink", 2)
	if got := p.Drain(8); got != 2 {
		t.Fatalf("Drain = %d, want 2", got)
	}
	if len(submitter.submitted) != 1 {
		t.Fatalf("submitted = %d, want 1", len(submitter.submitted))
	}
	sink.err = errDrain13975
	head := submitter.submitted[0]
	submitter.drain = []ReinjectCompletion{{
		RequestID: head.Lease.RequestID, PermitEpoch: head.Lease.PermitEpoch,
		QueueNumber: head.Lease.QueueNumber, QueueEpoch: head.Lease.QueueEpoch,
		Outcome: CompletionWritten, BytesWritten: 2,
		Family: 1, Hook: 1, OwnedIfindex: 7,
	}}
	p.Poll(time.Now())
	assertFlowsReaped13975(t, p)
	enqueue13975(t, p, "retire-sink", 3)
	sink.err = nil
	if got := p.Drain(8); got != 1 {
		t.Fatalf("Drain later = %d, want 1", got)
	}
	if len(submitter.submitted) != 2 {
		t.Fatalf("submitted = %d, want 2 after sink-error retire", len(submitter.submitted))
	}
}

func assertVerdicts13975(t *testing.T, p *CapturePipeline, want int) {
	t.Helper()
	// Sink is not exposed; count via verdicts on the shared sink.
	// Reach it through terminal calls already made: use Stats Dropped +
	// verdict list length via the pipeline's sink interface.
	sink, ok := p.sink.(*pipelineTestSink)
	if !ok {
		t.Fatalf("sink type %T, want *pipelineTestSink", p.sink)
	}
	if len(sink.verdicts) != want {
		t.Fatalf("sink verdicts = %d, want %d (head + follower exactly once)", len(sink.verdicts), want)
	}
	for _, v := range sink.verdicts {
		if v.v != VerdictDrop {
			t.Fatalf("verdict = %v, want DROP", v.v)
		}
	}
}

func assertFlowsReaped13975(t *testing.T, p *CapturePipeline) {
	t.Helper()
	p.mu.Lock()
	n := len(p.flows)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("flows after retire = %d, want 0 and no retired tombstone", n)
	}
}
