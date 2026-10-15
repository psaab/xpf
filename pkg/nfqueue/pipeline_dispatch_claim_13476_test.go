package nfqueue

import (
	"sync"
	"testing"
	"time"
)

type blockingDispatchEvaluator13476 struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func (e *blockingDispatchEvaluator13476) Evaluate(CaptureOrigin, ZoneSnapshotRef) ZoneEvaluation {
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.mu.Unlock()
	if call == 1 {
		e.once.Do(func() { close(e.entered) })
		<-e.release
	}
	return ZoneEvaluation{Decision: ZonePass, ZoneID: 1, IfID: 7, Reason: ZoneReasonZoned}
}

type concurrentVerdictSink13476 struct {
	mu    sync.Mutex
	calls int
}

func (s *concurrentVerdictSink13476) Verdict(*Packet, Verdict) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return nil
}

func TestCapturePipelineConcurrentDispatchClaimsFlowHead13476(t *testing.T) {
	evaluator := &blockingDispatchEvaluator13476{entered: make(chan struct{}), release: make(chan struct{})}
	sink := new(concurrentVerdictSink13476)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      pipelineTestRegistry(t),
		Phase:         PipelineShadow,
		Sink:          sink,
		ZoneEvaluator: evaluator,
		ZoneSnapshot:  passZoneSnapshot9506{},
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	frame := CaptureFrame{
		Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "same-flow",
		SnapshotGeneration: 1, ConfigGeneration: 1, FIBGeneration: 1,
		QueueNumber: 77, QueueEpoch: 1,
	}
	frame.phase = PipelineShadow
	p.mu.Lock()
	p.flows[frame.FlowKey] = &flowState{frames: []CaptureFrame{frame}}
	p.mu.Unlock()

	firstDone := make(chan struct{})
	go func() {
		p.dispatchEligible()
		close(firstDone)
	}()
	select {
	case <-evaluator.entered:
	case <-time.After(5 * time.Second):
		close(evaluator.release)
		t.Fatal("first dispatch did not enter zone evaluation")
	}
	p.dispatchEligible()
	close(evaluator.release)
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first dispatch did not finish")
	}

	evaluator.mu.Lock()
	evaluations := evaluator.calls
	evaluator.mu.Unlock()
	sink.mu.Lock()
	verdicts := sink.calls
	sink.mu.Unlock()
	if evaluations != 1 || verdicts != 1 {
		t.Fatalf("concurrent dispatch evaluated %d times and terminalized %d times, want 1 each", evaluations, verdicts)
	}
}
