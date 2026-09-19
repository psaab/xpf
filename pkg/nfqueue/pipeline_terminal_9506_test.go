package nfqueue

import (
	"errors"
	"testing"
)

func TestCapturePipelineSinkErrorNeverReplaysShadowFrame9506(t *testing.T) {
	sink := &pipelineTestSink{err: errors.New("ambiguous sink transport")}
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineShadow, Sink: sink,
		HandoffCap: 2, BatchCap: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 91), FlowKey: "sink-error"}
	if err := p.Enqueue(frame); err != nil {
		t.Fatal(err)
	}
	n := p.Drain(1)
	if n != 1 || sink.calls != 1 {
		t.Fatalf("initial drain=%d sink calls=%d, want one terminal attempt", n, sink.calls)
	}
	if got := p.Drain(1); got != 0 {
		t.Fatalf("sink error replayed shadow frame: drain=%d", got)
	}
}
