package nfqueue

import (
	"reflect"
	"testing"
	"time"
)

// #13239: dead reassembly state and permanently-zero counters must not exist.
func TestCapturePipelineNoDeadReassemblyState13239(t *testing.T) {
	typ := reflect.TypeOf(CapturePipeline{})
	for _, field := range []string{"fragPool", "fragHolds", "fragTimes", "fragmentDeadline"} {
		if _, ok := typ.FieldByName(field); ok {
			t.Fatalf("CapturePipeline retains dead reassembly field %q", field)
		}
	}
	statsTyp := reflect.TypeOf(PipelineStats{})
	for _, field := range []string{"ZoneDivergences", "EventDecodeErrors", "InputAcceptErrors", "Submitted", "AdmissionsRefused", "Retries", "OverlapRefusals"} {
		if _, ok := statsTyp.FieldByName(field); ok {
			t.Fatalf("PipelineStats retains permanently-zero counter %q", field)
		}
	}
	frameTyp := reflect.TypeOf(CaptureFrame{})
	if _, ok := frameTyp.FieldByName("InnerOverlap"); ok {
		t.Fatal("CaptureFrame retains never-read InnerOverlap")
	}
	cfgTyp := reflect.TypeOf(CapturePipelineConfig{})
	for _, field := range []string{"Queues", "FragmentSlots", "FragmentPieces", "FragmentDeadline"} {
		if _, ok := cfgTyp.FieldByName(field); ok {
			t.Fatalf("CapturePipelineConfig retains dead fragment config %q", field)
		}
	}
}

// #13239: fragments remain fail-closed and never reach a reassembly pool,
// while Poll on a fragmentless pipeline resolves nothing.
func TestCapturePipelineFragmentDenyUnchanged13239(t *testing.T) {
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: sink,
		HandoffCap: 8, BatchCap: 8, FragmentTombstoneCap: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := FragmentKey{Version: 4, Protocol: 17, IfID: 7, Generation: 1, ID: 99}
	frag := Fragment{Offset: 0, More: true, Data: []byte("ab")}
	if err := p.Enqueue(CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "f", Generation: 1, FragmentKey: &key, Fragment: &frag}); err != nil {
		t.Fatal(err)
	}
	if n := p.Drain(1); n != 1 || len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("fragment Drain=%d verdicts=%+v, want 1 DROP", n, sink.verdicts)
	}
	if got := p.Poll(time.Now()); got != 0 {
		t.Fatalf("Poll=%d, want 0 with no pending fragments", got)
	}
	if got := p.Stats().FragmentDrops; got != 1 {
		t.Fatalf("FragmentDrops=%d, want 1", got)
	}
}
