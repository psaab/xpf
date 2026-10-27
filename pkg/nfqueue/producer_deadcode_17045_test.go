package nfqueue

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

// #17045: the fragment-reassembly consumer was removed by #13239, so the
// production package must not carry the producer/pool/sink/batch apparatus.
// These are reflection/source-shape pins: they fail while any named
// production symbol remains reachable from package nfqueue's non-test files.
func TestNoDeadFragmentProducer17045(t *testing.T) {
	classTyp := reflect.TypeOf(CaptureClassification{})
	if _, ok := classTyp.MethodByName("FragmentPiece"); ok {
		t.Fatal("CaptureClassification still has FragmentPiece producer")
	}
	frameTyp := reflect.TypeOf(CaptureFrame{})
	if _, ok := frameTyp.FieldByName("Fragment"); ok {
		t.Fatal("CaptureFrame still carries Fragment *Fragment")
	}
	if _, ok := frameTyp.FieldByName("FragmentMalformed"); !ok {
		t.Fatal("CaptureFrame lacks FragmentMalformed replacement")
	}
	// Fields consumers actually read must remain.
	for _, f := range []string{"Version", "Proto", "Src", "Dst", "HasPorts", "SrcPort", "DstPort", "IsFragment", "FragMore", "FragOffset", "FragID", "FlowKey"} {
		if _, ok := reflect.TypeOf(CaptureClassification{}).FieldByName(f); !ok {
			t.Fatalf("CaptureClassification lost live field %q", f)
		}
	}
	if _, ok := reflect.TypeOf(CaptureClassification{}).MethodByName("FragmentKey"); !ok {
		t.Fatal("CaptureClassification lost FragmentKey (pipeline tombstone identity)")
	}
}

func TestCapturePipelineFragmentFlagDeny17045(t *testing.T) {
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry: pipelineTestRegistry(t), Phase: PipelineEnforcing, Sink: sink,
		HandoffCap: 8, BatchCap: 8, FragmentTombstoneCap: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := FragmentKey{Version: 4, Protocol: 17, IfID: 7, Generation: 1, ID: 17045}
	if err := p.Enqueue(CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 1), FlowKey: "f", Generation: 1, FragmentKey: &key, FragmentMalformed: true}); err != nil {
		t.Fatal(err)
	}
	if n := p.Drain(1); n != 1 || len(sink.verdicts) != 1 || sink.verdicts[0].v != VerdictDrop {
		t.Fatalf("flagged fragment Drain=%d verdicts=%+v, want 1 DROP", n, sink.verdicts)
	}
	if got := p.Stats().FragmentMetadataErrors; got != 1 {
		t.Fatalf("FragmentMetadataErrors=%d, want 1 for malformed-flagged frame", got)
	}
	// Key-only frame (well-formed fragment) still denies without metadata error.
	if err := p.Enqueue(CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, 2), FlowKey: "f", Generation: 1, FragmentKey: &key}); err != nil {
		t.Fatal(err)
	}
	if n := p.Drain(1); n != 1 || len(sink.verdicts) != 2 || sink.verdicts[1].v != VerdictDrop {
		t.Fatalf("key-only fragment Drain=%d verdicts=%+v, want DROP", n, sink.verdicts)
	}
	if got := p.Stats().FragmentMetadataErrors; got != 1 {
		t.Fatalf("FragmentMetadataErrors=%d, want still 1", got)
	}
}

func benchFragmentPacket17045() []byte {
	src, dst := net.ParseIP("10.1.0.1"), net.ParseIP("10.1.0.2")
	extra := []byte{0x00, 0x35, 0x00, 0x35, 0xaa, 0xbb}
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(extra)))
	binary.BigEndian.PutUint16(hdr[4:6], 77)
	binary.BigEndian.PutUint16(hdr[6:8], 0x2000)
	hdr[8] = 64
	hdr[9] = 17
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	return append(hdr, extra...)
}

func BenchmarkClassifyFragment17045(b *testing.B) {
	pkt := benchFragmentPacket17045()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := ClassifyCapturePayload(pkt)
		if err != nil || !c.IsFragment || !c.HasPayload() {
			b.Fatalf("classify: %+v %v", c, err)
		}
		if _, ok := c.FragmentKey(1, 0, 1); !ok {
			b.Fatal("no key")
		}
	}
}
