package logging

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15679 regression: TraceWriter compared rendered strings via normalizeTraceProto
// (only tcp/udp/icmp/icmpv6 knew their numbers), so a numeric "47" or named "ospf"
// filter never matched its records, and a bogus protocol widened to any. The writer
// now resolves via appid.ProtocolNumber into protoNum and compares rec.ProtocolNum.
func TestTraceProto15679NumericNamed(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()
	mk := func(pf *config.TracePacketFilter) *TraceWriter {
		tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rt.log", PacketFilters: []*config.TracePacketFilter{pf}})
		if err != nil {
			t.Fatalf("NewTraceWriter: %v", err)
		}
		t.Cleanup(tw.Close)
		return tw
	}
	// numeric 47 (GRE) must match ProtocolNum 47, not 6
	tw := mk(&config.TracePacketFilter{Name: "pf1", Protocol: "47"})
	if !tw.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "47", ProtocolNum: 47}) {
		t.Fatalf("numeric GRE filter did not match GRE record")
	}
	if tw.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "TCP", ProtocolNum: 6}) {
		t.Fatalf("numeric GRE filter matched TCP")
	}
	// named ospf (89)
	tw2 := mk(&config.TracePacketFilter{Name: "pf1", Protocol: "ospf"})
	if !tw2.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "89", ProtocolNum: 89}) {
		t.Fatalf("named ospf did not match 89")
	}
	if tw2.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "TCP", ProtocolNum: 6}) {
		t.Fatalf("ospf matched TCP")
	}
	// bogus / empty-protocol-with-InvalidPrefix must match none (compiler marks it; runtime via struct directly bogus)
	tw3 := mk(&config.TracePacketFilter{Name: "pf1", Protocol: "bogus"})
	if tw3.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "TCP", ProtocolNum: 6}) {
		t.Fatalf("bogus protocol matched")
	}
	// legacy record: ProtocolNum 0 fallback to rendered name
	tw4 := mk(&config.TracePacketFilter{Name: "pf1", Protocol: "tcp"})
	if !tw4.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "TCP", ProtocolNum: 0}) {
		t.Fatalf("legacy TCP record did not match tcp filter")
	}
	// explicit proto 0 filter (hand-built) must match only proto-0 records
	tw5 := mk(&config.TracePacketFilter{Name: "pf1", Protocol: "0"})
	if !tw5.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "0", ProtocolNum: 0}) {
		t.Fatalf("proto 0 filter did not match proto0 record (legacy fallback ambiguous?)")
	}
	if tw5.matchFilters(EventRecord{SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", Protocol: "TCP", ProtocolNum: 6}) {
		t.Fatalf("proto0 matched TCP")
	}
}
