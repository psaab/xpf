package flowexport

import (
	"errors"
	"testing"
)

// writeAll's result gates exportedFlows/exportedPkts, so an operator watching
// Stats no longer sees "exported" growth while every datagram hits the floor.
//
// FAIL-ON-REVERT: revert the success gate (unconditional Add after writeAll)
// and the AllCollectorsFailed tests below go RED — Stats reports (1,1) for a
// batch no collector received.

func TestNetflowExportedNotCountedWhenAllCollectorsFail(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	e, err := NewExporter(&ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmpl10713",
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer e.Close()

	// Replace the dialed conns with deterministically-failing fakes.
	bad1 := &writeFakeConn{}
	bad2 := &writeFakeConn{}
	sentinel := errors.New("collector down")
	bad1.setErr(sentinel)
	bad2.setErr(sentinel)
	e.conns.close()

	e.sendRecords(mkRec())

	flows, pkts := e.Stats()
	if flows != 0 || pkts != 0 {
		t.Fatalf("all collectors failed: exported = (%d flows, %d pkts), want (0, 0) (#10713)", flows, pkts)
	}
	h := e.conns.health()
	for i, hc := range h {
		if hc.WriteFailures == 0 {
			t.Fatalf("collector %d: WriteFailures = 0, want >0 (writes must still be attempted)", i)
		}
	}
}

func TestIPFIXExportedNotCountedWhenAllCollectorsFail(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	e, err := NewIPFIXExporter(&ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmpl10713",
	})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	defer e.Close()

	bad1 := &writeFakeConn{}
	bad2 := &writeFakeConn{}
	sentinel := errors.New("collector down")
	bad1.setErr(sentinel)
	bad2.setErr(sentinel)
	e.conns.close()
	e.conns = newHealthTestConns([]string{"bad1:9999", "bad2:9999"}, []*writeFakeConn{bad1, bad2})

	e.sendRecords(mkRec())

	flows, pkts := e.Stats()
	if flows != 0 || pkts != 0 {
		t.Fatalf("all collectors failed: exported = (%d flows, %d pkts), want (0, 0) (#10713)", flows, pkts)
	}
	h := e.conns.health()
	for i, hc := range h {
		if hc.WriteFailures == 0 {
			t.Fatalf("collector %d: WriteFailures = 0, want >0 (writes must still be attempted)", i)
		}
	}
}

// Partial delivery still counts: one reachable collector out of two means the
// batch WAS exported (>=1 success gate). Documents the gate semantics so a
// future "all must succeed" regression goes RED.
func TestNetflowExportedCountedOnPartialSuccess(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	e, err := NewExporter(&ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmpl10713",
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer e.Close()

	bad := &writeFakeConn{}
	good := &writeFakeConn{}
	bad.setErr(errors.New("collector down"))
	e.conns.close()
	e.conns = newHealthTestConns([]string{"bad:9999", "good:9999"}, []*writeFakeConn{bad, good})

	e.sendRecords(mkRec())

	flows, pkts := e.Stats()
	if flows != 1 || pkts != 1 {
		t.Fatalf("partial success: exported = (%d flows, %d pkts), want (1, 1)", flows, pkts)
	}
}

func TestIPFIXExportedCountedOnPartialSuccess(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	e, err := NewIPFIXExporter(&ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmpl10713",
	})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	defer e.Close()

	bad := &writeFakeConn{}
	good := &writeFakeConn{}
	bad.setErr(errors.New("collector down"))
	e.conns.close()
	e.conns = newHealthTestConns([]string{"bad:9999", "good:9999"}, []*writeFakeConn{bad, good})
	e.sendRecords(mkRec())

	flows, pkts := e.Stats()
	if flows != 1 || pkts != 1 {
		t.Fatalf("partial success: exported = (%d flows, %d pkts), want (1, 1)", flows, pkts)
	}
}
