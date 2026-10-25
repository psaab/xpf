package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16303 F5 daemon integration: the live-counter poll must feed tracked
// flows from the session snapshot source (here the d.flowLiveCounters
// seam standing in for the dataplane session store) so the exporter
// timers see advancing cumulative counters — not just the close-time
// Touch. Continued traffic crosses the active timer with a cumulative
// interim, is not idle-removed while counters advance, and the real
// close exports only its own record (the tracker entry is already
// forgotten by CloseFlow, so nothing double-counts).

func TestFlowLiveFeedDrivesActiveInactive16303(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})

	// Mutable live snapshot the poll reads.
	type counters struct{ fp, fb, rp, rb uint64 }
	live := &counters{}
	d.flowLiveCounters = func(key flowexport.FlowKey) (uint64, uint64, uint64, uint64, bool) {
		return live.fp, live.fb, live.rp, live.rb, true
	}

	cfg := openSamplingConfig16303(t, v9Port, ipfixPort, "1")
	// Tighten the template timeouts so CollectDueExports is observable
	// without waiting real minutes: rebuild exporters with 2s/1s via the
	// config's template stanza is fixed at 60/15, so drive the tracker
	// clock directly through CollectDueExports below instead.
	if !d.reconcileFlowExporters(cfg) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(34567, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 34567, DstPort: 443, Protocol: 6}
	// The v4 group (not groups[0], which may be the v6 group) holds it.
	var exp *flowexport.Exporter
	for _, g := range d.flowBundle.Load().groups {
		if !g.ec.GroupIsV6 {
			exp = g.exp
		}
	}
	if exp == nil || !exp.Tracked(key) {
		t.Fatal("sampled open must be tracked")
	}
	now := time.Now()
	// Traffic advances; poll once (production cadence is the 1s loop,
	// driven synchronously here).
	live.fp, live.fb, live.rp, live.rb = 100, 10000, 40, 4000
	d.feedFlowLiveCounters(now)
	live.fp, live.fb, live.rp, live.rb = 200, 20000, 90, 9000
	d.feedFlowLiveCounters(now.Add(30 * time.Second))
	// Keep activity fresh inside the 15s inactive window of the collect
	// below (the poll's job in production).
	live.fp, live.fb, live.rp, live.rb = 210, 21000, 95, 9500
	d.feedFlowLiveCounters(time.Now().Add(50 * time.Second))

	// Active timer (60s per template): collect 61s after the open. The
	// interim must carry the live-fed cumulative counters.
	due := exp.CollectDueExports(time.Now().Add(61 * time.Second))
	if len(due) != 1 || due[0].Packets != 210 || due[0].RevPackets != 95 {
		t.Fatalf("active interim from live feed = %+v, want 1 record fwd=210 rev=95", due)
	}
	if !exp.Tracked(key) {
		t.Fatal("flow must stay tracked after active interim")
	}
	// Real close at cumulative 280/130: the exported close record must
	// be only the remainder past the interim (210/95 already emitted),
	// and the flow is forgotten, so a later collect adds nothing.
	live.fp, live.fb = 280, 28000
	d.feedFlowLiveCounters(now.Add(62 * time.Second))
	// Give the close event its lifetime counters.
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 34567, 443, [4]byte{}, 0, uint16(trust), uint16(untrust))
	binary.LittleEndian.PutUint64(closeBuf[56:64], 280)
	binary.LittleEndian.PutUint64(closeBuf[64:72], 28000)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if exp.Tracked(key) {
		t.Fatal("close must forget the tracked flow")
	}
	if due := exp.CollectDueExports(now.Add(200 * time.Second)); len(due) != 0 {
		t.Fatalf("post-close collect must be empty (no double count), got %+v", due)
	}
	// Both the interim and the close remainder flush: Stats counts
	// records, and the remainder record proves the close exported once.
	if got := waitFlows(t, exp.Stats); got < 2 {
		t.Fatalf("exported records = %d, want >=2 (interim + close remainder)", got)
	}
}
