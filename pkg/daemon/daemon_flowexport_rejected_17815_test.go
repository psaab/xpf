package daemon

import (
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #17815: an open observed and REJECTED by the instance's 1-in-N
// sampling decision must not be re-sampled as an orphan at close.
// A rejected open currently records no state (trackFlowOpen marks
// state only when SampledForOpen returns true), so HasFlowState is
// false at close and the #16742 close-time fallback consumes a
// SECOND sampling slot. At rate 2 every eligible flow then exports
// (open consumes slot 1 and is rejected; close consumes slot 2
// and is selected), corrupting the advertised 1-in-2 rate.
// Genuine orphan closes (no open observed at all) must still get
// exactly one close-time decision (#16742), and opens selected at
// open must still export their close with no second slot.

func rejectedTestDaemon(t *testing.T, rate string) *Daemon {
	t.Helper()
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port, port, rate)) {
		t.Fatal("exporters must start")
	}
	return d
}

func samplingTotals17815(t *testing.T, d *Daemon) (evaluated, selected uint64) {
	t.Helper()
	// Template groups and the two protocol bundles duplicate the
	// SAME per-instance ExportConfig stats; sum per distinct
	// (protocol, instance) row and take it as the instance total:
	// v9 and IPFIX each evaluate the open once per bundle, so the
	// per-instance contract is what the v9 row reports alone. This
	// helper instead sums both protocols and callers compare
	// deltas against that combined cadence.
	for _, s := range d.FlowExportSamplingStats() {
		evaluated += s.Evaluated
		selected += s.Selected
	}
	return evaluated, selected
}

func openClose17815(t *testing.T, d *Daemon, srcPort uint16, trust, untrust uint32) {
	t.Helper()
	if !d.eventReader.ProcessRawEvent(openRaw16303(srcPort, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	closeBuf := closeRaw16742(srcPort, trust, untrust)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
}

// Core RED: rate 2, two eligible opens with closes. Pair 1's open
// consumes slot 1 and is rejected; its close must not consume slot
// 2. Pair 2 therefore consumes slot 2 and is selected. Exactly one
// flow may export, and each protocol bundle makes only one decision
// per open.
func TestRejectedOpenCloseDoesNotResample17815(t *testing.T) {
	d := rejectedTestDaemon(t, "2")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	openClose17815(t, d, 24001, trust, untrust)
	time.Sleep(300 * time.Millisecond)
	if f, _ := d.flowBundle.Load().firstExp().Stats(); f != 0 {
		t.Fatalf("v9 flows after rejected-open close = %d, want 0 (close must not consume slot 2)", f)
	}
	if ev, sel := samplingTotals17815(t, d); ev != 2 || sel != 0 {
		t.Fatalf("sampling after rejected-open close = %d/%d, want 2/0", ev, sel)
	}

	openClose17815(t, d, 24002, trust, untrust)
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("v9 flows after next sampled open close = %d, want 1", got)
	}
	if ev, sel := samplingTotals17815(t, d); ev != 4 || sel != 2 {
		t.Fatalf("sampling after second open = %d/%d, want 4/2 (one decision per open per protocol)", ev, sel)
	}
}

// Replacement-carry RED: a rejected open -> exporter-replacing
// reconcile -> close must still not re-sample. The negative decision
// is live flow state and must travel to the replacement exactly like
// the positive sampled mark does (#16742 carry).
func TestRejectedOpenSurvivesExporterReplacement17815(t *testing.T) {
	d := rejectedTestDaemon(t, "2")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	if !d.eventReader.ProcessRawEvent(openRaw16303(24011, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24011, DstPort: 443, Protocol: 6}
	oldExp := d.flowBundle.Load().firstExp()

	coll2, port2 := listenUDP(t)
	t.Cleanup(func() { coll2.Close() })
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port2, port2, "2")) {
		t.Fatal("replacing reconcile must apply")
	}
	newExp := d.flowBundle.Load().firstExp()
	if newExp == oldExp {
		t.Fatal("reconcile must replace exporter")
	}
	if !newExp.HasFlowState(key) {
		t.Fatal("replacement exporter must inherit the rejected open decision")
	}
	// Consume slot 1 in the replacement's fresh sampling counter. If
	// the rejected marker was not carried, this old flow's close now
	// consumes slot 2 and is incorrectly selected.
	if !d.eventReader.ProcessRawEvent(openRaw16303(24012, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("control open rejected")
	}
	closeBuf := closeRaw16742(24011, trust, untrust)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}

	time.Sleep(300 * time.Millisecond)
	if f, _ := newExp.Stats(); f != 0 {
		t.Fatalf("replacement v9 flows = %d, want 0 (rejected open remains rejected)", f)
	}
	if ev, sel := samplingTotals17815(t, d); ev != 2 || sel != 0 {
		t.Fatalf("replacement sampling = %d/%d, want 2/0 (only control opens; rejected close consumes no slot)", ev, sel)
	}
}

// Duplicate-sync RED (B): the HA sync walker re-registers an
// already-decided flow. A local SESSION_OPEN that was REJECTED
// (slot 1) followed by a peer-sync delta for the same flow must
// not consume a second decision (which at rate 2 would land on
// slot 2 and track the flow). Its close then exports nothing.
func TestSyncDuplicateOfRejectedOpenDoesNotResample17815(t *testing.T) {
	d := rejectedTestDaemon(t, "2")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	// Local open: slot 1, rejected.
	if !d.eventReader.ProcessRawEvent(openRaw16303(24021, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	// Same flow re-enters through the sync/promote path (sender-side
	// walker shape): must be a no-op for sampling purposes.
	d.trackFlowOpenFromSync(dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24021, DstPort: 443,
		IngressZoneID: uint16(trust), EgressZoneID: uint16(untrust),
		IngressIfindex: 11, EgressIfindex: 12,
	})
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24021, DstPort: 443, Protocol: 6}
	if d.flowBundle.Load().firstExp().Tracked(key) {
		t.Fatal("#17815: sync duplicate of a sampling-rejected open must not track it (second decision selected it)")
	}
	ev, sel := samplingTotals17815(t, d)
	if ev != 2 || sel != 0 {
		t.Fatalf("sampling evaluated=%d selected=%d, want 2/0 (one open decision per bundle; duplicate sync must not re-decide)", ev, sel)
	}
	// Its close must also export nothing (decided: rejected).
	closeBuf := closeRaw16742(24021, trust, untrust)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}

	time.Sleep(300 * time.Millisecond)
	if f, _ := d.flowBundle.Load().firstExp().Stats(); f != 0 {
		t.Fatalf("v9 flows = %d, want 0", f)
	}
}

// Sampled-sync control: a sync open for a flow with NO prior local
// decision is the legitimate #16742 promote arm — it makes the
// instance's one decision and, when selected (rate 1), tracks so
// the close exports. Repeated sync re-registration of that same
// (now tracked) flow must not reset/duplicate the decision.
func TestSyncOpenRegistersOnceWhenUndecided17815(t *testing.T) {
	d := rejectedTestDaemon(t, "1")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	delta := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24031, DstPort: 443,
		IngressZoneID: uint16(trust), EgressZoneID: uint16(untrust),
		IngressIfindex: 11, EgressIfindex: 12,
	}
	d.trackFlowOpenFromSync(delta)
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24031, DstPort: 443, Protocol: 6}
	if !d.flowBundle.Load().firstExp().Tracked(key) {
		t.Fatal("promote open from sync must be tracked (rate 1)")
	}
	// Duplicate registration (update delta / re-walk): no new
	// sampling decision may be consumed for the decided flow.
	d.trackFlowOpenFromSync(delta)
	ev, sel := samplingTotals17815(t, d)
	if ev != 2 || sel != 2 {
		t.Fatalf("sampling evaluated=%d selected=%d, want 2/2 (one decision per bundle total; duplicate sync re-registration must not re-decide)", ev, sel)
	}
	closeBuf := closeRaw16742(24031, trust, untrust)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("promoted flow close: v9 flows = %d, want 1", got)
	}
}

// Interface-scope RED (C): a nameless sync open falls back to zone
// sampling and broadens a sampled interface's output permission to
// an unsampled zone-mate. Keep the flow's actual egress interface
// unsampled while a sibling in the same zone has sampling output.
func TestSyncOpenRetainsInterfaceScope17815(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{
		11: "ge-0/0/0.0", // trust ingress
		12: "ge-0/0/2.0", // sampled output member of untrust
		14: "ge-0/0/4.0", // unsampled output member of untrust
	})
	text := `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/2 { unit 0 { family inet { address 192.0.2.1/24; sampling { output; } } } }
    ge-0/0/4 { unit 0 { family inet { address 192.0.2.2/24; } } }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone untrust { interfaces { ge-0/0/2.0; ge-0/0/4.0; } }
    }
}
forwarding-options {
    sampling {
        instance s {
            input { rate 1; }
            family inet {
                output {
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(port) + `; version9; }
                    flow-server 127.0.0.1 { port ` + strconv.Itoa(port) + `; version-ipfix; }
                }
            }
        }
    }
}
services {
    flow-monitoring {
        version9 { template t { flow-active-timeout 60; flow-inactive-timeout 15; } }
        version-ipfix { template t { flow-active-timeout 60; flow-inactive-timeout 15; } }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !d.reconcileFlowExporters(cfg) {
		t.Fatal("exporters must start")
	}

	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	d.trackFlowOpenFromSync(dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24041, DstPort: 443,
		IngressZoneID: uint16(trust), EgressZoneID: uint16(untrust),
		IngressIfindex: 11, EgressIfindex: 14,
	})
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24041, DstPort: 443, Protocol: 6}
	if d.flowBundle.Load().firstExp().Tracked(key) {
		t.Fatal("#17815: sync open on an unsampled interface must not be admitted via its sampled zone-mate")
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 0 || s.Selected != 0 || s.ZoneFiltered != 1 {
			t.Fatalf("sampling stats = %+v, want evaluated=0 selected=0 zone_filtered=1", s)
		}
	}
}
