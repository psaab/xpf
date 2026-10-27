package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16742 acceptance (a): open -> exporter-replacing reconcile -> close
// exports exactly one record. The replacement exporter inherits the
// open state via carryFlowState*Locked (same group key), so the close
// needs no second sampling slot and is not dropped.
// #16742 acceptance (b): a close with no open at rate 1 exports one
// record via the close-time fallback decision.
// Control: a close with no open at rate 2 whose fallback slot misses
// exports nothing; the next close (slot hits) exports.

// closeRaw16742 extends the canonical close payload to the full
// 168-byte SESSION_RT_FLOW frame (incl. the [148:152] egress ifindex)
// and stamps both interface indexes.
func closeRaw16742(srcPort uint16, trust, untrust uint32) []byte {
	buf := make([]byte, 168)
	copy(buf, buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, srcPort, 443, [4]byte{}, 0, uint16(trust), uint16(untrust)))
	binary.LittleEndian.PutUint32(buf[128:132], 11)
	binary.LittleEndian.PutUint32(buf[148:152], 12)
	return buf
}

func TestCloseAfterExporterReplacingReconcileExportsOnce16742(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port, port, "1")) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	if !d.eventReader.ProcessRawEvent(openRaw16303(23457, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("open rejected")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 23457, DstPort: 443, Protocol: 6}
	if b := d.v9Family().bundle.Load(); b == nil || !b.firstExp().Tracked(key) {
		t.Fatal("sampled open must be tracked before reconcile")
	}
	oldExp := d.v9Family().bundle.Load().firstExp()

	// Exporter-replacing reconcile: different collector port (hash
	// change) with the same instance/template/family group key.
	coll2, port2 := listenUDP(t)
	t.Cleanup(func() { coll2.Close() })
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port2, port2, "1")) {
		t.Fatal("replacing reconcile must apply")
	}
	newExp := d.v9Family().bundle.Load().firstExp()
	if newExp == nil || newExp == oldExp {
		t.Fatal("reconcile must swap to a new exporter")
	}
	if !newExp.Tracked(key) {
		t.Fatal("#16742: replacement exporter must inherit the open state (same group key)")
	}

	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 23457, 443, [4]byte{}, 0, uint16(trust), uint16(untrust))
	binary.LittleEndian.PutUint32(closeBuf[128:132], 11)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if got := waitFlows(t, newExp.Stats); got != 1 {
		t.Fatalf("replacement exporter flows = %d, want exactly 1", got)
	}
	// Exactly one: the retired source must not also export the close,
	// and no second record may appear after a flush window.
	time.Sleep(300 * time.Millisecond)
	if f, _ := newExp.Stats(); f != 1 {
		t.Fatalf("replacement exporter flows after settle = %d, want exactly 1", f)
	}
	if f, _ := oldExp.Stats(); f != 0 {
		t.Fatalf("retired exporter flows = %d, want 0 (close exported once, by replacement)", f)
	}
}

func TestCloseWithNoOpenAtRateOneExports16742(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port, port, "1")) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")

	// No open at all (failover / lost CREATE shape): close only.
	if !d.eventReader.ProcessRawEvent(closeRaw16742(23458, trust, untrust)) {
		t.Fatal("close rejected")
	}
	if got := waitFlows(t, d.v9Family().bundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("no-open close at rate 1: v9 flows = %d, want 1", got)
	}
	if got := waitFlows(t, d.ipfixFamily().bundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("no-open close at rate 1: ipfix flows = %d, want 1", got)
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 1 || s.Selected != 1 {
			t.Fatalf("close fallback sampling = %+v, want evaluated=1 selected=1 (one close-time decision per instance)", s)
		}
	}
}

func TestCloseWithNoOpenRateTwoFallbackCadence16742(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port, port, "2")) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	closeFor := func(port uint16) {
		if !d.eventReader.ProcessRawEvent(closeRaw16742(port, trust, untrust)) {
			t.Fatal("close rejected")
		}
	}
	// Rate 2: first no-open close consumes slot 1 (miss), second slot 2 (hit).
	closeFor(23459)
	closeFor(23460)
	if got := waitFlows(t, d.v9Family().bundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("rate-2 no-open closes: v9 flows = %d, want 1 (second close)", got)
	}
	for _, s := range d.FlowExportSamplingStats() {
		if s.Evaluated != 2 || s.Selected != 1 {
			t.Fatalf("close fallback cadence = %+v, want evaluated=2 selected=1", s)
		}
	}
}

func TestPromoteOpenFromSyncRegistersForExport16742(t *testing.T) {
	coll, port := listenUDP(t)
	t.Cleanup(func() { coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
	if !d.reconcileFlowExporters(openSamplingConfig16303(t, port, port, "1")) {
		t.Fatal("exporters must start")
	}
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	// Peer-synced open (promote): no SESSION_CREATE reaches the
	// EventReader; the sync delta is the only open signal.
	d.trackFlowOpenFromSync(dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 23461, DstPort: 443,
		IngressZoneID: uint16(trust), EgressZoneID: uint16(untrust),
		IngressIfindex: 11, EgressIfindex: 12,
	})
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 23461, DstPort: 443, Protocol: 6}
	if b := d.v9Family().bundle.Load(); b == nil || !b.firstExp().Tracked(key) {
		t.Fatal("#16742: promote open from sync must be tracked for flow export (no syslog CREATE)")
	}
	if b := d.ipfixFamily().bundle.Load(); b == nil || !b.firstExp().Tracked(key) {
		t.Fatal("#16742: promote open from sync must be tracked in ipfix too")
	}
	// Its close then exports via the recorded open (no fallback slot).
	closeBuf := buildSessionCloseRawEventV4(6, [4]byte{10, 0, 0, 102}, [4]byte{192, 0, 2, 200}, 23461, 443, [4]byte{}, 0, uint16(trust), uint16(untrust))
	binary.LittleEndian.PutUint32(closeBuf[128:132], 11)
	if !d.eventReader.ProcessRawEvent(closeBuf) {
		t.Fatal("close rejected")
	}
	if got := waitFlows(t, d.v9Family().bundle.Load().firstExp().Stats); got != 1 {
		t.Fatalf("promoted flow close: v9 flows = %d, want 1", got)
	}
}
