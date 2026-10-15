package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/logging"
)

// buildSessionCloseRawEventV4 builds the canonical 136-byte dataplane.Event
// RT_FLOW payload for a SESSION_CLOSE, byte-for-byte mirroring the Rust
// EventFrame::encode_session_close_rt_flow encoder
// (userspace-dp/src/event_stream/codec.rs). This is the #2460 cross-language
// wire-parity anchor: the offsets/endianness here MUST match the Rust
// encoder, and the resulting bytes MUST decode to a Type=="SESSION_CLOSE"
// EventRecord via logging.DecodeRawEventRecord / EventReader.ProcessRawEvent.
//
// Volume counters (offsets 56/64/112/120) and the created stamp (offset 108)
// are intentionally 0 — this fixture exercises the DECODE path, and zero is a
// legitimate wire value there.
//
// This comment previously said the dataplane "does not yet maintain
// per-session byte/packet accounting (tracked in #2501)". That stopped being
// true: userspace-dp/src/event_stream/codec/rt_flow.rs writes offsets 56 and
// 64 from "real per-session forward volume harvested from the closing entry's
// worker-owned counters", tagged #2501 in that file. #2501 is closed and the
// work landed.
//
// Corrected under #8942, which is about this exact failure: a deferral comment
// whose tracker is closed. It has two directions — the residual is still live
// and now tracked nowhere, or (as here) the residual was DONE and the comment
// still tells a reader the capability is missing. The second misleads about
// current behaviour, which is how someone designs around an absence that is not
// there.
func buildSessionCloseRawEventV4(
	proto uint8,
	srcIP, dstIP [4]byte,
	srcPort, dstPort uint16,
	natSrcIP [4]byte,
	natSrcPort uint16,
	ingressZone, egressZone uint16,
) []byte {
	buf := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
	// [8:12] src ip, [24:28] dst ip (16-byte slots, v4 left-aligned).
	copy(buf[8:12], srcIP[:])
	copy(buf[24:28], dstIP[:])
	// [40:42] src port, [42:44] dst port — BIG-endian.
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	// [48:50] ingress zone, [50:52] egress zone — little-endian.
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	// [52] event type = SESSION_CLOSE (2); [53] protocol; [55] addr family.
	buf[52] = dataplane.EventTypeSessionClose
	buf[53] = proto
	buf[55] = dataplane.AFInet
	// [72:76] nat src ip, [104:106] nat src port (BIG-endian).
	copy(buf[72:76], natSrcIP[:])
	binary.BigEndian.PutUint16(buf[104:106], natSrcPort)
	return buf
}

// flowIPFIXConfigPorts builds a sampling config with the v9 and IPFIX
// collectors bound to caller-chosen ports (so a test can bind a real UDP
// listener for each and observe the transmitted datagram). rate=1 so
// ShouldExport always admits the close.
func flowIPFIXConfigPorts(addr string, v9Port, ipfixPort int) *config.Config {
	cfg := flowSamplingConfig(addr, 1)
	fam := cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet
	fam.FlowServers[0].Port = v9Port
	fam.FlowServers[0].Version = config.FlowServerVersion9
	fam.FlowServers = append(fam.FlowServers, &config.FlowServer{
		Address: addr, Port: ipfixPort, Version: config.FlowServerVersionIPFIX,
	})
	cfg.Services.FlowMonitoring.VersionIPFIX = &config.NetFlowIPFIXConfig{
		Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}},
	}
	return cfg
}

// listenUDP binds a UDP socket on 127.0.0.1:0 and returns it plus its port.
func listenUDP(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// waitFlows polls an exporter's Stats() until it reports at least one
// EXPORTED FLOW RECORD (not a template — Stats.flows increments only in
// sendRecords, never in sendTemplates), or the 3s deadline elapses. The
// v9/IPFIX exporters flush queued records on a 100ms ticker started by
// reconcile, so a SESSION_CLOSE admitted by ShouldExport becomes an
// exported flow well within the deadline. A non-zero flow count is
// close-specific: it proves the SESSION_CLOSE-derived FlowRecord reached
// the real exporter and was transmitted, distinct from the unconditional
// startup template datagram.
func waitFlows(t *testing.T, stats func() (uint64, uint64)) uint64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if flows, _ := stats(); flows >= 1 {
			return flows
		}
		time.Sleep(10 * time.Millisecond)
	}
	flows, _ := stats()
	return flows
}

// TestSessionCloseRawEventDrivesFlowExport is the #2460 end-to-end (P1)
// assertion: a userspace SESSION_CLOSE RT_FLOW event delivered on the raw
// dataplane-event channel (exactly the path SetOnRawDataplaneEvent ->
// eventReader.ProcessRawEvent uses for the EventFrameTypeSessionClose frame)
// produces exactly one Type=="SESSION_CLOSE" EventRecord that reaches BOTH
// the NetFlow v9 and IPFIX flow-export callbacks, carrying the correct
// 5-tuple. It proves "both callbacks" two ways:
//
//  1. The two REAL exporters (flowExportCallback / ipfixExportCallback,
//     registered by reconcile) are bound to real UDP collectors and each
//     transmits a datagram for the admitted close — proving the record
//     truly reaches both production export paths, not just a spy.
//  2. Two distinct fanout callbacks gating identically on
//     rec.Type=="SESSION_CLOSE" (standing in for the NetFlow and IPFIX
//     consumers) BOTH fire exactly once with the correct tuple — the
//     deterministic content assertion the datagram-receipt cannot give.
//
// Volume counters are 0 (P2/#2501), asserted explicitly.
//
// Fail-on-revert: without the helper emitting the type-14 SESSION_CLOSE
// frame, no SESSION_CLOSE EventRecord is ever produced in userspace mode, so
// the flowExportCallback / ipfixExportCallback early-return on
// rec.Type != "SESSION_CLOSE" and never fire — exactly the #2460 defect.
// Dropping EITHER fanout callback registration drops its fire count to 0.
func TestSessionCloseRawEventDrivesFlowExport(t *testing.T) {
	v9Coll, v9Port := listenUDP(t)
	t.Cleanup(func() { v9Coll.Close() })
	ipfixColl, ipfixPort := listenUDP(t)
	t.Cleanup(func() { ipfixColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(flowIPFIXConfigPorts("127.0.0.1", v9Port, ipfixPort)) {
		t.Fatal("flow + ipfix exporters must start")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("v9 exporter must be live")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("ipfix exporter must be live")
	}
	// The two real export callbacks are registered exactly once.
	if n := d.eventReader.CallbackCount(); n != 2 {
		t.Fatalf("expected 2 real export callbacks (v9 + ipfix), got %d", n)
	}

	// Two distinct fanout callbacks standing in for the NetFlow and IPFIX
	// SESSION_CLOSE consumers — registered AFTER the two real callbacks so
	// all four see the record. Dropping either makes its count 0
	// (fail-on-revert for the "both callbacks" claim).
	var netflowFires, ipfixFires int
	var seen logging.EventRecord
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		netflowFires++
		seen = rec
	})
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		ipfixFires++
	})

	payload := buildSessionCloseRawEventV4(
		6, // TCP
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{172, 16, 80, 8}, 40000,
		2, 3, // trust -> untrust
	)

	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE payload")
	}

	// Both SESSION_CLOSE-gated consumers fire exactly once.
	if netflowFires != 1 {
		t.Fatalf("NetFlow SESSION_CLOSE callback fired %d times, want 1", netflowFires)
	}
	if ipfixFires != 1 {
		t.Fatalf("IPFIX SESSION_CLOSE callback fired %d times, want 1", ipfixFires)
	}

	// Both REAL exporters export a flow record for the close — proving the
	// SESSION_CLOSE-derived FlowRecord reaches both production export paths
	// (Stats.flows counts data records, not templates).
	if got := waitFlows(t, d.flowBundle.Load().firstExp().Stats); got < 1 {
		t.Fatalf("NetFlow v9 exporter exported %d flows after the SESSION_CLOSE, want >= 1", got)
	}
	if got := waitFlows(t, d.ipfixBundlePtr.Load().firstExp().Stats); got < 1 {
		t.Fatalf("IPFIX exporter exported %d flows after the SESSION_CLOSE, want >= 1", got)
	}

	// The daemon snapshot used by Prometheus must carry the same live
	// successful-write counts from both exporters.
	netflowFlows, netflowPackets := d.flowBundle.Load().firstExp().Stats()
	ipfixFlows, ipfixPackets := d.ipfixBundlePtr.Load().firstExp().Stats()
	if netflowFlows == 0 || netflowPackets == 0 {
		t.Fatalf("NetFlow v9 exporter counts = %d/%d, want nonzero flows and packets", netflowFlows, netflowPackets)
	}
	if ipfixFlows == 0 || ipfixPackets == 0 {
		t.Fatalf("IPFIX exporter counts = %d/%d, want nonzero flows and packets", ipfixFlows, ipfixPackets)
	}
	wantCounts := map[string][2]uint64{
		"netflow-v9": {netflowFlows, netflowPackets},
		"ipfix":      {ipfixFlows, ipfixPackets},
	}
	for protocol, want := range wantCounts {
		found := false
		for _, stats := range d.FlowExportBatchStats() {
			if stats.Protocol != protocol {
				continue
			}
			found = true
			if stats.ExportedFlows != want[0] || stats.ExportedPackets != want[1] {
				t.Errorf("%s batch stats exported flows/packets = %d/%d, want %d/%d",
					protocol, stats.ExportedFlows, stats.ExportedPackets, want[0], want[1])
			}
		}
		if !found {
			t.Errorf("%s missing from FlowExportBatchStats", protocol)
		}
	}

	// Record content (the deterministic boundary assertion).
	rec := seen
	if rec.Type != "SESSION_CLOSE" {
		t.Fatalf("Type = %q, want SESSION_CLOSE", rec.Type)
	}
	if rec.SrcAddr != "10.0.1.102:12345" {
		t.Fatalf("SrcAddr = %q, want 10.0.1.102:12345", rec.SrcAddr)
	}
	if rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("DstAddr = %q, want 172.16.80.200:443", rec.DstAddr)
	}
	if rec.Protocol != "TCP" {
		t.Fatalf("Protocol = %q, want TCP", rec.Protocol)
	}
	if rec.NATSrcAddr != "172.16.80.8:40000" {
		t.Fatalf("NATSrcAddr = %q, want 172.16.80.8:40000", rec.NATSrcAddr)
	}
	if rec.InZone != 2 || rec.OutZone != 3 {
		t.Fatalf("zones = (%d,%d), want (2,3)", rec.InZone, rec.OutZone)
	}
	// #2501: volume counters are 0 until per-session accounting lands. This
	// is asserted explicitly (NOT non-zero) — the P1 fix wires the record
	// through; the P2 follow-up populates the volume.
	if rec.SessionPkts != 0 || rec.SessionBytes != 0 {
		t.Fatalf("counters = (%d,%d), want (0,0) pending #2501",
			rec.SessionPkts, rec.SessionBytes)
	}
	if rec.RevSessionPkts != 0 || rec.RevSessionBytes != 0 {
		t.Fatalf("rev counters = (%d,%d), want (0,0) pending #2501",
			rec.RevSessionPkts, rec.RevSessionBytes)
	}
}

// TestNonSessionCloseRawEventDoesNotDriveFlowExport is the negative half of
// the fail-on-revert proof: a NON-close RT_FLOW event (policy deny) on the
// same raw channel must NOT reach the session-close export gate. If a future
// change broadened the gate (or mislabeled the close), this catches it.
func TestNonSessionCloseRawEventDoesNotDriveFlowExport(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 1)) {
		t.Fatal("exporters must start")
	}

	var sessionCloses int
	d.eventReader.AddCallback(func(rec logging.EventRecord, _ []byte) {
		if rec.Type == "SESSION_CLOSE" {
			sessionCloses++
		}
	})

	// A POLICY_DENY raw event (event-type byte 3, not 2).
	payload := buildSessionCloseRawEventV4(
		6,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{}, 0,
		2, 3,
	)
	payload[52] = dataplane.EventTypePolicyDeny

	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid POLICY_DENY payload")
	}
	if sessionCloses != 0 {
		t.Fatalf("a POLICY_DENY must not produce a SESSION_CLOSE record, got %d", sessionCloses)
	}
}

// twoInstanceV9Config builds a config with TWO NetFlow v9 sampling instances
// disambiguated by address family (#2462): "alpha" serves inet (IPv4) with its
// own collector, "bravo" serves inet6 (IPv6) with its own collector. Both at
// rate 1 so ShouldExport always admits. Each flow-server is pinned to version9
// so both land in the v9 bundle (exercising the per-instance fanout walk in
// flowExportCallback). The two collectors bind different ports so the test can
// observe each exporter's Stats independently.
func twoInstanceV9Config(addr string, alphaPort, bravoPort int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"alpha": {
				Name:      "alpha",
				InputRate: 1,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: addr, Port: alphaPort, Version: config.FlowServerVersion9},
					},
				},
			},
			"bravo": {
				Name:      "bravo",
				InputRate: 1,
				FamilyInet6: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: addr, Port: bravoPort, Version: config.FlowServerVersion9},
					},
				},
			},
		},
	}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{},
		},
	}
	return cfg
}

// groupStatsForInstance returns the summed exported-flow count across all
// template groups of the named instance in the live v9 bundle.
func groupStatsForInstance(b *exporterBundle, inst string) uint64 {
	var total uint64
	for _, g := range b.groups {
		if g.ec.InstanceName == inst {
			flows, _ := g.exp.Stats()
			total += flows
		}
	}
	return total
}

// waitInstanceFlows polls until the named instance's exporter(s) report at
// least one exported flow record, or the 3s deadline elapses.
func waitInstanceFlows(t *testing.T, b *exporterBundle, inst string) uint64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n := groupStatsForInstance(b, inst); n >= 1 {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
	return groupStatsForInstance(b, inst)
}

// TestSessionCloseMultiInstanceFamilyIsolation is the #2462 daemon-level
// fail-on-revert test for the per-instance fanout walk in flowExportCallback
// (and its IPFIX twin). Two v9 sampling instances are wired through the REAL
// reconcile + callback path: "alpha" (inet, rate 1) and "bravo" (inet6, rate
// 1). An IPv4 SESSION_CLOSE is fed on the raw dataplane-event channel and must
// reach ONLY alpha's exporter (its family) and NEVER bravo's — the
// no-cross-export guarantee. The callback makes ONE sampling decision per
// instance and fans only to that instance's groups.
//
// Fail-on-revert: reverting the callback to the pre-#2462 global decision —
// one ShouldExport on groups[0] then export to EVERY group regardless of
// family/instance — makes the IPv4 flow wrongly reach bravo (inet6), so
// bravo's exported-flow count goes from 0 to >= 1 and this test fails.
func TestSessionCloseMultiInstanceFamilyIsolation(t *testing.T) {
	alphaColl, alphaPort := listenUDP(t)
	t.Cleanup(func() { alphaColl.Close() })
	bravoColl, bravoPort := listenUDP(t)
	t.Cleanup(func() { bravoColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(twoInstanceV9Config("127.0.0.1", alphaPort, bravoPort)) {
		t.Fatal("two-instance v9 reconcile must start exporters")
	}
	b := d.flowBundle.Load()
	if b == nil || len(b.groups) != 2 {
		t.Fatalf("expected two v9 groups (alpha + bravo), got %v", b)
	}
	// Verify the per-instance family scoping the callback relies on.
	var alphaEC, bravoEC *flowexport.ExportConfig
	for _, g := range b.groups {
		switch g.ec.InstanceName {
		case "alpha":
			alphaEC = g.ec
		case "bravo":
			bravoEC = g.ec
		}
	}
	if alphaEC == nil || bravoEC == nil {
		t.Fatalf("both instances must resolve to a group: alpha=%v bravo=%v", alphaEC, bravoEC)
	}
	if !alphaEC.ServesFamily(false) || alphaEC.ServesFamily(true) {
		t.Errorf("alpha must serve v4 only: v4=%v v6=%v", alphaEC.ServesFamily(false), alphaEC.ServesFamily(true))
	}
	if bravoEC.ServesFamily(false) || !bravoEC.ServesFamily(true) {
		t.Errorf("bravo must serve v6 only: v4=%v v6=%v", bravoEC.ServesFamily(false), bravoEC.ServesFamily(true))
	}

	// Feed an IPv4 SESSION_CLOSE. Only alpha (inet) must export it.
	payload := buildSessionCloseRawEventV4(
		6, // TCP
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{172, 16, 80, 8}, 40000,
		2, 3, // trust -> untrust
	)
	if !d.eventReader.ProcessRawEvent(payload) {
		t.Fatal("ProcessRawEvent rejected a valid SESSION_CLOSE payload")
	}

	// alpha (the IPv4 instance) must export the flow.
	if got := waitInstanceFlows(t, b, "alpha"); got < 1 {
		t.Fatalf("alpha (inet) must export the IPv4 SESSION_CLOSE, got %d flows", got)
	}
	// bravo (inet6) must NEVER receive the IPv4 flow. Give the 100ms flush
	// ticker margin to (incorrectly) transmit before asserting zero — under
	// the pre-#2462 global-fanout behavior bravo would have exported by now.
	time.Sleep(300 * time.Millisecond)
	if got := groupStatsForInstance(b, "bravo"); got != 0 {
		t.Fatalf("bravo (inet6) must NOT export an IPv4 flow (#2462 isolation); got %d "+
			"— the callback wrongly fanned a v4 record to the inet6 instance", got)
	}
}

// TestEventFrameTypeSessionCloseConstant pins the Go frame-type constant so a
// drift from the Rust MSG_SESSION_CLOSE_RT_FLOW (14) is caught at unit level.
func TestEventFrameTypeSessionCloseConstant(t *testing.T) {
	if dpuserspace.EventFrameTypeSessionClose != 14 {
		t.Fatalf("EventFrameTypeSessionClose = %d, want 14 (must match Rust MSG_SESSION_CLOSE_RT_FLOW)",
			dpuserspace.EventFrameTypeSessionClose)
	}
}
