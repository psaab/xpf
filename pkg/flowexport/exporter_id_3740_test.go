package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #3740 regression guard. Two exporter groups pointed at the SAME collector
// but differing in their config identity (template name, or sampling-instance
// name) MUST present DISTINCT NetFlow v9 SourceID (RFC 3954 §5.1) and IPFIX
// Observation Domain ID (RFC 7011 §3.1) values. Before the fix both hardcoded
// 1, so two groups to one collector collided on the RFC decode key -- template
// redefinitions + interleaved sequence streams under one observation domain.
//
// Revert stableExporterID to a constant 1 (or restore `sourceID: 1` in
// NewExporter / NewIPFIXExporter) and the DISTINCT assertions below go RED:
// both streams carry the same id again.

// loopbackUDP returns a listening UDP collector on 127.0.0.1 and its address.
func loopbackUDP(t *testing.T) (net.PacketConn, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	return pc, pc.LocalAddr().String()
}

func readOne(t *testing.T, pc net.PacketConn) []byte {
	t.Helper()
	buf := make([]byte, 2048)
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom (collector got no packet): %v", err)
	}
	if n < 20 {
		t.Fatalf("short flow packet: %d bytes", n)
	}
	return buf[:n]
}

func mkRec() []FlowRecord {
	return []FlowRecord{{
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   1234,
		DstPort:   80,
		Protocol:  6,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}}
}

// v9SourceID reads the NetFlow v9 header SourceID (offset 16..20, big-endian).
func v9SourceID(pkt []byte) uint32 { return binary.BigEndian.Uint32(pkt[16:20]) }

// ipfixODID reads the IPFIX header Observation Domain ID (offset 12..16, BE).
func ipfixODID(pkt []byte) uint32 { return binary.BigEndian.Uint32(pkt[12:16]) }

func TestNetflowV9SourceIDDistinctPerGroup(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	// Two groups to the SAME collector, differing ONLY in TemplateName, under
	// one shared (non-empty) sampling instance.
	ecA := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
	}
	ecB := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplB",
	}
	eA, err := NewExporter(ecA)
	if err != nil {
		t.Fatalf("NewExporter A: %v", err)
	}
	defer eA.Close()
	eB, err := NewExporter(ecB)
	if err != nil {
		t.Fatalf("NewExporter B: %v", err)
	}
	defer eB.Close()

	eA.sendRecords(mkRec())
	idA := v9SourceID(readOne(t, pc))
	eB.sendRecords(mkRec())
	idB := v9SourceID(readOne(t, pc))

	if idA == 0 || idB == 0 {
		t.Fatalf("SourceID must be nonzero: A=%d B=%d", idA, idB)
	}
	if idA == idB {
		t.Fatalf("v9 SourceID collision: group A (tmplA) and group B (tmplB) "+
			"to the same collector both emitted SourceID=%d (#3740)", idA)
	}

	// A second axis: differ ONLY in InstanceName. Also distinct.
	ecC := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "instX",
		TemplateName: "tmplA",
	}
	eC, err := NewExporter(ecC)
	if err != nil {
		t.Fatalf("NewExporter C: %v", err)
	}
	defer eC.Close()
	eC.sendRecords(mkRec())
	idC := v9SourceID(readOne(t, pc))
	if idC == idA {
		t.Fatalf("v9 SourceID collision on instance axis: instX and inst0 "+
			"(same template) both emitted SourceID=%d (#3740)", idC)
	}
}

func TestIPFIXObservationDomainDistinctPerGroup(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	ecA := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
	}
	ecB := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplB",
	}
	eA, err := NewIPFIXExporter(ecA)
	if err != nil {
		t.Fatalf("NewIPFIXExporter A: %v", err)
	}
	defer eA.Close()
	eB, err := NewIPFIXExporter(ecB)
	if err != nil {
		t.Fatalf("NewIPFIXExporter B: %v", err)
	}
	defer eB.Close()

	eA.sendRecords(mkRec())
	idA := ipfixODID(readOne(t, pc))
	eB.sendRecords(mkRec())
	idB := ipfixODID(readOne(t, pc))

	if idA == 0 || idB == 0 {
		t.Fatalf("ODID must be nonzero: A=%d B=%d", idA, idB)
	}
	if idA == idB {
		t.Fatalf("IPFIX Observation Domain ID collision: group A (tmplA) and "+
			"group B (tmplB) to the same collector both emitted ODID=%d (#3740)", idA)
	}

	ecC := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "instX",
		TemplateName: "tmplA",
	}
	eC, err := NewIPFIXExporter(ecC)
	if err != nil {
		t.Fatalf("NewIPFIXExporter C: %v", err)
	}
	defer eC.Close()
	eC.sendRecords(mkRec())
	idC := ipfixODID(readOne(t, pc))
	if idC == idA {
		t.Fatalf("IPFIX ODID collision on instance axis: instX and inst0 "+
			"(same template) both emitted ODID=%d (#3740)", idC)
	}
}

// TestStableExporterIDDegenerateDefault: the truly-degenerate hand-built
// ExportConfig{} (no instance AND no template) keeps SourceID/ODID = 1, so the
// singular Build* helpers and the pre-#3740 unnamed single-default deployment
// are on the pre-existing wire.
func TestStableExporterIDDegenerateDefault(t *testing.T) {
	if got := stableExporterID("netflow9", "", "", false); got != 1 {
		t.Fatalf("degenerate default (netflow9) = %d, want 1", got)
	}
	if got := stableExporterID("ipfix", "", "", false); got != 1 {
		t.Fatalf("degenerate default (ipfix) = %d, want 1", got)
	}

	// End-to-end: a default-group exporter (empty instance + template) stamps 1.
	pcV9, addrV9 := loopbackUDP(t)
	defer pcV9.Close()
	eV9, err := NewExporter(&ExportConfig{Collectors: []CollectorConfig{{Address: addrV9}}})
	if err != nil {
		t.Fatalf("NewExporter default: %v", err)
	}
	defer eV9.Close()
	eV9.sendRecords(mkRec())
	if id := v9SourceID(readOne(t, pcV9)); id != 1 {
		t.Fatalf("default-group v9 SourceID = %d, want 1", id)
	}

	pcIP, addrIP := loopbackUDP(t)
	defer pcIP.Close()
	eIP, err := NewIPFIXExporter(&ExportConfig{Collectors: []CollectorConfig{{Address: addrIP}}})
	if err != nil {
		t.Fatalf("NewIPFIXExporter default: %v", err)
	}
	defer eIP.Close()
	eIP.sendRecords(mkRec())
	if id := ipfixODID(readOne(t, pcIP)); id != 1 {
		t.Fatalf("default-group IPFIX ODID = %d, want 1", id)
	}
}

// TestStableExporterIDFamilyMigration pins the #12148 migration contract:
// inet hashes retain their established values while inet6 gets a separate id.
func TestStableExporterIDFamilyMigration(t *testing.T) {
	cases := []struct {
		proto  string
		wantV4 uint32
	}{
		{"netflow9", 3503984933},
		{"ipfix", 2107433690},
	}
	for _, c := range cases {
		v4 := stableExporterID(c.proto, "inst0", "tmplA", false)
		v6 := stableExporterID(c.proto, "inst0", "tmplA", true)
		if v4 != c.wantV4 {
			t.Errorf("%s inet id = %d, want pre-#12148 value %d", c.proto, v4, c.wantV4)
		}
		if v4 == v6 {
			t.Errorf("%s inet and inet6 ids collide: %d", c.proto, v4)
		}
		if again := stableExporterID(c.proto, "inst0", "tmplA", true); again != v6 {
			t.Errorf("%s inet6 id is not deterministic: first=%d second=%d", c.proto, v6, again)
		}
	}

	// Preserve the historical unnamed inet default, but never let an unnamed
	// inet6 group share that id.
	if got := stableExporterID("netflow9", "", "", false); got != 1 {
		t.Errorf("unnamed inet id = %d, want historical 1", got)
	}
	if got := stableExporterID("netflow9", "", "", true); got == 1 {
		t.Error("unnamed inet6 id collides with historical inet default 1")
	}
}

// TestStableExporterIDHASymmetry: the id is a pure function of config-synced
// inputs and of NOTHING node-specific, so both cluster nodes ("node0"/"node1"
// builds) compute the SAME id for a given group -- a failover never presents
// the collector a new observation domain. Determinism across repeated
// evaluation stands in for the two builds (there is no node input to vary).
func TestStableExporterIDHASymmetry(t *testing.T) {
	cases := []struct {
		proto, inst, tmpl string
		isV6              bool
	}{
		{"netflow9", "inst0", "tmplA", false},
		{"netflow9", "instX", "", false},
		{"ipfix", "inst0", "tmplB", false},
		{"ipfix", "", "onlytmpl", false},
		{"netflow9", "inst0", "tmplA", true},
	}
	for _, c := range cases {
		node0 := stableExporterID(c.proto, c.inst, c.tmpl, c.isV6)
		node1 := stableExporterID(c.proto, c.inst, c.tmpl, c.isV6)
		if node0 != node1 {
			t.Fatalf("HA asymmetry for (%s,%s,%s,v6=%v): node0=%d node1=%d",
				c.proto, c.inst, c.tmpl, c.isV6, node0, node1)
		}
		if node0 == 0 {
			t.Fatalf("id must be nonzero for (%s,%s,%s,v6=%v)", c.proto, c.inst, c.tmpl, c.isV6)
		}
	}

	// The protocol tag disambiguates a v9 and an IPFIX group with an identical
	// instance/template (belt-and-braces; #2136 keeps them from co-pointing).
	if stableExporterID("netflow9", "inst0", "tmplA", false) == stableExporterID("ipfix", "inst0", "tmplA", false) {
		t.Fatal("netflow9 and ipfix groups with identical instance/template share an id")
	}
}
