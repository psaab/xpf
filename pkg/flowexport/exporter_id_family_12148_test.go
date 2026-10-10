package flowexport

import "testing"

// #12148 regression guard. #3740 made the per-group id a hash of
// (protocol, instance, template) and explicitly chose NOT to fold family —
// "one exporter serves both families". #6811 then split groups by family
// (collectorGroupKey{Template, IsV6}) WITHOUT updating the id. A dual-family
// instance with the same (or empty) template sending to one collector now gets
// TWO exporters with the SAME SourceID/ODID and independent sequence counters.
//
// For NetFlow v9 that is the #3740 defect again: RFC 3954 §5.1 tells collectors
// to key streams on (exporter source IP, Source ID), so same-source-IP v4/v6
// groups present interleaved sequences and false loss under one SourceID.
// (For IPFIX over UDP the RFC 7011 Transport Session includes UDP ports and each
// exporter owns its socket, so conforming collectors already keep the streams
// apart — the family fold below still applies for uniform, distinct ODIDs.)
//
// The fix folds GroupIsV6 into stableExporterID at config time (no per-record
// cost). The wire cells below fail pre-fix and pass post-fix; the unit cell
// pins the hash contract (it references the post-fix signature, so it is
// GREEN-after only).

// TestNetflowV9SourceIDDistinctAcrossFamily_12148: two v9 groups to the SAME
// collector, identical except GroupIsV6, MUST stamp distinct SourceIDs.
//
// FAIL-ON-REVERT: drop the family input from stableExporterID (or stop passing
// cfg.GroupIsV6 in NewExporter) and this REDS — both groups hash the same
// (protocol, instance, template) and emit one SourceID.
func TestNetflowV9SourceIDDistinctAcrossFamily_12148(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	ecV4 := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
		GroupIsV6:    false,
	}
	ecV6 := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
		GroupIsV6:    true,
	}
	eV4, err := NewExporter(ecV4)
	if err != nil {
		t.Fatalf("NewExporter v4: %v", err)
	}
	defer eV4.Close()
	eV6, err := NewExporter(ecV6)
	if err != nil {
		t.Fatalf("NewExporter v6: %v", err)
	}
	defer eV6.Close()

	eV4.sendRecords(mkRec())
	idV4 := v9SourceID(readOne(t, pc))
	eV6.sendRecords(mkRec())
	idV6 := v9SourceID(readOne(t, pc))

	if idV4 == 0 || idV6 == 0 {
		t.Fatalf("SourceID must be nonzero: v4=%d v6=%d", idV4, idV6)
	}
	if idV4 == idV6 {
		t.Fatalf("v9 SourceID collision across family: the inet and inet6 groups "+
			"(same instance, template, collector) both emitted SourceID=%d (#12148)", idV4)
	}
}

// TestIPFIXObservationDomainDistinctAcrossFamily_12148 is the IPFIX half:
// same shape, distinct Observation Domain IDs.
//
// FAIL-ON-REVERT: same mutation in NewIPFIXExporter.
func TestIPFIXObservationDomainDistinctAcrossFamily_12148(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()

	ecV4 := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
		GroupIsV6:    false,
	}
	ecV6 := &ExportConfig{
		Collectors:   []CollectorConfig{{Address: addr}},
		InstanceName: "inst0",
		TemplateName: "tmplA",
		GroupIsV6:    true,
	}
	eV4, err := NewIPFIXExporter(ecV4)
	if err != nil {
		t.Fatalf("NewIPFIXExporter v4: %v", err)
	}
	defer eV4.Close()
	eV6, err := NewIPFIXExporter(ecV6)
	if err != nil {
		t.Fatalf("NewIPFIXExporter v6: %v", err)
	}
	defer eV6.Close()

	eV4.sendRecords(mkRec())
	idV4 := ipfixODID(readOne(t, pc))
	eV6.sendRecords(mkRec())
	idV6 := ipfixODID(readOne(t, pc))

	if idV4 == 0 || idV6 == 0 {
		t.Fatalf("ODID must be nonzero: v4=%d v6=%d", idV4, idV6)
	}
	if idV4 == idV6 {
		t.Fatalf("IPFIX ODID collision across family: the inet and inet6 groups "+
			"(same instance, template, collector) both emitted ODID=%d (#12148)", idV4)
	}
}

// TestNetflowV9DualFamilySameCollectorWireDistinctFromConfig_12148 drives the
// exact reported shape through the real resolver: ONE instance, ONE template,
// ONE collector address configured under BOTH families. #6811 guarantees two
// groups (same address + different family = two destinations-with-family);
// #12148 requires their exporters to stamp DISTINCT wire SourceIDs.
//
// FAIL-ON-REVERT: any mutation that drops family from the id derivation REDS
// this — the resolvers still emit two groups, but both stamp one SourceID.
func TestNetflowV9DualFamilySameCollectorWireDistinctFromConfig_12148(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()
	host, port := splitHostPort(t, addr)

	// Same loopback collector under both families; template "t" exists in v9Svc.
	fo := bothFamiliesInstance(host, host, "t")
	inst := fo.Sampling.Instances["both"]
	inst.FamilyInet.FlowServers[0].Port = port
	inst.FamilyInet6.FlowServers[0].Port = port
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) != 2 {
		t.Fatalf("same collector under both families must resolve to 2 groups, got %d (#6811)", len(groups))
	}

	ids := make(map[uint32]bool, 2)
	for _, g := range groups {
		e, err := NewExporter(g)
		if err != nil {
			t.Fatalf("NewExporter(v6=%v): %v", g.GroupIsV6, err)
		}
		e.sendRecords(mkRec())
		pkt := readOne(t, pc)
		id := v9SourceID(pkt)
		if id == 0 {
			e.Close()
			t.Fatalf("group v6=%v emitted SourceID 0", g.GroupIsV6)
		}
		if prev, dup := ids[id]; dup {
			e.Close()
			t.Fatalf("v9 dual-family wire collision: groups %v and v6=%v both stamped "+
				"SourceID=%d to one collector (#12148)", prev, g.GroupIsV6, id)
		}
		ids[id] = g.GroupIsV6
		e.Close()
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct SourceIDs across the family groups, got %d", len(ids))
	}
}

// TestIPFIXDualFamilySameCollectorWireDistinctFromConfig_12148 is the IPFIX
// equivalent of the resolver-driven v9 cell above.
//
// FAIL-ON-REVERT: same mutation in the IPFIX constructor.
func TestIPFIXDualFamilySameCollectorWireDistinctFromConfig_12148(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()
	host, port := splitHostPort(t, addr)

	fo := bothFamiliesInstance(host, host, "t")
	inst := fo.Sampling.Instances["both"]
	inst.FamilyInet.FlowServers[0].Port = port
	inst.FamilyInet6.FlowServers[0].Port = port
	groups := ResolveIPFIXTemplateGroups(ipfixSvc(), fo)
	if len(groups) != 2 {
		t.Fatalf("same collector under both families must resolve to 2 groups, got %d (#6811)", len(groups))
	}

	ids := make(map[uint32]bool, 2)
	for _, g := range groups {
		e, err := NewIPFIXExporter(g)
		if err != nil {
			t.Fatalf("NewIPFIXExporter(v6=%v): %v", g.GroupIsV6, err)
		}
		e.sendRecords(mkRec())
		pkt := readOne(t, pc)
		id := ipfixODID(pkt)
		if id == 0 {
			e.Close()
			t.Fatalf("group v6=%v emitted ODID 0", g.GroupIsV6)
		}
		if prev, dup := ids[id]; dup {
			e.Close()
			t.Fatalf("IPFIX dual-family wire collision: groups %v and v6=%v both stamped "+
				"ODID=%d to one collector (#12148)", prev, g.GroupIsV6, id)
		}
		ids[id] = g.GroupIsV6
		e.Close()
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct ODIDs across the family groups, got %d", len(ids))
	}
}
