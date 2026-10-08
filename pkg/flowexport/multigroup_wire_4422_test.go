package flowexport

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4422 — multi-group wire-collision coverage (end-to-end, config-resolver
// driven).
//
// VERIFY-FIRST outcome: CORRECT for groups with different instance/template
// identities. #3740 gave those groups distinct SourceIDs / Observation Domain
// IDs via stableExporterID. #12148 also folds family into the identity, so a
// same-instance, same-template inet/inet6 pair gets separate domains. Two
// flow-monitoring groups pointed at the SAME collector therefore do NOT
// collide on the RFC decode key.
// The template IDs 256/257 are intentionally shared across groups — that is
// RFC-correct because a template ID is scoped PER observation domain, so
// template 256 under SourceID-A is a different template from template 256
// under SourceID-B.
//
// The existing #3740 guards (exporter_id_3740_test.go) prove distinctness for
// HAND-BUILT ExportConfig{} structs with explicit TemplateName/InstanceName.
// What no test covered is the REAL path: a two-group `services flow-monitoring`
// config -> ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups -> one
// NewExporter per group -> the SourceID/ODID actually written on the wire. This
// file pins that: the resolver-assigned (instance, template, family) identity
// must reach the wire as DISTINCT SourceIDs even when both groups target one
// collector, while the (correctly) shared data template ID stays 256.
//
// Fail-on-regression: revert stableExporterID to a constant (or drop
// InstanceName/TemplateName from the ExportConfig the resolver builds, or
// collapse the two template groups into one) and the DISTINCT assertions below
// go RED — the two groups present one collector an indistinguishable decode
// key again.

// splitHostPort splits a "host:port" collector address into the (host, port)
// pair a config.FlowServer carries.
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	return host, port
}

// v9DataTemplateID reads the FlowSet ID of a NetFlow v9 DATA packet (offset
// 20..22, big-endian) — for a data FlowSet this equals the template ID the
// records belong to (256 for IPv4).
func v9DataTemplateID(pkt []byte) uint16 { return binary.BigEndian.Uint16(pkt[20:22]) }

// ipfixDataSetID reads the Set ID of an IPFIX DATA message (offset 16..18,
// big-endian) — for a data set this equals the template ID (256 for IPv4).
func ipfixDataSetID(pkt []byte) uint16 { return binary.BigEndian.Uint16(pkt[16:18]) }

// TestNetflowV9MultiGroupWireDistinctFromConfig drives the whole chain from a
// real two-template `services flow-monitoring version9` config: two flow-servers
// at ONE collector reference two different templates ("fast"/"slow"). The
// resolver must emit two groups; each group's exporter must stamp a DISTINCT,
// nonzero SourceID on the wire, while both carry the (shared, RFC-correct) data
// template ID 256.
func TestNetflowV9MultiGroupWireDistinctFromConfig(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()
	host, port := splitHostPort(t, addr)

	// Two flow-servers at the SAME collector, referencing two distinct v9
	// templates — one sampling instance, so the ONLY thing that distinguishes
	// the two resolved groups is the template name.
	fo := samplingFO(
		&config.FlowServer{Address: host, Port: port, Version: config.FlowServerVersion9, Version9Template: "fast"},
		&config.FlowServer{Address: host, Port: port, Version: config.FlowServerVersion9, Version9Template: "slow"},
	)
	groups := ResolveV9TemplateGroups(twoTemplateV9Svc(), fo)
	if len(groups) != 2 {
		t.Fatalf("two templates to one collector must resolve to 2 groups, got %d", len(groups))
	}

	ids := make(map[uint32]string, 2)
	for _, g := range groups {
		e, err := NewExporter(g)
		if err != nil {
			t.Fatalf("NewExporter(%q): %v", g.TemplateName, err)
		}
		e.sendRecords(mkRec())
		pkt := readOne(t, pc)
		id := v9SourceID(pkt)
		if id == 0 {
			t.Fatalf("group %q emitted SourceID 0", g.TemplateName)
		}
		if tid := v9DataTemplateID(pkt); tid != templateIDv4 {
			t.Fatalf("group %q data template ID = %d, want %d (v4)", g.TemplateName, tid, templateIDv4)
		}
		if prev, dup := ids[id]; dup {
			e.Close()
			t.Fatalf("v9 multi-group wire collision: groups %q and %q both stamped "+
				"SourceID=%d to one collector (#4422/#3740)", prev, g.TemplateName, id)
		}
		ids[id] = g.TemplateName
		e.Close()
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct SourceIDs across the groups, got %d", len(ids))
	}
}

// TestIPFIXMultiGroupWireDistinctFromConfig is the IPFIX equivalent: two
// flow-servers at one collector reference two IPFIX templates; each group's
// exporter must stamp a DISTINCT, nonzero Observation Domain ID while both
// carry the shared data set/template ID 256.
func TestIPFIXMultiGroupWireDistinctFromConfig(t *testing.T) {
	pc, addr := loopbackUDP(t)
	defer pc.Close()
	host, port := splitHostPort(t, addr)

	fo := samplingFO(
		&config.FlowServer{Address: host, Port: port, Version: config.FlowServerVersionIPFIX, VersionIPFIXTemplate: "fast"},
		&config.FlowServer{Address: host, Port: port, Version: config.FlowServerVersionIPFIX, VersionIPFIXTemplate: "slow"},
	)
	groups := ResolveIPFIXTemplateGroups(twoTemplateIPFIXSvc(), fo)
	if len(groups) != 2 {
		t.Fatalf("two templates to one collector must resolve to 2 groups, got %d", len(groups))
	}

	ids := make(map[uint32]string, 2)
	for _, g := range groups {
		e, err := NewIPFIXExporter(g)
		if err != nil {
			t.Fatalf("NewIPFIXExporter(%q): %v", g.TemplateName, err)
		}
		e.sendRecords(mkRec())
		pkt := readOne(t, pc)
		id := ipfixODID(pkt)
		if id == 0 {
			t.Fatalf("group %q emitted ODID 0", g.TemplateName)
		}
		if sid := ipfixDataSetID(pkt); sid != ipfixTemplateIDv4 {
			t.Fatalf("group %q data set ID = %d, want %d (v4)", g.TemplateName, sid, ipfixTemplateIDv4)
		}
		if prev, dup := ids[id]; dup {
			e.Close()
			t.Fatalf("IPFIX multi-group wire collision: groups %q and %q both stamped "+
				"ODID=%d to one collector (#4422/#3740)", prev, g.TemplateName, id)
		}
		ids[id] = g.TemplateName
		e.Close()
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct ODIDs across the groups, got %d", len(ids))
	}
}
