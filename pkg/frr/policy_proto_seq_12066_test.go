package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// protoSeqBlock12066 describes one rendered route-map sequence.
type protoSeqBlock12066 struct {
	header      string
	body        string
	protos      int
	communities int
}

// protoSeqBlocks12066 splits rendered output into per-sequence blocks keyed by
// the route-map header line, preserving emission order.
func protoSeqBlocks12066(t *testing.T, got, routeMap string) []protoSeqBlock12066 {
	t.Helper()
	var blocks []protoSeqBlock12066
	for _, chunk := range strings.Split(got, "route-map ") {
		if chunk == "" {
			continue
		}
		header, body, _ := strings.Cut(chunk, "\n")
		if !strings.HasPrefix(header, routeMap+" ") {
			continue
		}
		blocks = append(blocks, protoSeqBlock12066{
			header:      "route-map " + header,
			body:        body,
			protos:      strings.Count(body, "match source-protocol "),
			communities: strings.Count(body, "match community "),
		})
	}
	return blocks
}

// TestPolicyProtoSeqOneSequencePerProtocol_12066 proves a term matching
// multiple protocols ("from protocol [ bgp ospf static ]") renders ONE
// route-map sequence per source protocol. FRR replaces a same-type rule, so
// multiple `match source-protocol` lines in one sequence keep only the last
// protocol and flap on every reload.
func TestPolicyProtoSeqOneSequencePerProtocol_12066(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXPORT-ALL": {
				Name: "EXPORT-ALL",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"bgp", "ospf", "direct"},
						Action:        "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// "direct" maps to FRR "connected"; all three must render, each alone.
	if n := strings.Count(got, "match source-protocol "); n != 3 {
		t.Fatalf("got %d match source-protocol lines, want 3:\n%s", n, got)
	}

	blocks := protoSeqBlocks12066(t, got, "EXPORT-ALL")
	// Three term sequences (10/20/30) plus the trailing default (40).
	wantHeaders := []string{
		"route-map EXPORT-ALL permit 10",
		"route-map EXPORT-ALL permit 20",
		"route-map EXPORT-ALL permit 30",
		"route-map EXPORT-ALL deny 40",
	}
	if len(blocks) != len(wantHeaders) {
		t.Fatalf("got %d EXPORT-ALL sequences, want %d:\n%s", len(blocks), len(wantHeaders), got)
	}
	for i, want := range []string{"bgp", "ospf", "connected"} {
		b := blocks[i]
		if b.protos != 1 || !strings.Contains(b.body, "match source-protocol "+want+"\n") {
			t.Errorf("%s has protocol matches %q, want only %q:\n%s", b.header,
				strings.TrimSpace(b.body), want, got)
		}
	}
	if blocks[3].protos != 0 {
		t.Errorf("trailing default %s holds %d match source-protocol lines, want 0:\n%s",
			blocks[3].header, blocks[3].protos, got)
	}
	if got := config.RouteMapSequenceCount(po, po.PolicyStatements["EXPORT-ALL"]); got != uint64(len(blocks)-1) {
		t.Errorf("RouteMapSequenceCount = %d, want %d term sequences:", got, len(blocks)-1)
	}
}

// TestPolicyProtoSeqCrossProduct_12066 proves the protocol OR-set multiplies
// with the other OR dimensions: 2 protocols x 2 communities = 4 sequences,
// each holding exactly one of each match type.
func TestPolicyProtoSeqCrossProduct_12066(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"XPROD": {
				Name: "XPROD",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"bgp", "ospf"},
						FromCommunity: []string{"c1", "c2"},
						Action:        "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
		Communities: map[string]*config.CommunityDef{
			"c1": {Name: "c1", Members: []string{"65000:1"}},
			"c2": {Name: "c2", Members: []string{"65000:2"}},
		},
	}

	got := m.generatePolicyOptions(po)
	blocks := protoSeqBlocks12066(t, got, "XPROD")
	if len(blocks) != 5 { // 4 term sequences + trailing default
		t.Fatalf("got %d XPROD sequences, want 5 (2 proto x 2 comm + default):\n%s", len(blocks), got)
	}
	wantMatches := []struct{ proto, community string }{
		{"bgp", "c1"}, {"ospf", "c1"}, {"bgp", "c2"}, {"ospf", "c2"},
	}
	for i, want := range wantMatches {
		b := blocks[i]
		if b.protos != 1 || !strings.Contains(b.body, "match source-protocol "+want.proto+"\n") {
			t.Errorf("%s has protocol matches %q, want only %q:\n%s",
				b.header, strings.TrimSpace(b.body), want.proto, got)
		}
		if b.communities != 1 || !strings.Contains(b.body, "match community "+want.community+"\n") {
			t.Errorf("%s has community matches %q, want only %q:\n%s",
				b.header, strings.TrimSpace(b.body), want.community, got)
		}
	}
	if got := config.RouteMapSequenceCount(po, po.PolicyStatements["XPROD"]); got != 4 {
		t.Errorf("RouteMapSequenceCount = %d, want 4", got)
	}
}

// TestPolicyProtoSeqFamilySplit_12066 proves the protocol OR-set multiplies
// with the #2607 family split: mixed v4+v6 route-filters x 2 protocols =
// 4 sequences.
func TestPolicyProtoSeqFamilySplit_12066(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"FAMSPLIT": {
				Name: "FAMSPLIT",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"bgp", "ospf"},
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "exact"},
							{Prefix: "2001:db8::/32", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)
	blocks := protoSeqBlocks12066(t, got, "FAMSPLIT")
	if len(blocks) != 5 { // 2 families x 2 protocols + trailing default
		t.Fatalf("got %d FAMSPLIT sequences, want 5 (2 fam x 2 proto + default):\n%s", len(blocks), got)
	}

	for i, b := range blocks[:4] {
		wantProto := []string{"bgp", "ospf", "bgp", "ospf"}[i]
		wantFamily := "v4"
		match := "match ip address prefix-list FAMSPLIT-t1_v4"
		if i >= 2 {
			wantFamily = "v6"
			match = "match ipv6 address prefix-list FAMSPLIT-t1_v6"
		}
		if b.protos != 1 || !strings.Contains(b.body, "match source-protocol "+wantProto+"\n") {
			t.Errorf("%s has protocol matches %q, want only %q:\n%s",
				b.header, strings.TrimSpace(b.body), wantProto, got)
		}
		if !strings.Contains(b.body, match) {
			t.Errorf("%s does not contain the %s-family match %q:\n%s",
				b.header, wantFamily, match, got)
		}
	}
	if got := config.RouteMapSequenceCount(po, po.PolicyStatements["FAMSPLIT"]); got != 4 {
		t.Errorf("RouteMapSequenceCount = %d, want 4", got)
	}
}
