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
	for i, want := range wantHeaders {
		if blocks[i].header != want {
			t.Errorf("sequence %d header = %q, want %q:\n%s", i, blocks[i].header, want, got)
		}
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

	// Collect the emitted per-family prefix-list definitions so the
	// reference assertions below compare full tokens, not substrings
	// (#12068: names are now `<policy>-<term>-xpf-inline-<hash>`).
	defined := map[string]bool{}
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "ip prefix-list "); ok {
			name, _, _ := strings.Cut(rest, " ")
			defined[name] = true
		}
		if rest, ok := strings.CutPrefix(line, "ipv6 prefix-list "); ok {
			name, _, _ := strings.Cut(rest, " ")
			defined[name] = true
		}
	}
	for i, b := range blocks[:4] {
		wantProto := []string{"bgp", "ospf", "bgp", "ospf"}[i]
		wantFamily := "v4"
		wantPrefix := "match ip address prefix-list "
		if i >= 2 {
			wantFamily = "v6"
			wantPrefix = "match ipv6 address prefix-list "
		}
		if b.protos != 1 || !strings.Contains(b.body, "match source-protocol "+wantProto+"\n") {
			t.Errorf("%s has protocol matches %q, want only %q:\n%s",
				b.header, strings.TrimSpace(b.body), wantProto, got)
		}
		ref := ""
		for _, line := range strings.Split(b.body, "\n") {
			line = strings.TrimSpace(line)
			if rest, ok := strings.CutPrefix(line, strings.TrimSpace(wantPrefix)+" "); ok {
				ref, _, _ = strings.Cut(rest, " ")
			}
		}
		if ref == "" {
			t.Errorf("%s has no %s-family prefix-list match:\n%s",
				b.header, wantFamily, got)
		} else if !defined[ref] {
			t.Errorf("%s references undefined %s-family prefix-list %q:\n%s",
				b.header, wantFamily, ref, got)
		} else {
			wantNS := "FAMSPLIT-t1_v4-xpf-inline-"
			if wantFamily == "v6" {
				wantNS = "FAMSPLIT-t1_v6-xpf-inline-"
			}
			if !strings.HasPrefix(ref, wantNS) {
				t.Errorf("%s references %q, want the #12068 namespaced form %q*:\n%s",
					b.header, ref, wantNS, got)
			}
		}
	}
	if got := config.RouteMapSequenceCount(po, po.PolicyStatements["FAMSPLIT"]); got != 4 {
		t.Errorf("RouteMapSequenceCount = %d, want 4", got)
	}
}

// TestPolicyProtoSeqDeduplicatesCanonicalProtocols_12066 proves aliased and
// literal duplicate protocols render one modifying sequence, so a non-
// terminating set action cannot run more than once for the same source match.
func TestPolicyProtoSeqDeduplicatesCanonicalProtocols_12066(t *testing.T) {
	cases := []struct {
		name      string
		routeMap  string
		protocols []string
		wantProto string
	}{
		{
			name:      "direct-connected-alias",
			routeMap:  "ALIASED",
			protocols: []string{"direct", "connected"},
			wantProto: "connected",
		},
		{
			name:      "literal-duplicate",
			routeMap:  "DUPLICATE",
			protocols: []string{"bgp", "bgp"},
			wantProto: "bgp",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{frrConf: "/dev/null"}
			po := &config.PolicyOptionsConfig{
				PolicyStatements: map[string]*config.PolicyStatement{
					tc.routeMap: {
						Name: tc.routeMap,
						Terms: []*config.PolicyTerm{{
							Name:          "t1",
							FromProtocols: tc.protocols,
							ASPathPrepend: []string{"65000"},
						}},
						DefaultAction: "reject",
					},
				},
			}

			got := m.generatePolicyOptions(po)
			blocks := protoSeqBlocks12066(t, got, tc.routeMap)
			if len(blocks) != 2 {
				t.Fatalf("got %d route-map sequences, want one modifying sequence plus default:\n%s",
					len(blocks), got)
			}
			if blocks[0].header != "route-map "+tc.routeMap+" permit 10" {
				t.Errorf("modifying sequence header = %q, want permit 10", blocks[0].header)
			}
			if blocks[0].protos != 1 ||
				!strings.Contains(blocks[0].body, "match source-protocol "+tc.wantProto+"\n") {
				t.Errorf("modifying sequence has source-protocol matches %q, want only %q:\n%s",
					strings.TrimSpace(blocks[0].body), tc.wantProto, got)
			}
			if strings.Count(blocks[0].body, "set as-path prepend 65000\n") != 1 ||
				strings.Count(blocks[0].body, "on-match next\n") != 1 {
				t.Errorf("duplicate protocols must not duplicate the policy's non-terminating prepend:\n%s",
					blocks[0].body)
			}
			if got := config.RouteMapSequenceCount(po, po.PolicyStatements[tc.routeMap]); got != 1 {
				t.Errorf("RouteMapSequenceCount = %d, want 1 modifying sequence", got)
			}
		})
	}
}

// TestPolicyProtoSeqPaddedEquivalentDedupes_12066 proves padded and mixed-case
// spellings of the same protocol collapse to one modifying sequence. The
// strict gate accepts the broader FRRRoutingProtocolKeyword domain (trim +
// case-fold) WITHOUT rewriting the stored token, so compile preserves the raw
// spelling (e.g. "bgp ") and canonicalization must happen at render/count
// time. Without it [ bgp "bgp " ] expands to two modifying sequences and a
// non-terminating prepend runs twice for the same route.
func TestPolicyProtoSeqPaddedEquivalentDedupes_12066(t *testing.T) {
	cases := []struct {
		name     string
		routeMap string
		fromFrag string
		raw      []string
		want     string
	}{
		{
			name:     "padded-bgp",
			routeMap: "PADDED",
			fromFrag: `[ bgp "bgp " ]`,
			raw:      []string{"bgp", "bgp "},
			want:     "bgp",
		},
		{
			name:     "padded-alias",
			routeMap: "PADALIAS",
			fromFrag: `[ direct "connected " ]`,
			raw:      []string{"direct", "connected "},
			want:     "connected",
		},
		{
			name:     "mixed-case",
			routeMap: "MIXEDCASE",
			fromFrag: `[ BGP bgp ]`,
			raw:      []string{"BGP", "bgp"},
			want:     "bgp",
		},
		{
			name:     "padded-mixed-alias",
			routeMap: "PADMIXED",
			fromFrag: `[ " Direct " CONNECTED ]`,
			raw:      []string{" Direct ", "CONNECTED"},
			want:     "connected",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			cmds := []string{
				"set policy-options policy-statement " + tc.routeMap + " term t1 from protocol " + tc.fromFrag,
				"set policy-options policy-statement " + tc.routeMap + " term t1 then as-path-prepend 65000",
				"set policy-options policy-statement " + tc.routeMap + " then reject",
			}
			for _, cmd := range cmds {
				path, err := config.ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			ps := cfg.PolicyOptions.PolicyStatements[tc.routeMap]
			if ps == nil || len(ps.Terms) == 0 {
				t.Fatalf("compiled %s has no terms", tc.routeMap)
			}
			gotProtos := ps.Terms[0].FromProtocols
			if len(gotProtos) != len(tc.raw) {
				t.Fatalf("compiled FromProtocols = %q, want raw %q", gotProtos, tc.raw)
			}
			for i := range tc.raw {
				if gotProtos[i] != tc.raw[i] {
					t.Fatalf("compiled FromProtocols = %q, want raw %q (strict accepts without rewriting)", gotProtos, tc.raw)
				}
			}
			m := &Manager{frrConf: "/dev/null"}
			got := m.generatePolicyOptions(&cfg.PolicyOptions)
			blocks := protoSeqBlocks12066(t, got, tc.routeMap)
			if len(blocks) != 2 {
				t.Fatalf("got %d route-map sequences, want one modifying sequence plus default:\n%s",
					len(blocks), got)
			}
			if blocks[0].protos != 1 ||
				!strings.Contains(blocks[0].body, "match source-protocol "+tc.want+"\n") {
				t.Errorf("modifying sequence has source-protocol matches %q, want only %q:\n%s",
					strings.TrimSpace(blocks[0].body), tc.want, got)
			}
			if strings.Count(blocks[0].body, "set as-path prepend 65000\n") != 1 {
				t.Errorf("padded-equivalent protocols must not duplicate the non-terminating prepend:\n%s",
					blocks[0].body)
			}
			if n := config.RouteMapSequenceCount(&cfg.PolicyOptions, ps); n != 1 {
				t.Errorf("RouteMapSequenceCount = %d, want 1 modifying sequence", n)
			}
		})
	}
}
