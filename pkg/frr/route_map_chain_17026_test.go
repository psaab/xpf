package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #17026 (R4-Q42-03): the #15156 redistribute chain composer was a
// renamed clone of the #5277 BGP chain composer with its own
// hand-summed overflow predicate. These cells pin the dedup:
//
//   - Parity: for chains whose members need no per-source filtering,
//     the redistribute composer and the BGP composer render the same
//     member sequences; only the tail verb (deny vs permit) and the
//     map name differ. Any future divergence in the shared composer
//     breaks one side of this comparison.
//   - Regression (TestRedistChainTerminatingMemberRenders17026): a
//     terminating first member followed by a large second member
//     renders the first member's sequences plus its default — it is
//     NOT quarantined to a lone deny. This is the acceptance shape
//     from the issue (OSPF arm renders 4,001 sequences), executed
//     through the real strict commit gate (configstore.CheckText).
//   - Belt: a genuinely oversized non-terminating chain still
//     quarantines to exactly one bounded deny header on BOTH
//     composers, so the dedup did not weaken the fail-closed belt.
//
// Note on the reported deny-all shape: on current master the plain
// terminating shape already renders (the #16868 truncation was
// hand-copied into the clone's count loop after the report's
// verification revision). The live defect this dedup removes is the
// duplicate algorithm itself — two render loops and two overflow
// arithmetics (hand sum vs the saturating, truncating SSOT) that
// must be kept in agreement by hand, including under variant
// filtering where the filtered statements the clone counted were
// re-derived separately from the statements it rendered.

// chain17026PO builds A (4000 prefix-list refs, authored default) and
// B (4000 refs, no default) with every referenced list defined, so
// RouteMapSequenceCount counts 4000 per member and the terms actually
// render (no dangling-match elision).
func chain17026PO(aDefault string) *config.PolicyOptionsConfig {
	lists := make(map[string]*config.PrefixList, 8000)
	mk := func(prefix string, def string) *config.PolicyStatement {
		names := make([]string, 4000)
		for i := range names {
			names[i] = fmt.Sprintf("%s%d", prefix, i)
			lists[names[i]] = &config.PrefixList{Prefixes: []string{fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)}}
		}
		return &config.PolicyStatement{
			DefaultAction: def,
			Terms:         []*config.PolicyTerm{{Name: "t", PrefixList: names, Action: "reject"}},
		}
	}
	return &config.PolicyOptionsConfig{
		PrefixLists: lists,
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": mk("pla", aDefault),
			"B": mk("plb", ""),
		},
	}
}

func routeMapHeaderCount17026(got, name string) int {
	n := 0
	for _, ln := range strings.Split(got, "\n") {
		if strings.HasPrefix(ln, "route-map "+name+" ") {
			n++
		}
	}
	return n
}

// TestRedistChainTerminatingMemberRenders17026 is acceptance (3)
// executed through the real strict gate: OSPF `export [ A B ]` with
// A terminating (default reject, 4000 sequences) and B at 4000
// sequences commits clean and the composed redistribute map renders
// A's 4000 term sequences plus its default (4001 headers), NOT the
// quarantine deny. On the pre-#17026 hand sum (8000 > 6552 before
// the #16868 truncation was itself hand-copied, and still divergent
// under variant filtering) this shape was the reported deny-all;
// the SSOT count that now governs the belt is 4000.
func TestRedistChainTerminatingMemberRenders17026(t *testing.T) {
	sets := []string{
		"set system host-name fw1",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf export [ A B ]",
		"set policy-options policy-statement A term t from protocol static",
		"set policy-options policy-statement A term t then reject",
		"set policy-options policy-statement A then reject",
		"set policy-options policy-statement B term t from protocol static",
		"set policy-options policy-statement B term t then accept",
	}
	for i := range 4000 {
		sets = append(sets,
			fmt.Sprintf("set policy-options policy-statement A term t from prefix-list pla%d", i),
			fmt.Sprintf("set policy-options prefix-list pla%d 10.%d.%d.0/24", i, (i/256)%256, i%256),
			fmt.Sprintf("set policy-options policy-statement B term t from prefix-list plb%d", i),
			fmt.Sprintf("set policy-options prefix-list plb%d 10.%d.%d.0/24", i, (i/256)%256, i%256),
		)
	}
	cfg, err := configstore.CheckText(strings.Join(sets, "\n"), -1)
	if err != nil {
		t.Fatalf("strict gate must accept the terminating-member chain: %v", err)
	}
	// SSOT sanity: the chain counts 4000 (truncated at A), in bound.
	if n := config.ComposedChainSequenceCount(&cfg.PolicyOptions, cfg.PolicyOptions.PolicyStatements, []string{"A", "B"}); n != 4000 {
		t.Fatalf("SSOT chain count = %d, want 4000 (truncated at terminating A)", n)
	}
	section := New().buildManagedSection(&FullConfig{OSPF: cfg.Protocols.OSPF, PolicyOptions: &cfg.PolicyOptions})
	name := "A-B-xpf-chain-static-xpf-redist-ospf"
	if got := routeMapHeaderCount17026(section, name); got != 4001 {
		t.Fatalf("composed redistribute map must render 4001 sequences (4000 terms + A default), got %d headers for %s", got, name)
	}
	if !strings.Contains(section, "redistribute static route-map "+name) {
		t.Fatalf("OSPF section must attach the composed map:\n%s", section[:min(len(section), 2000)])
	}
	// The quarantine shape (exactly one header, deny 10) must be absent.
	if strings.Count(section, "route-map "+name+" ") == 1 {
		t.Fatalf("composed map collapsed to the quarantine deny:\n%s", section[:min(len(section), 500)])
	}
}

// TestChainComposerParity17026 pins BGP/redistribute parity over the
// shared composer: same members, same order, same sequences — only
// the fall-off verb differs (BGP permit #2998 vs redistribute deny).
func TestChainComposerParity17026(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Terms: []*config.PolicyTerm{
				{Name: "a1", Action: "reject"},
				{Name: "a2", NextPolicy: true},
			}},
			"B": {DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "b1", Action: "accept"},
			}},
			"C": {Terms: []*config.PolicyTerm{
				{Name: "c1", Action: "accept"},
			}},
		},
	}
	cases := []struct {
		name  string
		chain []string
	}{
		{"terminating-default", []string{"A", "B", "C"}},
		{"fallthrough", []string{"A", "C"}},
		{"single", []string{"C"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bgp := New().renderComposedRouteMap(po, "X-xpf-chain", tc.chain)
			red := New().renderRedistComposedMapCluster15158(po, "X-xpf-chain", tc.chain, "static", false)
			// Redistribute members are per-source filtered copies;
			// with no `from protocol` terms the filtered statements
			// are term-identical, so the bodies must match except
			// the final fall-off verb.
			if bgp == red {
				return // terminated chains have no fall-off at all
			}
			// Replace the differing tail verb: the BGP fall-off is
			// the LAST route-map header (permit -> deny). Member
			// defaults keep their authored verbs on both sides.
			idx := strings.LastIndex(bgp, "route-map X-xpf-chain permit ")
			if idx < 0 {
				t.Fatalf("parity: BGP render has no permit tail to normalize\nBGP:\n%s\nREDIST:\n%s", bgp, red)
			}
			norm := bgp[:idx] + "route-map X-xpf-chain deny " + bgp[idx+len("route-map X-xpf-chain permit "):]
			if norm != red {
				t.Fatalf("parity: bodies differ beyond tail verb\nBGP:\n%s\nREDIST:\n%s", bgp, red)
			}
		})
	}
}

// TestChainComposerOversizeParity17026 pins the belt on both
// adapters: a non-terminating chain summing past the ceiling
// quarantines to exactly one bounded deny header on each.
func TestChainComposerOversizeParity17026(t *testing.T) {
	po := chain17026PO("")
	chain := []string{"A", "B"}
	if n := config.ComposedChainSequenceCount(po, po.PolicyStatements, chain); n <= config.MaxRouteMapSequences {
		t.Fatalf("fixture must overflow the SSOT count, got %d", n)
	}
	bgp := New().renderComposedRouteMap(po, "A-B-xpf-chain", chain)
	if got := routeMapHeaderCount17026(bgp, "A-B-xpf-chain"); got != 1 {
		t.Fatalf("BGP oversize must quarantine to 1 header, got %d", got)
	}
	red := New().renderRedistComposedMapCluster15158(po, "A-B-xpf-chain-static-xpf-redist", chain, "static", false)
	if got := routeMapHeaderCount17026(red, "A-B-xpf-chain-static-xpf-redist"); got != 1 {
		t.Fatalf("redistribute oversize must quarantine to 1 header, got %d:\n%.300s", got, red)
	}
	if !strings.Contains(red, "route-map A-B-xpf-chain-static-xpf-redist deny 10\n") {
		t.Fatalf("redistribute quarantine must be the bounded deny 10, got:\n%.300s", red)
	}
}

// TestChainComposerTerminatingRender17026 is the direct-construction
// twin of the strict-gate regression: terminating A renders 4001
// headers through the redistribute adapter and the same count
// through the BGP adapter (whose tail is unreachable).
func TestChainComposerTerminatingRender17026(t *testing.T) {
	po := chain17026PO("reject")
	chain := []string{"A", "B"}
	red := New().renderRedistComposedMapCluster15158(po, "A-B-xpf-chain-static-xpf-redist", chain, "static", false)
	if got := routeMapHeaderCount17026(red, "A-B-xpf-chain-static-xpf-redist"); got != 4001 {
		t.Fatalf("redistribute terminating chain must render 4001 headers, got %d", got)
	}
	bgp := New().renderComposedRouteMap(po, "A-B-xpf-chain", chain)
	if got := routeMapHeaderCount17026(bgp, "A-B-xpf-chain"); got != 4001 {
		t.Fatalf("BGP terminating chain must render 4001 headers, got %d", got)
	}
}
