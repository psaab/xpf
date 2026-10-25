package frr

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16869: regression of #15157. A single-policy BGP export with an
// explicit policy default and a `then next policy` term sent the escape
// to the policy's own default instead of the Junos BGP default export,
// once any peer in the instance originates. Arm A (reject default +
// other-peer origination) must render the escape onto the carved pair
// (permit `match source-protocol bgp`, then deny) placed after the
// explicit default; non-carved and no-next-policy controls stay
// byte-identical in shape.

// nextPolicyPO16869: EXP is the traced policy — `term transit { from
// { protocol bgp; community TRANSIT; } then next policy; }` with an
// explicit policy-level default (parameterised). LOCAL originates
// static routes so a different neighbour flips origination on.
func nextPolicyPO16869(defaultAction string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name:          "EXP",
				DefaultAction: defaultAction,
				Terms: []*config.PolicyTerm{
					{Name: "transit", FromProtocols: []string{"bgp"}, FromCommunity: []string{"TRANSIT"}, NextPolicy: true},
				},
			},
			"LOCAL": {
				Name: "LOCAL",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"},
				},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"adv": {Name: "adv", Prefixes: []string{"192.0.2.0/24"}},
		},
		Communities: map[string]*config.CommunityDef{
			"TRANSIT": {Name: "TRANSIT", Members: []string{"65001:100"}},
		},
	}
}

func nextPolicyFC16869(defaultAction string, originate bool) *FullConfig {
	neighbors := []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
	}
	if originate {
		neighbors = append(neighbors, &config.BGPNeighbor{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}})
	}
	return &FullConfig{
		PolicyOptions: nextPolicyPO16869(defaultAction),
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			RouterID:  "1.1.1.1",
			Neighbors: neighbors,
		},
	}
}

// Arm A: reject default + other-peer origination. Pre-fix this rendered
// `permit 10 ... on-match goto 30` + `deny 20` + `deny 30`, so bgpd
// denied the TRANSIT BGP route the operator handed to the default
// policy. Post-fix the escape lands on the carved pair after the
// explicit default.
func TestBGPCarvedSingleNextPolicyEscapeRejectDefault16869(t *testing.T) {
	got := New().buildManagedSection(nextPolicyFC16869("reject", true))
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	for _, want := range []string{
		"route-map EXP permit 10\n",
		" on-match goto 30\n",
		"route-map EXP deny 20\n",
		"route-map EXP permit 30\n match source-protocol bgp\n",
		"route-map EXP deny 40\n",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("carved next-policy escape missing %q:\n%s", want, exp)
		}
	}
	// The explicit deny must precede the carved permit, and the escape
	// must not target the plain fallback at the default.
	if strings.Index(exp, "route-map EXP deny 20") > strings.Index(exp, "route-map EXP permit 30") {
		t.Errorf("explicit default must precede carved permit:\n%s", exp)
	}
	if strings.Contains(exp, "route-map EXP deny 30\n") {
		t.Errorf("escape must not land on a plain deny (the policy's own default):\n%s", exp)
	}
}

// Arm D: accept default + origination. Pre-fix the escape landed on a
// plain unconditional permit; post-fix it lands on the carved pair so
// only BGP-sourced routes are permitted by the escape.
func TestBGPCarvedSingleNextPolicyEscapeAcceptDefault16869(t *testing.T) {
	got := New().buildManagedSection(nextPolicyFC16869("accept", true))
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	for _, want := range []string{
		"route-map EXP permit 10\n",
		" on-match goto 30\n",
		"route-map EXP permit 20\n",
		"route-map EXP permit 30\n match source-protocol bgp\n",
		"route-map EXP deny 40\n",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("carved next-policy escape (accept) missing %q:\n%s", want, exp)
		}
	}
}

// Arm B control: reject default, NO origination — the non-carved render
// is unchanged (plain fallback escape, no carved pair).
func TestBGPNextPolicyNoOriginationNotCarved16869(t *testing.T) {
	got := New().buildManagedSection(nextPolicyFC16869("reject", false))
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	for _, want := range []string{
		"route-map EXP permit 10\n",
		" on-match goto 30\n",
		"route-map EXP deny 20\n",
		"route-map EXP permit 30\n",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("non-carved control missing %q:\n%s", want, exp)
		}
	}
	if strings.Contains(exp, "route-map EXP permit 30\n match source-protocol bgp") ||
		strings.Contains(exp, "route-map EXP deny 40\n") {
		t.Errorf("no-origination render must not append a carved pair:\n%s", exp)
	}
}

// Arm C control: no explicit default + origination — the pre-existing
// #15157 carved tail is unchanged (escape lands on the carved permit,
// plain fallback past the pair).
func TestBGPCarvedSingleNextPolicyNoDefault16869(t *testing.T) {
	got := New().buildManagedSection(nextPolicyFC16869("", true))
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	for _, want := range []string{
		"route-map EXP permit 10\n",
		" on-match goto 20\n",
		"route-map EXP permit 20\n match source-protocol bgp\n",
		"route-map EXP deny 30\n",
		"route-map EXP permit 40\n",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("no-default carved control missing %q:\n%s", want, exp)
		}
	}
}

// Control: explicit default + origination but NO next-policy term —
// nothing can escape past the terminating default, so no carved pair
// is emitted (byte-identical to the pre-#16869 explicit-default shape).
func TestBGPCarvedExplicitDefaultNoNextPolicy16869(t *testing.T) {
	po := nextPolicyPO16869("reject")
	po.PolicyStatements["EXP"].Terms = []*config.PolicyTerm{
		{Name: "t1", FromProtocols: []string{"bgp"}, Action: "accept"},
	}
	fc := nextPolicyFC16869("reject", true)
	fc.PolicyOptions = po
	got := New().buildManagedSection(fc)
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	if strings.Contains(exp, "route-map EXP permit 30\n") ||
		strings.Contains(exp, "route-map EXP deny 40\n") {
		t.Errorf("explicit default without next-policy must not append a carved pair:\n%s", exp)
	}
	if !strings.Contains(exp, "route-map EXP deny 20\n") {
		t.Errorf("explicit reject default must remain the plain tail:\n%s", exp)
	}
	if strings.Contains(exp, "on-match goto") {
		t.Errorf("no next-policy term must not emit a goto:\n%s", exp)
	}
}

// Finding 2 (accepted tradeoff, mirroring the composed renderer's
// shared-name note): the standalone map is one FRR object keyed by
// policy name. A policy used as BOTH an export (carved, originating
// instance) and an import therefore serves the import attachment with
// the same carved map — the import-side next-policy escape also lands
// on the BGP-source-only pair instead of the plain fallback. This is
// fail-closed for import (deny rather than permit), never fail-open
// for export, and is pinned here so the change is examined rather
// than silent. A policy used ONLY as an import never carves.
func TestBGPCarvedDualUseImportSharesCarvedEscape16869(t *testing.T) {
	fc := nextPolicyFC16869("reject", true)
	// Neighbour C imports the same EXP policy A exports.
	fc.BGP.Neighbors = append(fc.BGP.Neighbors,
		&config.BGPNeighbor{Address: "192.0.2.5", PeerAS: 65006, FamilyInet: true, Import: []string{"EXP"}})
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "neighbor 192.0.2.5 route-map EXP in\n") {
		t.Fatalf("dual-use neighbour C must attach EXP in:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 192.0.2.1 route-map EXP out\n") {
		t.Fatalf("export neighbour A must attach EXP out:\n%s", got)
	}
	exp := routeMapBlock15157(got, "EXP")
	for _, want := range []string{
		" on-match goto 30\n",
		"route-map EXP deny 20\n",
		"route-map EXP permit 30\n match source-protocol bgp\n",
		"route-map EXP deny 40\n",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("dual-use shared map missing %q:\n%s", want, exp)
		}
	}

	// Import-only control: same policy, origination present (LOCAL on
	// B), but EXP is never exported — the map must not carve.
	fc2 := nextPolicyFC16869("reject", true)
	fc2.BGP.Neighbors[0].Export = nil
	fc2.BGP.Neighbors[0].Import = []string{"EXP"}
	got2 := New().buildManagedSection(fc2)
	exp2 := routeMapBlock15157(got2, "EXP")
	if exp2 == "" {
		t.Fatalf("import-only EXP map missing:\n%s", got2)
	}
	if !strings.Contains(exp2, "route-map EXP permit 30\n") ||
		strings.Contains(exp2, "route-map EXP permit 30\n match source-protocol bgp") {
		t.Errorf("import-only EXP must keep the plain fallback escape:\n%s", exp2)
	}
}

// maxRenderedSeq16869 parses every `route-map <name> <verb> <seq>`
// header for name and returns (count, maxSeq).
func maxRenderedSeq16869(t *testing.T, rendered, name string) (int, int) {
	t.Helper()
	headers := routeMapHeaders6807(rendered, name)
	maxSeq := 0
	for _, h := range headers {
		f := strings.Fields(h)
		n, err := strconv.Atoi(f[3])
		if err != nil {
			t.Fatalf("unparseable header %q: %v", h, err)
		}
		if n > maxSeq {
			maxSeq = n
		}
	}
	return len(headers), maxSeq
}

// Finding 1 boundary, EXECUTED render: the wide term references
// DEFINED single-family prefix-lists so every counted variant
// actually renders (undefined names are skipped at render and would
// make this a count-only fixture — Astra R2). Both arms drive the
// real originating-neighbour section path (buildManagedSection).
// At the ceiling (count 6552) the carved render must top out at
// exactly 65530; one variant over (count 6553) the belt must render
// only the quarantine deny. Both explicit defaults are covered.
func TestBGPCarvedNextPolicySequenceBoundary16869(t *testing.T) {
	mkFC := func(n int, defaultAction string) *FullConfig {
		pls := make([]string, n)
		lists := make(map[string]*config.PrefixList, n)
		for i := range pls {
			pls[i] = fmt.Sprintf("pl%d", i)
			lists[pls[i]] = &config.PrefixList{Name: pls[i], Prefixes: []string{"10.0.0.0/8"}}
		}
		po := &config.PolicyOptionsConfig{
			PrefixLists: lists,
			Communities: map[string]*config.CommunityDef{
				"TRANSIT": {Name: "TRANSIT", Members: []string{"65001:100"}},
			},
			PolicyStatements: map[string]*config.PolicyStatement{
				"BIGEXP": {
					Name:          "BIGEXP",
					DefaultAction: defaultAction,
					Terms: []*config.PolicyTerm{
						{Name: "wide", PrefixList: pls, Action: "accept"},
						{Name: "transit", FromProtocols: []string{"bgp"}, FromCommunity: []string{"TRANSIT"}, NextPolicy: true},
					},
				},
				"LOCAL": {
					Name:  "LOCAL",
					Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"}},
				},
			},
		}
		po.PrefixLists["adv"] = &config.PrefixList{Name: "adv", Prefixes: []string{"192.0.2.0/24"}}
		return &FullConfig{
			PolicyOptions: po,
			BGP: &config.BGPConfig{
				LocalAS:  65001,
				RouterID: "1.1.1.1",
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"BIGEXP"}},
					{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}},
				},
			},
		}
	}
	// T term sequences = n + 1; count = T + 2. At ceiling: T=6550.
	for _, da := range []string{"reject", "accept"} {
		t.Run("admitted-"+da, func(t *testing.T) {
			fc := mkFC(int(config.MaxRouteMapSequences)-3, da)
			if got := config.RouteMapSequenceCount(fc.PolicyOptions, fc.PolicyOptions.PolicyStatements["BIGEXP"]); got != uint64(config.MaxRouteMapSequences) {
				t.Fatalf("count = %d, want %d", got, config.MaxRouteMapSequences)
			}
			got := New().buildManagedSection(fc)
			block := routeMapBlock15157(got, "BIGEXP")
			if block == "" {
				t.Fatalf("BIGEXP block missing:\n%s", got)
			}
			n, maxSeq := maxRenderedSeq16869(t, block, "BIGEXP")
			// 6550 terms + default + carved pair = 6553 headers.
			if n != 6553 || maxSeq != 65530 {
				t.Fatalf("headers=%d maxSeq=%d, want 6553/65530", n, maxSeq)
			}
			defaultVerb := "deny"
			if da == "accept" {
				defaultVerb = "permit"
			}
			for _, want := range []string{
				fmt.Sprintf("route-map BIGEXP %s 65510\n", defaultVerb),
				" on-match goto 65520\n",
				"route-map BIGEXP permit 65520\n match source-protocol bgp\n",
				"route-map BIGEXP deny 65530\n",
			} {
				if !strings.Contains(block, want) {
					t.Errorf("missing %q", want)
				}
			}
		})
	}
	t.Run("over-quarantined", func(t *testing.T) {
		fc := mkFC(int(config.MaxRouteMapSequences)-2, "reject")
		if got := config.RouteMapSequenceCount(fc.PolicyOptions, fc.PolicyOptions.PolicyStatements["BIGEXP"]); got != uint64(config.MaxRouteMapSequences)+1 {
			t.Fatalf("count = %d, want %d", got, config.MaxRouteMapSequences+1)
		}
		got := New().buildManagedSection(fc)
		headers := routeMapHeaders6807(got, "BIGEXP")
		if len(headers) != 1 || headers[0] != fmt.Sprintf("route-map BIGEXP deny %d", quarantineDenySeq) {
			t.Fatalf("over-ceiling must render only quarantine deny, got %v", headers)
		}
	})
}

// Astra R1: community-chain (#16835) orphan expansion. Each orphan
// term over SH (2 distinct expanded members) emits 5 slots (4 chain
// + body) but was historically counted as 1. 1310 such terms + the
// transit term = 6551 emitted term slots; with the explicit default
// and carved pair the old count (1313) admitted the policy and the
// carved deny rendered at 65540. Now the count mirrors the chain
// weight (6553 > ceiling) and the belt quarantines it; the adjacent
// 1309-term control is admitted and renders at exactly 65530.
func TestBGPCarvedCommunityChainBoundary16869(t *testing.T) {
	mkFC := func(n int) *FullConfig {
		terms := make([]*config.PolicyTerm, 0, n+1)
		for i := 0; i < n; i++ {
			terms = append(terms, &config.PolicyTerm{Name: fmt.Sprintf("c%d", i), FromCommunity: []string{"SH"}, Action: "reject"})
		}
		terms = append(terms, &config.PolicyTerm{Name: "transit", FromProtocols: []string{"bgp"}, FromCommunity: []string{"TRANSIT"}, NextPolicy: true})
		po := &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{"adv": {Name: "adv", Prefixes: []string{"192.0.2.0/24"}}},
			Communities: map[string]*config.CommunityDef{
				"SH":      {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
				"TRANSIT": {Name: "TRANSIT", Members: []string{"65001:100"}},
			},
			PolicyStatements: map[string]*config.PolicyStatement{
				"EXP":   {Name: "EXP", DefaultAction: "reject", Terms: terms},
				"LOCAL": {Name: "LOCAL", Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"}}},
			},
		}
		return &FullConfig{
			PolicyOptions: po,
			BGP: &config.BGPConfig{
				LocalAS:  65001,
				RouterID: "1.1.1.1",
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
					{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}},
				},
			},
		}
	}
	// Over: 1310 orphans. Count = 1310*5 + 1 (transit) + 2 = 6553.
	over := mkFC(1310)
	if got := config.RouteMapSequenceCount(over.PolicyOptions, over.PolicyOptions.PolicyStatements["EXP"]); got != 6553 {
		t.Fatalf("community-chain count = %d, want 6553", got)
	}
	// Cross-check the config mirror against the frr weight directly.
	if w := communityExtraTermSeqWeight16835(over.PolicyOptions, over.PolicyOptions.PolicyStatements["EXP"].Terms[0]); w != 4 {
		t.Fatalf("frr orphan extra weight = %d, want 4", w)
	}
	got := New().buildManagedSection(over)
	if headers := routeMapHeaders6807(got, "EXP"); len(headers) != 1 || headers[0] != fmt.Sprintf("route-map EXP deny %d", quarantineDenySeq) {
		t.Fatalf("over-ceiling community-chain policy must quarantine, got %v", headers)
	}
	// Control: 1309 orphans -> count 6548, admitted. Chain slots can
	// leave numbering gaps (each orphan alternative reserves its
	// guard), so assert the safety invariant (exact header count, no
	// sequence past 65535, carved pair present) rather than an exact
	// max that depends on gap placement.
	under := mkFC(1309)
	if got := config.RouteMapSequenceCount(under.PolicyOptions, under.PolicyOptions.PolicyStatements["EXP"]); got != 6548 {
		t.Fatalf("control count = %d, want 6548", got)
	}
	got = New().buildManagedSection(under)
	block := routeMapBlock15157(got, "EXP")
	n, maxSeq := maxRenderedSeq16869(t, block, "EXP")
	if n != 6549 {
		t.Fatalf("control headers=%d, want 6549", n)
	}
	if maxSeq == 0 || maxSeq > 65535 {
		t.Fatalf("control maxSeq=%d out of range", maxSeq)
	}
	if !strings.Contains(block, "match source-protocol bgp") {
		t.Errorf("control must carve the escape")
	}
}

// Opus R1: composed carved chain with NO explicit-default member
// (E=0). Two no-default members summing to 6550 term slots render
// the carved pair at the fall-off; the old ComposedChainSequenceCount
// (6550... plus per-member reserves) must admit only renders whose
// highest sequence is <= 65535, and quarantine one slot over.
func TestBGPComposedCarvedBoundary16869(t *testing.T) {
	mkPO := func(n int) *config.PolicyOptionsConfig {
		// Member A: n one-sequence accept terms (defined lists).
		// Member B: 1 accept term. Total term slots = n+1.
		termsA := make([]*config.PolicyTerm, 0, n)
		lists := make(map[string]*config.PrefixList, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("pl%d", i)
			lists[name] = &config.PrefixList{Name: name, Prefixes: []string{"10.0.0.0/8"}}
			termsA = append(termsA, &config.PolicyTerm{Name: fmt.Sprintf("a%d", i), PrefixList: []string{name}, Action: "accept"})
		}
		return &config.PolicyOptionsConfig{
			PrefixLists: lists,
			PolicyStatements: map[string]*config.PolicyStatement{
				"A": {Name: "A", Terms: termsA},
				"B": {Name: "B", Terms: []*config.PolicyTerm{{Name: "b", Action: "accept"}}},
			},
		}
	}
	const composed = "A-B-xpf-chain"
	// Config count (non-carved formula) = term slots = n+1. At
	// n=6550: count 6551, frr carved belt +1 = 6552 == ceiling,
	// admitted. Render: 6551 terms + carved pair, highest 65530.
	po := mkPO(6550)
	if got := config.ComposedChainSequenceCount(po, po.PolicyStatements, []string{"A", "B"}); got != uint64(config.MaxRouteMapSequences)-1 {
		t.Fatalf("composed count = %d, want %d", got, config.MaxRouteMapSequences-1)
	}
	rendered := New().renderComposedRouteMapExport15157(po, composed, []string{"A", "B"}, true)
	n, maxSeq := maxRenderedSeq16869(t, rendered, composed)
	if n != 6553 || maxSeq != 65530 {
		t.Fatalf("composed headers=%d maxSeq=%d, want 6553/65530", n, maxSeq)
	}
	if !strings.Contains(rendered, "match source-protocol bgp") {
		t.Fatalf("composed boundary render must carve")
	}
	// One more term slot: count 6552, belt 6553 -> quarantined.
	po = mkPO(6551)
	if got := config.ComposedChainSequenceCount(po, po.PolicyStatements, []string{"A", "B"}); got != uint64(config.MaxRouteMapSequences) {
		t.Fatalf("composed over count = %d, want %d", got, config.MaxRouteMapSequences)
	}
	rendered = New().renderComposedRouteMapExport15157(po, composed, []string{"A", "B"}, true)
	if headers := routeMapHeaders6807(rendered, composed); len(headers) != 1 {
		t.Fatalf("over-ceiling composed chain must render only quarantine deny, got %v", headers)
	}
}

// No-default single carved boundary (pre-existing tail): config
// count = T (no reserve); the frr carved belt adds +2 (pair +
// fallback beyond the reserved fallback). At belt-total 6552 the
// section render tops out at 65530; one over quarantines.
func TestBGPCarvedNoDefaultBoundary16869(t *testing.T) {
	mkFC := func(n int) *FullConfig {
		pls := make([]string, n)
		lists := make(map[string]*config.PrefixList, n)
		for i := range pls {
			pls[i] = fmt.Sprintf("pl%d", i)
			lists[pls[i]] = &config.PrefixList{Name: pls[i], Prefixes: []string{"10.0.0.0/8"}}
		}
		lists["adv"] = &config.PrefixList{Name: "adv", Prefixes: []string{"192.0.2.0/24"}}
		po := &config.PolicyOptionsConfig{
			PrefixLists: lists,
			Communities: map[string]*config.CommunityDef{"TRANSIT": {Name: "TRANSIT", Members: []string{"65001:100"}}},
			PolicyStatements: map[string]*config.PolicyStatement{
				"EXP": {Name: "EXP", Terms: []*config.PolicyTerm{
					{Name: "wide", PrefixList: pls, Action: "accept"},
					{Name: "transit", FromProtocols: []string{"bgp"}, FromCommunity: []string{"TRANSIT"}, NextPolicy: true},
				}},
				"LOCAL": {Name: "LOCAL", Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"}}},
			},
		}
		return &FullConfig{
			PolicyOptions: po,
			BGP: &config.BGPConfig{
				LocalAS:  65001,
				RouterID: "1.1.1.1",
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
					{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}},
				},
			},
		}
	}
	// T = n+1; belt total = T+2. Ceiling: T = 6550, n = 6549.
	fc := mkFC(int(config.MaxRouteMapSequences) - 3)
	if got := config.RouteMapSequenceCount(fc.PolicyOptions, fc.PolicyOptions.PolicyStatements["EXP"]); got != uint64(config.MaxRouteMapSequences)-2 {
		t.Fatalf("no-default count = %d, want %d", got, config.MaxRouteMapSequences-2)
	}
	got := New().buildManagedSection(fc)
	block := routeMapBlock15157(got, "EXP")
	n, maxSeq := maxRenderedSeq16869(t, block, "EXP")
	// 6550 terms + carved pair + fallback = 6553 headers.
	if n != 6553 || maxSeq != 65530 {
		t.Fatalf("no-default headers=%d maxSeq=%d, want 6553/65530", n, maxSeq)
	}
	for _, want := range []string{
		"route-map EXP permit 65510\n match source-protocol bgp\n",
		"route-map EXP deny 65520\n",
		"route-map EXP permit 65530\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %q", want)
		}
	}
	// One over: belt total 6553 -> quarantine deny only.
	fc = mkFC(int(config.MaxRouteMapSequences) - 2)
	got = New().buildManagedSection(fc)
	if headers := routeMapHeaders6807(got, "EXP"); len(headers) != 1 {
		t.Fatalf("over-ceiling no-default must quarantine, got %v", headers)
	}
}

// beltTotal16869 must not wrap the saturation sentinel: a count of
// math.MaxUint64 plus any reserve stays over the ceiling.
func TestBeltTotalSaturates16869(t *testing.T) {
	const maxU = ^uint64(0)
	for _, reserve := range []uint64{0, 1, 2} {
		if got := beltTotal16869(maxU, reserve); got != maxU {
			t.Errorf("beltTotal(MaxUint64,%d) = %d, want MaxUint64", reserve, got)
		}
		if got := beltTotal16869(maxU-1, reserve); reserve > 0 && got != maxU {
			t.Errorf("beltTotal(MaxUint64-1,%d) = %d, want MaxUint64", reserve, got)
		}
		if got := beltTotal16869(6550, reserve); got != 6550+reserve {
			t.Errorf("beltTotal(6550,%d) = %d, want %d", reserve, got, 6550+reserve)
		}
	}
}

// Saturation through the real belts: a policy whose Cartesian
// product saturates RouteMapSequenceCount (46341^2 protocol x
// as-path dimension, with a dangling as-path so the render folds to
// the fail-closed deny instead of expanding) must quarantine on
// every carved path — single (+1/+2 reserves) and composed (+1) —
// and with origination toggled through buildManagedSection. Before
// beltTotal16869, MaxUint64+reserve wrapped to 0/1 and bypassed the
// guard. The dangling reference is the safety valve: never make
// these references defined.
func TestBGPCarvedSaturatedCountQuarantines16869(t *testing.T) {
	const n = 46341
	saturatedPO := func(withNext bool) *config.PolicyOptionsConfig {
		protos := make([]string, 2*n)
		for i := range protos {
			protos[i] = "x" + strconv.Itoa(i)
		}
		repeat := make([]string, n)
		for i := range repeat {
			repeat[i] = "MISSING"
		}
		// Four ~46341-wide dimensions: 46341^4 (x2 family split)
		// overflows uint64 and the count saturates. The refs are
		// dangling so a (buggy) render folds closed instead of
		// expanding — never define them.
		terms := []*config.PolicyTerm{
			{Name: "wide", FromProtocols: protos, FromASPath: repeat, PrefixList: repeat, FromCommunity: repeat, RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}, {Prefix: "2001:db8::/32", MatchType: "exact"}}, Action: "reject"},
		}
		if withNext {
			terms = append(terms, &config.PolicyTerm{Name: "esc", FromCommunity: []string{"C"}, NextPolicy: true})
		}
		return &config.PolicyOptionsConfig{
			Communities: map[string]*config.CommunityDef{"C": {Name: "C", Members: []string{"65000:1"}}},
			ASPaths:     map[string]*config.ASPathDef{},
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: terms},
			},
		}
	}
	assertQuarantine := func(t *testing.T, got, name string) {
		t.Helper()
		headers := routeMapHeaders6807(got, name)
		if len(headers) != 1 || headers[0] != fmt.Sprintf("route-map %s deny %d", name, quarantineDenySeq) {
			t.Fatalf("saturated %s must render only quarantine deny, got %v", name, headers)
		}
	}
	for _, withNext := range []bool{false, true} {
		po := saturatedPO(withNext)
		if got := config.RouteMapSequenceCount(po, po.PolicyStatements["P"]); got != ^uint64(0) {
			t.Fatalf("prerequisite: count must saturate, got %d", got)
		}
		got := New().generatePolicyOptionsForSection15157(po, map[string]bool{"P": true}, nil, nil, map[string]bool{"P": true})
		assertQuarantine(t, got, "P")
	}
	// Composed reserve.
	po := saturatedPO(false)
	po.PolicyStatements["B"] = &config.PolicyStatement{Name: "B", Terms: []*config.PolicyTerm{{Name: "b", Action: "reject"}}}
	if got := config.ComposedChainSequenceCount(po, po.PolicyStatements, []string{"P", "B"}); got != ^uint64(0) {
		t.Fatalf("prerequisite: composed count must saturate, got %d", got)
	}
	got := New().renderComposedRouteMapExport15157(po, "PB", []string{"P", "B"}, true)
	assertQuarantine(t, got, "PB")
	// Real section path with origination toggle: saturated EXP on A,
	// LOCAL origination on B. Without origination the non-carved
	// belt already quarantined; with it the carved belt must too.
	for _, origin := range []bool{false, true} {
		po := saturatedPO(false)
		po.PolicyStatements["EXP"] = po.PolicyStatements["P"]
		delete(po.PolicyStatements, "P")
		po.PolicyStatements["EXP"].Name = "EXP"
		po.PolicyStatements["LOCAL"] = &config.PolicyStatement{Name: "LOCAL", Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"}}}
		po.PrefixLists = map[string]*config.PrefixList{"adv": {Name: "adv", Prefixes: []string{"192.0.2.0/24"}}}
		neighbors := []*config.BGPNeighbor{
			{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
		}
		if origin {
			neighbors = append(neighbors, &config.BGPNeighbor{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}})
		}
		fc := &FullConfig{PolicyOptions: po, BGP: &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: neighbors}}
		if got := bgpInstanceHasOrigination15157(fc.BGP, po); got != origin {
			t.Fatalf("origination toggle = %v, want %v", got, origin)
		}
		assertQuarantine(t, New().buildManagedSection(fc), "EXP")
	}
}
