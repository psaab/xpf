package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16868 (R3-B07-05): redistChainForSource15156 admitted a chain member
// only if that member's own #14698 enrolment included the source. A
// reject-only guard, a protocol-less reject guard, or a policy whose
// only terminal for a source is its policy-level `then reject` enrols
// nothing and silently dropped out of the chain, so the single
// surviving policy's per-source map was rendered instead of the
// composed map and the rejected routes were exported.
//
// Fix: whenever any member enrols a source, the whole defined chain
// composes for that source — every defined member's applicable
// per-source terms and terminal DefaultAction run in chain order,
// whether or not that member enrols the source by itself. A member
// whose default terminates the chain truncates later members, mirroring
// #5277. Bare-token-only and no-enrolment chains are unchanged.

func guardChainPO16868() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// k1: reject-only guard naming static with route filters.
			"NO-60": {
				Name: "NO-60",
				Terms: []*config.PolicyTerm{
					{Name: "bad", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.60.0/24", MatchType: "exact"}}, Action: "reject"},
				},
			},
			"STATICS": {
				Name: "STATICS",
				Terms: []*config.PolicyTerm{
					{Name: "statics", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
			// k2: protocol-less (no-from) reject guard.
			"NO-60-NOFROM": {
				Name: "NO-60-NOFROM",
				Terms: []*config.PolicyTerm{
					{Name: "bad", RouteFilters: []*config.RouteFilter{{Prefix: "192.168.60.0/24", MatchType: "exact"}}, Action: "reject"},
				},
			},
			// k3: only terminal for connected is the policy default reject.
			"ONLY-STATIC": {
				Name: "ONLY-STATIC",
				Terms: []*config.PolicyTerm{
					{Name: "statics", FromProtocols: []string{"static"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
			"DIRECT": {
				Name: "DIRECT",
				Terms: []*config.PolicyTerm{
					{Name: "direct", FromProtocols: []string{"direct"}, Action: "accept"},
				},
			},
		},
	}
}

func ospfChainSection16868(t *testing.T, po *config.PolicyOptionsConfig, export []string) string {
	t.Helper()
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   export,
			Areas: []*config.OSPFArea{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
			},
		},
	}
	return New().buildManagedSection(fc)
}

func TestOSPFRejectOnlyGuardComposesChain16868(t *testing.T) {
	po := guardChainPO16868()
	got := ospfChainSection16868(t, po, []string{"NO-60", "STATICS"})
	composed := "NO-60-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix + "-ospf"
	if !strings.Contains(got, " redistribute static route-map "+composed+"\n") {
		t.Fatalf("reject-only guard must compose: want redistribute static route-map %s\n%s", composed, got)
	}
	if strings.Contains(got, " redistribute static route-map STATICS-static-xpf-redist-ospf\n") {
		t.Fatalf("single-survivor per-source map must not be the OSPF attachment when the guard composes\n%s", got)
	}
	deny := strings.Index(got, "route-map "+composed+" deny")
	permit := strings.Index(got, "route-map "+composed+" permit")
	if deny < 0 || permit < 0 || deny > permit {
		t.Fatalf("composed map must deny NO-60 before permitting STATICS: deny@%d permit@%d\n%s", deny, permit, got)
	}
	seqs := strings.Join(redistSeqs16864(t, got, composed), "\n")
	if !strings.Contains(seqs, "192.168.60") && !strings.Contains(got, "192.168.60") {
		t.Fatalf("composed map must carry the NO-60 reject filter\n%s", got)
	}
}

func TestOSPFProtocolLessRejectGuardComposesChain16868(t *testing.T) {
	po := guardChainPO16868()
	got := ospfChainSection16868(t, po, []string{"NO-60-NOFROM", "STATICS"})
	composed := "NO-60-NOFROM-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix + "-ospf"
	if !strings.Contains(got, " redistribute static route-map "+composed+"\n") {
		t.Fatalf("protocol-less reject guard must compose: want %s\n%s", composed, got)
	}
	if strings.Contains(got, " redistribute static route-map STATICS-static-xpf-redist-ospf\n") {
		t.Fatalf("protocol-less guard dropped: STATICS per-source map attached instead of composed\n%s", got)
	}
	deny := strings.Index(got, "route-map "+composed+" deny")
	permit := strings.Index(got, "route-map "+composed+" permit")
	if deny < 0 || permit < 0 || deny > permit {
		t.Fatalf("composed map must deny before permit: deny@%d permit@%d\n%s", deny, permit, got)
	}
}

func TestOSPFPolicyDefaultRejectGuardComposesConnected16868(t *testing.T) {
	po := guardChainPO16868()
	got := ospfChainSection16868(t, po, []string{"ONLY-STATIC", "DIRECT"})
	composed := "ONLY-STATIC-DIRECT" + ReservedChainSuffix + "-connected" + config.ReservedRedistSuffix + "-ospf"
	if !strings.Contains(got, " redistribute connected route-map "+composed+"\n") {
		t.Fatalf("policy-default-reject guard must compose for connected: want %s\n%s", composed, got)
	}
	if strings.Contains(got, " redistribute connected route-map DIRECT-connected-xpf-redist-ospf\n") {
		t.Fatalf("DIRECT per-source map attached; ONLY-STATIC default reject dropped\n%s", got)
	}
	// The composed connected map must be deny-only (default reject is
	// terminal): no permit sequence at all.
	seqs := redistSeqs16864(t, got, composed)
	for _, s := range seqs {
		if strings.HasPrefix(s, "permit") {
			t.Fatalf("composed connected map must not permit (ONLY-STATIC then reject is terminal), seq %q\n%s", s, got)
		}
	}
	// The static source still enrols via ONLY-STATIC alone.
	if !strings.Contains(got, " redistribute static route-map ONLY-STATIC-static-xpf-redist-ospf\n") {
		t.Fatalf("static must keep ONLY-STATIC per-source attachment\n%s", got)
	}
}

func TestOSPFGuardFallthroughTermUnchanged16868(t *testing.T) {
	// k0 positive control: the pre-existing #15156 fixture, whose guard
	// carries the synthetic fall-through term, is unchanged.
	po := chainPO15156()
	got := ospfChainSection16868(t, po, []string{"NO-RFC1918", "STATICS"})
	composed := "NO-RFC1918-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix + "-ospf"
	if !strings.Contains(got, " redistribute static route-map "+composed+"\n") {
		t.Fatalf("k0 control must keep composed attachment %s\n%s", composed, got)
	}
	firstDeny := strings.Index(got, "route-map "+composed+" deny")
	firstPermit := strings.Index(got, "route-map "+composed+" permit")
	if firstDeny < 0 || firstPermit < 0 || firstDeny > firstPermit {
		t.Fatalf("k0 composed map must deny before permit\n%s", got)
	}
}

// The #15156 fixture without its synthetic guard-fallthrough term must
// now compose identically — the acceptance's "without the synthetic
// term" cell.
func TestOSPFChainWithoutSyntheticGuardTerm16868(t *testing.T) {
	po := chainPO15156()
	po.PolicyStatements["NO-RFC1918"].Terms = po.PolicyStatements["NO-RFC1918"].Terms[:3]
	got := ospfChainSection16868(t, po, []string{"NO-RFC1918", "STATICS"})
	composed := "NO-RFC1918-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix + "-ospf"
	if !strings.Contains(got, " redistribute static route-map "+composed+"\n") {
		t.Fatalf("reject-only NO-RFC1918 (no synthetic term) must compose %s\n%s", composed, got)
	}
	firstDeny := strings.Index(got, "route-map "+composed+" deny")
	firstPermit := strings.Index(got, "route-map "+composed+" permit")
	if firstDeny < 0 || firstPermit < 0 || firstDeny > firstPermit {
		t.Fatalf("composed map must deny before permit without synthetic term\n%s", got)
	}
}

func TestBGPRejectGuardChainComposes16868(t *testing.T) {
	// One neighbour's effective chain [NO-60 STATICS]: the guard and
	// the acceptor share the chain, so static composes over both.
	po := guardChainPO16868()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	composed := "NO-60-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix
	if !strings.Contains(got, "redistribute static route-map "+composed+"\n") {
		t.Fatalf("BGP chain must compose guard+acceptor for static, want %s\n%s", composed, got)
	}
	if strings.Contains(got, "redistribute static route-map STATICS-static-xpf-redist\n") {
		t.Fatalf("BGP chain attached STATICS alone; NO-60 guard dropped\n%s", got)
	}
	deny := strings.Index(got, "route-map "+composed+" deny")
	permit := strings.Index(got, "route-map "+composed+" permit")
	if deny < 0 || permit < 0 || deny > permit {
		t.Fatalf("BGP composed map must deny before permit\n%s", got)
	}
}

func TestISISRejectGuardComposes16868(t *testing.T) {
	po := guardChainPO16868()
	fc := &FullConfig{
		PolicyOptions: po,
		ISIS: &config.ISISConfig{
			NET:    "49.0001.0100.0100.1001.00",
			Level:  "level-2",
			Export: []string{"NO-60", "STATICS"},
		},
	}
	got := New().buildManagedSection(fc)
	composed := "NO-60-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix
	lines := redistLinesIn15156(t, got, "router isis")
	found := false
	for _, ln := range lines {
		if strings.Contains(ln, " static ") {
			found = true
			if !strings.Contains(ln, composed) {
				t.Fatalf("IS-IS chain line must reference composed map %s: %q\n%s", composed, ln, got)
			}
			if strings.Contains(ln, "STATICS-static-xpf-redist") && !strings.Contains(ln, composed) {
				t.Fatalf("IS-IS attached STATICS alone: %q", ln)
			}
		}
	}
	if !found {
		t.Fatalf("IS-IS chain must emit composed redistribute lines, got %v\n%s", lines, got)
	}
}

// evalOrSeqs16868 simulates FRR route-map evaluation over the spliced
// OR map for the two probe routes: "bad" matches 192.168.60.0/24
// (the NO-60 reject filter), "good" matches 192.168.50.0/24. A permit
// with `on-match goto N` jumps to sequence N on match; a permit/deny
// without a continuation is terminal. Returns the terminal verb.
func evalOrSeqs16868(t *testing.T, seqs []string, route string) string {
	t.Helper()
	type seq struct {
		verb     string
		num      int
		gotoN    int
		matchBad bool
		matchAny bool
	}
	var parsed []seq
	byNum := map[int]int{}
	for _, s := range seqs {
		f := strings.Fields(s)
		if len(f) < 2 {
			t.Fatalf("unparseable seq %q", s)
		}
		var n, g int
		fmtSscanf16868(t, f[1], &n)
		// A retained conditional sequence (it kept its match
		// clauses — only demoted denies become bare goto permits)
		// matches "bad" when its clauses name the guard's filter
		// and "good" otherwise. Inline ACL names embed the guard
		// policy name (NO-60 / NO-RFC1918), which is the marker.
		p := seq{verb: f[0], num: n, gotoN: -1, matchAny: !strings.Contains(s, "match ") || strings.Contains(s, "on-match goto")}
		if strings.Contains(s, "match ") && (strings.Contains(s, "NO-60") || strings.Contains(s, "NO-RFC1918")) {
			p.matchBad = true
			p.matchAny = false
		}
		if i := strings.Index(s, "on-match goto "); i >= 0 {
			fmtSscanf16868(t, strings.Fields(s[i+len("on-match goto "):])[0], &g)
			p.gotoN = g
		}
		byNum[n] = len(parsed)
		parsed = append(parsed, p)
	}
	idx := 0
	for idx < len(parsed) {
		p := parsed[idx]
		matched := p.matchAny || (p.matchBad && route == "bad")
		if matched {
			if p.gotoN >= 0 {
				j, ok := byNum[p.gotoN]
				if !ok {
					t.Fatalf("goto target %d has no sequence in %v", p.gotoN, seqs)
				}
				idx = j
				continue
			}
			return p.verb
		}
		idx++
	}
	return "deny"
}

func fmtSscanf16868(t *testing.T, s string, out *int) {
	t.Helper()
	if _, err := fmt.Sscanf(s, "%d", out); err != nil {
		t.Fatalf("bad seq number %q: %v", s, err)
	}
}

// TestBGPCrossChainOrSemantics16868 pins the Astra counterexample:
// neighbour A exports [NO-60 STATICS], neighbour B exports [STATICS].
// Origination must be the OR of the chains — both statics originate
// (B accepts .60), regardless of neighbour order — while A's own
// chain still rejects .60 for A (per-peer route-map out is separate).
// A terminal-default guard in the first chain must not veto either.
func TestBGPCrossChainOrSemantics16868(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first []string
	}{
		{"guard-chain first", []string{"NO-60", "STATICS"}},
		{"acceptor first", []string{"STATICS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			po := guardChainPO16868()
			var neighbors []*config.BGPNeighbor
			if tc.name == "guard-chain first" {
				neighbors = []*config.BGPNeighbor{
					{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
					{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
				}
			} else {
				neighbors = []*config.BGPNeighbor{
					{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
					{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
				}
			}
			fc := &FullConfig{
				PolicyOptions: po,
				BGP: &config.BGPConfig{
					LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: neighbors,
				},
			}
			got := New().buildManagedSection(fc)
			top, af6 := bgpRedistLines14586(t, got)
			_ = af6
			var staticLines []string
			for _, ln := range top {
				if strings.Contains(ln, "redistribute static") {
					staticLines = append(staticLines, ln)
				}
			}
			if len(staticLines) != 1 {
				t.Fatalf("exactly one redistribute static expected, got %v\n%s", staticLines, got)
			}
			// The attachment must be the OR map; evaluate it.
			fields := strings.Fields(staticLines[0])
			mapName := fields[len(fields)-1]
			seqs := redistSeqs16864(t, got, mapName)
			if v := evalOrSeqs16868(t, seqs, "good"); v != "permit" {
				t.Errorf("192.168.50.0/24 must originate (permit), evaluated %q over %v", v, seqs)
			}
			if v := evalOrSeqs16868(t, seqs, "bad"); v != "permit" {
				t.Errorf("192.168.60.0/24 must originate via B's chain (OR permit), evaluated %q over %v — a reject in A's chain vetoed B", v, seqs)
			}
			// Every goto target must exist and exceed its sequence.
			for _, s := range seqs {
				if !strings.Contains(s, "permit") && strings.Contains(s, "on-match") {
					t.Errorf("deny sequence carries a continuation (FRR rejects it): %q", s)
				}
			}
		})
	}
}

// TestBGPCrossChainTerminalGuardOr16868: the first chain
// [ONLY-STATIC DIRECT] default-rejects connected inside the chain
// (ONLY-STATIC's only terminal for connected is its policy-level
// reject, truncated before DIRECT); the second chain [DIRECT]
// accepts it. The first chain's terminal default must not veto
// the second chain's accept in the OR map.
func TestBGPCrossChainTerminalGuardOr16868(t *testing.T) {
	po := guardChainPO16868()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"ONLY-STATIC", "DIRECT"}},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"DIRECT"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	top, _ := bgpRedistLines14586(t, got)
	var connLines []string
	for _, ln := range top {
		if strings.Contains(ln, "redistribute connected") {
			connLines = append(connLines, ln)
		}
	}
	if len(connLines) != 1 {
		t.Fatalf("exactly one redistribute connected expected, got %v\n%s", connLines, got)
	}
	fields := strings.Fields(connLines[0])
	seqs := redistSeqs16864(t, got, fields[len(fields)-1])
	if v := evalOrSeqs16868(t, seqs, "good"); v != "permit" {
		t.Errorf("connected must originate via DIRECT chain despite ONLY-STATIC default reject, evaluated %q over %v", v, seqs)
	}
}
