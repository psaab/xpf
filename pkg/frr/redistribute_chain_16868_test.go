package frr

import (
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
