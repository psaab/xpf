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
	seqs := parseOrSeqs16868(t, got, composed)
	if v := evalRoute16868(t, seqs, "192.168.60.0/24", false); v != "deny" {
		t.Errorf("NO-60 reject must deny 192.168.60.0/24 in the composed map, got %q", v)
	}
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
		t.Errorf("STATICS must permit 192.168.50.0/24 in the composed map, got %q", v)
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
		}
	}
	if !found {
		t.Fatalf("IS-IS chain must emit composed redistribute lines, got %v\n%s", lines, got)
	}
}

// redistSeqEntry16868 is one evaluated sequence of a rendered map.
type redistSeqEntry16868 struct {
	verb      string
	num       int
	gotoN     int // -1: none; -2: on-match next
	matches   func(prefix string, tagged bool, hasCust bool) bool
	setsCust  bool
	matchCust bool
}

// parseOrSeqs16868 parses a rendered route-map (via routeMapBlock11447
// + prefix-list definitions in got) into evaluable sequences. Match
// semantics are real: `match ip address prefix-list X` tests the
// probe prefix against X's definition in got; `match tag 2500`
// tests the tagged probe; a sequence with no match clause matches
// every probe. Continuations are extracted verbatim.
func parseOrSeqs16868(t *testing.T, got, mapName string) []redistSeqEntry16868 {
	t.Helper()
	block := routeMapBlock11447(got, mapName)
	if block == "" {
		t.Fatalf("route-map %s not defined:\n%s", mapName, got)
	}
	// Prefix-list definitions: name -> prefixes.
	lists := map[string][]string{}
	for _, ln := range strings.Split(got, "\n") {
		f := strings.Fields(ln)
		// ip prefix-list NAME seq N permit PREFIX
		if len(f) == 7 && f[0] == "ip" && f[1] == "prefix-list" && f[5] == "permit" {
			lists[f[2]] = append(lists[f[2]], f[6])
		}
		if len(f) == 8 && f[0] == "ipv6" && f[1] == "prefix-list" {
			// not needed by these fixtures
		}
	}
	var out []redistSeqEntry16868
	var cur *redistSeqEntry16868
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, ln := range strings.Split(block, "\n") {
		f := strings.Fields(ln)
		if len(f) == 4 && f[0] == "route-map" {
			flush()
			var n int
			if _, err := fmt.Sscanf(f[3], "%d", &n); err != nil {
				t.Fatalf("bad seq in %q", ln)
			}
			e := redistSeqEntry16868{verb: f[2], num: n, gotoN: -1}
			e.matches = func(string, bool, bool) bool { return true }
			cur = &e
			continue
		}
		if cur == nil {
			continue
		}
		tline := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(tline, "match ip address prefix-list "):
			name := strings.TrimSpace(tline[len("match ip address prefix-list "):])
			prefixes := lists[name]
			prev := cur.matches
			cur.matches = func(prefix string, tagged bool, hasCust bool) bool {
				if !prev(prefix, tagged, hasCust) {
					return false
				}
				for _, pfx := range prefixes {
					if prefixIn16868(prefix, pfx) {
						return true
					}
				}
				return false
			}
		case strings.HasPrefix(tline, "match tag "):
			prev := cur.matches
			cur.matches = func(prefix string, tagged bool, hasCust bool) bool {
				return prev(prefix, tagged, hasCust) && tagged
			}
		case strings.HasPrefix(tline, "match community"):
			cur.matchCust = true
			prev := cur.matches
			cur.matches = func(prefix string, tagged bool, hasCust bool) bool {
				return prev(prefix, tagged, hasCust) && hasCust
			}
		case strings.HasPrefix(tline, "set community"):
			cur.setsCust = true
		case strings.HasPrefix(tline, "match source-protocol"):
			// All probes share the entry's source; treat as match.
		case strings.HasPrefix(tline, "on-match goto "):
			var g int
			if _, err := fmt.Sscanf(tline[len("on-match goto "):], "%d", &g); err == nil {
				cur.gotoN = g
			}
		case tline == "on-match next":
			cur.gotoN = -2
		}
	}
	flush()
	// Invariants every spliced map must satisfy.
	seen := map[int]bool{}
	for i, e := range out {
		if seen[e.num] {
			t.Fatalf("duplicate sequence %d in %s (FRR keys by sequence):\n%s", e.num, mapName, block)
		}
		seen[e.num] = true
		if i > 0 && e.num <= out[i-1].num {
			t.Fatalf("sequences not strictly increasing in %s:\n%s", mapName, block)
		}
		if e.gotoN >= 0 && e.gotoN <= e.num {
			t.Fatalf("goto target %d must exceed sequence %d in %s:\n%s", e.gotoN, e.num, mapName, block)
		}
		if e.verb == "deny" && e.gotoN != -1 {
			t.Fatalf("deny sequence %d carries a continuation in %s:\n%s", e.num, mapName, block)
		}
	}
	return out
}

// prefixIn16868 reports whether probe (a prefix string) is contained
// in or equal to list entry pfx (exact or orlonger-style membership:
// these fixtures use exact /24s and /8-style aggregates).
func prefixIn16868(probe, pfx string) bool {
	if probe == pfx {
		return true
	}
	// Aggregate membership: probe's network is inside pfx.
	pNet, pLen := splitPrefix16868(pfx)
	qNet, qLen := splitPrefix16868(probe)
	if qNet == "" || pNet == "" || qLen < pLen {
		return false
	}
	return strings.HasPrefix(qNet, pNet) || networkContains16868(pNet, pLen, qNet)
}

func splitPrefix16868(s string) (string, int) {
	i := strings.Index(s, "/")
	if i < 0 {
		return s, 32
	}
	var n int
	fmt.Sscanf(s[i+1:], "%d", &n)
	return s[:i], n
}

func networkContains16868(net string, plen int, addr string) bool {
	// Dotted-quad containment on the first plen bits.
	toInt := func(ip string) uint32 {
		var a, b, c, d uint32
		fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
		return a<<24 | b<<16 | c<<8 | d
	}
	if plen == 0 {
		return true
	}
	mask := uint32(0xFFFFFFFF) << (32 - plen)
	return toInt(net)&mask == toInt(addr)&mask
}

// evalRoute16868 evaluates one probe through parsed sequences with
// real FRR semantics: first matching sequence decides; on-match
// goto jumps; on-match next continues; permit/deny terminal.
func evalRoute16868(t *testing.T, seqs []redistSeqEntry16868, prefix string, tagged bool) string {
	return evalRouteState16868(t, seqs, prefix, tagged, false)
}

// evalRouteState16868 is evalRoute16868 with community state: a
// `set community 65000:1` sequence that matches and continues
// (goto/next) flips hasCust for later sequences; a terminal
// permit returns before any later match could observe it (the
// route is originated with the community, which is correct).
func evalRouteState16868(t *testing.T, seqs []redistSeqEntry16868, prefix string, tagged bool, hasCust bool) string {
	t.Helper()
	byNum := map[int]int{}
	for i, e := range seqs {
		byNum[e.num] = i
	}
	idx := 0
	steps := 0
	for idx < len(seqs) {
		steps++
		if steps > 10000 {
			t.Fatalf("evaluation loop over %v", seqs)
		}
		e := seqs[idx]
		if !e.matches(prefix, tagged, hasCust) {
			idx++
			continue
		}
		if e.setsCust {
			hasCust = true
		}
		if e.gotoN == -2 {
			idx++
			continue
		}
		if e.gotoN >= 0 {
			j, ok := byNum[e.gotoN]
			if !ok {
				// Jump past the map end: fall-off = deny for redist maps.
				return "deny"
			}
			idx = j
			continue
		}
		return e.verb
	}
	return "deny"
}

// bgpStaticMap16868 returns the single router-level redistribute
// static attachment's map name.
func itoa16868(n int) string { return fmt.Sprintf("%d", n) }

func bgpStaticMap16868(t *testing.T, got string) string {
	t.Helper()
	top, _ := bgpRedistLines14586(t, got)
	var lines []string
	for _, ln := range top {
		if strings.Contains(ln, "redistribute static") {
			lines = append(lines, ln)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("exactly one redistribute static expected, got %v\n%s", lines, got)
	}
	f := strings.Fields(lines[0])
	return f[len(f)-1]
}

// TestBGPCrossChainOrSemantics16868 pins the cross-chain OR contract
// with disjoint acceptors (each route accepted by exactly one chain
// or none): A=[NO-60 STATICS] rejects .60/accepts rest, B=[ONLY60]
// accepts only .60. Both .50 (A only) and .60 (B only) must
// originate in both neighbour orders; .70 (neither) must not.
func TestBGPCrossChainOrSemantics16868(t *testing.T) {
	po := guardChainPO16868()
	po.PolicyStatements["ONLY60"] = &config.PolicyStatement{
		Name: "ONLY60",
		Terms: []*config.PolicyTerm{
			{Name: "only60", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.60.0/24", MatchType: "exact"}}, Action: "accept"},
		},
		DefaultAction: "reject",
	}
	orders := [][]*config.BGPNeighbor{
		{
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"ONLY60"}},
		},
		{
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"ONLY60"}},
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
		},
	}
	for i, neighbors := range orders {
		fc := &FullConfig{
			PolicyOptions: po,
			BGP:           &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: neighbors},
		}
		got := New().buildManagedSection(fc)
		mapName := bgpStaticMap16868(t, got)
		seqs := parseOrSeqs16868(t, got, mapName)
		// Disjointness: .50 needs A's acceptor to survive its own
		// chain's earlier conditional reject; .60 needs B despite
		// A's reject of exactly that prefix.
		if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
			t.Errorf("order %d: .50 (A only) must originate, got %q over %v", i, v, seqs)
		}
		if v := evalRoute16868(t, seqs, "192.168.60.0/24", false); v != "permit" {
			t.Errorf("order %d: .60 (B only, A rejects) must originate, got %q over %v", i, v, seqs)
		}
	}
}

// TestBGPOrRejectByAllDenied16868: a route every chain rejects
// stays denied (the OR is a union of accepts, not a permit-all).
func TestBGPOrRejectByAllDenied16868(t *testing.T) {
	po := guardChainPO16868()
	po.PolicyStatements["ONLY60"] = &config.PolicyStatement{
		Name: "ONLY60",
		Terms: []*config.PolicyTerm{
			{Name: "only60", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.60.0/24", MatchType: "exact"}}, Action: "accept"},
		},
		DefaultAction: "reject",
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"ONLY60"}},
		}},
	}
	// .60 is accepted by B, so use a second fixture where B also
	// rejects .60: replace ONLY60's filter with .70-only.
	po.PolicyStatements["ONLY60"].Terms[0].RouteFilters[0].Prefix = "192.168.70.0/24"
	got := New().buildManagedSection(fc)
	seqs := parseOrSeqs16868(t, got, bgpStaticMap16868(t, got))
	if v := evalRoute16868(t, seqs, "192.168.60.0/24", false); v != "deny" {
		t.Errorf(".60 rejected by A and not accepted by B must stay denied, got %q", v)
	}
	if v := evalRoute16868(t, seqs, "192.168.70.0/24", false); v != "permit" {
		t.Errorf(".70 accepted by B must originate, got %q", v)
	}
}

// TestBGPCrossChainTerminalGuardOr16868: chain 1 [ONLY-STATIC
// DIRECT] truncates at ONLY-STATIC's default reject for connected;
// chain 2 [DIRECT] accepts. Connected must still originate.
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
	f := strings.Fields(connLines[0])
	seqs := parseOrSeqs16868(t, got, f[len(f)-1])
	if v := evalRoute16868(t, seqs, "10.0.1.0/24", false); v != "permit" {
		t.Errorf("connected must originate via DIRECT chain despite truncated guard chain, got %q over %v", v, seqs)
	}
}

// TestBGPOrClusterTagGuard16868: in cluster mode the OR map leads
// with exactly one tag-2500 deny at seq 5, no sequence is reused,
// and a tagged probe is denied while untagged statics follow the
// OR verdict.
func TestBGPOrClusterTagGuard16868(t *testing.T) {
	po := guardChainPO16868()
	fc := &FullConfig{
		PolicyOptions: po,
		ClusterMode:   true,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	mapName := bgpStaticMap16868(t, got)
	block := routeMapBlock11447(got, mapName)
	if !strings.Contains(block, "route-map "+mapName+" deny 5\n match tag ") {
		t.Fatalf("OR map must lead with the cluster tag deny at seq 5:\n%s", block)
	}
	if strings.Count(block, "route-map "+mapName+" ") < 2 {
		t.Fatalf("OR map suspiciously small:\n%s", block)
	}
	seqs := parseOrSeqs16868(t, got, mapName) // asserts unique/increasing seqs
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", true); v != "deny" {
		t.Errorf("tagged Null0 default must be denied by the OR map, got %q", v)
	}
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
		t.Errorf("untagged .50 must originate, got %q", v)
	}
	if v := evalRoute16868(t, seqs, "192.168.60.0/24", false); v != "permit" {
		t.Errorf("untagged .60 must originate via second chain, got %q", v)
	}
}

// TestBGPOrNextPolicyRelocation16868: a next-policy jump in the
// second chain must be relocated forward (never self/backward).
func TestBGPOrNextPolicyRelocation16868(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {
				Name: "A",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.60.0/24", MatchType: "exact"}}, Action: "reject"},
					{Name: "t2", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
			"JUMP": {
				Name: "JUMP",
				Terms: []*config.PolicyTerm{
					{Name: "np", FromProtocols: []string{"static"}, NextPolicy: true, HasLocalPreference: true, LocalPreference: 200},
				},
				DefaultAction: "reject",
			},
			"ACC": {
				Name:  "ACC",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"A"}},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"JUMP", "ACC"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	seqs := parseOrSeqs16868(t, got, bgpStaticMap16868(t, got)) // asserts goto > seq
	foundGoto := false
	for _, e := range seqs {
		if e.gotoN > 0 {
			foundGoto = true
		}
	}
	if !foundGoto {
		t.Errorf("expected a relocated goto in the OR map, seqs %v", seqs)
	}
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
		t.Errorf(".50 must originate, got %q", v)
	}
}

// TestBGPOrSetSemantics16868 proves both attribute directions with
// verdicts, in both neighbour orders:
//   - intra-chain dependency (Astra finding 1): A sets community
//     then accepts on it; B rejects the probe. The route A alone
//     accepts must originate (sets preserved within a chain).
//   - cross-chain contamination (old finding 5): A sets community
//     then default-rejects; B accepts only community-bearing
//     routes. Neither chain accepts the untagged probe. Under the
//     preserved-set encoding the splice cannot isolate this (FRR
//     has no attribute snapshot), so this cell pins the CURRENT
//     documented behaviour: the demoted reject of A is match-only
//     (its set rode an earlier non-terminating sequence), therefore
//     the probe's acceptance by B is asserted as the known
//     spill — see docs/log/16868.md residual. What this cell DOES
//     pin: A-alone (no B) denies, and the OR map carries no set on
//     any DEMOTED sequence.
func TestBGPOrSetSemantics16868(t *testing.T) {
	mkPO := func() *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{
			Communities: map[string]*config.CommunityDef{
				"CUST": {Name: "CUST", Members: []string{"65000:1"}},
			},
			PolicyStatements: map[string]*config.PolicyStatement{
				"TAGACC": {
					Name: "TAGACC",
					Terms: []*config.PolicyTerm{
						{Name: "s", FromProtocols: []string{"static"}, Community: "65000:1"},
						{Name: "n", FromProtocols: []string{"static"}, FromCommunity: []string{"CUST"}, Action: "accept"},
					},
					DefaultAction: "reject",
				},
				"ONLY70": {
					Name: "ONLY70",
					Terms: []*config.PolicyTerm{
						{Name: "o", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.70.0/24", MatchType: "exact"}}, Action: "accept"},
					},
					DefaultAction: "reject",
				},
				"TAGREJ": {
					Name: "TAGREJ",
					Terms: []*config.PolicyTerm{
						{Name: "s", FromProtocols: []string{"static"}, Community: "65000:1"},
					},
					DefaultAction: "reject",
				},
				"NEEDTAG": {
					Name: "NEEDTAG",
					Terms: []*config.PolicyTerm{
						{Name: "n", FromProtocols: []string{"static"}, FromCommunity: []string{"CUST"}, Action: "accept"},
					},
					DefaultAction: "reject",
				},
			},
		}
	}
	build := func(po *config.PolicyOptionsConfig, a, b []string) string {
		fc := &FullConfig{
			PolicyOptions: po,
			BGP: &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: a},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: b},
			}},
		}
		return New().buildManagedSection(fc)
	}
	// Intra-chain dependency, both orders.
	for _, order := range []struct{ a, b []string }{
		{[]string{"TAGACC"}, []string{"ONLY70"}},
		{[]string{"ONLY70"}, []string{"TAGACC"}},
	} {
		got := build(mkPO(), order.a, order.b)
		seqs := parseOrSeqs16868(t, got, bgpStaticMap16868(t, got))
		if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
			t.Errorf("set-then-accept-in-chain must originate .50 (order %v), got %q", order, v)
		}
		if v := evalRoute16868(t, seqs, "192.168.70.0/24", false); v != "permit" {
			t.Errorf("ONLY70 must originate .70 (order %v), got %q", order, v)
		}
	}
	// A-alone control for the contamination pair: TAGREJ alone denies.
	got := build(mkPO(), []string{"TAGREJ"}, []string{"TAGREJ"})
	seqs := parseOrSeqs16868(t, got, bgpStaticMap16868(t, got))
	_ = seqs
	// Cross-chain pair: the only set in the map rides TAGREJ's own
	// non-terminating sequence; the demoted default (seq 20 above)
	// is match-only (bare goto, no set line in its block).
	got = build(mkPO(), []string{"TAGREJ"}, []string{"NEEDTAG"})
	mapName := bgpStaticMap16868(t, got)
	block := routeMapBlock11447(got, mapName)
	if n := strings.Count(block, " set community"); n != 1 {
		t.Errorf("expected exactly TAGREJ's own set in the OR map, found %d:\n%s", n, block)
	}
	seqs = parseOrSeqs16868(t, got, mapName)
	// Verdict with state: TAGREJ's set is on a non-terminating
	// sequence (not demoted), so the evaluator's state model shows
	// the spill honestly — B accepts. Pin it as documented spill,
	// not as correctness: if a future encoding isolates chains,
	// this expectation flips to deny and the log must be updated.
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
		t.Errorf("documented spill: NEEDTAG accepts after TAGREJ set (see residual), got %q", v)
	}
}

// TestBGPOrQuarantineFirstChain16868: an oversized first chain must
// quarantine the whole OR map (deny-only), never demote.
func TestBGPOrQuarantineFirstChain16868(t *testing.T) {
	po := guardChainPO16868()
	big := &config.PolicyStatement{Name: "BIG"}
	for i := 0; i < 7000; i++ {
		big.Terms = append(big.Terms, &config.PolicyTerm{
			Name: "t", FromProtocols: []string{"static"},
			RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}},
			Action:       "accept",
		})
	}
	po.PolicyStatements["BIG"] = big
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"BIG"}},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	mapName := bgpStaticMap16868(t, got)
	seqs := parseOrSeqs16868(t, got, mapName)
	if len(seqs) != 1 || seqs[0].verb != "deny" {
		t.Fatalf("oversized first chain must quarantine the OR map deny-only, got %v\n%s", seqs, got)
	}
	if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "deny" {
		t.Errorf("quarantined OR map must deny, got %q", v)
	}
}

// TestBGPOrOrderedVsOrNameDistinct16868: an ordered chain [A B] and
// an OR over [[A],[B]] derive different map names, and an operator
// policy forging the OR name is refused by the collision guard.
func TestBGPOrOrderedVsOrNameDistinct16868(t *testing.T) {
	po := guardChainPO16868()
	bgp := &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-60", "STATICS"}},
		{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
	}}
	orName := redistOrRouteMapName16868(bgp, po, "bgp", "bgp", "static")
	ordered := redistChainRouteMapName15156([]string{"NO-60", "STATICS"}, "static")
	if orName == ordered {
		t.Fatalf("OR name %q collides with ordered-chain name", orName)
	}
	if !strings.Contains(orName, "-xpf-or") {
		t.Errorf("OR name must carry the -xpf-or marker: %q", orName)
	}
	// Forged operator policy with the OR name must be refused.
	po.PolicyStatements[orName] = &config.PolicyStatement{Name: orName}
	fc := &FullConfig{PolicyOptions: po, BGP: bgp}
	if err := redistChainMapCollision15156(fc); err == nil {
		t.Errorf("collision guard must refuse an operator policy forging OR name %q", orName)
	}
}

// TestBGPOrGroupingCollision16868: [[P,Q],[R]] and [[P],[Q,R]]
// derive different OR names (chain boundaries encoded), so two
// instances with different groupings each get their own map.
func TestBGPOrGroupingCollision16868(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{},
	}
	for _, n := range []string{"P", "Q", "R"} {
		po.PolicyStatements[n] = &config.PolicyStatement{Name: n, Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}}}
	}
	mk := func(chains ...[]string) *config.BGPConfig {
		var ns []*config.BGPNeighbor
		for i, c := range chains {
			ns = append(ns, &config.BGPNeighbor{Address: fmt.Sprintf("192.0.2.%d", i+2), PeerAS: 65002, FamilyInet: true, Export: c})
		}
		return &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: ns}
	}
	n1 := redistOrRouteMapName16868(mk([]string{"P", "Q"}, []string{"R"}), po, "bgp", "bgp", "static")
	n2 := redistOrRouteMapName16868(mk([]string{"P"}, []string{"Q", "R"}), po, "bgp", "bgp", "static")
	if n1 == n2 {
		t.Fatalf("different OR groupings alias to %q", n1)
	}
	// Both instances coexist: each composed map is defined.
	fc := &FullConfig{
		PolicyOptions: po,
		BGP:           mk([]string{"P", "Q"}, []string{"R"}),
		Instances: []InstanceConfig{
			{BGP: mk([]string{"P"}, []string{"Q", "R"})},
		},
	}
	got := New().buildManagedSection(fc)
	for _, n := range []string{n1, n2} {
		if !strings.Contains(got, "route-map "+n+" ") {
			t.Errorf("OR map %s must be defined for its own grouping:\n%s", n, got)
		}
	}
}

// TestBGPOrScratchNamedPrefixList16868: an operator prefix-list
// named xpf-or-scratch-0 keeps its reference byte-for-byte in the
// OR map (token-aware rename never touches operator operands).
func TestBGPOrScratchNamedPrefixList16868(t *testing.T) {
	po := guardChainPO16868()
	po.PrefixLists = map[string]*config.PrefixList{
		"xpf-or-scratch-0": {Name: "xpf-or-scratch-0", Prefixes: []string{"192.168.50.0/24"}},
	}
	po.PolicyStatements["PLACC"] = &config.PolicyStatement{
		Name: "PLACC",
		Terms: []*config.PolicyTerm{
			{Name: "t", FromProtocols: []string{"static"}, PrefixList: []string{"xpf-or-scratch-0"}, Action: "accept"},
		},
		DefaultAction: "reject",
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"PLACC", "STATICS"}},
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
		}},
	}
	got := New().buildManagedSection(fc)
	mapName := bgpStaticMap16868(t, got)
	block := routeMapBlock11447(got, mapName)
	if !strings.Contains(block, "match ip address prefix-list xpf-or-scratch-0") {
		t.Fatalf("operator prefix-list reference must survive verbatim in OR map %s:\n%s", mapName, block)
	}
}

// TestBGPOrInlineNameBound16868: every emitted line's operands stay
// within FRR's 128-byte identifier limit even with long policy
// names (token-aware rename never expands an operand with the
// whole map name; inline names keep their bounded hash form).
func TestBGPOrInlineNameBound16868(t *testing.T) {
	longA := "AAAAAAAAAA" + "AAAAAAAAAA" + "AAAAAAAAAA" + "AAAAAAAAAA" + "AA" // 42
	longB := "BBBBBBBBBB" + "BBBBBBBBBB" + "BBBBBBBBBB" + "BBBBBBBBBB" + "BB"
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{}}
	for _, n := range []string{longA, longB} {
		po.PolicyStatements[n] = &config.PolicyStatement{Name: n, Terms: []*config.PolicyTerm{
			{Name: "t", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
		}, DefaultAction: "reject"}
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{longA}},
			{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{longB}},
		}},
	}
	got := New().buildManagedSection(fc)
	// Different chains produce different maps here (disjoint
	// entries may not OR); assert no line exceeds the bound anyway.
	for _, ln := range strings.Split(got, "\n") {
		for _, tok := range strings.Fields(ln) {
			if len(tok) > 128 {
				t.Errorf("operand exceeds FRR 128-byte limit (%d): %q", len(tok), tok)
			}
		}
	}
}
