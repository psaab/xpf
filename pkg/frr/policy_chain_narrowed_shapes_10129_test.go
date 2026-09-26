package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_narrowed_shapes_10129_test.go — #10129 regression coverage.
//
// F-008 follow-up of #9947: a narrowed BGP policy chain (some members survive)
// used to render the surviving subset permit-terminated (Junos BGP
// default-accept, #2998). The RED baseline was [ACCEPTER,GHOST] attaching the
// shared ACCEPTER map and ApplyFull returning nil. Production now attaches a
// private deny-terminated alias for suffix-narrowed fall-through and empty
// survivors, leaving shared maps untouched.
//
// The rollout deliberately keeps the #8363 discriminator: ghost-first/middle
// sites retain their surviving members and do not receive an inserted
// terminator, while terminating-default and match-all-final-term survivors
// remain on their explicitly terminating shared map. Strict commit still
// rejects undefined references; tolerant load, peer-sync, and rollback use the
// render-side collision belt and the alias preserves the known-safe shapes.
// See docs/log/10129.md and the cohort evidence in docs/log/9947.md.

func policyOptions10129() *config.PolicyOptionsConfig {
	over := func() []string { return []string{"PL"} }
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// Populated fall-through survivor: one terminating match term, no
			// policy default → non-matching routes fall through to the BGP
			// default-accept permit (#2998). The shape a suffix deny WOULD
			// change (permit→deny for fall-through).
			"ACCEPTER": {Name: "ACCEPTER", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: over(), Action: "accept"},
			}},
			// B is deliberately distinguishable from ACCEPTER (PL2, not PL): with
			// identical bodies a swapped or duplicated survivor would still pass
			// the composed order assertions below.
			"B": {Name: "B", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"PL2"}, Action: "accept"},
			}},
			// Empty survivor: defined, no terms, no default → match-all
			// permit-10 today; [EMPTY,SYNTH-DENY] renders lone deny-10,
			// reachable by all (TestEmptySurvivorSynthesizedDenyIsReachable9947).
			"EMPTY": {Name: "EMPTY"},
			// Terminating-default survivors: the policy default ends the
			// composed render (break) — later members never emit.
			"TERMACCEPT": {Name: "TERMACCEPT", DefaultAction: "accept", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: over(), Action: "accept"},
			}},
			"TERMREJECT": {Name: "TERMREJECT", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: over(), Action: "accept"},
			}},
			// Match-all final term, no policy default: t2 matches every route
			// and terminates, so any trailing/member deny is shadowed.
			"MATCHALL": {Name: "MATCHALL", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: over(), Action: "accept"},
				{Name: "t2", Action: "accept"},
			}},
			// Stand-in for a member-synthesized suffix deny.
			"SYNTH-DENY": {Name: "SYNTH-DENY", DefaultAction: "reject"},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL":  {Name: "PL", Prefixes: []string{"10.0.0.0/8"}},
			"PL2": {Name: "PL2", Prefixes: []string{"192.168.0.0/16"}},
		},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
	}
}

// routeMapSeqBody10129 returns the body lines (between the seq header and its
// exit) for route-map name sequence seq, or fails when the header is absent.
func routeMapSeqBody10129(t *testing.T, section, name string, seq int) string {
	t.Helper()
	lines := strings.Split(section, "\n")
	want := fmt.Sprintf("route-map %s ", name)
	suffix := fmt.Sprintf(" %d", seq)
	for i, ln := range lines {
		if !strings.HasPrefix(ln, want) || !strings.HasSuffix(ln, suffix) {
			continue
		}
		var body []string
		for _, rest := range lines[i+1:] {
			if strings.HasPrefix(rest, "route-map ") || strings.TrimSpace(rest) == "exit" {
				break
			}
			body = append(body, rest)
		}
		return strings.Join(body, "\n")
	}
	t.Fatalf("no sequence %d under route-map %q in:\n%s", seq, name, section)
	return ""
}

// Production behavior: a suffix-narrowed fall-through survivor attaches a
// private deny-terminated alias. The shared standalone map remains
// permit-terminated for intact attachments.
func TestNarrowedSuffixSafePopulatedSingleAttachesDenyAlias10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
			},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 1 || !sites[0].GhostsAreSuffix || len(sites[0].Kept) != 1 || sites[0].Kept[0] != "ACCEPTER" {
		t.Fatalf("want single suffix-narrowed [ACCEPTER], got %+v", sites)
	}
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map "+alias+" in\n") {
		t.Fatalf("must attach narrowed alias %s, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " deny 20") {
		t.Fatalf("narrowed alias must render [match, deny], got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 20); strings.Contains(body, "match ") {
		t.Fatalf("alias deny-20 must be unconditional:\n%s", section)
	}
	if !strings.Contains(section, "route-map ACCEPTER permit 20\n") {
		t.Fatalf("shared standalone map must retain its trailing permit:\n%s", section)
	}
}

// The production apply path writes the narrowed alias and still completes a
// clean reload. A collision in the alias belt is covered separately as a
// fail-closed apply.
func TestNarrowedSuffixSafeStillAppliesCleanly10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
			},
		},
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("narrowed alias must apply cleanly, got: %v", err)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if !strings.Contains(string(data), "neighbor 10.0.2.1 route-map "+alias+" in\n") ||
		!strings.Contains(string(data), "route-map "+alias+" deny 20\n") {
		t.Fatalf("applied config must attach the deny alias %q:\n%s", alias, data)
	}
}

// Production behavior: a suffix-narrowed composed chain attaches a private
// deny-terminated alias, preserving both surviving members in order.
func TestNarrowedSuffixSafePopulatedComposedAttachesDenyAlias10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.2", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "B", "GHOST"}},
			},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 1 || !sites[0].GhostsAreSuffix || len(sites[0].Kept) != 2 {
		t.Fatalf("want single suffix-narrowed [ACCEPTER B], got %+v", sites)
	}
	alias := narrowedAliasName10129([]string{"ACCEPTER", "B"})
	const shared = "ACCEPTER-B-xpf-chain"
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.2 route-map "+alias+" in\n") {
		t.Fatalf("must attach narrowed alias %s, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 3 || !strings.HasSuffix(headers[2], " deny 30") {
		t.Fatalf("narrowed alias must render [A, B, deny], got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 30); strings.Contains(body, "match ") {
		t.Fatalf("alias deny-30 must be unconditional:\n%s", section)
	}
	a := strings.Index(section, "route-map "+alias+" permit 10\n match ip address prefix-list PL\n")
	b := strings.Index(section, "route-map "+alias+" permit 20\n match ip address prefix-list PL2")
	if a < 0 || b < 0 || a > b {
		t.Fatalf("alias must preserve both survivors distinctly and in order:\n%s", section)
	}
	if !strings.Contains(section, "route-map "+shared+" permit 30\n") {
		t.Fatalf("shared composed map must retain its trailing permit:\n%s", section)
	}
}

// Non-suffix narrowed chains use a private alias with a trailing deny. The
// alias keeps every surviving member in order; it does not synthesize a chain
// member at the ghost position (the #8363 insertion hazard). Cover ghost-first
// and ghost-middle in both BGP directions and AFIs, asserting the attached map
// really terminates with deny rather than merely checking the alias helper.
func TestNarrowedGhostFirstMiddleAliasesDenyAcrossBGPContexts10821(t *testing.T) {
	positions := []struct {
		name string
		auth []string
		kept []string
	}{
		{name: "ghost-first", auth: []string{"GHOST", "ACCEPTER"}, kept: []string{"ACCEPTER"}},
		{name: "ghost-middle", auth: []string{"ACCEPTER", "GHOST", "B"}, kept: []string{"ACCEPTER", "B"}},
	}
	for _, position := range positions {
		for _, direction := range []string{"import", "export"} {
			for _, family := range []string{"v4", "v6"} {
				name := position.name + "/" + direction + "/" + family
				t.Run(name, func(t *testing.T) {
					address := "10.0.2.3"
					neighbor := &config.BGPNeighbor{
						Address: address, PeerAS: 65002,
						FamilyInet: family == "v4", FamilyInet6: family == "v6",
					}
					if family == "v6" {
						address = "2001:db8::3"
						neighbor.Address = address
					}
					if direction == "import" {
						neighbor.Import = position.auth
					} else {
						neighbor.Export = position.auth
					}
					po := policyOptions10129()
					fc := &FullConfig{
						PolicyOptions: po,
						BGP: &config.BGPConfig{
							LocalAS: 65001, RouterID: "1.1.1.1",
							Neighbors: []*config.BGPNeighbor{neighbor},
						},
					}
					sites := narrowedChainSites(fc.BGP, po)
					if len(sites) != 1 || sites[0].GhostsAreSuffix {
						t.Fatalf("want exactly one non-suffix narrowed site, got %+v", sites)
					}
					m := New()
					section := m.buildManagedSection(fc)
					alias := narrowedAliasName10129(position.kept)
					action := "in"
					if direction == "export" {
						action = "out"
					}
					attachment := fmt.Sprintf("neighbor %s route-map %s %s\n", address, alias, action)
					if !strings.Contains(section, attachment) {
						t.Fatalf("non-suffix %s chain must attach deny alias %q:\n%s", direction, alias, section)
					}
					headers := routeMapHeaders6807(section, alias)
					denySeq := (len(position.kept) + 1) * 10
					if len(headers) != len(position.kept)+1 ||
						!strings.HasSuffix(headers[len(headers)-1], fmt.Sprintf(" deny %d", denySeq)) {
						t.Fatalf("attached alias trailing action must be deny-%d, got %v:\n%s", denySeq, headers, section)
					}
					if body := routeMapSeqBody10129(t, section, alias, denySeq); strings.Contains(body, "match ") {
						t.Fatalf("trailing deny-%d must be unconditional:\n%s", denySeq, section)
					}
					for i, policy := range position.kept {
						prefixList := "PL"
						if policy == "B" {
							prefixList = "PL2"
						}
						seq := (i + 1) * 10
						want := fmt.Sprintf("route-map %s permit %d\n match ip address prefix-list %s\n", alias, seq, prefixList)
						if !strings.Contains(section, want) {
							t.Errorf("alias lost or reordered surviving policy %s:\n%s", policy, section)
						}
					}
					if got := m.NarrowedPolicyChainsSuffixShape(); len(got) != 0 {
						t.Fatalf("non-suffix sites must remain outside the suffix-shape gauge, got %v", got)
					}
				})
			}
		}
	}
}

func TestNarrowedNonSuffixTerminatingGhostsRequirePositionProof10821(t *testing.T) {
	cases := []struct {
		name string
		auth []string
		kept []string
		safe bool
	}{
		{name: "ghost-after-match-all", auth: []string{"MATCHALL", "GHOST", "B"}, kept: []string{"MATCHALL", "B"}, safe: true},
		{name: "ghost-before-match-all", auth: []string{"GHOST", "MATCHALL"}, kept: []string{"MATCHALL"}, safe: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			po := policyOptions10129()
			fc := &FullConfig{
				PolicyOptions: po,
				BGP: &config.BGPConfig{
					LocalAS: 65001, RouterID: "1.1.1.1",
					Neighbors: []*config.BGPNeighbor{{
						Address: "10.0.2.5", PeerAS: 65002, FamilyInet: true, Import: tc.auth,
					}},
				},
			}
			sites := narrowedChainSites(fc.BGP, po)
			if len(sites) != 1 || sites[0].GhostsAreSuffix {
				t.Fatalf("want one non-suffix site, got %+v", sites)
			}
			if got := narrowedGhostsAfterTerminator10821(sites[0], po); got != tc.safe {
				t.Fatalf("ghost-after-terminator proof=%v, want %v; site=%+v", got, tc.safe, sites[0])
			}
			err := narrowedAliasCollision10129(fc)
			if tc.safe && err != nil {
				t.Fatalf("a ghost after match-all must remain on the shared terminating map: %v", err)
			}
			if !tc.safe && err == nil {
				t.Fatal("reachable ghost before match-all must fail closed instead of retaining BGP permit fall-off")
			}
		})
	}
}

// A survivor with a terminating policy default ends the composed render: later
// kept members never emit. Code-read until now; pinned here because a future
// suffix deny lands behind that break.
func TestTerminatingDefaultSurvivorBreaksComposedRender10129(t *testing.T) {
	po := policyOptions10129()
	got := New().renderComposedRouteMap(po, "T-xpf-chain", []string{"TERMACCEPT", "ACCEPTER"})
	if n := strings.Count(got, "route-map T-xpf-chain "); n != 2 {
		t.Fatalf("terminating-default member must end render at 2 sequences, got %d:\n%s", n, got)
	}
	if action, _ := seqAction8363(t, got, "T-xpf-chain", 20); action != "permit" {
		t.Errorf("sequence 20 must be TERMACCEPT's default permit, got %q:\n%s", action, got)
	}
	// ACCEPTER contributes exactly one match sequence when rendered; here only
	// TERMACCEPT's own match may appear (seq 10). Two PL matches would mean the
	// later member survived the break.
	if n := strings.Count(got, "match ip address prefix-list PL"); n != 1 {
		t.Errorf("later kept member must be absent after a terminating default, got %d matches:\n%s", n, got)
	}
}

// Suffix member deny after a terminating-default survivor is NOT EMITTED (the
// break drops it): deny-inert, no outage and no fix. This splits the
// suffix-safe denominator: terminating-default survivors must size separately
// from fall-through survivors (deny changes behavior) and empty survivors
// (deny flips permit-all to deny-all, #9947).
func TestSuffixDenyAfterTerminatingDefaultSurvivorIsNotEmitted10129(t *testing.T) {
	po := policyOptions10129()
	for _, tc := range []struct {
		name  string
		chain []string
		want  int // sequences: term + terminating default; SYNTH-DENY absent
	}{
		{"accept-default", []string{"TERMACCEPT", "SYNTH-DENY"}, 2},
		{"reject-default", []string{"TERMREJECT", "SYNTH-DENY"}, 2},
	} {
		got := New().renderComposedRouteMap(po, "TD-xpf-chain", tc.chain)
		if n := strings.Count(got, "route-map TD-xpf-chain "); n != tc.want {
			t.Errorf("%s: want %d sequences (SYNTH-DENY dropped by the break), got %d:\n%s",
				tc.name, tc.want, n, got)
		}
		if tc.name == "accept-default" && strings.Contains(got, "deny") {
			t.Errorf("%s: synthesized deny must be absent (no deny at all), got:\n%s", tc.name, got)
		}
	}
}

// Match-all final term (no policy default): the suffix member deny IS emitted
// but shadowed — t2 matches every route and terminates (no on-match next), so
// FRR first-match never reaches the deny (Fact 1, #8363). Deny-inert like the
// terminating-default shape, but by shadowing rather than by break.
func TestMatchAllFinalTermShadowsSuffixDeny10129(t *testing.T) {
	po := policyOptions10129()
	got := New().renderComposedRouteMap(po, "M-xpf-chain", []string{"MATCHALL", "SYNTH-DENY"})
	if n := strings.Count(got, "route-map M-xpf-chain "); n != 3 {
		t.Fatalf("want 3 sequences (t1, match-all t2, deny), got %d:\n%s", n, got)
	}
	if action, cont := seqAction8363(t, got, "M-xpf-chain", 20); action != "permit" || cont {
		t.Fatalf("t2 must be terminating match-all permit (no on-match next), got %q cont=%v:\n%s",
			action, cont, got)
	}
	if body := routeMapSeqBody10129(t, got, "M-xpf-chain", 20); strings.Contains(body, "match ") {
		t.Fatalf("t2 must carry no match clause (match-all), got body %q:\n%s", body, got)
	}
	if action, _ := seqAction8363(t, got, "M-xpf-chain", 30); action != "deny" {
		t.Fatalf("suffix deny must still emit at seq 30 (shadowed, not deleted), got %q:\n%s", action, got)
	}
}

// Single-policy alias shape — direct-call PRIMITIVE, unattached (not an
// attachment-site render): same body, deny trailing instead of permit.
// Reachability splits by survivor: fall-through survivor → deny catches the
// rest; match-all-final-term survivor → deny shadowed (inert). The shared map
// keeps its permit trailing (re-render check is vacuous for the pure function;
// attached alias behavior is still owed).
func TestSingleAliasTrailingDenyShape10129(t *testing.T) {
	po := policyOptions10129()
	m := New()
	// Fall-through survivor: alias deny is the last sequence behind a
	// conditional match — reachable by every non-matching route.
	base := m.renderRouteMapForPolicy(po, "ACCEPTER", po.PolicyStatements["ACCEPTER"], "permit")
	alias := m.renderRouteMapForPolicy(po, "ACCEPTER-alias", po.PolicyStatements["ACCEPTER"], "deny")
	baseHeaders := routeMapHeaders6807(base, "ACCEPTER")
	aliasHeaders := routeMapHeaders6807(alias, "ACCEPTER-alias")
	if len(baseHeaders) != 2 || len(aliasHeaders) != 2 {
		t.Fatalf("single render must be [match, trailing], base %v alias %v", baseHeaders, aliasHeaders)
	}
	if !strings.HasSuffix(aliasHeaders[1], " deny 20") {
		t.Fatalf("alias must end in deny-20, got %q", aliasHeaders[1])
	}
	if strings.Contains(routeMapSeqBody10129(t, alias, "ACCEPTER-alias", 10), "match ") == false {
		t.Fatalf("alias seq 10 must stay conditional (fall-through reaches deny-20):\n%s", alias)
	}
	// Shared map untouched by aliasing: re-render base, still permit-terminated.
	again := m.renderRouteMapForPolicy(po, "ACCEPTER", po.PolicyStatements["ACCEPTER"], "permit")
	if !strings.Contains(again, "route-map ACCEPTER permit 20") {
		t.Fatalf("aliasing must never mutate the shared map's permit trailing:\n%s", again)
	}
	// Match-all survivor: alias deny emitted but shadowed by terminating t2.
	malias := m.renderRouteMapForPolicy(po, "MATCHALL-alias", po.PolicyStatements["MATCHALL"], "deny")
	mheaders := routeMapHeaders6807(malias, "MATCHALL-alias")
	if len(mheaders) != 3 {
		t.Fatalf("match-all alias must be [t1, t2, trailing], got %v:\n%s", mheaders, malias)
	}
	if !strings.HasSuffix(mheaders[2], " deny 30") {
		t.Fatalf("match-all alias must end in deny-30, got %q:\n%s", mheaders[2], malias)
	}
	if body := routeMapSeqBody10129(t, malias, "MATCHALL-alias", 20); strings.Contains(body, "match ") {
		t.Fatalf("t2 must stay match-all (deny-30 shadowed):\n%s", malias)
	}
	if _, cont := seqAction8363(t, malias, "MATCHALL-alias", 20); cont {
		t.Fatalf("t2 must terminate (deny-30 unreachable):\n%s", malias)
	}
}

// Explicit-default standalone aliases: renderRouteMapForPolicy applies the
// supplied trailing action UNCONDITIONALLY, so a blind "deny" alias on an
// explicit-accept survivor FLIPS its terminating permit to deny (behavior
// change — NOT deny-inert, unlike the member-synthesis break above). A future
// alias must therefore preserve explicit defaults — policyTrailingAction(name,
// ps, nil) is exactly that rule (explicit accept/reject preserved; no-default
// resolves deny, the desired fall-through close) — instead of a blind "deny".
func TestExplicitDefaultStandaloneAliasTrailing10129(t *testing.T) {
	po := policyOptions10129()
	m := New()
	// TERMACCEPT: base permit-20 (explicit default), blind alias deny-20.
	base := m.renderRouteMapForPolicy(po, "TERMACCEPT", po.PolicyStatements["TERMACCEPT"], "permit")
	alias := m.renderRouteMapForPolicy(po, "TERMACCEPT-alias", po.PolicyStatements["TERMACCEPT"], "deny")
	if !strings.Contains(base, "route-map TERMACCEPT permit 20") {
		t.Fatalf("explicit-accept base must end in permit-20:\n%s", base)
	}
	if !strings.Contains(alias, "route-map TERMACCEPT-alias deny 20") {
		t.Fatalf("blind deny alias flips the explicit default to deny-20:\n%s", alias)
	}
	// The preserve rule a future alias must use.
	if got := policyTrailingAction("TERMACCEPT", po.PolicyStatements["TERMACCEPT"], nil); got != "permit" {
		t.Fatalf("policyTrailingAction(TERMACCEPT, nil) must preserve permit, got %q", got)
	}
	if got := policyTrailingAction("TERMREJECT", po.PolicyStatements["TERMREJECT"], nil); got != "deny" {
		t.Fatalf("policyTrailingAction(TERMREJECT, nil) must preserve deny, got %q", got)
	}
	if got := policyTrailingAction("ACCEPTER", po.PolicyStatements["ACCEPTER"], nil); got != "deny" {
		t.Fatalf("policyTrailingAction(no-default, nil) must resolve deny (fall-through close), got %q", got)
	}
	// TERMREJECT: base and blind alias agree (deny-20) — inert there.
	rbase := m.renderRouteMapForPolicy(po, "TERMREJECT", po.PolicyStatements["TERMREJECT"], "deny")
	if !strings.Contains(rbase, "route-map TERMREJECT deny 20") {
		t.Fatalf("explicit-reject base must end in deny-20:\n%s", rbase)
	}
}

// Empty-survivor narrowed chains attach a private deny-all alias. An empty
// survivor contributes no match sequence, so the alias's lone deny-10 is
// reachable by every route (permit-all → deny-all).
func TestEmptySurvivorNarrowedAttachesDenyAll10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.5", PeerAS: 65002, FamilyInet: true, Import: []string{"EMPTY", "GHOST"}},
			},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 1 || !sites[0].GhostsAreSuffix || len(sites[0].Kept) != 1 || sites[0].Kept[0] != "EMPTY" {
		t.Fatalf("want single suffix-narrowed [EMPTY], got %+v", sites)
	}
	alias := narrowedAliasName10129([]string{"EMPTY"})
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.5 route-map "+alias+" in\n") {
		t.Fatalf("must attach empty-survivor alias %q, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 1 || !strings.HasSuffix(headers[0], " deny 10") {
		t.Fatalf("empty alias must render lone deny-10, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 10); strings.Contains(body, "match ") {
		t.Fatalf("empty alias deny-10 must be match-all:\n%s", section)
	}
}

// New-shape suffix discriminator: terminating-default and match-all survivors
// classify exactly like populated ones (ghost position decides, survivor shape
// does not). Survivor shape decides DENY REACHABILITY (above), not the suffix
// predicate — the two discriminators must never be conflated in sizing.
func TestNarrowedSuffixDiscriminatorForNewShapes10129(t *testing.T) {
	po := policyOptions10129()
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.6", PeerAS: 65002, FamilyInet: true, Import: []string{"TERMACCEPT", "GHOST"}},
			{Address: "10.0.2.7", PeerAS: 65002, FamilyInet: true, Import: []string{"GHOST", "TERMACCEPT"}},
			{Address: "10.0.2.8", PeerAS: 65002, FamilyInet: true, Import: []string{"MATCHALL", "GHOST"}},
			{Address: "10.0.2.9", PeerAS: 65002, FamilyInet: true, Import: []string{"MATCHALL", "GHOST", "B"}},
		},
	}
	sites := narrowedChainSites(bgp, po)
	if len(sites) != 4 {
		t.Fatalf("want 4 narrowed sites, got %+v", sites)
	}
	wantSuffix := map[string]bool{
		"neighbor 10.0.2.6 import": true,
		"neighbor 10.0.2.7 import": false,
		"neighbor 10.0.2.8 import": true,
		"neighbor 10.0.2.9 import": false,
	}
	for _, s := range sites {
		if wantSuffix[s.Where] != s.GhostsAreSuffix {
			t.Errorf("%s: GhostsAreSuffix=%v, want %v (%+v)", s.Where, s.GhostsAreSuffix, wantSuffix[s.Where], s)
		}
	}
}

// VRF instances narrow exactly like global and attach the same private alias.
// A shared surviving chain across neighbors/VRFs/instances dedupes to one
// alias definition while each attachment points at it.
func TestNarrowedVRFMatchesGlobal10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		Instances: []InstanceConfig{
			{
				VRFName: "VRF-A",
				BGP: &config.BGPConfig{
					LocalAS: 65001, RouterID: "1.1.1.1",
					Neighbors: []*config.BGPNeighbor{
						{Address: "10.0.3.1", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
					},
				},
			},
		},
	}
	sites := narrowedChainSites(fc.Instances[0].BGP, po)
	if len(sites) != 1 || !sites[0].GhostsAreSuffix {
		t.Fatalf("VRF must detect the same suffix-narrowed site, got %+v", sites)
	}
	m := New()
	section := m.buildManagedSection(fc)
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if !strings.Contains(section, "neighbor 10.0.3.1 route-map "+alias+" in\n") {
		t.Fatalf("VRF must attach the narrowed alias %q:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " deny 20") {
		t.Fatalf("VRF alias must be deny-terminated, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 20); strings.Contains(body, "match ") {
		t.Fatalf("VRF alias deny-20 must be unconditional:\n%s", section)
	}
	if got := m.NarrowedPolicyChains(); len(got) != 1 {
		t.Fatalf("VRF site must feed the narrowed gauges, got %v", got)
	}
	if got := m.NarrowedPolicyChainsSuffixShape(); len(got) != 1 {
		t.Fatalf("VRF suffix site must feed the deny-safe gauge, got %v", got)
	}
}

// Nil PolicyOptions: every authored name is a ghost, so no chain can NARROW
// (kept is empty) — the emptied path owns it, with no double-count under the
// narrowed description. Defines the nil-PO corner a future deny must preserve.
func TestNarrowedNilPolicyOptionsIsEmptiedNotNarrowed10129(t *testing.T) {
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.10", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
		},
	}
	if sites := narrowedChainSites(bgp, nil); len(sites) != 0 {
		t.Fatalf("nil PolicyOptions must yield zero narrowed sites (emptied owns it), got %+v", sites)
	}
	n := bgp.Neighbors[0]
	global := bgpGlobalImportChain(bgp, nil)
	if got := bgpNeighborImportRef(n, bgp, global, nil); got != emptiedChainDenyName {
		t.Fatalf("nil-PO import must attach the emptied deny, got %q", got)
	}
}

// Oversized (quarantine) survivor: the chain still NARROWS (warn fires — the
// member is defined, size is not membership), but the attachment is already the
// #6807 bounded deny, so there is no surviving permit for a future deny to
// close. Defines quarantine interplay as warn + already-fail-closed (a future
// deny there is redundant; a future reject there would be a false positive).
func TestNarrowedQuarantinedSurvivorAlreadyDenies10129(t *testing.T) {
	over := make([]string, config.MaxRouteMapSequences+1)
	for i := range over {
		over[i] = fmt.Sprintf("pl%d", i)
	}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"BIG": {Name: "BIG", Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: over}}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.11", PeerAS: 65002, FamilyInet: true, Import: []string{"BIG", "GHOST"}},
			},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 1 || !sites[0].GhostsAreSuffix {
		t.Fatalf("oversized survivor must still narrow (warn), got %+v", sites)
	}
	m := New()
	section := m.buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.11 route-map BIG in\n") {
		t.Fatalf("must still attach BIG (quarantined under its own name):\n%s", section)
	}
	headers := routeMapHeaders6807(section, "BIG")
	if len(headers) != 1 || !strings.HasSuffix(headers[0], fmt.Sprintf(" deny %d", quarantineDenySeq)) {
		t.Fatalf("oversized survivor must attach the bounded deny, got %v:\n%s", headers, section)
	}
	if got := m.NarrowedPolicyChains(); len(got) != 1 {
		t.Fatalf("quarantined narrowing must still feed the narrowed gauge, got %v", got)
	}
}
