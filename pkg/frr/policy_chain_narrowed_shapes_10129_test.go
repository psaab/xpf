package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_narrowed_shapes_10129_test.go — #10129 measurement-first.
//
// F-008 follow-up of #9947: a narrowed BGP policy chain (some members survive)
// renders the surviving subset permit-terminated (Junos BGP default-accept,
// #2998). STEP-0 RED (since removed) proved it on base: [ACCEPTER,GHOST]
// attached ACCEPTER permit-terminated and ApplyFull returned nil.
//
// ADJUDICATION (2 hostile plan reviews, pre-implementation): HostilePlanA KILL +
// HostilePlanB RESCOPE killed the render-rejection plan — suffix-only reject is
// incoherent (the #8363 suffix rule constrains deny SYNTHESIS, not rejection;
// ghost-first/middle would still install the hole), strict already rejects every
// narrowed candidate at store.Commit so commit-path loudness is unreachable and
// 100% of firings are lenient log-and-continue (warm keeps last-good narrowed —
// hole persists loudly; cold boot with no prior managed section leaves FRR
// without managed peers/routes — outage, not a filter), and any reject
// wedges the ipmon failover actuator plus sync/rollback/feed divergence on an
// unmeasured population. The parent constraint (migration-safe: no silent
// load-time outage) kills the immediate-deny alternative for the same unmeasured
// population. So this ships NO behavior change: warn-only stays, and these cells
// pin the per-shape reachability the issue owes BEFORE any deny ships
// ("terminating-default survivors and match-all-final-term survivors need
// per-shape reachability cells"), plus the attached-map baselines a future deny
// diffs against. Deny/reject behavior stays OPEN at #10129 pending fleet split +
// migration rollout design. See docs/log/10129.md.

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

// Baseline: narrowed suffix-safe single-kept chain attaches the surviving
// standalone map permit-terminated. Pins today's hole (fall-through permitted)
// so a future deny diffs against fact, not argument.
func TestNarrowedSuffixSafePopulatedSingleAttachesPermitTerminated10129(t *testing.T) {
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
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map ACCEPTER in\n") {
		t.Fatalf("must attach surviving ACCEPTER, got:\n%s", section)
	}
	headers := routeMapHeaders6807(section, "ACCEPTER")
	if len(headers) != 2 {
		t.Fatalf("surviving single must render exactly [match, trailing], got %v:\n%s", headers, section)
	}
	if !strings.HasSuffix(headers[1], " permit 20") {
		t.Fatalf("surviving single must end in permit-20, got %q:\n%s", headers[1], section)
	}
	// The terminal permit must be UNCONDITIONAL (no match clause): deleting the
	// BGP default-accept fallback would leave a conditional permit + FRR's
	// implicit deny, which a last-header-says-permit check cannot tell apart.
	if body := routeMapSeqBody10129(t, section, "ACCEPTER", 20); strings.Contains(body, "match ") {
		t.Fatalf("trailing permit-20 must be unconditional (fall-through permitted):\n%s", section)
	}
	for _, h := range headers {
		if f := strings.Fields(h); f[2] == "deny" {
			t.Fatalf("warn-only baseline must render no deny in the survivor, got %q:\n%s", h, section)
		}
	}
}

// Kept pin guarding the KILL: narrowed warn-only still applies cleanly at the
// ApplyFull boundary (no rejection shipped). A future render-level deny would
// redden the permit-terminated baselines above; a future ApplyFull-level
// rejection would redden THIS cell instead — the two guards cover the two
// layers the hostile reviews distinguished.
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
		t.Fatalf("warn-only narrowing must apply cleanly (no rejection shipped), got: %v", err)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "neighbor 10.0.2.1 route-map ACCEPTER in\n") {
		t.Fatalf("applied config must attach the surviving subset:\n%s", data)
	}
}

// Baseline: narrowed suffix-safe multi-kept chain attaches the composed
// surviving subset permit-terminated, members in order.
func TestNarrowedSuffixSafePopulatedComposedAttachesPermitTerminated10129(t *testing.T) {
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
	const composed = "ACCEPTER-B-xpf-chain"
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.2 route-map "+composed+" in\n") {
		t.Fatalf("must attach composed surviving subset %s, got:\n%s", composed, section)
	}
	headers := routeMapHeaders6807(section, composed)
	if len(headers) != 3 {
		t.Fatalf("surviving composed must render exactly [A, B, trailing], got %v:\n%s", headers, section)
	}
	if !strings.HasSuffix(headers[2], " permit 30") {
		t.Fatalf("surviving composed must end in unconditional permit-30, got %q:\n%s", headers[2], section)
	}
	// Unconditional: deleting the fall-off-the-end fallback would leave
	// conditional permits + FRR's implicit deny behind a last-header-says-permit
	// check.
	if body := routeMapSeqBody10129(t, section, composed, 30); strings.Contains(body, "match ") {
		t.Fatalf("trailing permit-30 must be unconditional (fall-through permitted):\n%s", section)
	}
	// Both survivors' DISTINCT matches present, in chain order (nothing deleted
	// today; PL vs PL2 tells a swap or duplication apart).
	a := strings.Index(section, "route-map "+composed+" permit 10\n match ip address prefix-list PL\n")
	b := strings.Index(section, "route-map "+composed+" permit 20\n match ip address prefix-list PL2")
	if a < 0 || b < 0 || a > b {
		t.Fatalf("both survivors must render distinctly and in order in %s:\n%s", composed, section)
	}
}

// Ghost-first/middle narrowed chains still install their survivors today
// (warn-only): nothing is deleted by the RENDER. Combined with
// TestDenyBeforeASurvivingMemberDeletesTheRestOfTheChain8363 (a deny AT a
// non-final ghost position deletes), this is why a future deny must discriminate
// on GhostsAreSuffix — and why these sites must keep today's behavior.
func TestNarrowedGhostFirstMiddleSurvivorsNotDeleted10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.3", PeerAS: 65002, FamilyInet: true, Import: []string{"GHOST", "ACCEPTER"}},
				{Address: "10.0.2.4", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST", "B"}},
			},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 2 {
		t.Fatalf("want two narrowed sites, got %+v", sites)
	}
	for _, s := range sites {
		if s.GhostsAreSuffix {
			t.Fatalf("ghost-first/middle must NOT classify suffix, got %+v", s)
		}
	}
	m := New()
	section := m.buildManagedSection(fc)
	// Ghost-first keeps single ACCEPTER standalone; ghost-middle keeps composed.
	if !strings.Contains(section, "neighbor 10.0.2.3 route-map ACCEPTER in\n") {
		t.Fatalf("ghost-first must still attach surviving ACCEPTER:\n%s", section)
	}
	const composed = "ACCEPTER-B-xpf-chain"
	if !strings.Contains(section, "neighbor 10.0.2.4 route-map "+composed+" in\n") {
		t.Fatalf("ghost-middle must still attach surviving composed %s:\n%s", composed, section)
	}
	if !strings.Contains(section, "route-map "+composed+" permit 10\n match ip address prefix-list PL\n") ||
		!strings.Contains(section, "route-map "+composed+" permit 20\n match ip address prefix-list PL2") {
		t.Fatalf("ghost-middle survivors must both render (not deleted):\n%s", section)
	}
	// Gauges discriminate: both reported narrowed, neither deny-safe.
	if got := m.NarrowedPolicyChains(); len(got) != 2 {
		t.Fatalf("want 2 narrowed descriptors, got %v", got)
	}
	if got := m.NarrowedPolicyChainsSuffixShape(); len(got) != 0 {
		t.Fatalf("ghost-first/middle must contribute zero deny-safe descriptors, got %v", got)
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

// Empty-survivor narrowed baseline: [EMPTY,GHOST] attaches EMPTY standalone as
// lone match-all permit-10 (permit-all today). The synthesis direction is pinned
// by TestEmptySurvivorSynthesizedDenyIsReachable9947 (member deny lands deny-10,
// reachable by all: permit-all→deny-all flip, highest-impact denominator member,
// NOT an over-count). This cell pins the ATTACHED today those futures diff.
func TestEmptySurvivorNarrowedAttachesPermitAll10129(t *testing.T) {
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
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.5 route-map EMPTY in\n") {
		t.Fatalf("must attach surviving EMPTY, got:\n%s", section)
	}
	headers := routeMapHeaders6807(section, "EMPTY")
	if len(headers) != 1 || !strings.HasSuffix(headers[0], " permit 10") {
		t.Fatalf("empty survivor must render lone permit-10, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, "EMPTY", 10); strings.Contains(body, "match ") {
		t.Fatalf("empty permit-10 must be match-all:\n%s", section)
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

// VRF instances narrow exactly like global: same detector, same warn path,
// same permit-terminated attachment. A future deny must therefore cover VRF
// attachments with the same alias/dedupe rules (shared surviving chain across
// neighbors/VRFs/instances dedupes to one alias definition).
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
	if !strings.Contains(section, "neighbor 10.0.3.1 route-map ACCEPTER in\n") {
		t.Fatalf("VRF must attach the same surviving subset:\n%s", section)
	}
	headers := routeMapHeaders6807(section, "ACCEPTER")
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " permit 20") {
		t.Fatalf("VRF survivor must be permit-terminated like global, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, "ACCEPTER", 20); strings.Contains(body, "match ") {
		t.Fatalf("VRF trailing permit-20 must be unconditional:\n%s", section)
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
