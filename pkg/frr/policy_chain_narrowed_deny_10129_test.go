package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// RED-then-GREEN in-harness for #10129 deny mechanism (non-activated).
// These helpers are NOT wired to attachment sites (no behavior flip);
// they prove the alias machinery is ready for a measured rollout.
// Existing attachment baselines (permit-terminated) stay green throughout.

func TestNarrowedAliasNameIsDistinct10129(t *testing.T) {
	// Single kept: alias must differ from standalone, end in reserved suffix.
	got := narrowedAliasName10129([]string{"ACCEPTER"})
	if got == "ACCEPTER" {
		t.Fatalf("single alias must differ from standalone, got %q", got)
	}
	if !strings.HasSuffix(got, ReservedChainSuffix) {
		t.Fatalf("single alias %q must end in %q (existing strict gate covers)", got, ReservedChainSuffix)
	}
	// Composed kept: alias must differ from composed, end in suffix.
	composed := composedChainName([]string{"ACCEPTER", "B"})
	alias := narrowedAliasName10129([]string{"ACCEPTER", "B"})
	if alias == composed {
		t.Fatalf("composed alias must differ from shared %q, got %q", composed, alias)
	}
	if !strings.HasSuffix(alias, ReservedChainSuffix) {
		t.Fatalf("composed alias %q must end in %q", alias, ReservedChainSuffix)
	}
	// Dedupe: same kept => same alias.
	if again := narrowedAliasName10129([]string{"ACCEPTER"}); again != got {
		t.Fatalf("same kept must dedupe to one alias, got %q vs %q", got, again)
	}
}

func TestNarrowedSurvivorShapeClassifies10129(t *testing.T) {
	po := policyOptions10129()
	cases := map[string]string{
		"ACCEPTER":   "fall-through",
		"EMPTY":      "empty",
		"TERMACCEPT": "terminating-default",
		"TERMREJECT": "terminating-default",
		"MATCHALL":   "match-all",
	}
	for name, want := range cases {
		got := narrowedSurvivorShape10129([]string{name}, po)
		if got != want {
			t.Errorf("%s: shape=%q, want %q", name, got, want)
		}
	}
	// Chain-level: terminating-default anywhere dominates (break, inert).
	if got := narrowedSurvivorShape10129([]string{"ACCEPTER", "TERMACCEPT"}, po); got != "terminating-default" {
		t.Errorf("chain with terminating-default: shape=%q, want terminating-default", got)
	}
	// Match-all anywhere shadows later (inert).
	if got := narrowedSurvivorShape10129([]string{"MATCHALL", "ACCEPTER"}, po); got != "match-all" {
		t.Errorf("chain with match-all: shape=%q, want match-all", got)
	}
	// Empty invisible beside fall-through: [EMPTY,ACCEPTER] is fall-through.
	if got := narrowedSurvivorShape10129([]string{"EMPTY", "ACCEPTER"}, po); got != "fall-through" {
		t.Errorf("[EMPTY,ACCEPTER]: shape=%q, want fall-through", got)
	}
	// All-empty: empty (flip, highest impact).
	if got := narrowedSurvivorShape10129([]string{"EMPTY", "EMPTY2"}, &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EMPTY":  {Name: "EMPTY"},
			"EMPTY2": {Name: "EMPTY2"},
		},
	}); got != "empty" {
		t.Errorf("all-empty chain: shape=%q, want empty", got)
	}
}
func TestNarrowedAliasRenderSingleDenyTerminates10129(t *testing.T) {
	po := policyOptions10129()
	name, rendered := New().renderNarrowedChainAlias10129(po, []string{"ACCEPTER"})
	if name != narrowedAliasName10129([]string{"ACCEPTER"}) {
		t.Fatalf("unexpected alias name %q", name)
	}
	headers := routeMapHeaders6807(rendered, name)
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " deny 20") {
		t.Fatalf("single narrowed alias must terminate with deny-20, got %v:\n%s", headers, rendered)
	}
	if body := routeMapSeqBody10129(t, rendered, name, 20); strings.Contains(body, "match ") {
		t.Fatalf("alias deny-20 must be unconditional:\n%s", rendered)
	}
	if !strings.Contains(rendered, "match ip address prefix-list PL") {
		t.Fatalf("alias must preserve survivor match body:\n%s", rendered)
	}
	// The shared standalone map is not passed through this primitive and is
	// therefore untouched; this is the alias-vs-shared-map invariant.
}

func TestNarrowedAliasRenderComposedDenyTerminates10129(t *testing.T) {
	po := policyOptions10129()
	name, rendered := New().renderNarrowedChainAlias10129(po, []string{"ACCEPTER", "B"})
	headers := routeMapHeaders6807(rendered, name)
	if len(headers) != 3 || !strings.HasSuffix(headers[2], " deny 30") {
		t.Fatalf("composed narrowed alias must terminate with deny-30, got %v:\n%s", headers, rendered)
	}
	if body := routeMapSeqBody10129(t, rendered, name, 30); strings.Contains(body, "match ") {
		t.Fatalf("composed alias deny-30 must be unconditional:\n%s", rendered)
	}
	a := strings.Index(rendered, "match ip address prefix-list PL")
	b := strings.Index(rendered, "match ip address prefix-list PL2")
	if a < 0 || b < 0 || a > b {
		t.Fatalf("alias must preserve both composed survivors in order:\n%s", rendered)
	}
	if name == composedChainName([]string{"ACCEPTER", "B"}) {
		t.Fatalf("alias must not mutate/reuse shared composed map name %q", name)
	}
}

func TestNarrowedAliasEligibilityDiscriminatesPositionAndShape10129(t *testing.T) {
	po := policyOptions10129()
	cases := []struct {
		name   string
		auth   []string
		kept   []string
		suffix bool
		want   bool
	}{
		{name: "suffix-fall-through", auth: []string{"ACCEPTER", "GHOST"}, kept: []string{"ACCEPTER"}, suffix: true, want: true},
		{name: "suffix-empty", auth: []string{"EMPTY", "GHOST"}, kept: []string{"EMPTY"}, suffix: true, want: true},
		{name: "suffix-terminating-default", auth: []string{"TERMACCEPT", "GHOST"}, kept: []string{"TERMACCEPT"}, suffix: true, want: false},
		{name: "suffix-match-all", auth: []string{"MATCHALL", "GHOST"}, kept: []string{"MATCHALL"}, suffix: true, want: false},
		{name: "ghost-first", auth: []string{"GHOST", "ACCEPTER"}, kept: []string{"ACCEPTER"}, suffix: false, want: false},
		{name: "ghost-middle", auth: []string{"ACCEPTER", "GHOST", "B"}, kept: []string{"ACCEPTER", "B"}, suffix: false, want: false},
	}
	for _, tc := range cases {
		site := narrowedChainSite{Authored: tc.auth, Kept: tc.kept, GhostsAreSuffix: tc.suffix}
		if got := narrowedAliasEligible10129(site, po); got != tc.want {
			t.Errorf("%s: eligible=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNarrowedAliasPreservesExplicitDefault10129(t *testing.T) {
	po := policyOptions10129()
	name, rendered := New().renderNarrowedChainAlias10129(po, []string{"TERMACCEPT"})
	headers := routeMapHeaders6807(rendered, name)
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " permit 20") {
		t.Fatalf("explicit accept must remain permit in alias, got %v:\n%s", headers, rendered)
	}
}

func TestNarrowedAliasDedupeAcrossGlobalAndVRF10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", Import: []string{"ACCEPTER", "GHOST"}},
		}},
		Instances: []InstanceConfig{{BGP: &config.BGPConfig{Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.3.1", Import: []string{"ACCEPTER", "GHOST"}},
		}}}},
	}
	names := narrowedAliasNames10129(fc)
	if len(names) != 1 {
		t.Fatalf("same survivor chain across global/VRF must dedupe one alias, got %v", names)
	}
	if err := narrowedAliasCollision10129(fc); err != nil {
		t.Fatalf("non-colliding deduped alias rejected: %v", err)
	}
}

func TestNarrowedAliasCollisionWithOperatorPolicy10129(t *testing.T) {
	po := policyOptions10129()
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	po.PolicyStatements[alias] = &config.PolicyStatement{Name: alias}
	fc := &FullConfig{PolicyOptions: po, BGP: &config.BGPConfig{
		Neighbors: []*config.BGPNeighbor{{Address: "10.0.2.1", Import: []string{"ACCEPTER", "GHOST"}}},
	}}
	if err := narrowedAliasCollision10129(fc); err == nil || !strings.Contains(err.Error(), "operator policy-statement") {
		t.Fatalf("operator alias collision must fail closed, got %v", err)
	}
}
func TestNarrowedShapeGaugeCountsPopulation10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{PolicyOptions: po, BGP: &config.BGPConfig{
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", Import: []string{"ACCEPTER", "GHOST"}},
			{Address: "10.0.2.2", Import: []string{"EMPTY", "GHOST"}},
			{Address: "10.0.2.3", Import: []string{"TERMACCEPT", "GHOST"}},
			{Address: "10.0.2.4", Import: []string{"MATCHALL", "GHOST"}},
		},
	}}
	m := New()
	m.recordNarrowed(narrowedChainSites(fc.BGP, po))
	got := m.NarrowedPolicyChainShapes()
	want := map[string]int{
		"fall-through":        1,
		"empty":               1,
		"terminating-default": 1,
		"match-all":           1,
	}
	if len(got) != len(want) {
		t.Fatalf("shape gauge keys=%v, want %v", got, want)
	}
	for shape, count := range want {
		if got[shape] != count {
			t.Errorf("shape %q count=%d, want %d (all population=%d)", shape, got[shape], count, len(m.NarrowedPolicyChains()))
		}
	}
}
func TestNarrowedQuarantinedShapeIsMeasured10129(t *testing.T) {
	po := policyOptions10129()
	terms := make([]*config.PolicyTerm, config.MaxRouteMapSequences+1)
	for i := range terms {
		terms[i] = &config.PolicyTerm{Name: fmt.Sprintf("t%d", i), Action: "accept"}
	}
	po.PolicyStatements["BIG"] = &config.PolicyStatement{Name: "BIG", Terms: terms}
	if got := narrowedSurvivorShape10129([]string{"BIG"}, po); got != "quarantined" {
		t.Fatalf("oversized survivor shape=%q, want quarantined", got)
	}
	site := narrowedChainSite{Kept: []string{"BIG"}, GhostsAreSuffix: true}
	if narrowedAliasEligible10129(site, po) {
		t.Fatal("quarantined survivor must not be alias-eligible")
	}
}
func TestNarrowedAliasManagedSectionEndToEndTestMode10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
				{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Import: []string{"ACCEPTER"}},
				{Address: "10.0.2.3", PeerAS: 65004, FamilyInet: true},
				{Address: "10.0.2.4", PeerAS: 65005, FamilyInet: true, Import: []string{"GHOST-ONLY"}},
			},
		},
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}, narrowedAliasesEnabled10129: true}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("test-mode narrowed alias apply failed: %v", err)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	section := string(data)
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map "+alias+" in\n") {
		t.Fatalf("narrowed attachment did not swap to alias %q:\n%s", alias, section)
	}
	if !strings.Contains(section, "route-map "+alias+" deny 20\n") {
		t.Fatalf("alias definition is not deny-terminated:\n%s", section)
	}
	if !strings.Contains(section, "route-map ACCEPTER permit 20\n") {
		t.Fatalf("shared standalone map was mutated; full chain must remain permit:\n%s", section)
	}
	if !strings.Contains(section, "neighbor 10.0.2.2 route-map ACCEPTER in\n") {
		t.Fatalf("full chain attachment changed unexpectedly:\n%s", section)
	}
	if strings.Contains(section, "neighbor 10.0.2.3 route-map ") {
		t.Fatalf("empty authored chain unexpectedly gained a route-map:\n%s", section)
	}
	if !strings.Contains(section, "neighbor 10.0.2.4 route-map "+emptiedChainDenyName+" in\n") {
		t.Fatalf("all-undefined control did not retain the existing emptied deny:\n%s", section)
	}
	if got := len(m.NarrowedPolicyChains()); got != 1 {
		t.Fatalf("warn/gauge narrowed population=%d, want 1", got)
	}
}
func TestNarrowedAliasCollisionWithComposedChain10129(t *testing.T) {
	po := policyOptions10129()
	po.PolicyStatements["B-xpf-narrowed"] = &config.PolicyStatement{
		Name:  "B-xpf-narrowed",
		Terms: po.PolicyStatements["B"].Terms,
	}
	fc := &FullConfig{PolicyOptions: po, BGP: &config.BGPConfig{
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", Import: []string{"ACCEPTER", "B", "GHOST"}},
			{Address: "10.0.2.2", Import: []string{"ACCEPTER", "B-xpf-narrowed"}},
		},
	}}
	if err := narrowedAliasCollision10129(fc); err == nil || !strings.Contains(err.Error(), "composed chain") {
		t.Fatalf("alias-vs-composed collision must fail closed, got %v", err)
	}
}

func TestNarrowedAliasCollisionWithDistinctKeptChains10129(t *testing.T) {
	po := policyOptions10129()
	po.PolicyStatements["ACCEPTER-B"] = &config.PolicyStatement{
		Name:  "ACCEPTER-B",
		Terms: po.PolicyStatements["B"].Terms,
	}
	fc := &FullConfig{PolicyOptions: po, BGP: &config.BGPConfig{
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", Import: []string{"ACCEPTER", "B", "GHOST"}},
			{Address: "10.0.2.2", Import: []string{"ACCEPTER-B", "GHOST"}},
		},
	}}
	if err := narrowedAliasCollision10129(fc); err == nil || !strings.Contains(err.Error(), "distinct surviving chains") {
		t.Fatalf("alias-vs-alias separator collision must fail closed, got %v", err)
	}
}

func TestNarrowedAliasCannotEqualEmptiedDeny10129(t *testing.T) {
	// The chosen alias has a mandatory "-xpf-narrowed" component immediately
	// before the existing reserved suffix, while #7625's name does not. This
	// proves the fourth collision pair is impossible by construction rather
	// than silently relying on the direct guard's dead branch.
	alias := narrowedAliasName10129([]string{"xpf-emptied-chain"})
	if alias == emptiedChainDenyName {
		t.Fatalf("narrowed alias unexpectedly equals emptied deny %q", alias)
	}
	if !strings.Contains(alias, "-xpf-narrowed"+ReservedChainSuffix) {
		t.Fatalf("alias %q lost its disambiguating narrowed marker", alias)
	}
}
