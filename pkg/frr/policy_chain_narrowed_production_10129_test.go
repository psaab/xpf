package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// policy_chain_narrowed_production_10129_test.go — #10129 production rollout.
//
// F-008 follow-up of #9947: a narrowed BGP policy chain whose ghosts form a
// suffix and whose survivors fall through (or are empty) must attach a
// deny-terminated alias in PRODUCTION — default New()/Manager, no mechanism
// switch. Every cell here runs the ordinary render path, so reverting the
// rollout (re-gating the alias) reds them.
//
// The no-overreach battery already exists and stays green through the flip:
// TestNarrowedGhostFirstMiddleSurvivorsNotDeleted10129 (non-suffix keeps the
// surviving subset), TestNarrowedNilPolicyOptionsIsEmptiedNotNarrowed10129
// (nil PolicyOptions stays emptied-owned), TestNarrowedQuarantinedSurvivorAlreadyDenies10129
// (quarantined keeps its bounded deny under its own name), and the
// terminating-default / match-all pure-render pins (deny-inert shapes stay
// on the shared map).

// A narrowed suffix-safe single-kept chain attaches the deny-terminated
// alias; the shared standalone map keeps its BGP-accept trailing permit
// (never mutated — other attachments still need it).
func TestNarrowedProductionSingleAttachesDenyAlias10129(t *testing.T) {
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
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map "+alias+" in\n") {
		t.Fatalf("narrowed [ACCEPTER,GHOST] must attach deny alias %q, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 2 || !strings.HasSuffix(headers[1], " deny 20") {
		t.Fatalf("single alias must terminate with deny-20, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 20); strings.Contains(body, "match ") {
		t.Fatalf("alias deny-20 must be unconditional:\n%s", section)
	}
	if !strings.Contains(section, "match ip address prefix-list PL") {
		t.Fatalf("alias must preserve the survivor match body:\n%s", section)
	}
	// Shared map untouched: intact attachments still fall through to permit.
	if !strings.Contains(section, "route-map ACCEPTER permit 20\n") {
		t.Fatalf("shared standalone map must keep its trailing permit-20:\n%s", section)
	}
}

// A narrowed suffix-safe multi-kept chain attaches the deny-terminated
// composed alias with both survivors rendered distinctly and in order; the
// shared composed map keeps its trailing permit.
func TestNarrowedProductionComposedAttachesDenyAlias10129(t *testing.T) {
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
	alias := narrowedAliasName10129([]string{"ACCEPTER", "B"})
	const shared = "ACCEPTER-B-xpf-chain"
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.2 route-map "+alias+" in\n") {
		t.Fatalf("narrowed [ACCEPTER,B,GHOST] must attach deny alias %q, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 3 || !strings.HasSuffix(headers[2], " deny 30") {
		t.Fatalf("composed alias must terminate with deny-30, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 30); strings.Contains(body, "match ") {
		t.Fatalf("composed alias deny-30 must be unconditional:\n%s", section)
	}
	a := strings.Index(section, "route-map "+alias+" permit 10\n match ip address prefix-list PL\n")
	b := strings.Index(section, "route-map "+alias+" permit 20\n match ip address prefix-list PL2")
	if a < 0 || b < 0 || a > b {
		t.Fatalf("alias must preserve both survivors distinctly and in order:\n%s", section)
	}
	if !strings.Contains(section, "route-map "+shared+" permit 30\n") {
		t.Fatalf("shared composed map must keep its trailing permit-30:\n%s", section)
	}
}

// The empty-survivor shape flips permit-all to deny-all: the attached alias
// renders lone deny-10, reachable by every route (#9947 measurement). This
// is the highest-impact member of the denominator, never an over-count.
func TestNarrowedProductionEmptySurvivorAttachesDenyAll10129(t *testing.T) {
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
	alias := narrowedAliasName10129([]string{"EMPTY"})
	section := New().buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.5 route-map "+alias+" in\n") {
		t.Fatalf("narrowed [EMPTY,GHOST] must attach deny alias %q, got:\n%s", alias, section)
	}
	headers := routeMapHeaders6807(section, alias)
	if len(headers) != 1 || !strings.HasSuffix(headers[0], " deny 10") {
		t.Fatalf("empty-survivor alias must render lone deny-10, got %v:\n%s", headers, section)
	}
	if body := routeMapSeqBody10129(t, section, alias, 10); strings.Contains(body, "match ") {
		t.Fatalf("empty alias deny-10 must be match-all:\n%s", section)
	}
}

// VRF attachments narrow exactly like global, and the same surviving chain
// shared across global/VRF dedupes to one alias definition.
func TestNarrowedProductionVRFAttachesDenyAlias10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"ACCEPTER", "GHOST"}},
			},
		},
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
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	m := New()
	section := m.buildManagedSection(fc)
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map "+alias+" in\n") {
		t.Fatalf("global narrowed site must attach deny alias %q:\n%s", alias, section)
	}
	if !strings.Contains(section, "neighbor 10.0.3.1 route-map "+alias+" in\n") {
		t.Fatalf("VRF narrowed site must attach the same deny alias %q:\n%s", alias, section)
	}
	// One definition (single alias = 2 sequences), not one per site. The
	// attachment references are separate from route-map definitions.
	defs := strings.Count(section, "route-map "+alias+" permit") +
		strings.Count(section, "route-map "+alias+" deny")
	if defs != 2 {
		t.Fatalf("shared surviving chain must dedupe to one alias definition, got %d sequences:\n%s", defs, section)
	}
	if got := m.NarrowedPolicyChains(); len(got) != 2 {
		t.Fatalf("both sites must feed the narrowed gauges, got %v", got)
	}
}

// The export direction swaps to the alias too, in both address families.
func TestNarrowedProductionExportAttachesDenyAlias10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.6", PeerAS: 65002, FamilyInet: true, FamilyInet6: true, Export: []string{"ACCEPTER", "GHOST"}},
			},
		},
	}
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	section := New().buildManagedSection(fc)
	if n := strings.Count(section, "neighbor 10.0.2.6 route-map "+alias+" out\n"); n != 2 {
		t.Fatalf("narrowed export must attach deny alias %q in both families, got %d:\n%s", alias, n, section)
	}
}

// An operator policy-statement whose raw name is the alias's rendered FRR
// name also fails closed. This drives the tolerant invalid-name path where
// comparing only PolicyStatements[rawAlias] would miss the merge.
func TestNarrowedProductionRenderedAliasCollisionFailsApplyClosed10129(t *testing.T) {
	po := policyOptions10129()
	const unsafe = "ACCEPTER alias"
	po.PolicyStatements[unsafe] = &config.PolicyStatement{
		Name:  unsafe,
		Terms: po.PolicyStatements["ACCEPTER"].Terms,
	}
	alias := narrowedAliasName10129([]string{unsafe})
	renderedAlias := frrName(alias)
	if alias == renderedAlias {
		t.Fatalf("fixture must exercise final-name sanitization: raw=%q rendered=%q", alias, renderedAlias)
	}
	po.PolicyStatements[renderedAlias] = &config.PolicyStatement{Name: renderedAlias}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{unsafe, "GHOST"}},
			},
		},
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	if err := m.ApplyFull(fc); err == nil || !strings.Contains(err.Error(), "collides with operator policy-statement") {
		t.Fatalf("rendered alias-vs-operator collision must fail the apply closed, got %v", err)
	}
}

// Deny-inert survivor shapes are the explicit discriminator: a terminating
// default or a match-all final term already ends evaluation, so a suffix
// alias is neither needed nor emitted. Their attachments remain on the
// shared maps with the authored terminal action.
func TestNarrowedProductionDenyInertShapesRemainShared10129(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.7", PeerAS: 65002, FamilyInet: true, Import: []string{"TERMACCEPT", "GHOST"}},
				{Address: "10.0.2.8", PeerAS: 65003, FamilyInet: true, Import: []string{"MATCHALL", "GHOST"}},
			},
		},
	}
	section := New().buildManagedSection(fc)
	for _, tc := range []struct {
		address string
		shared  string
		kept    []string
	}{
		{"10.0.2.7", "TERMACCEPT", []string{"TERMACCEPT"}},
		{"10.0.2.8", "MATCHALL", []string{"MATCHALL"}},
	} {
		if !strings.Contains(section, "neighbor "+tc.address+" route-map "+tc.shared+" in\n") {
			t.Fatalf("deny-inert %s must retain shared attachment:\n%s", tc.shared, section)
		}
		alias := narrowedAliasName10129(tc.kept)
		if strings.Contains(section, "route-map "+alias+" ") {
			t.Fatalf("deny-inert %s must not emit alias %q:\n%s", tc.shared, alias, section)
		}
	}
	if !strings.Contains(section, "route-map TERMACCEPT permit 20\n") ||
		!strings.Contains(section, "route-map MATCHALL permit 20\n") {
		t.Fatalf("deny-inert shared maps must retain their authored terminal permits:\n%s", section)
	}
}
func TestNarrowedProductionWarnParity10129(t *testing.T) {
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
	m := New()
	section := m.buildManagedSection(fc)
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if !strings.Contains(section, "neighbor 10.0.2.1 route-map "+alias+" in\n") {
		t.Fatalf("precondition: eligible site must attach the alias:\n%s", section)
	}
	if got := m.NarrowedPolicyChains(); len(got) != 1 {
		t.Fatalf("eligible narrowing must still feed the narrowed gauge, got %v", got)
	}
	if got := m.NarrowedPolicyChainsSuffixShape(); len(got) != 1 {
		t.Fatalf("eligible narrowing must still feed the deny-safe gauge, got %v", got)
	}
}
