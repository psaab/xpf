package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12896: the zone-detail policy summary must annotate each row's LIVE
// applicability instead of delegating quarantine labeling to callers that only
// annotate the viewed zone. Two defect directions are pinned here against the
// classic z174/z214 StableZoneID collision (sorted z174 survives, z214 is the
// quarantined loser):
//
//   - healthy viewed zone: rows whose peer zone is quarantined (exact
//     `trust -> z214` and wildcard `any -> z214`) would be DROPPED by the
//     apply-time scrub, so they carry ZoneQuarantinePoliciesQualifier instead
//     of reading as governing; a scoped global whose configured side the scrub
//     prunes renders the surviving scope (authored scope when the prune empties
//     it) plus the qualifier. Live rows stay unqualified.
//   - quarantined viewed zone: wildcard (`any -> X`, `any -> any`) and
//     unscoped-global rows no longer list at all — a zone the builder omits
//     cannot be governed by anything — while the literal references that name
//     it stay visible for diagnosis, each scrub-marked.
//
// Every assertion marked RED fails on pre-#12896 master.

func quarantineSummaryConfig12896(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	anyMatch := func() config.PolicyMatch {
		return config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust", "z174", "z214"),
			Policies: []*config.ZonePairPolicies{
				{ // config idx 0 — exact, names the quarantined loser
					FromZone: "trust", ToZone: "z214",
					Policies: []*config.Policy{{Name: "peer-dead", Action: config.PolicyPermit, Match: anyMatch()}},
				},
				{ // config idx 1 — exact, both sides live
					FromZone: "trust", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "live-exact", Action: config.PolicyPermit, Match: anyMatch()}},
				},
				{ // config idx 2 — single wildcard, live for a healthy viewed zone
					FromZone: "any", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "live-wild", Action: config.PolicyPermit, Match: anyMatch()}},
				},
				{ // config idx 3 — both-any, live for a healthy viewed zone
					FromZone: "any", ToZone: "any",
					Policies: []*config.Policy{{Name: "live-anyany", Action: config.PolicyDeny, Match: anyMatch()}},
				},
				{ // config idx 4 — single wildcard whose concrete side is the loser
					FromZone: "any", ToZone: "z214",
					Policies: []*config.Policy{{Name: "wild-dead", Action: config.PolicyPermit, Match: anyMatch()}},
				},
			},
			GlobalPolicies: []*config.Policy{
				// unscoped global: applies to every INSTALLED zone — live under
				// trust, excluded under quarantined z214.
				{Name: "g-unscoped", Action: config.PolicyDeny, Match: anyMatch()},
				// scoped global whose whole to-side is the quarantined loser:
				// the scrub empties the side and drops the rule.
				{Name: "g-dead-scope", Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						ToZones:              []string{"z214"},
					}},
				// scoped global with a surviving member: the scrub prunes z214
				// and keeps the rule for trust.
				{Name: "g-mixed", Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						ToZones:              []string{"trust", "z214"},
					}},
			},
		},
	}
}

func summaryLine12896(t *testing.T, lines []string, needle string) string {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("no summary line contains %q:\n%s", needle, strings.Join(lines, "\n"))
	return ""
}

// TestZoneDetailPolicySummaryHealthyZoneQualifiesScrubbedRows12896 pins the
// healthy-viewed-zone direction: peer-dead rows appear (diagnosis) but carry
// the qualifier; live rows never do.
func TestZoneDetailPolicySummaryHealthyZoneQualifiesScrubbedRows12896(t *testing.T) {
	lines := ZoneDetailPolicySummary(quarantineSummaryConfig12896(t), "trust", nil, false)
	qual := config.ZoneQuarantinePoliciesQualifier

	// RED on master: the exact peer-dead row was rendered as governing.
	if l := summaryLine12896(t, lines, "peer-dead"); !strings.Contains(l, qual) {
		t.Fatalf("exact trust->z214 row lacks scrub qualifier:\n%s", l)
	}
	// RED on master: the wildcard row whose concrete side is the loser.
	if l := summaryLine12896(t, lines, "wild-dead"); !strings.Contains(l, qual) {
		t.Fatalf("wildcard any->z214 row lacks scrub qualifier:\n%s", l)
	}
	// RED on master: the scoped global rendered its authored (scrubbed) scope
	// with no qualifier.
	if l := summaryLine12896(t, lines, "g-dead-scope"); !strings.Contains(l, qual) {
		t.Fatalf("emptied-scope global lacks scrub qualifier:\n%s", l)
	} else if !strings.Contains(l, "-> z214:") {
		t.Fatalf("emptied-scope global should keep its authored scope on the dead row:\n%s", l)
	}
	// RED on master: the mixed-scope global rendered "trust z214" unqualified;
	// post-fix it shows the surviving scope plus the qualifier.
	if l := summaryLine12896(t, lines, "g-mixed"); !strings.Contains(l, qual) || !strings.Contains(l, "any -> trust:") {
		t.Fatalf("mixed-scope global must render pruned scope + qualifier:\n%s", l)
	}

	// Controls (GREEN pre and post): live rows stay unqualified.
	for _, live := range []string{"live-exact", "live-wild", "live-anyany", "g-unscoped"} {
		if l := summaryLine12896(t, lines, live); strings.Contains(l, qual) {
			t.Fatalf("live row %q gained quarantine qualifier:\n%s", live, l)
		}
	}
}

// TestZoneDetailPolicySummaryQuarantinedZoneExcludesGoverningRows12896 pins
// the quarantined-viewed-zone direction: wildcard and unscoped-global rows no
// longer list (nothing governns an omitted zone), while the literal references
// that name the loser stay visible, each scrub-marked.
func TestZoneDetailPolicySummaryQuarantinedZoneExcludesGoverningRows12896(t *testing.T) {
	got := strings.Join(ZoneDetailPolicySummary(quarantineSummaryConfig12896(t), "z214", nil, false), "\n")
	qual := config.ZoneQuarantinePoliciesQualifier

	// RED on master: these listed as governing the quarantined zone.
	for _, governed := range []string{"live-anyany", "live-wild", "live-exact", "g-unscoped"} {
		if strings.Contains(got, governed) {
			t.Fatalf("row %q does not govern the quarantined zone and must not list under it:\n%s", governed, got)
		}
	}
	// RED on master: the literal reference listed without the qualifier.
	if l := summaryLine12896(t, strings.Split(got, "\n"), "peer-dead"); !strings.Contains(l, qual) {
		t.Fatalf("literal trust->z214 reference under the loser lacks scrub qualifier:\n%s", l)
	}
	if l := summaryLine12896(t, strings.Split(got, "\n"), "wild-dead"); !strings.Contains(l, qual) {
		t.Fatalf("literal any->z214 reference under the loser lacks scrub qualifier:\n%s", l)
	}
	// The scoped globals that literally name z214 stay for diagnosis: the
	// emptied one dead-marked with its authored scope, the mixed one pruned to
	// its surviving member. RED on master: both rendered unqualified.
	if l := summaryLine12896(t, strings.Split(got, "\n"), "g-dead-scope"); !strings.Contains(l, qual) {
		t.Fatalf("emptied-scope global under the loser lacks scrub qualifier:\n%s", l)
	}
	if l := summaryLine12896(t, strings.Split(got, "\n"), "g-mixed"); !strings.Contains(l, qual) || !strings.Contains(l, "any -> trust:") {
		t.Fatalf("mixed-scope global under the loser must render pruned scope + qualifier:\n%s", l)
	}
}

// TestZoneDetailPolicySummaryNoQuarantineUnchanged12896 is the no-collision
// control: with no quarantined zone the render is byte-identical to the
// pre-fix presenter (no qualifiers, wildcard selection intact for a live zone).
func TestZoneDetailPolicySummaryNoQuarantineUnchanged12896(t *testing.T) {
	anyMatch := config.PolicyMatch{
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"any"},
		Applications:         []string{"any"},
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{FromZone: "any", ToZone: "any",
					Policies: []*config.Policy{{Name: "anyany", Action: config.PolicyDeny, Match: anyMatch}}},
				{FromZone: "trust", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "exact", Action: config.PolicyPermit, Match: anyMatch}}},
			},
			GlobalPolicies: []*config.Policy{
				{Name: "g", Action: config.PolicyDeny, Match: anyMatch},
			},
		},
	}
	got := strings.Join(ZoneDetailPolicySummary(cfg, "trust", nil, false), "\n")
	if strings.Contains(got, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("no-collision config gained quarantine qualifier:\n%s", got)
	}
	for _, want := range []string{"[zone-pair] any -> any: anyany", "[zone-pair] trust -> untrust: exact", "[global] any -> any: g"} {
		if !strings.Contains(got, want) {
			t.Fatalf("no-collision render lost %q:\n%s", want, got)
		}
	}
}
