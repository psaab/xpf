package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3684: direct unit tests for the shared zone-detail policy summary presenter
// consumed by the local CLI + gRPC-text renderers (L10). These pin the
// metadata thread (id/scheduler/log/count/exclusion + default posture) and the
// haveSched=false fallback (no rule claimed inactive) at the SSOT boundary,
// independent of the CLI/gRPC harnesses.

func metadataSummaryConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy:               config.PolicyPermit,
			DefaultPolicyLogSessionInit: true,
			Zones:                       zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:          "sched-off",
							Action:        config.PolicyPermit,
							SchedulerName: "workhours",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"any"},
								DestinationAddresses: []string{"any"},
								Applications:         []string{"any"},
							},
						},
						{
							Name:   "logged-rule",
							Action: config.PolicyPermit,
							Count:  true,
							Log:    &config.PolicyLog{SessionInit: true, SessionClose: true},
							Match: config.PolicyMatch{
								SourceAddresses:            []string{"net10"},
								SourceAddressExcluded:      true,
								DestinationAddresses:       []string{"any"},
								DestinationAddressExcluded: true,
								Applications:               []string{"any"},
							},
						},
					},
				},
			},
			GlobalPolicies: []*config.Policy{
				{
					Name:          "g-sched-off",
					Action:        config.PolicyDeny,
					SchedulerName: "workhours",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
				},
			},
		},
	}
}

// TestZoneDetailPolicySummaryMetadata pins the full metadata render for an
// inactive scheduler.
func TestZoneDetailPolicySummaryMetadata(t *testing.T) {
	cfg := metadataSummaryConfig()
	got := strings.Join(
		ZoneDetailPolicySummary(cfg, "untrust", map[string]bool{"workhours": false}, true),
		"\n",
	)
	for _, want := range []string{
		"  Policy summary (evaluation order: zone-pair, global, default-policy):",
		"    [zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours (inactive)]",
		"    [zone-pair] trust -> untrust: logged-rule (permit) [id 1, log at-create,at-close, count, source-address (except), destination-address (except)]",
		"    [global] any -> any: g-sched-off (deny) [id 2, scheduler workhours (inactive)]",
		"    [default] default-policy: permit [id 4294967295, log at-create]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
}

// TestZoneDetailPolicySummaryNoRuntimeSchedulerState asserts the fallback:
// haveSched=false means the runtime scheduler state is unknown, so NO rule is
// claimed inactive (matching the #3062/#3414 detail renderer), while the
// scheduler binding is still shown.
func TestZoneDetailPolicySummaryNoRuntimeSchedulerState(t *testing.T) {
	cfg := metadataSummaryConfig()
	got := strings.Join(
		ZoneDetailPolicySummary(cfg, "untrust", nil, false),
		"\n",
	)
	if strings.Contains(got, "(inactive)") {
		t.Fatalf("haveSched=false must not claim any rule inactive:\n%s", got)
	}
	if !strings.Contains(got, "[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours]") {
		t.Fatalf("scheduler binding dropped in the unknown-state fallback:\n%s", got)
	}
}

// TestZoneDetailPolicySummaryNoApplicablePolicy asserts a zone with no
// zone-pair/global rule still shows the "(no ...)" note AND the effective
// default-policy catch-all (with sentinel id), never a bare omission.
func TestZoneDetailPolicySummaryNoApplicablePolicy(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust", "mgmt"),
		},
	}
	got := strings.Join(ZoneDetailPolicySummary(cfg, "mgmt", nil, false), "\n")
	if !strings.Contains(got, "    (no zone-pair or global policies affecting this zone)") {
		t.Fatalf("missing no-applicable-policy note:\n%s", got)
	}
	if !strings.Contains(got, "    [default] default-policy: deny [id 4294967295]") {
		t.Fatalf("missing default-policy catch-all with sentinel id:\n%s", got)
	}
}

// TestZoneDetailPolicySummaryNilConfig guards the nil-config path.
func TestZoneDetailPolicySummaryNilConfig(t *testing.T) {
	if lines := ZoneDetailPolicySummary(nil, "trust", nil, false); lines != nil {
		t.Fatalf("nil cfg should return nil, got %v", lines)
	}
}

// TestZoneDetailPolicySummaryWildcardZonePairs pins the #4885 fix: a wildcard
// zone-pair side ("any") that governs the queried zone must be INCLUDED, and
// zone-pair lines must render in the runtime's tier order (exact, then
// single-wildcard, then both-any) regardless of config placement.
//
// The config below is deliberately authored in REVERSE tier order —
// both-any first, single-wildcard next, exact last, plus one unrelated set —
// so a passing test proves both the inclusion filter and the re-ordering.
func TestZoneDetailPolicySummaryWildcardZonePairs(t *testing.T) {
	anyMatch := config.PolicyMatch{
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"any"},
		Applications:         []string{"any"},
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust", "dmz"),
			Policies: []*config.ZonePairPolicies{
				{ // config idx 0 — both-any: governs every zone
					FromZone: "any", ToZone: "any",
					Policies: []*config.Policy{{Name: "anyany", Action: config.PolicyDeny, Match: anyMatch}},
				},
				{ // config idx 1 — single-wildcard: from any -> untrust governs a trust ingress
					FromZone: "any", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "wild-ingress", Action: config.PolicyPermit, Match: anyMatch}},
				},
				{ // config idx 2 — exact: literally names trust
					FromZone: "trust", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "exact", Action: config.PolicyPermit, Match: anyMatch}},
				},
				{ // config idx 3 — unrelated: neither side is trust/any
					FromZone: "dmz", ToZone: "untrust",
					Policies: []*config.Policy{{Name: "unrelated", Action: config.PolicyPermit, Match: anyMatch}},
				},
			},
		},
	}
	lines := ZoneDetailPolicySummary(cfg, "trust", nil, false)
	got := strings.Join(lines, "\n")

	// Inclusion: the wildcard + both-any sets that govern trust must appear;
	// the unrelated dmz->untrust set must not.
	idxExact := indexOfLine(t, lines, "exact")
	idxWild := indexOfLine(t, lines, "wild-ingress")
	idxAny := indexOfLine(t, lines, "anyany")
	if strings.Contains(got, "unrelated") {
		t.Fatalf("dmz->untrust set does not govern trust and must be omitted:\n%s", got)
	}
	// Ordering: exact, then single-wildcard, then both-any — despite reverse
	// config placement.
	if !(idxExact < idxWild && idxWild < idxAny) {
		t.Fatalf("zone-pair lines out of runtime tier order (exact=%d wild=%d any=%d):\n%s",
			idxExact, idxWild, idxAny, got)
	}
	// The rendered wildcard sides keep the "any" token.
	if !strings.Contains(got, "[zone-pair] any -> untrust: wild-ingress") {
		t.Fatalf("single-wildcard line missing/misrendered:\n%s", got)
	}
	if !strings.Contains(got, "[zone-pair] any -> any: anyany") {
		t.Fatalf("both-any line missing/misrendered:\n%s", got)
	}
}

// indexOfLine returns the index of the first line containing sub, failing the
// test if none matches.
func indexOfLine(t *testing.T, lines []string, sub string) int {
	t.Helper()
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	t.Fatalf("no summary line contains %q:\n%s", sub, strings.Join(lines, "\n"))
	return -1
}
