package config

import (
	"strings"
	"testing"
)

// TestRouteMapSequenceCount_ProtoDimension_12066 pins the #12066 admission
// count: FromProtocols is an OR dimension in the pkg/frr renderer's Cartesian
// expansion, so the factor is max(1,|unique canonical source protocols|).
// Alias `direct` normalizes to `connected` before duplicates are removed.
func TestRouteMapSequenceCount_ProtoDimension_12066(t *testing.T) {
	cases := []struct {
		name string
		ps   *PolicyStatement
		want uint64
	}{
		{"nil-protocols-single", &PolicyStatement{Terms: []*PolicyTerm{{Name: "t"}}}, 1},
		{
			"single-protocol-single",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp"}}}},
			1,
		},
		{
			"three-protocols",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp", "ospf", "direct"}}}},
			3,
		},
		{
			"proto-cross-product", // 2 pl x 2 proto x 2 comm = 8
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				PrefixList:    []string{"a", "b"},
				FromProtocols: []string{"bgp", "ospf"},
				FromCommunity: []string{"c1", "c2"},
			}}},
			8,
		},
		{
			"proto-family-split", // mixed v4+v6 route-filters x 2 proto = 4
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				FromProtocols: []string{"bgp", "ospf"},
				RouteFilters:  []*RouteFilter{{Prefix: "10.0.0.0/8"}, {Prefix: "2001:db8::/32"}},
			}}},
			4,
		},
		{
			"proto-sum-over-terms", // 2 + 3 = 5
			&PolicyStatement{Terms: []*PolicyTerm{
				{Name: "t1", FromProtocols: []string{"bgp", "ospf"}},
				{Name: "t2", FromProtocols: []string{"bgp", "ospf", "static"}},
			}},
			5,
		},
		{
			"direct-connected-alias-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"direct", "connected"}}}},
			1,
		},
		{
			"literal-protocol-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp", "bgp"}}}},
			1,
		},
		{
			"padded-protocol-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp", "bgp "}}}},
			1,
		},
		{
			"mixed-case-protocol-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"BGP", "bgp"}}}},
			1,
		},
		{
			"padded-direct-alias-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"direct", "connected "}}}},
			1,
		},
		{
			"padded-case-alias-dedup",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{" Direct ", "CONNECTED"}}}},
			1,
		},
		{
			"unknown-protocols-stay-distinct",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"unknown-a", "unknown-b"}}}},
			2,
		},
		{
			"deduped-protocol-cross-product", // 2 pl x 1 canonical proto x 2 comm = 4
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				PrefixList:    []string{"a", "b"},
				FromProtocols: []string{"direct", "connected"},
				FromCommunity: []string{"c1", "c2"},
			}}},
			4,
		},
	}
	for _, c := range cases {
		if got := RouteMapSequenceCount(nil, c.ps); got != c.want {
			t.Errorf("%s: RouteMapSequenceCount = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestPolicyProtoSeqAdmissionRejectsNearCeiling_12066 proves protocol
// expansion reaches the strict admission gate: 3,277 communities fit below
// the limit before the protocol factor, while two protocols expand to 6,554
// sequences and are rejected with protocol-specific guidance.
func TestPolicyProtoSeqAdmissionRejectsNearCeiling_12066(t *testing.T) {
	communityCount := MaxRouteMapSequences/2 + 1
	termWithoutProtocol := &PolicyTerm{
		Name:          "t",
		FromCommunity: makeNames("c", communityCount),
	}
	oldPolicy := &PolicyStatement{Name: "PROTO-BIG", Terms: []*PolicyTerm{termWithoutProtocol}}
	oldCount := RouteMapSequenceCount(nil, oldPolicy)
	if oldCount != uint64(communityCount) || oldCount > MaxRouteMapSequences {
		t.Fatalf("count without protocol factor = %d, want %d at/below %d",
			oldCount, communityCount, MaxRouteMapSequences)
	}

	term := *termWithoutProtocol
	term.FromProtocols = []string{"bgp", "ospf"}
	policy := &PolicyStatement{Name: "PROTO-BIG", Terms: []*PolicyTerm{&term}}
	cfg := &Config{}
	cfg.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{"PROTO-BIG": policy}

	newCount := RouteMapSequenceCount(&cfg.PolicyOptions, policy)
	if want := uint64(communityCount * 2); newCount != want || newCount <= MaxRouteMapSequences {
		t.Fatalf("count with protocol factor = %d, want %d over ceiling %d",
			newCount, want, MaxRouteMapSequences)
	}
	err := validatePolicyRouteMapSequenceBoundStrict(cfg)
	if err == nil {
		t.Fatalf("strict sequence bound accepted a two-protocol policy with %d communities", communityCount)
	}
	if !strings.Contains(err.Error(), "from protocol") {
		t.Fatalf("overflow error must identify the protocol dimension, got %q", err)
	}
}

// TestPolicyProtoSeqAliasDedupAdmissionPassesNearCeiling_12066 proves alias
// normalization and deduplication also keep the strict admission count aligned
// with the renderer near the sequence ceiling.
func TestPolicyProtoSeqAliasDedupAdmissionPassesNearCeiling_12066(t *testing.T) {
	communityCount := MaxRouteMapSequences/2 + 1
	policy := &PolicyStatement{
		Name: "PROTO-ALIASED",
		Terms: []*PolicyTerm{{
			Name:          "t",
			FromCommunity: makeNames("c", communityCount),
			FromProtocols: []string{"direct", "connected"},
		}},
	}
	cfg := &Config{}
	cfg.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{"PROTO-ALIASED": policy}

	if got := RouteMapSequenceCount(&cfg.PolicyOptions, policy); got != uint64(communityCount) {
		t.Fatalf("deduped count = %d, want %d", got, communityCount)
	}
	if err := validatePolicyRouteMapSequenceBoundStrict(cfg); err != nil {
		t.Fatalf("strict sequence bound rejected deduplicated aliased protocols: %v", err)
	}
}
