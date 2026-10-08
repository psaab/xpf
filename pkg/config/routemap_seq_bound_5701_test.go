package config

import (
	"fmt"
	"strings"
	"testing"
)

// TestRouteMapSequenceCount_5701 pins the projected-count arithmetic that the
// #5701 bound relies on: it must mirror the pkg/frr renderer's per-term
// Cartesian expansion (family split x from-prefix-list x from-community x
// from-as-path x from-protocol), each OR-set clamped to a minimum of 1.
func TestRouteMapSequenceCount_5701(t *testing.T) {
	cases := []struct {
		name string
		ps   *PolicyStatement
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", &PolicyStatement{Name: "e"}, 0},
		{"one-bare-term", &PolicyStatement{Terms: []*PolicyTerm{{Name: "t"}}}, 1},
		{
			"prefix-list-or", // 3 prefix-lists → 3 sequences
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", PrefixList: []string{"a", "b", "c"}}}},
			3,
		},
		{
			"cross-product", // 2 pl x 3 comm x 2 asp = 12
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				PrefixList:    []string{"a", "b"},
				FromCommunity: []string{"c1", "c2", "c3"},
				FromASPath:    []string{"p1", "p2"},
			}}},
			12,
		},
		{
			"mixed-family-doubles", // mixed v4+v6 route-filters → x2; x 4 pl = 8
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:         "t",
				RouteFilters: []*RouteFilter{{Prefix: "10.0.0.0/8"}, {Prefix: "2001:db8::/32"}},
				PrefixList:   []string{"a", "b", "c", "d"},
			}}},
			8,
		},
		{
			"single-family-no-double", // all v4 route-filters → x1
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:         "t",
				RouteFilters: []*RouteFilter{{Prefix: "10.0.0.0/8"}, {Prefix: "192.0.2.0/24"}},
				PrefixList:   []string{"a", "b"},
			}}},
			2,
		},
		{
			"sum-over-terms", // 3 + 2 = 5
			&PolicyStatement{Terms: []*PolicyTerm{
				{Name: "t1", PrefixList: []string{"a", "b", "c"}},
				{Name: "t2", FromCommunity: []string{"c1", "c2"}},
			}},
			5,
		},
	}
	for _, c := range cases {
		if got := RouteMapSequenceCount(nil, c.ps); got != c.want {
			t.Errorf("%s: RouteMapSequenceCount = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestRouteMapSequenceCount_OverCeilingNoWrap_5701 proves a large policy is
// counted ABOVE the ceiling (not wrapped back into the in-bound range where it
// would evade the gate). Two modestly-sized OR-sets whose product clears the
// ceiling exercise the multiply; the underlying uint64 saturation on true
// product overflow is guaranteed by checkedMulU64 (proven in
// firewall_filter_expand_test).
func TestRouteMapSequenceCount_OverCeilingNoWrap_5701(t *testing.T) {
	// 83 x 83 = 6889 > 6552.
	ps := &PolicyStatement{Terms: []*PolicyTerm{{
		Name:          "t",
		PrefixList:    makeNames("pl", 83),
		FromCommunity: makeNames("c", 83),
	}}}
	if got := RouteMapSequenceCount(nil, ps); got != 83*83 {
		t.Fatalf("count = %d, want %d", got, 83*83)
	}
	if RouteMapSequenceCount(nil, ps) <= MaxRouteMapSequences {
		t.Fatalf("83x83 must exceed the ceiling %d", MaxRouteMapSequences)
	}
}

// TestPolicyRouteMapSequenceBound_GateDirect_5701 exercises the gate function
// directly: an over-ceiling policy is rejected (error names the policy); an
// at/under-ceiling policy passes.
func TestPolicyRouteMapSequenceBound_GateDirect_5701(t *testing.T) {
	// Exactly at the ceiling passes; one over is rejected.
	atCeil := &Config{}
	atCeil.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{
		"OK": {Name: "OK", Terms: []*PolicyTerm{{Name: "t", PrefixList: makeNames("pl", MaxRouteMapSequences)}}},
	}
	if err := validatePolicyRouteMapSequenceBoundStrict(atCeil); err != nil {
		t.Fatalf("policy at the ceiling (%d) must pass, got %v", MaxRouteMapSequences, err)
	}

	over := &Config{}
	over.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{
		"TOOBIG": {Name: "TOOBIG", Terms: []*PolicyTerm{{Name: "t", PrefixList: makeNames("pl", MaxRouteMapSequences+1)}}},
	}
	err := validatePolicyRouteMapSequenceBoundStrict(over)
	if err == nil {
		t.Fatal("policy one over the ceiling must be rejected")
	}
	if !strings.Contains(err.Error(), "TOOBIG") {
		t.Fatalf("error must name the oversized policy TOOBIG, got %q", err.Error())
	}
}

// TestPolicyRouteMapSequenceBound_CompileReject_5701 is the fail-on-revert
// wiring test. A policy whose Cartesian expansion exceeds the FRR route-map
// sequence ceiling is REJECTED by the strict commit path (CompileConfig),
// rather than compiling and later poisoning the frr-reload with a `route-map`
// line past sequence 65535.
//
// FAIL-ON-REVERT: removing validatePolicyRouteMapSequenceBoundStrict from
// runUniformGates (or dropping the bound) makes CompileConfig accept the
// oversized policy, so the reject assertion fires RED.
func TestPolicyRouteMapSequenceBound_CompileReject_5701(t *testing.T) {
	// 82 prefix-lists x 82 as-paths in ONE term = 6724 sequences > the 6552
	// ceiling.
	//
	// #7471: each as-path is now DEFINED. `from as-path` became
	// definedness-gated (validatePolicyASPathReferencesStrict), and that gate
	// runs before this one — so leaving them dangling would make this test pass
	// for the wrong reason: the as-path gate would reject first and the
	// sequence-bound gate under test would never run. Defining them keeps the
	// SEQUENCE BOUND the subject.
	//
	// `from prefix-list` remains ungated, so those refs stay dangling.
	const n = 82
	var sets []string
	for i := 0; i < n; i++ {
		sets = append(sets, fmt.Sprintf("set policy-options policy-statement BIG term t1 from prefix-list pl%d", i))
	}
	for i := 0; i < n; i++ {
		sets = append(sets, fmt.Sprintf(`set policy-options as-path asp%d "^%d "`, i, 65000+i))
		sets = append(sets, fmt.Sprintf("set policy-options policy-statement BIG term t1 from as-path asp%d", i))
	}
	tree := flatTreeFromSets(t, sets...)

	// Sanity: the flat-set produced an over-ceiling policy (lenient load keeps
	// it so we can measure the compiled count).
	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	if got := RouteMapSequenceCount(&lenient.PolicyOptions, lenient.PolicyOptions.PolicyStatements["BIG"]); got <= MaxRouteMapSequences {
		t.Fatalf("test setup: BIG must exceed the ceiling, got %d (max %d)", got, MaxRouteMapSequences)
	}

	// Strict commit path REJECTS.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig must reject a policy that overflows the FRR route-map sequence ceiling")
	} else if !strings.Contains(err.Error(), "route-map sequences") || !strings.Contains(err.Error(), "BIG") {
		t.Fatalf("reject error must name the policy and the route-map sequence overflow, got %q", err.Error())
	}

	// Tolerant load DOWNGRADES to a warning (no hard fail, #1960 no-brick).
	found := false
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "route-map sequence") && strings.Contains(w, "BIG") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must record a route-map sequence downgrade warning, got %v", lenient.Warnings)
	}
}

// TestPolicyRouteMapSequenceBound_NormalPasses_5701 proves the common case is
// undisturbed: an ordinary multi-term policy compiles clean.
func TestPolicyRouteMapSequenceBound_NormalPasses_5701(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set policy-options policy-statement EXPORT term t1 from protocol bgp",
		"set policy-options policy-statement EXPORT term t1 then accept",
		"set policy-options policy-statement EXPORT term t2 then reject",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a normal policy must compile, got %v", err)
	}
}

// makeNames returns n distinct "<prefix><i>" strings.
func makeNames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}
