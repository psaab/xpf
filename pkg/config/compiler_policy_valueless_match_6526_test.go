package config

import (
	"fmt"
	"strings"
	"testing"
)

// compiler_policy_valueless_match_6526_test.go is the fail-on-revert guard for
// the #6526 valueless-match-dimension gate — the second finding emitted by
// validatePolicyRequiredMatchStrict, backed by policyValuelessMatchDimensions.
//
// The defect: a security-policy `match` leaf written with NO OPERAND satisfied
// the #3044 required-dimension gate (which decided presence from the leaf
// NAME) and compiled to the BYTE-IDENTICAL empty slice the OMITTED form
// produces, which the userspace matcher reads as match-ANY. `then permit` then
// permitted every source; a scoped-global `match from-zone` / `match to-zone`
// collapsed to the all-zones wildcard. It was reachable through the CLI's own
// `set` path — `set security policies from-zone trust to-zone untrust policy p
// match source-address` with the value left off committed cleanly — so an
// operator hitting enter one token early shipped a permit-any policy. It also
// bypassed the #5575 LenientContentDropped poison, because that poison used
// the same name-based predicate.
//
// These tests pin THREE DISTINCT outcomes and attribute each to the gate that
// produced it, asserting the specific gate's OWN message rather than a bare
// `err != nil` (two gates can reject these probes, so `err != nil` would pass
// even if the #6526 check never ran):
//
//	match stanza                | outcome
//	----------------------------|------------------------------------------
//	source-address 10.0.0.0/8;  | ACCEPTED, Match.SourceAddresses=[10.0.0.0/8]
//	source-address;             | REJECTED by #6526 ("carries NO value")
//	(omitted entirely)          | REJECTED by #3044 ("missing required criterion")
//
// Reverting the fix (make policyValuelessMatchDimensions return nil, or drop
// the emitValueless call in validatePolicyRequiredMatchStrict) turns the
// no-operand subtests GREEN on the BAD config — exactly the regression these
// tests catch.

// Gate fingerprints. Each assertion below requires the EXPECTED gate's marker
// AND forbids the other gate's marker, so a finding can never be silently
// re-attributed.
const (
	gate3044Marker = "match is missing required criterion"
	gate3044Tag    = "(#3044)"
	gate6526Marker = "is present but carries NO value"
	gate6526Tag    = "(#6526)"
)

// buildValuelessMatchFlatTree builds a config tree through the CLI's OWN flat
// `set` path — ParseSetCommand + ConfigTree.SetPath — never NewParser, which
// treats newlines as whitespace and would merge every set line into one node.
func buildValuelessMatchFlatTree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// Hierarchical trees are built via parseHierText (#16139 kit) through the
// HIERARCHICAL parser (a `load override` / on-disk config), the other AST
// shape the compiler must handle.

// zonePairHier wraps a `match { ... }` body in a complete zone-pair policy
// with the referenced zones defined, so the zone-reference gate does not
// pre-empt the match gates under test.
func zonePairHier(matchBody string) string {
	return `security {
	zones { security-zone trust; security-zone untrust; }
	policies {
		from-zone trust to-zone untrust {
			policy p { match { ` + matchBody + ` } then { permit; } }
		}
	}
}`
}

// globalHier wraps a `match { ... }` body in a complete global policy.
func globalHier(matchBody string) string {
	return `security { policies { global {
	policy g { match { ` + matchBody + ` } then { permit; } }
} } }`
}

// assertRejectedBy6526 asserts the strict compile failed with the #6526
// valueless-dimension message naming exactly wantDims, and that the #3044
// missing-dimension gate did NOT produce it.
func assertRejectedBy6526(t *testing.T, err error, wantDims string) {
	t.Helper()
	if err == nil {
		t.Fatalf("strict commit ACCEPTED a match dimension written with no operand — " +
			"the dimension compiles to the empty match-ANY slice and the policy widens (#6526)")
	}
	msg := err.Error()
	want := fmt.Sprintf("match criterion %s is present but carries NO value", wantDims)
	if !strings.Contains(msg, want) {
		t.Fatalf("error %q does not carry the #6526 valueless-dimension finding %q", msg, want)
	}
	if !strings.Contains(msg, gate6526Tag) {
		t.Fatalf("error %q is not tagged %s", msg, gate6526Tag)
	}
	if strings.Contains(msg, gate3044Marker) {
		t.Fatalf("error %q was produced by the #3044 missing-dimension gate, not the #6526 "+
			"valueless-dimension gate — the probe is not attributable", msg)
	}
}

// assertRejectedBy3044 asserts the strict compile failed with the ORIGINAL
// #3044 missing-dimension message naming exactly wantDims, and that the #6526
// gate did NOT produce it. This is the differential control: the omitted form
// must stay attributable to the gate that already covered it.
func assertRejectedBy3044(t *testing.T, err error, wantDims string) {
	t.Helper()
	if err == nil {
		t.Fatalf("strict commit ACCEPTED a policy with an omitted required match dimension (#3044)")
	}
	msg := err.Error()
	want := fmt.Sprintf("%s %s", gate3044Marker, wantDims)
	if !strings.Contains(msg, want) {
		t.Fatalf("error %q does not carry the #3044 missing-dimension finding %q", msg, want)
	}
	if !strings.Contains(msg, gate3044Tag) {
		t.Fatalf("error %q is not tagged %s", msg, gate3044Tag)
	}
	if strings.Contains(msg, gate6526Marker) {
		t.Fatalf("error %q was produced by the #6526 valueless-dimension gate, not the #3044 "+
			"missing-dimension gate — the probe is not attributable", msg)
	}
}

// TestPolicyValuelessMatchDimensionRejectedFlatSet drives the reproduction
// through the CLI's own `set` path for ALL FIVE value-bearing dimensions:
// source-address, destination-address, application, and the scoped-global
// from-zone / to-zone. A fix that closes only source-address is incomplete —
// the same shape collapses `match from-zone <z>` to the all-zones wildcard.
func TestPolicyValuelessMatchDimensionRejectedFlatSet(t *testing.T) {
	zonePair := func(extra ...string) []string {
		return append([]string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
		}, extra...)
	}
	cases := []struct {
		name     string
		cmds     []string
		wantDims string
	}{
		{
			name: "source-address with no operand",
			cmds: zonePair(
				"set security policies from-zone trust to-zone untrust policy p match source-address",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			wantDims: `"source-address"`,
		},
		{
			name: "destination-address with no operand",
			cmds: zonePair(
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			wantDims: `"destination-address"`,
		},
		{
			name: "application with no operand",
			cmds: zonePair(
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			),
			wantDims: `"application"`,
		},
		{
			name: "global from-zone with no operand",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g match from-zone",
				"set security policies global policy g then permit",
			},
			wantDims: `"from-zone"`,
		},
		{
			name: "global to-zone with no operand",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g match to-zone",
				"set security policies global policy g then permit",
			},
			wantDims: `"to-zone"`,
		},
		{
			name: "global from-zone and to-zone both with no operand",
			cmds: []string{
				"set security policies global policy g match source-address any",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g match from-zone",
				"set security policies global policy g match to-zone",
				"set security policies global policy g then permit",
			},
			wantDims: `"from-zone", "to-zone"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildValuelessMatchFlatTree(t, tc.cmds))
			assertRejectedBy6526(t, err, tc.wantDims)
		})
	}
}

// TestPolicyValuelessMatchDimensionRejectedHierarchical drives the same
// reproduction through the HIERARCHICAL parser — the `load override` /
// on-disk-config shape, where the no-operand leaf is written `source-address;`.
func TestPolicyValuelessMatchDimensionRejectedHierarchical(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantDims string
	}{
		{
			name:     "source-address with no operand",
			body:     zonePairHier(`source-address; destination-address any; application any;`),
			wantDims: `"source-address"`,
		},
		{
			name:     "destination-address with no operand",
			body:     zonePairHier(`source-address any; destination-address; application any;`),
			wantDims: `"destination-address"`,
		},
		{
			name:     "application with no operand",
			body:     zonePairHier(`source-address any; destination-address any; application;`),
			wantDims: `"application"`,
		},
		{
			name:     "global from-zone with no operand",
			body:     globalHier(`source-address any; destination-address any; application any; from-zone;`),
			wantDims: `"from-zone"`,
		},
		{
			name:     "global to-zone with no operand",
			body:     globalHier(`source-address any; destination-address any; application any; to-zone;`),
			wantDims: `"to-zone"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, tc.body))
			assertRejectedBy6526(t, err, tc.wantDims)
		})
	}
}

// TestPolicyMatchDimensionThreeOutcomesAreDistinct is the differential core of
// this guard: the SAME dimension, written three ways, must produce THREE
// DISTINCT results — accepted with the configured value, rejected by the NEW
// #6526 check, rejected by the ORIGINAL #3044 check. If the no-operand form
// and the omitted form produced the same message the tests could not tell them
// apart, and a regression that re-collapsed them would go unnoticed.
func TestPolicyMatchDimensionThreeOutcomesAreDistinct(t *testing.T) {
	zonePairCmds := func(srcLine string) []string {
		cmds := []string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
		}
		if srcLine != "" {
			cmds = append(cmds, srcLine)
		}
		return append(cmds,
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application any",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		)
	}

	t.Run("flat-set", func(t *testing.T) {
		t.Run("normal value accepted", func(t *testing.T) {
			cfg, err := CompileConfig(buildValuelessMatchFlatTree(t, zonePairCmds(
				"set security policies from-zone trust to-zone untrust policy p match source-address 10.0.0.0/8")))
			if err != nil {
				t.Fatalf("strict commit rejected a policy with a real source-address value: %v", err)
			}
			assertOnlyPolicySources(t, cfg, []string{"10.0.0.0/8"})
		})
		t.Run("no operand rejected by 6526", func(t *testing.T) {
			_, err := CompileConfig(buildValuelessMatchFlatTree(t, zonePairCmds(
				"set security policies from-zone trust to-zone untrust policy p match source-address")))
			assertRejectedBy6526(t, err, `"source-address"`)
		})
		t.Run("omitted rejected by 3044", func(t *testing.T) {
			_, err := CompileConfig(buildValuelessMatchFlatTree(t, zonePairCmds("")))
			assertRejectedBy3044(t, err, `"source-address"`)
		})
	})

	t.Run("hierarchical", func(t *testing.T) {
		t.Run("normal value accepted", func(t *testing.T) {
			cfg, err := CompileConfig(parseHierText(t, zonePairHier(
				`source-address 10.0.0.0/8; destination-address any; application any;`)))
			if err != nil {
				t.Fatalf("strict commit rejected a policy with a real source-address value: %v", err)
			}
			assertOnlyPolicySources(t, cfg, []string{"10.0.0.0/8"})
		})
		t.Run("no operand rejected by 6526", func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, zonePairHier(
				`source-address; destination-address any; application any;`)))
			assertRejectedBy6526(t, err, `"source-address"`)
		})
		t.Run("omitted rejected by 3044", func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, zonePairHier(
				`destination-address any; application any;`)))
			assertRejectedBy3044(t, err, `"source-address"`)
		})
	})
}

// assertOnlyPolicySources asserts the compiled config holds exactly one
// zone-pair policy whose source-address set is want. It pins the ACCEPTED
// outcome to a real value, not merely to the absence of an error — an empty
// slice would otherwise satisfy "accepted" and hide the very widening this
// gate exists to stop.
func assertOnlyPolicySources(t *testing.T, cfg *Config, want []string) {
	t.Helper()
	var got []string
	n := 0
	for _, zp := range cfg.Security.Policies {
		for _, p := range zp.Policies {
			n++
			got = p.Match.SourceAddresses
			if p.LenientContentDropped {
				t.Fatalf("policy %q was poisoned (LenientContentDropped) on a clean strict commit", p.Name)
			}
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 compiled zone-pair policy, got %d", n)
	}
	if len(got) != len(want) {
		t.Fatalf("Match.SourceAddresses = %v (n=%d), want %v (n=%d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Match.SourceAddresses = %v, want %v", got, want)
		}
	}
}

// TestPolicyValuelessMatchLenientWarnsAndPoisons asserts the #1960 no-brick
// split: on the TOLERANT load / peer-sync path a valueless dimension does NOT
// fail the compile (an already-persisted or peer-synced config an older binary
// silently accepted still BOOTS) but IS surfaced as a warning AND poisoned via
// the #5575 LenientContentDropped flag, so the userspace snapshot builder
// publishes the rule as never-match instead of as the widened permit. The
// warning assertion is on the #6526 message specifically, not on the mere
// presence of some warning.
func TestPolicyValuelessMatchLenientWarnsAndPoisons(t *testing.T) {
	cases := []struct {
		name     string
		tree     func(t *testing.T) *ConfigTree
		wantDims string
		global   bool
	}{
		{
			name: "flat-set source-address",
			tree: func(t *testing.T) *ConfigTree {
				return buildValuelessMatchFlatTree(t, []string{
					"set security zones security-zone trust",
					"set security zones security-zone untrust",
					"set security policies from-zone trust to-zone untrust policy p match source-address",
					"set security policies from-zone trust to-zone untrust policy p match destination-address any",
					"set security policies from-zone trust to-zone untrust policy p match application any",
					"set security policies from-zone trust to-zone untrust policy p then permit",
				})
			},
			wantDims: `"source-address"`,
		},
		{
			name: "hierarchical application",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, zonePairHier(
					`source-address any; destination-address any; application;`))
			},
			wantDims: `"application"`,
		},
		{
			name: "global from-zone",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, globalHier(
					`source-address any; destination-address any; application any; from-zone;`))
			},
			wantDims: `"from-zone"`,
			global:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must not brick on a valueless match dimension: %v", err)
			}
			want := fmt.Sprintf("match criterion %s is present but carries NO value", tc.wantDims)
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, want) && strings.Contains(w, gate6526Tag) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected a downgraded #6526 valueless-dimension warning %q, got warnings: %v", want, cfg.Warnings)
			}
			pols := cfg.Security.GlobalPolicies
			if !tc.global {
				pols = nil
				for _, zp := range cfg.Security.Policies {
					pols = append(pols, zp.Policies...)
				}
			}
			if len(pols) != 1 {
				t.Fatalf("expected exactly 1 compiled policy, got %d", len(pols))
			}
			if !pols[0].LenientContentDropped {
				t.Fatalf("policy %q compiled leniently with a valueless match dimension but was NOT "+
					"poisoned (LenientContentDropped=false) — the widened permit would be published "+
					"to the dataplane (#5575/#6526)", pols[0].Name)
			}
		})
	}
}

// TestPolicyValuelessMatchCompilesToSameEmptySetAsOmitted pins the PREMISE the
// gate rests on: on the tolerant path (the only path that still compiles these
// configs) a no-operand dimension and an omitted dimension produce the SAME
// empty match set, which the userspace matcher reads as match-ANY. If a future
// change made the no-operand form compile to something distinguishable, this
// documents that the gate's rationale would need revisiting.
func TestPolicyValuelessMatchCompilesToSameEmptySetAsOmitted(t *testing.T) {
	srcOf := func(t *testing.T, body string) []string {
		t.Helper()
		cfg, err := CompileConfigLenient(parseHierText(t, body))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		for _, zp := range cfg.Security.Policies {
			for _, p := range zp.Policies {
				return p.Match.SourceAddresses
			}
		}
		t.Fatalf("no compiled policy")
		return nil
	}
	noOperand := srcOf(t, zonePairHier(`source-address; destination-address any; application any;`))
	omitted := srcOf(t, zonePairHier(`destination-address any; application any;`))
	if len(noOperand) != 0 || len(omitted) != 0 {
		t.Fatalf("expected both forms to compile to an EMPTY source set, got no-operand=%v omitted=%v",
			noOperand, omitted)
	}
}

// TestPolicyValuelessMatchDoesNotOverReject is the false-positive control: the
// gate must fire ONLY on a dimension that actually compiles to an empty set.
func TestPolicyValuelessMatchDoesNotOverReject(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{
			// source-address-excluded / destination-address-excluded are
			// BOOLEAN modifier leaves that legitimately carry no operand.
			// Flagging them would reject valid Junos.
			name: "address-excluded modifiers carry no operand by design",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, zonePairHier(
					`source-address any; source-address-excluded; destination-address any; `+
						`destination-address-excluded; application any;`))
			},
		},
		{
			// The #2419 bracketed list collapses onto ONE leaf's Keys;
			// firewallMatchValues sees all three, so the dimension is valued.
			name: "bracketed list is a valued dimension",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, zonePairHier(
					`source-address [ 10.0.0.0/8 192.168.0.0/16 ]; destination-address any; application any;`))
			},
		},
		{
			// #3842 union semantics: a duplicate `match {}` block supplies the
			// value, so the dimension does NOT compile to an empty set and is
			// not widened — the gate must not fire.
			name: "duplicate match block supplies the value",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, `security {
	zones { security-zone trust; security-zone untrust; }
	policies { from-zone trust to-zone untrust { policy p {
		match { source-address; destination-address any; application any; }
		match { source-address 10.0.0.0/8; }
		then { permit; }
	} } }
}`)
			},
		},
		{
			// The explicit wildcard is a VALUE, not an absence — Junos parity.
			name: "explicit any is a value",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, zonePairHier(
					`source-address any; destination-address any; application any;`))
			},
		},
		{
			// A global policy that simply OMITS from-zone/to-zone is the
			// documented all-zones form and must keep committing.
			name: "global policy without from-zone/to-zone",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierText(t, globalHier(
					`source-address any; destination-address any; application any;`))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(tc.tree(t)); err != nil {
				t.Fatalf("strict commit rejected a policy the #6526 gate must not flag: %v", err)
			}
		})
	}
}

// TestPolicyValuelessAndMissingTogetherReportsMissingFirst pins the documented
// precedence when a policy trips BOTH findings: the omitted dimension is the
// more fundamental authoring error and is reported first, so the operator sees
// a stable, deterministic message rather than one that depends on walk order.
func TestPolicyValuelessAndMissingTogetherReportsMissingFirst(t *testing.T) {
	_, err := CompileConfig(parseHierText(t, zonePairHier(
		`source-address; destination-address any;`)))
	assertRejectedBy3044(t, err, `"application"`)
}

// TestPolicyValuelessMatchZonePairFromZoneStaysUnsupported guards the scoping
// choice: from-zone/to-zone are value-bearing ONLY under a global policy.
// Under a ZONE-PAIR policy they are not match siblings at all, so the #3113
// unsupported-match-leaf gate — which runs first — owns them, and the #6526
// gate must not double-attribute the same typo.
func TestPolicyValuelessMatchZonePairFromZoneStaysUnsupported(t *testing.T) {
	body := zonePairHier(`source-address any; destination-address any; application any; from-zone;`)

	_, err := CompileConfig(parseHierText(t, body))
	if err == nil {
		t.Fatalf("strict commit accepted `match from-zone` under a zone-pair policy")
	}
	if !strings.Contains(err.Error(), "is not supported") || !strings.Contains(err.Error(), "(#3113)") {
		t.Fatalf("expected the #3113 unsupported-match-leaf gate to own zone-pair from-zone, got: %v", err)
	}
	if strings.Contains(err.Error(), gate6526Marker) {
		t.Fatalf("the #6526 gate double-attributed a zone-pair from-zone the #3113 gate owns: %v", err)
	}

	// The strict path returns only the FIRST finding, and #3113 runs before
	// the #3044/#6526 walk — so the assertion above cannot by itself prove the
	// global-only scoping. The LENIENT path collects EVERY finding, so it can:
	// exactly one warning (the #3113 one) must mention this leaf.
	cfg, lerr := CompileConfigLenient(parseHierText(t, body))
	if lerr != nil {
		t.Fatalf("lenient compile must not brick: %v", lerr)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, gate6526Marker) {
			t.Fatalf("the #6526 gate warned about a zone-pair `match from-zone` that the #3113 gate "+
				"already owns — one typo, two findings: %s", w)
		}
	}
	sawUnsupported := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#3113)") && strings.Contains(w, "from-zone") {
			sawUnsupported = true
			break
		}
	}
	if !sawUnsupported {
		t.Fatalf("expected the #3113 unsupported-leaf warning for zone-pair from-zone, got: %v", cfg.Warnings)
	}
}
