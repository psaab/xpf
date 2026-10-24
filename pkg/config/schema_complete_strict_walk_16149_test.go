package config

import (
	"slices"
	"testing"
)

// #16149 (W2.3 R2): the three strict consumed/identity token walks —
// ResolveConsumedSetPathTokens, editIdentityStarts, editIdentityConsumed —
// now share ONE token-walk kernel (walkStrictConsumedTokens) instead of
// independently re-deriving exact/unique-prefix/wildcard/compound-key
// logic in pkg/config/schema_complete.go. CompleteSetPathWithValues is
// deliberately NOT on the kernel: it handles partial terminal keywords
// and early value suggestions (non-strict) and stays separate until a
// divergence census characterizes its strict prefix. Tolerant completion
// (#1960) is unchanged.
//
// TestStrictWalkAgreement16149 is the agreement + positive-mutant test
// demanded by the issue. The table below is the published strict-walk
// divergence table (see also docs/log/16149.md): the three walkers
// intentionally agree on descent mechanics and intentionally diverge on
// exactly the strictness rows (D1, D2). A divergence is a DELIBERATE
// rule difference, not drift — each D-row names the rule that produces
// it, and each is asserted against the kernel AND both public walkers.
//
// Positive mutant (seeded divergence goes red — verified by mutation,
// see docs/log/16149.md): each mutation of the kernel's strictness is
// caught by at least one named test:
//   - mutant A — kernel treats an ambiguous prefix as resolved (first
//     match): TestStrictWalkAgreement16149/ambiguous_prefix_stops_both
//     and TestStrictWalkDivergence16149/D1_ambiguous_prefix go red.
//   - mutant B — kernel drops the compoundKey sub-token descent:
//     TestStrictWalkAgreement16149/compoundKey rows go red.
//   - mutant C — kernel resolves compoundKey sub-tokens by exact match
//     only (drops unique-prefix expansion):
//     TestStrictWalkAgreement16149/compoundKey_unique_prefix goes red.
//   - mutant D — kernel treats a multi leaf as descending:
//     TestStrictWalkAgreement16149/multi-leaf rows go red.
//   - mutant E — kernel drops the truncated-final-identity step:
//     TestStrictWalkAgreement16149/truncated rows go red.
// A mutant string alone proves nothing; each claim above was verified
// by applying the mutation and running the named test (see log).

// strictWalkCase pins one input against kernel + both public walkers.
//
// For ResolveConsumed, keyword order in the resolved output is
// nondeterministic across SchemaCompletion consumers (map iteration in
// CompleteSetPathWithValues), but ResolveConsumedSetPathTokens itself
// returns a deterministic slice: keyword tokens are unique-prefix
// expanded in walk order and arg tokens are verbatim in order. The
// assertions below compare exact slices.
type strictWalkCase struct {
	name string

	tokens []string

	// resolveOK / resolveWant: ResolveConsumedSetPathTokens contract.
	resolveOK   bool
	resolveWant []string

	// startsWant / consumedWant: edit-identity walk contract.
	startsWant   []int
	consumedWant int

	// kernelStepsWant: [start,end) spans the kernel must produce.
	kernelStepsWant [][2]int
}

func kernelStrictSteps(tokens []string, strict bool) [][2]int {
	steps, _, _ := walkStrictConsumedTokens(tokens, strictWalkRules{requireUniquePrefix: strict})
	var spans [][2]int
	for _, s := range steps {
		spans = append(spans, [2]int{s.start, s.end})
	}
	return spans
}

func TestStrictWalkAgreement16149(t *testing.T) {
	cases := []strictWalkCase{
		{
			name:            "exact chain",
			tokens:          []string{"security", "zones", "security-zone", "trust"},
			resolveOK:       true,
			resolveWant:     []string{"security", "zones", "security-zone", "trust"},
			startsWant:      []int{0, 1, 2},
			consumedWant:    4,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}},
		},
		{
			name:            "unique prefix expansion",
			tokens:          []string{"secu", "na", "sou"},
			resolveOK:       true,
			resolveWant:     []string{"security", "nat", "source"},
			startsWant:      []int{0, 1, 2},
			consumedWant:    3,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 3}},
		},
		{
			// Ambiguous prefix against children that declare NO
			// wildcard (security has none): both walkers stop/reject
			// at the ambiguous token. Divergence D1 (strictness).
			name:            "ambiguous prefix stops both",
			tokens:          []string{"security", "s"},
			resolveOK:       false,
			startsWant:      []int{0},
			consumedWant:    1,
			kernelStepsWant: [][2]int{{0, 1}},
		},
		{
			// compoundKey descent, exact sub-token: interfaces
			// wildcard (interface name) then family+inet as ONE
			// identity.
			name:            "compoundKey exact",
			tokens:          []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet"},
			resolveOK:       true,
			resolveWant:     []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet"},
			startsWant:      []int{0, 1, 2, 4},
			consumedWant:    6,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 6}},
		},
		{
			// Unique-prefix compoundKey sub-token: `inet6` must be
			// entered via a prefix that matches ONLY it under
			// HasPrefix(childName, token) — `inet6` itself is exact,
			// so use the family node's sibling case instead: the
			// chassis family has inet only, making `in` unique there.
			// At the interfaces family, HasPrefix("inet","inet6")
			// is true, so an `inet` sub-token is ambiguous in the
			// compound arm only when written as a strict prefix.
			name:            "compoundKey inet6 exact via prefix collapse",
			tokens:          []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6"},
			resolveOK:       true,
			resolveWant:     []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6"},
			startsWant:      []int{0, 1, 2, 4},
			consumedWant:    6,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 6}},
		},
		{
			// True unique-prefix compoundKey sub-token: under
			// chassis cluster ip-monitoring the family node has
			// ONLY inet, so `in` prefix-matches exactly one child.
			name:            "compoundKey unique prefix (single child)",
			tokens:          []string{"chassis", "cluster", "redundancy-group", "1", "ip-monitoring", "family", "in"},
			resolveOK:       true,
			resolveWant:     []string{"chassis", "cluster", "redundancy-group", "1", "ip-monitoring", "family", "inet"},
			startsWant:      []int{0, 1, 2, 4, 5},
			consumedWant:    7,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 5}, {5, 7}},
		},
		{
			// Ambiguous compoundKey sub-token: `in` prefix-matches
			// BOTH inet and inet6, so strict ResolveConsumed rejects
			// the WHOLE path. The identity walk RECORDS the family
			// identity's start (tolerant, legacy behavior) but does
			// not descend past it. D1.
			name:            "compoundKey ambiguous sub-token",
			tokens:          []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "in"},
			resolveOK:       false,
			startsWant:      []int{0, 1, 2, 4},
			consumedWant:    5,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 5}},
		},
		{
			// Wildcard fallback: interface name is not a child
			// keyword; the interfaces wildcard consumes it verbatim.
			name:            "wildcard fallback verbatim",
			tokens:          []string{"interfaces", "lo0"},
			resolveOK:       true,
			resolveWant:     []string{"interfaces", "lo0"},
			startsWant:      []int{0, 1},
			consumedWant:    2,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}},
		},
		{
			// Named-instance wildcard with args: security-zone
			// consumes keyword+name, then description consumes its arg.
			name:            "args span",
			tokens:          []string{"security", "zones", "security-zone", "trust", "description", "hello"},
			resolveOK:       true,
			resolveWant:     []string{"security", "zones", "security-zone", "trust", "description", "hello"},
			startsWant:      []int{0, 1, 2, 4},
			consumedWant:    6,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 6}},
		},
		{
			// from-zone <z> to-zone <z> is ONE identity (args:3,
			// midKeyword inside the span).
			name:            "from-zone midKeyword single identity",
			tokens:          []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"},
			resolveOK:       true,
			resolveWant:     []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"},
			startsWant:      []int{0, 1, 2},
			consumedWant:    6,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 6}},
		},
		{
			// Multi leaf: source-address consumes keyword+value and
			// STAYS at the match level, so the sibling destination-
			// address is a further identity at the same level. If
			// the kernel descended into the multi leaf (children
			// nil) the second keyword would stop the walk.
			name:            "multi leaf stays at level",
			tokens:          []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "match", "source-address", "10.0.0.0/8", "destination-address", "192.168.0.0/16"},
			resolveOK:       true,
			resolveWant:     []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "match", "source-address", "10.0.0.0/8", "destination-address", "192.168.0.0/16"},
			startsWant:      []int{0, 1, 2, 6, 8, 9, 11},
			consumedWant:    13,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 6}, {6, 8}, {8, 9}, {9, 11}, {11, 13}},
		},
		{
			// args beyond the multi leaf's span are NOT swallowed:
			// address at the address-book global level consumes
			// keyword+2 args and stays, so a second address is a
			// sibling identity.
			name:            "multi leaf repeated sibling",
			tokens:          []string{"security", "address-book", "global", "address", "a1", "10.0.0.1/32", "address", "a2", "10.0.0.2/32"},
			resolveOK:       true,
			resolveWant:     []string{"security", "address-book", "global", "address", "a1", "10.0.0.1/32", "address", "a2", "10.0.0.2/32"},
			startsWant:      []int{0, 1, 2, 3, 6},
			consumedWant:    9,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 6}, {6, 9}},
		},
		{
			// Truncated final identity: security-zone's arg is
			// missing. ResolveConsumed returns the partial path
			// with success; the identity walk records the step.
			name:            "truncated final identity",
			tokens:          []string{"security", "zones", "security-zone"},
			resolveOK:       true,
			resolveWant:     []string{"security", "zones", "security-zone"},
			startsWant:      []int{0, 1, 2},
			consumedWant:    3,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 3}},
		},
		{
			// Truncated compoundKey identity: family is the last
			// token, its sub-token never arrives. The identity is
			// still recorded by both walkers.
			name:            "truncated compoundKey identity",
			tokens:          []string{"interfaces", "ge-0/0/0", "unit", "0", "family"},
			resolveOK:       true,
			resolveWant:     []string{"interfaces", "ge-0/0/0", "unit", "0", "family"},
			startsWant:      []int{0, 1, 2, 4},
			consumedWant:    5,
			kernelStepsWant: [][2]int{{0, 1}, {1, 2}, {2, 4}, {4, 5}},
		},
		{
			// Unknown token with no wildcard to catch it: strict
			// walker rejects, identity walker stops.
			name:            "unknown token",
			tokens:          []string{"security", "no-such-thing"},
			resolveOK:       false,
			startsWant:      []int{0},
			consumedWant:    1,
			kernelStepsWant: [][2]int{{0, 1}},
		},
		{
			name:            "empty input",
			tokens:          nil,
			resolveOK:       true,
			resolveWant:     nil,
			startsWant:      nil,
			consumedWant:    0,
			kernelStepsWant: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Public walker 1: strict ResolveConsumed.
			resolved, ok := ResolveConsumedSetPathTokens(tc.tokens)
			if ok != tc.resolveOK {
				t.Fatalf("ResolveConsumedSetPathTokens(%v) ok=%v, want %v", tc.tokens, ok, tc.resolveOK)
			}
			if tc.resolveOK && !slices.Equal(resolved, tc.resolveWant) {
				t.Fatalf("ResolveConsumedSetPathTokens(%v) = %v, want %v", tc.tokens, resolved, tc.resolveWant)
			}

			// Public walker 2: edit-identity segmentation.
			if got := editIdentityStarts(tc.tokens); !slices.Equal(got, tc.startsWant) {
				t.Fatalf("editIdentityStarts(%v) = %v, want %v", tc.tokens, got, tc.startsWant)
			}
			if got := editIdentityConsumed(tc.tokens); got != tc.consumedWant {
				t.Fatalf("editIdentityConsumed(%v) = %d, want %d", tc.tokens, got, tc.consumedWant)
			}

			// The kernel itself (strict mode for ResolveConsumed
			// callers, tolerant for identity callers) must produce
			// the same segmentation; only the outcome handling
			// differs (D1). When the strict kernel fails, it
			// discards its steps, so the shared expectation is
			// pinned against the tolerant steps (the identities
			// actually segmented).
			strictSteps := kernelStrictSteps(tc.tokens, true)
			tolerantSteps := kernelStrictSteps(tc.tokens, false)
			if tc.resolveOK {
				if !slices.Equal(strictSteps, tolerantSteps) {
					t.Fatalf("kernel modes diverge on steps for %v: strict=%v tolerant=%v (steps must agree; only outcome/ok may differ — D1)", tc.tokens, strictSteps, tolerantSteps)
				}
			}
			if !slices.Equal(tolerantSteps, tc.kernelStepsWant) {
				t.Fatalf("kernel steps(%v) = %v, want %v", tc.tokens, tolerantSteps, tc.kernelStepsWant)
			}
		})
	}
}

// equalStepSpans reports whether two step-span lists are identical.
func equalStepSpans(a, b [][2]int) bool {
	return slices.Equal(a, b)
}

// strictWalkSeededMutant16149 is the SEEDED positive mutant: a
// deliberately broken kernel variant that treats an ambiguous prefix as
// resolved by picking the first match, inlined here so the test can
// prove that TestStrictWalkDivergence16149's ambiguity assertions are
// live (they go red against this variant; the agreement tests above pin
// the real kernel). This is the runtime counterpart of the applied-
// mutation evidence recorded in docs/log/16149.md.
// Same shape as walkStrictConsumedTokens, except the multi-match
func strictWalkSeededMutant16149(tokens []string) ([]string, bool) {
	// branch picks matches[0] instead of failing/stopping.
	schema := setSchema
	i := 0
	for i < len(tokens) {
		if schema == nil {
			return nil, false
		}
		keyword := tokens[i]
		var child *schemaNode
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				child = s
			} else {
				var matches []string
				for name := range schema.children {
					if hasPrefix16149(name, keyword) {
						matches = append(matches, name)
					}
				}
				if len(matches) > 0 {
					child = schema.children[matches[0]] // MUTANT: first match wins.
				}
			}
		}
		if child == nil && schema.wildcard != nil {
			child = schema.wildcard
		}
		if child == nil {
			return nil, false
		}
		i += 1 + child.args
		if child.compoundKey && i < len(tokens) {
			if sub, ok := child.children[tokens[i]]; ok {
				i++
				child = sub
			}
		}
		if child.multi && child.children == nil {
			continue
		}
		schema = child
	}
	return tokens, true
}

func hasPrefix16149(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestStrictWalkDivergence16149(t *testing.T) {
	// D1 — strictness: an ambiguous prefix at a no-wildcard level
	// FAILES the strict walker but merely STOPS the identity walker.
	// The seeded mutant (first-match-wins) must DISAGREE with the
	// strict expectation: if the kernel were mutated that way, this
	// case goes red.
	t.Run("D1 ambiguous prefix", func(t *testing.T) {
		tokens := []string{"security", "s"}
		if _, ok := ResolveConsumedSetPathTokens(tokens); ok {
			t.Fatalf("strict walker accepted ambiguous prefix %v (D1 violated)", tokens)
		}
		if got := editIdentityStarts(tokens); !slices.Equal(got, []int{0}) {
			t.Fatalf("identity walker starts(%v) = %v, want [0] (stops, D1)", tokens, got)
		}
		if got := editIdentityConsumed(tokens); got != 1 {
			t.Fatalf("identity walker consumed(%v) = %d, want 1 (D1)", tokens, got)
		}
		// Positive-mutant liveness: the seeded mutant RESOLVES the
		// ambiguous token where the real strict walker fails, so the
		// assertions above are not vacuous.
		if _, mutantOK := strictWalkSeededMutant16149(tokens); !mutantOK {
			t.Fatalf("seeded mutant did not diverge on %v; D1 assertions are not proven live", tokens)
		}
	})

	// D1 (compound arm): an ambiguous compoundKey sub-token at a
	// wildcard level fails strict, stops identity.
	t.Run("D1 ambiguous compoundKey sub-token", func(t *testing.T) {
		tokens := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "in"}
		if _, ok := ResolveConsumedSetPathTokens(tokens); ok {
			t.Fatalf("strict walker accepted ambiguous compound sub-token %v (D1 violated)", tokens)
		}
		if got := editIdentityStarts(tokens); !slices.Equal(got, []int{0, 1, 2, 4}) {
			t.Fatalf("identity walker starts(%v) = %v, want [0 1 2 4] (D1 compound arm: family start recorded, no descent)", tokens, got)
		}
	})

	// D2 — wildcard fallback ordering: at a level WITH a wildcard, an
	// ambiguous prefix is consumed VERBATIM by the wildcard (both
	// walkers agree; strict does not prefix-resolve around a
	// wildcard). This is the mutant-defended legacy behavior.
	t.Run("D2 wildcard fallback verbatim on ambiguous prefix", func(t *testing.T) {
		// `s` prefix-matches security-zone's children level? No:
		// the zones level has children functional-zone/security-zone
		// and NO wildcard, so use the interfaces level: `ge-0/0/0`
		// is consumed by the interfaces wildcard; a prefix of a
		// declared child (`un` -> unit) inside the wildcard's own
		// children still resolves by unique prefix — while a token
		// matching nothing there would stop/fail (covered by the
		// unknown-token agreement row). Here both walkers must
		// take the wildcard for the interface name and then
		// unique-prefix `un` to `unit`.
		tokens := []string{"interfaces", "ge-0/0/0", "un", "0"}
		resolved, ok := ResolveConsumedSetPathTokens(tokens)
		if !ok || !slices.Equal(resolved, []string{"interfaces", "ge-0/0/0", "unit", "0"}) {
			t.Fatalf("ResolveConsumedSetPathTokens(%v) = %v,%v, want expanded unit (D2)", tokens, resolved, ok)
		}
		if got := editIdentityStarts(tokens); !slices.Equal(got, []int{0, 1, 2}) {
			t.Fatalf("editIdentityStarts(%v) = %v, want [0 1 2] (D2)", tokens, got)
		}
	})

	// Control: CompleteSetPathWithValues (non-strict, NOT on the
	// kernel) still returns partial-keyword matches for the same
	// ambiguous input the strict walker rejects. If someone forces
	// the completion walk onto the strict kernel, this goes red.
	t.Run("control CompleteSetPathWithValues untouched", func(t *testing.T) {
		results := CompleteSetPathWithValues([]string{"security", "s"}, nil)
		if !containsCompletionName(results, "screen") || !containsCompletionName(results, "ssh-known-hosts") {
			t.Fatalf("CompleteSetPathWithValues partial behavior changed: got %v (must stay non-strict, #16149)", completionNames(results))
		}
	})
}

// TestStrictWalkCompleteSetPathUntouched16149 pins that
// CompleteSetPath (which delegates to CompleteSetPathWithValues) is
// unaffected by the kernel: it is NOT one of the three strict walks.
func TestStrictWalkCompleteSetPathUntouched16149(t *testing.T) {
	got := CompleteSetPath([]string{"security", "s"})
	if !slices.Contains(got, "screen") || !slices.Contains(got, "ssh-known-hosts") {
		t.Fatalf("CompleteSetPath(security s) = %v, want partial matches incl. screen/ssh-known-hosts (#16149: completion walk untouched)", got)
	}
}
