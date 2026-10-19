package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Issue 15003 (A04-02): the #12832 address-set graph gate enumerated every
// DAG path with no memo, and re-ran once per root set. With depth capped at
// 5 nested edges and breadth B per tier the gate cost grows as ~B^6 per
// compile, paid on commit, commit check (under the store read lock), boot
// load and SyncApply. expandAddrSetMode had the same un-memoised shape.
//
// THE REGRESSION IS TIMING-BOUNDED, NOT QUALITATIVE: pre-fix and post-fix
// return the same accept/reject answers on every graph below -- the only
// observable difference is wall-clock. A diamond lattice of breadth 20 at
// the maximum admitted depth validates in well under 1s with the memoised
// (max-depth-below-node) pass; without the memo it re-walks 20^5+ paths per
// root across 120 roots and cannot meet the budget. Removing either memo
// makes this test fail by timeout/over-budget, not by a wrong answer.

// buildAddrSetLattice15003 builds `breadth` sets at each of 6 tiers
// (t0..t5). Every tier-n set references every tier-(n+1) set via a
// cross-kind `address` member (the #12832 edge kind), and every tier-5 set
// references the one real address. The longest path is exactly 5 nested
// edges, so the whole book is admissible -- this is a legal config.
func buildAddrSetLattice15003(breadth int) *AddressBook {
	ab := &AddressBook{
		Addresses:   map[string]*Address{"leaf": {Name: "leaf", Value: "192.0.2.1/32"}},
		AddressSets: map[string]*AddressSet{},
	}
	name := func(tier, i int) string { return fmt.Sprintf("t%d_%d", tier, i) }
	for i := range breadth {
		ab.AddressSets[name(5, i)] = &AddressSet{Name: name(5, i), Addresses: []string{"leaf"}}
	}
	for tier := 4; tier >= 0; tier-- {
		for i := range breadth {
			members := make([]string, 0, breadth)
			for j := range breadth {
				members = append(members, name(tier+1, j))
			}
			ab.AddressSets[name(tier, i)] = &AddressSet{Name: name(tier, i), Addresses: members}
		}
	}
	return ab
}

func TestAddrSetGraphGateMemoised15003(t *testing.T) {
	const breadth = 20
	ab := buildAddrSetLattice15003(breadth)
	cfg := &Config{}
	cfg.Security.AddressBook = ab

	// Strict gate: validates every root. Budget is the issue acceptance
	// bound (B=20 compiles in under 1s); the memoised pass is O(sets).
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- validateAddressSetMembersDefinedStrict(cfg) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("strict validation rejected admissible lattice: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("strict address-set graph gate did not finish within 10s at breadth %d -- "+
			"path enumeration is not memoised (issue 15003)", breadth)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("strict address-set graph gate took %v at breadth %d; want < 1s (issue 15003 acceptance)",
			elapsed, breadth)
	} else {
		t.Logf("breadth-%d lattice strict-validated in %v", breadth, elapsed)
	}

	// Expansion: ID-graph and leaf modes share the same memoised walk.
	for _, tc := range []struct {
		name string
		fn   func() ([]string, error)
	}{
		{"id-graph", func() ([]string, error) { return ExpandAddressSet("t0_0", ab) }},
		{"leaves", func() ([]string, error) { return expandAddressSetLeaves("t0_0", ab) }},
	} {
		edone := make(chan struct{}, 1)
		var got []string
		var err error
		estart := time.Now()
		go func() {
			got, err = tc.fn()
			edone <- struct{}{}
		}()
		select {
		case <-edone:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s expansion did not finish within 10s at breadth %d -- "+
				"expandAddrSetMode is not memoised (issue 15003)", tc.name, breadth)
		}
		if err != nil {
			t.Fatalf("%s expansion failed: %v", tc.name, err)
		}
		if elapsed := time.Since(estart); elapsed > time.Second {
			t.Fatalf("%s expansion took %v at breadth %d; want < 1s", tc.name, elapsed, breadth)
		}
		// Both modes dedupe to tier-1 set names (id-graph) / the leaf.
		want := []string{"leaf"}
		if tc.name == "id-graph" {
			want = want[:0]
			for j := range breadth {
				want = append(want, fmt.Sprintf("t1_%d", j))
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s expansion = %v; want %v", tc.name, got, want)
		}
	}
}

// Memoised results must be identical to the pre-fix recursion: a shared
// child reached at different depths, error precedence, and the exact
// cycle/depth messages are unchanged.
func TestAddrSetMemoPreservesSemantics15003(t *testing.T) {
	// Depth depends on the reaching path: `deep` is 6 edges below `top`
	// (too deep) but only 1 edge below `shallow`. A name-only memo that
	// served the shallow success into the deep context would wrongly admit
	// the book; a name-only memo serving the deep failure into the shallow
	// context would wrongly reject it.
	mixed := &AddressBook{
		Addresses: map[string]*Address{"a0": {Name: "a0", Value: "192.0.2.1/32"}},
		AddressSets: map[string]*AddressSet{
			"top":     {Name: "top", AddressSets: []string{"c1", "deep"}},
			"c1":      {Name: "c1", AddressSets: []string{"c2"}},
			"c2":      {Name: "c2", AddressSets: []string{"c3"}},
			"c3":      {Name: "c3", AddressSets: []string{"c4"}},
			"c4":      {Name: "c4", AddressSets: []string{"deep"}},
			"deep":    {Name: "deep", AddressSets: []string{"bottom"}},
			"bottom":  {Name: "bottom", Addresses: []string{"a0"}},
			"shallow": {Name: "shallow", AddressSets: []string{"deep"}},
		},
	}
	// Sorted root order visits c-roots and deep/shallow before top; the
	// gate must still reject via top -> ... -> deep (6 edges to bottom).
	cfg := &Config{}
	cfg.Security.AddressBook = mixed
	err := validateAddressSetMembersDefinedStrict(cfg)
	if err == nil || !strings.Contains(err.Error(), "address-set nesting too deep (max 5): bottom") {
		t.Fatalf("strict validation error = %v; want depth error naming bottom", err)
	}

	// The shallow root alone is admissible and expands.
	if _, err := expandAddressSetLeaves("shallow", mixed); err != nil {
		t.Fatalf("shallow expansion rejected: %v", err)
	}
	if _, err := ExpandAddressSet("shallow", mixed); err != nil {
		t.Fatalf("shallow ID-graph expansion rejected: %v", err)
	}
	// Expanding from the long way round -- top -> c1..c4 -> deep -> bottom --
	// must fail with the same depth error even though `deep` was already
	// expanded successfully via `shallow` in an earlier call and (within
	// this call) `bottom` is first reached within budget via top -> deep.
	// Only a height-carrying memo gets both right.
	if _, err := expandAddressSetLeaves("top", mixed); err == nil ||
		!strings.Contains(err.Error(), "address-set nesting too deep (max 5): bottom") {
		t.Fatalf("top leaf expansion error = %v; want depth error naming bottom", err)
	}

	// Cycle message unchanged, reached through a shared (diamond) prefix so
	// the memo cannot mask it.
	cyc := &AddressBook{
		Addresses: map[string]*Address{},
		AddressSets: map[string]*AddressSet{
			"root": {Name: "root", AddressSets: []string{"a", "b"}},
			"a":    {Name: "a", AddressSets: []string{"spin"}},
			"b":    {Name: "b", AddressSets: []string{"spin"}},
			"spin": {Name: "spin", AddressSets: []string{"spin"}},
		},
	}
	cfg.Security.AddressBook = cyc
	err = validateAddressSetMembersDefinedStrict(cfg)
	if err == nil || !strings.Contains(err.Error(), `cycle detected in address-set "spin"`) {
		t.Fatalf("strict validation error = %v; want cycle error naming spin", err)
	}
	if _, err := ExpandAddressSet("root", cyc); err == nil ||
		!strings.Contains(err.Error(), `cycle detected in address-set "spin"`) {
		t.Fatalf("expansion error = %v; want cycle error naming spin", err)
	}
}

// naiveExpand15003 mirrors the pre-#15003 expansion WITHOUT a memo, so the
// differential cell below can prove the memoised curve replaced the naive
// recursion rather than asserting against a remembered number (the #8889
// pattern). Bodies are counted identically to addrSetExpandMemo15003.
func naiveExpand15003(
	memo *addrSetExpandMemo15003,
	name string,
	ab *AddressBook,
	visited map[string]bool,
	depth int,
	resolveCrossKind bool,
) ([]string, error) {
	as, err := addressSetForExpansion(name, ab, visited, depth)
	if err != nil {
		return nil, err
	}
	visited[name] = true
	defer delete(visited, name)
	memo.bodies++

	var result []string
	seen := make(map[string]bool)
	add := func(member string) {
		if !seen[member] {
			seen[member] = true
			result = append(result, member)
		}
	}
	for _, addrName := range as.Addresses {
		if resolveCrossKind {
			if _, isAddress := ab.Addresses[addrName]; !isAddress {
				if _, isSet := ab.AddressSets[addrName]; isSet {
					expanded, err := naiveExpand15003(memo, addrName, ab, visited, depth+1, true)
					if err != nil {
						return nil, err
					}
					for _, a := range expanded {
						add(a)
					}
					continue
				}
			}
		}
		add(addrName)
	}
	for _, setName := range as.AddressSets {
		expanded, err := naiveExpand15003(memo, setName, ab, visited, depth+1, resolveCrossKind)
		if err != nil {
			return nil, err
		}
		for _, a := range expanded {
			add(a)
		}
	}
	return result, nil
}

// THE CURVE: memoised expansion executes at most one body per set in the
// lattice; the naive recursion executes ~B^5. And CORRECTNESS BEFORE
// SPEED: memoised and naive results (and error texts) agree everywhere.
func TestAddrSetExpansionIsLinear15003(t *testing.T) {
	for _, breadth := range []int{2, 3} {
		ab := buildAddrSetLattice15003(breadth)
		memo := newAddrSetExpandMemo15003(ab)
		got, err := memo.expand("t0_0", 0, true, make(map[string]bool))
		if err != nil {
			t.Fatalf("breadth %d: memoised expansion failed: %v", breadth, err)
		}
		naiveMemo := &addrSetExpandMemo15003{ab: ab}
		want, err := naiveExpand15003(naiveMemo, "t0_0", ab, make(map[string]bool), 0, true)
		if err != nil {
			t.Fatalf("breadth %d: naive expansion failed: %v", breadth, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("breadth %d: memoised = %v; naive = %v", breadth, got, want)
		}
		sets := len(ab.AddressSets)
		if memo.bodies > sets {
			t.Fatalf("breadth %d: memoised bodies = %d; want <= %d sets", breadth, memo.bodies, sets)
		}
		if naiveMemo.bodies <= sets {
			t.Fatalf("breadth %d: naive bodies = %d; fixture does not exercise fan-out (sets=%d)",
				breadth, naiveMemo.bodies, sets)
		}
		t.Logf("breadth=%d sets=%d memoised-bodies=%d naive-bodies=%d",
			breadth, sets, memo.bodies, naiveMemo.bodies)
	}

	diff := func(t *testing.T, ab *AddressBook, root string) {
		t.Helper()
		for _, mode := range []bool{false, true} {
			memo := newAddrSetExpandMemo15003(ab)
			got, gerr := memo.expand(root, 0, mode, make(map[string]bool))
			naiveMemo := &addrSetExpandMemo15003{ab: ab}
			want, werr := naiveExpand15003(naiveMemo, root, ab, make(map[string]bool), 0, mode)
			if (gerr == nil) != (werr == nil) {
				t.Fatalf("mode=%v root=%s: memoised err=%v naive err=%v", mode, root, gerr, werr)
			}
			if gerr != nil && gerr.Error() != werr.Error() {
				t.Fatalf("mode=%v root=%s: memoised err=%q naive err=%q", mode, root, gerr, werr)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mode=%v root=%s: memoised=%v naive=%v", mode, root, got, want)
			}
		}
	}

	// From `r`, the first edge enters a breadth-2 lattice under its own
	// names (height 5; one more edge from r fits exactly); the second
	// enters the SAME subtree via a 1-edge detour (too deep for the second
	// entry). A name-only success memo would serve the first result into
	// the detour and wrongly admit `r`.
	tradeoff := &AddressBook{
		Addresses:   map[string]*Address{"leaf": {Name: "leaf", Value: "192.0.2.9/32"}},
		AddressSets: map[string]*AddressSet{},
	}
	lattice := buildAddrSetLattice15003(2)
	for name, set := range lattice.AddressSets {
		members := make([]string, len(set.Addresses))
		for i, a := range set.Addresses {
			members[i] = a
			if _, isSet := lattice.AddressSets[a]; isSet {
				members[i] = "L_" + a
			}
		}
		tradeoff.AddressSets["L_"+name] = &AddressSet{
			Name:        "L_" + name,
			Addresses:   members,
			AddressSets: prefixNames15003(set.AddressSets),
		}
	}
	tradeoff.AddressSets["r"] = &AddressSet{Name: "r", AddressSets: []string{"L_t0_0", "detour"}}
	tradeoff.AddressSets["detour"] = &AddressSet{Name: "detour", AddressSets: []string{"L_t0_0"}}
	diff(t, tradeoff, "r")

	// Cross-kind vs address-set edge mixes, including a shadowed set name.
	mixed := &AddressBook{
		Addresses: map[string]*Address{
			"a0": {Name: "a0", Value: "192.0.2.1/32"},
			"s":  {Name: "s", Value: "192.0.2.2/32"},
		},
		AddressSets: map[string]*AddressSet{
			"root": {Name: "root", Addresses: []string{"x", "s"}, AddressSets: []string{"x", "y"}},
			"x":    {Name: "x", Addresses: []string{"a0"}},
			"y":    {Name: "y", Addresses: []string{"x"}},
			"s":    {Name: "s", Addresses: []string{"a0"}},
		},
	}
	diff(t, mixed, "root")
}

func prefixNames15003(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "L_" + n
	}
	return out
}
