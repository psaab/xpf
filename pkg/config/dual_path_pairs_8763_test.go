package config

import (
	"sort"
	"strings"
	"testing"
)

// #8763: which ADMITTED (container, head) pairs are reachable BOTH below a
// `family` compound-key node and on a path crossing none.
//
// WHY THIS SET IS THE THING TO BIND. #8763's plan of record is "land the
// traversal with the compoundKey path admitting nothing". That is not
// expressible: `compactNormalizeInScope(kw, head)` is a pair predicate with no
// path context, so switching a pair off to hold the compound path shut also
// switches it off at every site that folds TODAY. The pairs where that trade
// exists are exactly the ones below, and enumerating them is the whole
// question — which is why it must not be a list somebody keeps by hand.
//
// It was kept by hand once and it was wrong in both directions. The list in
// circulation named five pairs; three of them (`dynamic-dns provider`,
// `dynamic-dns source-address`, `dynamic-dns ttl`) are genuinely dual-path but
// are NOT ADMITTED, so switching them off costs nothing and they were never
// part of the blocker; and four admitted dual-path pairs were missing from it
// (`then count`, `then log`, `version-ipfix template`, `version9 template`).
// A hand-kept population is wrong in the direction nobody checks: the members
// that are absent.
//
// THE DUAL-PATH PROPERTY IS A SCHEMA FACT, NOT AN INVENTORY FACT. The #2419
// inventory is a census of DIVERGENT SITES; a pair rule applies to the whole
// grammar, so "no other inventory line carries this head" answers a different
// question. This walks setSchema.
func TestDualPathAdmittedPairsAreTheMeasuredSix8763(t *testing.T) {
	underFam, noFam, paths := walkPairsByFamilyReach8763(setSchema)

	var dualAdmitted, dualUnadmitted, famOnlyAdmitted []string
	for pair := range underFam {
		kw, head, ok := splitPair8763(pair)
		if !ok {
			continue
		}
		admitted := compactNormalizeInScope(kw, head)
		switch {
		case noFam[pair] && admitted:
			dualAdmitted = append(dualAdmitted, pair)
		case noFam[pair]:
			dualUnadmitted = append(dualUnadmitted, pair)
		case admitted:
			famOnlyAdmitted = append(famOnlyAdmitted, pair)
		}
	}
	sort.Strings(dualAdmitted)
	sort.Strings(dualUnadmitted)

	// MEASURED at the real compoundKey shape (`family inet { … }`, one node)
	// with the traversal fix applied, each against its BRACED reference and
	// with the fold count recorded so an inert cell cannot pass as a verdict:
	//
	//	pair                     folds  elided(off) vs braced  elided(ON) vs braced
	//	from protocol              1     SAME                   SAME    reads-but-inert
	//	then count                 1     SAME                   SAME    reads-but-inert
	//	then log                   1     SAME                   SAME    reads-but-inert
	//	then loss-priority         1     SAME                   SAME    reads-but-inert
	//	version-ipfix template     1     DIFF                   SAME    clean recovery
	//	version9 template          1     DIFF                   SAME    clean recovery
	//
	// The first four are already read out of the packed tail by the firewall
	// filter compiler (packedBodyChildren), so the fold fires and changes
	// nothing. The last two are a genuine #8755-class silent drop under
	// `family inet` that the fold repairs exactly.
	//
	// All six are BENIGN at the family shape, so the blocker dissolves and no
	// path context is needed. If this list changes, that conclusion does not
	// carry to the new member and the measurement has to be retaken.
	want := []string{
		"from protocol",
		"then count",
		"then log",
		"then loss-priority",
		"version-ipfix template",
		"version9 template",
	}
	if strings.Join(dualAdmitted, "\n") != strings.Join(want, "\n") {
		t.Errorf("the DUAL-PATH ADMITTED pair set has moved.\n got: %v\nwant: %v\n\n"+
			"Each of these pairs folds at a site with no `family` ancestor TODAY and would "+
			"also fold below `family` once #8763's traversal lands. A pair predicate cannot "+
			"tell the two apart, so a new member needs the family-shape measurement (elided vs "+
			"BRACED reference, with the fold count, at `family inet { … }`) before the traversal "+
			"is widened -- do not delete it from this list to make the cell green (#8763).",
			dualAdmitted, want)
	}

	t.Logf("#8763 dual-path ADMITTED (the blocker set): %v", dualAdmitted)
	for _, p := range dualAdmitted {
		t.Logf("    %-24s %v", p, paths[p])
	}
	// Recorded, not asserted: dual-path but NOT admitted. These fold nothing
	// today, so excluding them under the compound path costs nothing -- the
	// three `dynamic-dns` pairs the circulated list named are all here.
	t.Logf("#8763 dual-path but NOT admitted (excluding these costs nothing today): %v", dualUnadmitted)

	// THE BOUNDARY OF WHAT WAS MEASURED, stated so it is not read as covered.
	// These pairs are admitted and sit ONLY below a `family`, so they fold
	// nothing today and go live the moment the traversal lands. They are NOT
	// covered by the six-pair measurement above; lane-8015's spot-check named
	// several of them (firewall filter match/action leaves, VRRP
	// authentication) and they remain separate work.
	t.Logf("#8763 admitted and FAMILY-ONLY -- goes live with the traversal, NOT measured here: %d pairs",
		len(famOnlyAdmitted))
	if len(famOnlyAdmitted) == 0 {
		t.Errorf("no admitted family-only pairs found: the walk is not reaching below `family` at all, " +
			"so the dual-path split above is measuring nothing (#8763)")
	}
}

// walkPairsByFamilyReach8763 returns, for every (container, head) pair the
// grammar offers, whether it is reachable with a compoundKey ancestor
// (underFam) and whether it is reachable without one (noFam).
//
// The visited set is keyed on (node, crossed) rather than on node alone. A
// shared subtree -- `routing-instances <n> protocols ospf` re-hosting the same
// schema the top-level `protocols` uses -- is reached under both conditions,
// and a node-only key would record whichever arrived first and silently drop
// the other. That is the defect this whole issue is about, one level up.
func walkPairsByFamilyReach8763(root *schemaNode) (underFam, noFam map[string]bool, paths map[string][]string) {
	underFam, noFam, paths = map[string]bool{}, map[string]bool{}, map[string][]string{}
	type key struct {
		n       *schemaNode
		crossed bool
	}
	seen := map[key]bool{}

	var walk func(n *schemaNode, crossed bool, path []string)
	walk = func(n *schemaNode, crossed bool, path []string) {
		if n == nil || seen[key{n, crossed}] {
			return
		}
		seen[key{n, crossed}] = true
		for kw, c := range n.children {
			if c == nil {
				continue
			}
			for head := range c.children {
				pair := kw + " " + head
				tag := "no-family: "
				if crossed {
					underFam[pair] = true
					tag = "under-family: "
				} else {
					noFam[pair] = true
				}
				p := tag + strings.Join(append(append([]string(nil), path...), kw, head), " ")
				if !contains8763(paths[pair], p) {
					paths[pair] = append(paths[pair], p)
					sort.Strings(paths[pair])
				}
			}
			next := crossed || c.compoundKey
			walk(c, next, append(append([]string(nil), path...), kw))
			walk(c.wildcard, next, append(append([]string(nil), path...), kw, "*"))
		}
		walk(n.wildcard, crossed, append(append([]string(nil), path...), "*"))
	}
	walk(root, false, nil)
	return underFam, noFam, paths
}

func splitPair8763(pair string) (kw, head string, ok bool) {
	i := strings.IndexByte(pair, ' ')
	if i <= 0 || i == len(pair)-1 {
		return "", "", false
	}
	return pair[:i], pair[i+1:], true
}

func contains8763(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// The walk's own arithmetic, exercised against a SYNTHETIC schema.
//
// Every branch that matters here -- the compoundKey flag setting `crossed`, the
// (node, crossed) visit key, the dual/family-only/no-family split -- is
// unreachable in the live walk's failure direction: production has exactly
// seven compoundKey nodes and they are all named `family`, so a mutation that
// broke the propagation would still produce a plausible-looking set. A guard's
// arithmetic cannot be tested against data that never reaches the branch, which
// is why this builds inputs that do.
func TestFamilyReachWalkSeparatesTheThreeClasses8763(t *testing.T) {
	leaf := func() *schemaNode { return &schemaNode{} }
	// dualHost offers (c, h) with no family above it; famHost offers the same
	// pair below one. shared is reached BOTH ways, which is the case a
	// node-only visit key loses.
	shared := &schemaNode{children: map[string]*schemaNode{
		"c": {children: map[string]*schemaNode{"h": leaf()}},
	}}
	famOnly := &schemaNode{children: map[string]*schemaNode{
		"f": {children: map[string]*schemaNode{"g": leaf()}},
	}}
	root := &schemaNode{children: map[string]*schemaNode{
		"plain": shared,
		"family": {compoundKey: true, children: map[string]*schemaNode{
			"inet": {children: map[string]*schemaNode{
				"viaFamily": shared,
				"only":      famOnly,
			}},
		}},
	}}
	underFam, noFam, _ := walkPairsByFamilyReach8763(root)

	for _, tc := range []struct {
		pair              string
		wantUnder, wantNo bool
		why               string
	}{
		{"c h", true, true, "reached through `plain` AND through `family inet`: DUAL"},
		{"f g", true, false, "reached only under `family inet`: FAMILY-ONLY"},
		{"plain c", false, true, "container above the family node: NO-FAMILY"},
		{"family inet", false, true, "the compound node's own pair sits ABOVE the descent"},
		{"inet only", true, false, "the compound sub-key's children are already under the family"},
	} {
		if underFam[tc.pair] != tc.wantUnder || noFam[tc.pair] != tc.wantNo {
			t.Errorf("pair %q: under-family=%v no-family=%v, want %v/%v (%s)",
				tc.pair, underFam[tc.pair], noFam[tc.pair], tc.wantUnder, tc.wantNo, tc.why)
		}
	}
	if underFam["c h"] && noFam["c h"] {
		t.Logf("shared subtree recorded under BOTH conditions -- the (node, crossed) visit key holds")
	}
}
