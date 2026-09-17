package config

import (
	"sort"
	"strings"
	"testing"
)

// #8436 — the CONSERVATION census.
//
// The compiler has no single rule for duplicate named blocks in the
// hierarchical AST. Each call site picks its own reduction, and SIX different
// dispositions have been measured (append both / first-wins / last-wins whole /
// last-wins per field / find-or-create merge / last-wins with per-field wipe).
// Every instance so far has been closed by adding a `namedDupRules` row or a
// bespoke gate — #3884, #4287, #5180, #5631/#5878, #5649, #8426, #8427, #8433 —
// and that is an OPT-IN pattern whose opt-ins are discovered one review at a
// time. A registry-row test proves the row exists; it cannot see the next
// uncovered container, and the uncovered set is not written down anywhere.
//
// This census writes it down. The property it binds is CONSERVATION:
//
//	<kw> NAME { A; }  <kw> NAME { B; }      (two hierarchical blocks)
//	                 ==
//	<kw> NAME { A; B; }                     (what flat-set `set` produces)
//
// Flat-set merges correctly in every measured case, so the merged form is the
// reference. Where the duplicate form does not equal it, configuration the
// operator authored is silently lost — reachable through a hierarchical config
// file, `load merge` or `load override`, though NOT through `set`.
//
// A divergent site is not automatically a bug to fix here; several are already
// REJECTED at commit by namedDupRules, which is conservation achieved by
// refusal rather than by merging. What the census supplies is the enumeration,
// so the next fix is chosen from a list rather than discovered.

type dupSite8436 struct {
	container []string // token path to the enclosing container
	keyword   string   // the named-container keyword
	node      *schemaNode
	leafA     string // first distinct leaf child
	valA      string
	leafB     string // second distinct leaf child
	valB      string
	// #9024: complete STATEMENTS, which may be nested. A container whose
	// children are all containers (`forwarding-options sampling instance`,
	// whose only children are `input` and `family`) has no scalar leaf to put
	// in a two-leaf fixture, and used to leave the population before any
	// verdict was formed -- which is how the census reported "SILENT: 0" while
	// two proven silent drops sat inside it. These carry `input { rate 100; }`
	// where the leaf fields carried `rate` and `100`.
	stmtA string
	stmtB string
	// unprobeable is non-empty when the container is ELIGIBLE (a named
	// container with children) but no two-block fixture can be built for it.
	//
	// Issue 9024: these used to be dropped by the collector, before the
	// census ever saw them -- so they landed in NEITHER the population nor
	// the named skip list, and the skip ratchet could not guard them because
	// the ratchet guards the population and the population was filtered first.
	// Measured at the time: 85 of 139 eligible containers, 61%, invisible.
	// Among them `forwarding-options sampling instance`, `security policies
	// from-zone` and both `security nat ... rule-set` containers.
	unprobeable string
}

// collectDupSites8436 finds every NAMED container (args >= 1, has children)
// that carries at least two distinct value leaves, which is what a conservation
// probe needs: one leaf per block, so a reduction that drops a block is visible.
func collectDupSites8436() []dupSite8436 {
	var out []dupSite8436
	seen := map[string]bool{}
	var walk func(n *schemaNode, path []string, depth int)
	walk = func(n *schemaNode, path []string, depth int) {
		if n == nil || depth > 5 {
			return
		}
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ch := n.children[name]
			if ch == nil {
				continue
			}
			if ch.args >= 1 && ch.children != nil && len(path) >= 1 {
				key := strings.Join(path, "/") + "|" + name
				if !seen[key] {
					seen[key] = true
					la, va, lb, vb, ok := twoLeaves8436(ch)
					site := dupSite8436{
						container: append([]string(nil), path...),
						keyword:   name, node: ch,
						leafA: la, valA: va, leafB: lb, valB: vb,
					}
					if ok {
						site.stmtA = la + " " + va + ";"
						site.stmtB = lb + " " + vb + ";"
					} else if sa, sb, ok2 := twoStatements8436(ch); ok2 {
						// #9024: no two DIRECT scalar leaves, but a nested
						// fixture reaches one. This is the container-only case
						// the census used to drop.
						site.stmtA, site.stmtB, ok = sa, sb, true
					}
					if !ok {
						// Issue 9024: record WHY rather than dropping it. The
						// two reasons are different facts: a container whose
						// children are all containers has no scalar pair to
						// write twice, while one with too few synthesizable
						// leaves might gain one when the schema grows.
						site.unprobeable = "no two synthesizable single-value leaf children"
						allContainers := len(ch.children) > 0
						for _, g := range ch.children {
							if g == nil || g.children == nil {
								allContainers = false
							}
						}
						if allContainers {
							site.unprobeable = "container-only children (no scalar leaf to duplicate)"
						}
					}
					out = append(out, site)
				}
			}
			elem := name
			for i := 0; i < ch.args; i++ {
				elem += " xpfname"
			}
			walk(ch, append(append([]string(nil), path...), elem), depth+1)
		}
	}
	walk(setSchema, nil, 0)
	sort.Slice(out, func(i, j int) bool {
		a := strings.Join(out[i].container, " ") + " " + out[i].keyword
		b := strings.Join(out[j].container, " ") + " " + out[j].keyword
		return a < b
	})
	return out
}

// twoLeaves8436 picks two DISTINCT single-value leaf children and a value for
// each. Two different leaves, not two values of one leaf: a multi-value leaf
// legitimately accumulates, so using one would measure the leaf's own list
// semantics rather than the BLOCK's reduction.
// nestedStatement8436 returns a complete Junos STATEMENT that reaches a scalar
// leaf under c, descending through container-only children, or ok=false.
//
// #9024: THE CENSUS SKIPPED EVERY CONTAINER-ONLY CHILD, AND THAT IS EXACTLY THE
// CASE THAT NEEDS A NESTED FIXTURE RATHER THAN A SKIP. `forwarding-options
// sampling instance` has no scalar leaf children at all -- only the containers
// `input` and `family` -- so no two-leaf fixture could be built and the site
// left the population before any verdict was formed. It was a CONFIRMED silent
// drop at the time (#9023), and the census reported "SILENT: 0".
//
// Descending is bounded and deterministic: sorted names, first scalar leaf wins,
// depth capped. The cap is a guard against a cyclic schema (`groups` mirrors the
// top-level children), not an expected limit.
func nestedStatement8436(c *schemaNode, depth int) (stmt string, ok bool) {
	if c == nil || depth > 6 {
		return "", false
	}
	names := make([]string, 0, len(c.children))
	for name := range c.children {
		names = append(names, name)
	}
	sort.Strings(names)

	// A scalar leaf directly here is always preferred: the shallower the
	// fixture, the fewer unrelated validators it can trip.
	for _, name := range names {
		ch := c.children[name]
		if ch == nil || ch.children != nil || ch.wildcard != nil || ch.args != 1 || ch.multi {
			continue
		}
		if v, _, got := synthPair(ch); got {
			return name + " " + v + ";", true
		}
	}
	// Otherwise descend into the first container child that yields one.
	for _, name := range names {
		ch := c.children[name]
		if ch == nil || ch.children == nil {
			continue
		}
		inner, got := nestedStatement8436(ch, depth+1)
		if !got {
			continue
		}
		head := name
		if ch.args == 1 {
			// A named container needs an instance name before its body.
			head = name + " xpfinner"
		}
		return head + " { " + inner + " }", true
	}
	return "", false
}

// twoStatements8436 returns two statements under DISTINCT children of c, so a
// duplicate-block fixture can put one in each block and both in the merged one.
//
// It supersedes twoLeaves8436, which required two DIRECT scalar leaves and
// therefore could not fixture a container whose children are all containers.
func twoStatements8436(c *schemaNode) (stmtA, stmtB string, ok bool) {
	names := make([]string, 0, len(c.children))
	for name := range c.children {
		names = append(names, name)
	}
	sort.Strings(names)
	var got []string
	for _, name := range names {
		ch := c.children[name]
		if ch == nil {
			continue
		}
		if ch.children == nil && ch.wildcard == nil && ch.args == 1 && !ch.multi {
			if v, _, ok2 := synthPair(ch); ok2 {
				got = append(got, name+" "+v+";")
			}
		} else if ch.children != nil {
			if inner, ok2 := nestedStatement8436(ch, 1); ok2 {
				head := name
				if ch.args == 1 {
					head = name + " xpfinner"
				}
				got = append(got, head+" { "+inner+" }")
			}
		}
		if len(got) == 2 {
			return got[0], got[1], true
		}
	}
	return "", "", false
}

func twoLeaves8436(c *schemaNode) (leafA, valA, leafB, valB string, ok bool) {
	names := make([]string, 0, len(c.children))
	for name := range c.children {
		names = append(names, name)
	}
	sort.Strings(names)
	var picked []string
	var vals []string
	for _, name := range names {
		ch := c.children[name]
		if ch == nil || ch.children != nil || ch.wildcard != nil || ch.args != 1 || ch.multi {
			continue
		}
		v, _, got := synthPair(ch)
		if !got {
			continue
		}
		picked = append(picked, name)
		vals = append(vals, v)
		if len(picked) == 2 {
			return picked[0], vals[0], picked[1], vals[1], true
		}
	}
	return "", "", "", "", false
}

type dupCensusResult8436 struct {
	checked   int
	divergent []string
	verdict   map[string]string // siteKey -> "SILENT" | "rejected-at-commit"
	skipped   map[string]int
	// skippedSites is every site the census could not CHECK, by key. Pinned
	// (dupConservationSkipped8436) for the same reason the non-conserving list
	// is: a skip is not a pass. `services rpm probe xpfname test` sat in a skip
	// COUNT for seven batches while silently losing configuration — a number
	// cannot be read as a defect, and a named set can.
	skippedSites []string
}

func runDupConservationCensus8436(t *testing.T) dupCensusResult8436 {
	t.Helper()
	res := dupCensusResult8436{skipped: map[string]int{}, verdict: map[string]string{}}
	for _, s := range collectDupSites8436() {
		siteKey := strings.Join(s.container, " ") + " " + s.keyword
		if strings.HasPrefix(s.container[0], "groups") {
			res.skipped["under groups (schema re-host, duplicate coverage)"]++
			continue
		}
		note := func(reason string) {
			res.skipped[reason]++
			res.skippedSites = append(res.skippedSites, siteKey)
		}
		// Issue 9024: an eligible container the collector could not build a
		// fixture for is a RECORDED skip, not an absence. Before this it left
		// the census upstream of every bucket, so "SILENT: 0" was a statement
		// about 9 containers while 139 were eligible.
		if s.unprobeable != "" {
			note(s.unprobeable)
			continue
		}
		named := s.keyword + " xpfname"
		stmtA, stmtB := s.stmtA, s.stmtB
		if siteKey == "chassis cluster redundancy-group" {
			// #10002: chassis RG and per-RG node identities are numeric.
			// The generic census name (`xpfname`) used to be accepted only
			// because Atoi failures defaulted to zero; use valid identities
			// here so the conservation probe still exercises this container
			// instead of becoming an unprobeable malformed fixture.
			named = s.keyword + " 1"
			stmtA = strings.ReplaceAll(stmtA, "node xpfinner", "node 0")
			stmtB = strings.ReplaceAll(stmtB, "node xpfinner", "node 0")
		}
		ctx := contextFor(s.container)
		dup := nest(s.container, ctx+
			named+" { "+stmtA+" } "+
			named+" { "+stmtB+" }")
		merged := nest(s.container, ctx+
			named+" { "+stmtA+" "+stmtB+" }")

		cd, cm := compileText(t, dup), compileText(t, merged)
		if cd == nil || cm == nil {
			note("a spelling did not parse or compile")
			continue
		}
		// VACUITY GUARD. If the MERGED form compiles the same as a block
		// carrying only leafA, then leafB is not observable in the typed config
		// and this site cannot show a loss either way.
		onlyA := compileText(t, nest(s.container, ctx+named+" { "+stmtA+" }"))
		if onlyA == nil || cfgEqual(cm, onlyA) {
			note("second leaf not observable in the typed config")
			continue
		}
		res.checked++
		if !cfgEqual(cd, cm) {
			// Does STRICT commit already refuse the duplicate? That is
			// conservation by refusal (namedDupRules or a bespoke gate) and it
			// is a different disposition from a silent loss. The census
			// compiles LENIENTLY above so it can see the reduction either way;
			// this second compile is what tells the two apart, and it is the
			// column that decides which sites are candidates for the next fix.
			verdict := "SILENT"
			if tree, perrs := NewParser(dup).Parse(); len(perrs) == 0 {
				if _, err := CompileConfig(tree); err != nil {
					verdict = "rejected-at-commit"
				}
			}
			res.divergent = append(res.divergent, siteKey)
			res.verdict[siteKey] = verdict
		}
	}
	sort.Strings(res.divergent)
	return res
}

// TestDuplicateBlockConservationCensus8436 reports the enumeration #8436 asks
// for. It is a REPORT, not a gate: a divergent site may already be rejected at
// commit by namedDupRules (conservation by refusal), and the census compiles
// leniently so it sees the reduction rather than the rejection.
func TestDuplicateBlockConservationCensus8436(t *testing.T) {
	res := runDupConservationCensus8436(t)
	t.Logf("#8436 duplicate-block conservation census")
	t.Logf("  named containers CHECKED (vacuity-guarded): %d", res.checked)
	t.Logf("  containers that DO NOT conserve:            %d", len(res.divergent))
	keys := make([]string, 0, len(res.skipped))
	for k := range res.skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  SKIPPED — %-52s %d", k, res.skipped[k])
	}
	silent := 0
	for _, d := range res.divergent {
		if res.verdict[d] == "SILENT" {
			silent++
		}
		t.Logf("    NOT CONSERVED [%-18s] %s", res.verdict[d], d)
	}
	t.Logf("  of those, SILENT (no commit gate at all):    %d", silent)
	// Issue 9024: print the DENOMINATOR beside the verdict. "SILENT: 0" over a
	// population of 9 reads identically to "SILENT: 0" over a population of
	// 139, and the difference is the whole finding.
	t.Logf("  ...over a CHECKED population of %d; %d eligible containers are UNPROBED and named in dupConservationSkipped8436",
		len(res.verdict), len(res.skippedSites))
	if res.checked < 20 {
		t.Fatalf("only %d containers checked — the walk is not reaching the schema, "+
			"and a census that inspects nothing reports a clean sheet", res.checked)
	}
}

// TestDuplicateBlockConservationIsPinned8436 is the anti-drift half: the set of
// non-conserving containers is PINNED, so a new container added to setSchema
// that silently loses configuration on a duplicate shows up as a diff rather
// than waiting for a review to find it.
func TestDuplicateBlockConservationIsPinned8436(t *testing.T) {
	res := runDupConservationCensus8436(t)
	got := map[string]bool{}
	for _, d := range res.divergent {
		got[d] = true
	}
	want := map[string]bool{}
	for _, d := range dupConservationInventory8436 {
		want[d] = true
	}
	var added, removed []string
	for d := range got {
		if !want[d] {
			added = append(added, d)
		}
	}
	for d := range want {
		if !got[d] {
			removed = append(removed, d)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	for _, d := range added {
		t.Errorf("NEW non-conserving container %q — a duplicate hierarchical block here "+
			"silently loses what the flat-set spelling would have merged. Either add a "+
			"namedDupRules row (conservation by refusal), make the compile merge, or add "+
			"this line to dupConservationInventory8436 with a reason (#8436)", d)
	}
	for _, d := range removed {
		t.Errorf("container %q now CONSERVES but is still listed in "+
			"dupConservationInventory8436 — delete the line; a stale entry hides the next "+
			"regression at that site (#8436)", d)
	}

	// #8436: THE SKIP SET IS PINNED TOO, and it is the half that was missing.
	//
	// A site the census cannot CHECK is not a site that conserves. `services
	// rpm probe xpfname test` sat in the "a spelling did not parse or compile"
	// count for seven batches — the synthesized probe omits the required
	// `target` — while being a genuine SILENT loss: two `test T` blocks
	// overwrote each other. The census reported it as a number, and a number
	// cannot be read as a defect.
	//
	// A NEW skip now fails exactly as a new non-conserving container does, and
	// a stale skip fails too. That makes "the census could not probe this" a
	// decision someone records rather than the one place a defect can hide from
	// the guard #8436 asked for.
	gotSkip := map[string]bool{}
	for _, k := range res.skippedSites {
		gotSkip[k] = true
	}
	wantSkip := map[string]bool{}
	for _, k := range dupConservationSkipped8436 {
		wantSkip[k] = true
	}
	var newSkip, goneSkip []string
	for k := range gotSkip {
		if !wantSkip[k] {
			newSkip = append(newSkip, k)
		}
	}
	for k := range wantSkip {
		if !gotSkip[k] {
			goneSkip = append(goneSkip, k)
		}
	}
	sort.Strings(newSkip)
	sort.Strings(goneSkip)
	for _, k := range newSkip {
		t.Errorf("NEW unprobed container %q — the census could not build a duplicate "+
			"fixture for it, so it is neither checked nor listed. That is where a silent "+
			"reduction hides (it is where `services rpm probe xpfname test` hid). Fix the "+
			"fixture so the site is CHECKED, or add this line to "+
			"dupConservationSkipped8436 with the reason it cannot be (#8436)", k)
	}
	for _, k := range goneSkip {
		t.Errorf("container %q is no longer skipped but is still listed in "+
			"dupConservationSkipped8436 — delete the line; a stale skip entry claims the "+
			"census cannot see a site it now checks (#8436)", k)
	}
}
