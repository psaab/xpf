package config

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// #8921: a keyword-keyed admission is live at EVERY site where a container of
// that keyword declares that head, and every one of them was adjudicated by
// measuring a single fixture at a single site.
//
// This is #8921's item 3 -- the cheapest of its three asks and the one that
// stops the population growing while the other two are open. It makes a new
// multi-site admission impossible to land silently. It does not itself
// adjudicate anything: every cell it records is adjudicated by
// multisite_adjudication_8921_test.go (item 2), and docs/config-schema.md
// records why that settles item 1 without parent-qualifying the predicate.
//
// WHY THAT IS THE USEFUL BOUNDARY. Items 1 and 2 are large: parent-qualifying
// means giving the predicate context it does not have and adding a parent term
// to every scope entry; adjudicating 163 pairs at every declaring site is 163
// fixtures nobody has built. Both are honest costs of a keyword-keyed
// predicate. Neither is a reason to let the debt keep growing in the meantime,
// and a ratchet is the difference between a known debt and an unknown one.
//
// THE FAILURE THIS PREVENTS IS NOT HYPOTHETICAL. #8933 admitted eight
// `then <action>` pairs. `then` has 14 container sites. Nothing collided only
// because the firewall `then` happens to declare none of those eight names --
// safe by coincidence of naming, not by construction. That collision check was
// done by hand because someone remembered to; this cell is that check as a
// mechanism.

// multisitePath8921 is the recorded population.
const multisitePath8921 = "testdata/multisite_admissions_8921.txt"

// multisiteRegistry8921 reads the registry as pair -> SITE PATHS.
//
// IT USED TO STORE A COUNT, AND THAT WAS A REAL BLIND SPOT rather than a
// tidiness question. #8921 exists to record WHICH schema sites an admission is
// effective at -- the whole finding is that a pair adjudicated at one site is
// live at every site declaring that keyword. A count cannot see a
// SUBSTITUTION: a pair that loses one declaring site and gains another holds
// its count, and the ratchet says nothing, while the thing the issue is about
// has changed completely.
//
// lane-8388 found this shape in two of their own ratchets on the same day and
// asked whether mine had it. It did. Their sentence is the general form:
//
//	A ratchet keyed on a COUNT cannot see a SUBSTITUTION, and the direction
//	that looks like nothing happened is the one nobody audits.
//
// The membership form costs one comma-joined field and reports the swap by
// name. It also makes the registry self-documenting: a reader can see where an
// admission lands without re-running the walk.
func multisiteRegistry8921(t *testing.T) map[string][]string {
	t.Helper()
	f, err := os.Open(multisitePath8921)
	if err != nil {
		t.Fatalf("cannot read the #8921 registry: %v -- this cell is blind without it", err)
	}
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("malformed registry row %q", line)
		}
		siteList := strings.Split(parts[1], ",")
		sort.Strings(siteList)
		out[parts[0]] = siteList
	}
	return out
}

// sameSites8921 compares two site lists as SETS.
func sameSites8921(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// admittedDeclaringSites8921 walks the schema and, for every admitted
// (container keyword, head) pair, records the paths where a container of that
// keyword DECLARES that head.
//
// Descends into `wildcard` nodes, because an earlier version of the #8880
// walk silently missed pairs reachable only through an instance slot -- but
// records NOTHING at the slot itself. A statement directly under a wildcard
// slot has the operator's INSTANCE NAME in Keys[0], and normalizeCompactNodes
// asks the predicate with Keys[0], so no (keyword, head) pair is ever
// consulted there. This walk used to carry the parent's keyword into the slot
// and so recorded `interfaces unit` as live at `interfaces/*`; measured, the
// fold does not fire on `interfaces { ge-0/0/0 unit 0; }`, and the #2419 census
// rules that site divergent for exactly that reason. The pair was live at one
// site, not two.
//
// EXCLUDES `groups`, which mirrors the whole schema. Including it makes every
// admitted pair multi-site by construction -- measured at 575 of 575 -- and
// erases the distinction this cell exists to draw.
func admittedDeclaringSites8921() map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	var walk func(path, kw string, n *schemaNode)
	walk = func(path, kw string, n *schemaNode) {
		if n == nil || seen[path] {
			return
		}
		seen[path] = true
		for name, c := range n.children {
			if c == nil {
				continue
			}
			if kw != "" && compactNormalizeInScope(kw, name) {
				key := kw + " " + name
				out[key] = append(out[key], path)
			}
			walk(path+"/"+name, name, c)
		}
		if n.wildcard != nil {
			walk(path+"/*", "", n.wildcard)
		}
	}
	for k, c := range setSchema.children {
		if k == "groups" {
			continue
		}
		walk(k, k, c)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// SCOPE, so a reader does not mistake this for a gap: this walks ADMITTED PAIRS
// -- entries in `compactNormalizeInScope`, which is keyed on (container, head)
// and therefore reaches every container sharing that keyword. A
// `packedStatements` opt-in is declared on a single schemaNode and cannot leak
// to a same-named neighbour, so it is outside this population BY CONSTRUCTION
// rather than by omission. See docs/config-schema.md.
func TestMultisiteAdmissionsAreRecorded8921(t *testing.T) {
	reg := multisiteRegistry8921(t)
	if len(reg) == 0 {
		t.Fatal("NON-VACUITY: the registry parsed to zero rows, so every comparison " +
			"below passes by having nothing to compare")
	}

	sites := admittedDeclaringSites8921()
	measured := map[string][]string{}
	for pair, paths := range sites {
		if len(paths) > 1 {
			cp := append([]string{}, paths...)
			sort.Strings(cp)
			measured[pair] = cp
		}
	}
	if len(measured) == 0 {
		t.Fatal("NON-VACUITY: the walk found NO multi-site admission at all. Either " +
			"the traversal broke or the predicate stopped admitting anything; " +
			"either way this cell is reporting agreement it did not check")
	}

	// REGENERATION. The registry moved from counts to site lists (#9094) and
	// 210 rows cannot be hand-migrated. This writes the CURRENT measurement,
	// so it must never be run to make a failure go away -- the error text
	// below says what to check first.
	if os.Getenv("UPDATE_8921") != "" {
		var keys []string
		for k := range measured {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("# #8921: admitted brace-elision pairs that are EFFECTIVE AT MORE THAN ONE\n")
		b.WriteString("# declaring schema site, and WHERE.\n")
		b.WriteString("#\n")
		b.WriteString("# Site LISTS, not counts (#9094): a count cannot see a SUBSTITUTION -- a\n")
		b.WriteString("# pair that loses one declaring site and gains another holds its count\n")
		b.WriteString("# while the thing this issue is about has changed completely.\n")
		b.WriteString("#\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "%s\t%s\n", k, strings.Join(measured[k], ","))
		}
		if err := os.WriteFile(multisitePath8921, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s with %d multi-site pairs", multisitePath8921, len(keys))
		return
	}

	var added, removed, changed []string
	for pair, now := range measured {
		was, ok := reg[pair]
		if !ok {
			added = append(added, fmt.Sprintf("%s (live at %d sites: %s)",
				pair, len(now), strings.Join(now, ", ")))
			continue
		}
		if sameSites8921(was, now) {
			continue
		}
		// Name the SITES that moved, not just the counts. A substitution --
		// same count, different sites -- is invisible to a count and is the
		// reason this compares membership.
		var gained, lost []string
		inWas := map[string]bool{}
		for _, x := range was {
			inWas[x] = true
		}
		inNow := map[string]bool{}
		for _, x := range now {
			inNow[x] = true
		}
		for _, x := range now {
			if !inWas[x] {
				gained = append(gained, x)
			}
		}
		for _, x := range was {
			if !inNow[x] {
				lost = append(lost, x)
			}
		}
		desc := fmt.Sprintf("%s: %d -> %d site(s)", pair, len(was), len(now))
		if len(was) == len(now) {
			desc = fmt.Sprintf("%s: SUBSTITUTION (still %d sites, different ones)",
				pair, len(now))
		}
		if len(gained) > 0 {
			desc += "\n      + " + strings.Join(gained, "\n      + ")
		}
		if len(lost) > 0 {
			desc += "\n      - " + strings.Join(lost, "\n      - ")
		}
		changed = append(changed, desc)
	}
	for pair, was := range reg {
		if _, ok := measured[pair]; !ok {
			removed = append(removed, fmt.Sprintf("%s (was %d sites: %s)",
				pair, len(was), strings.Join(was, ", ")))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	if len(added) > 0 {
		t.Errorf("#8921: %d admission(s) are effective at MORE THAN ONE declaring "+
			"site and are not recorded:\n  %s\n\n"+
			"The scope predicate is keyed on (container keyword, head) with no "+
			"parent context, so this admission is live everywhere a container of "+
			"that keyword declares that head -- including sites nobody measured a "+
			"fixture at. #8933 admitted eight `then <action>` pairs against 14 "+
			"`then` containers and collided with none only because the firewall "+
			"`then` declares none of those names: safe by coincidence of naming, "+
			"not by construction.\n\n"+
			"WALK THE SCHEMA AND CHECK EVERY LISTED SITE before adding a row. "+
			"Adding it without looking records the debt instead of paying it, "+
			"which is what #8921 exists to stop.",
			len(added), strings.Join(added, "\n  "))
	}
	if len(changed) > 0 {
		t.Errorf("#8921: %d recorded admission(s) changed their declaring-site "+
			"count:\n  %s\n\n"+
			"A count that GREW means the schema now declares that head somewhere "+
			"new and the admission followed it there silently. A count that SHRANK "+
			"means a declaring site disappeared. Neither is wrong on its own; both "+
			"mean the adjudication behind this row no longer covers what the row "+
			"describes.",
			len(changed), strings.Join(changed, "\n  "))
	}
	if len(removed) > 0 {
		t.Errorf("#8921: %d recorded admission(s) are no longer multi-site:\n  %s\n\n"+
			"This is the direction that looks like progress and can be either. It "+
			"is progress if an admission was narrowed or a duplicate declaration "+
			"removed. It is a BLIND SPOT if the walk stopped reaching a site -- the "+
			"#8880 ratchet's traversal silently missed pairs reachable only through "+
			"an instance slot until that was found. Confirm which before deleting "+
			"the row; a shrinking ratchet nobody checks is how a census goes quiet.",
			len(removed), strings.Join(removed, "\n  "))
	}
}

// The registry is only meaningful if the walk is stable. Go randomises map
// iteration, and the #8880 census recorded a per-pair property that drifted
// between runs on one unchanged tree for exactly that reason.
func TestMultisiteWalkIsStableAcrossRuns8921(t *testing.T) {
	first := admittedDeclaringSites8921()
	for run := 1; run < 3; run++ {
		next := admittedDeclaringSites8921()
		if len(next) != len(first) {
			t.Fatalf("run %d found %d admitted pairs, run 0 found %d -- the walk is "+
				"not deterministic and every count derived from it is a sample",
				run, len(next), len(first))
		}
		for pair, paths := range first {
			got := next[pair]
			if len(got) != len(paths) {
				t.Errorf("run %d: %q has %d declaring sites, run 0 had %d",
					run, pair, len(got), len(paths))
			}
		}
	}
}
