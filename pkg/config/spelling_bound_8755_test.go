package config

import (
	"strings"
	"testing"
)

// #8755: the SPELLING BOUND on the #8690 register, and the filter-input site it
// was first measured on.
//
// HISTORY: the bound below is not the current one. At 769f2f622, through the
// real pass under the production scope, the idiomatic `family inet { filter
// input f4; }` DROPPED the filter and was UNREACHABLE: normalizeCompactNodes
// recursed into a braced `Keys=[family inet]` with schema.children["family"],
// advancing the schema one level where the node advanced two, so no pair was
// asked for that shape even under admit-all. Only the one-liner was reachable,
// hence "a scope entry closes ONE of four losing spellings".
//
// #8763 made the pass descend a compoundKey node, and ("inet","filter") and
// ("filter","input") have since been admitted. Measured at ac03dce96 (#9446),
// every spelling binds "f4":
//
//	family inet { filter { input f4; } }   fully braced
//	family inet { filter input f4; }       idiomatic elision
//	family inet filter input f4;           one-liner
//	family { inet { filter input f4; } }
//	family { inet filter input f4; }
//
// The bound on the sites still `open` is not one sentence any more. It differs
// per site, so TestSpellingBoundNotesAreMeasured_9446 measures each entry and
// holds its note to that measurement.
//
// `unit`-level sites are NOT subject to any of this: there the second token is
// an instance ARG consumed by `identity`, not a child keyword.

func filterInOf8755(t *testing.T, text string) (string, bool) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		return "", false
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", false
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		return "", false
	}
	return ifc.Units[0].FilterInputV4, true
}

const fwFilter8755 = `firewall { family inet { filter f4 { term t { then discard; } } } } `

func ifaceSpelling8755(inner string) string {
	return fwFilter8755 + `interfaces { ge-0/0/0 { unit 0 { ` + inner + ` } } }`
}

// THE CONTROL. The fully braced spelling must keep the filter, or every
// comparison below is about a fixture that never bound one.
func TestTheBracedSpellingKeepsTheFilter_8755(t *testing.T) {
	got, ok := filterInOf8755(t, ifaceSpelling8755(`family inet { filter { input f4; } }`))
	if !ok {
		t.Fatal("the braced control did not compile")
	}
	if got != "f4" {
		t.Fatalf("the fully braced spelling binds %q, want \"f4\" — the other cells in "+
			"this file compare against it and are meaningless if it does not bind", got)
	}
}

// THE REPAIRED BOUND, pinned. At 769f2f622 this cell was green while the
// idiomatic elision and the one-liner both DROPPED the filter, and it fired only
// on the partial state between. The fix has since shipped in full, which turned
// its silent "both drop" arm into a regression that passed. Every spelling now
// has to bind what the fully braced control binds (#9446).
func TestEveryFilterSpellingBindsTheFilter_8755(t *testing.T) {
	// The control is READ, not merely asserted elsewhere: every comparison below
	// is against what the fully braced spelling actually binds. A control that
	// is only checked in its own cell can stop binding without this one
	// noticing — found by mutation, where blanking that check killed nothing.
	want, okC := filterInOf8755(t, ifaceSpelling8755(`family inet { filter { input f4; } }`))
	if !okC || want == "" {
		t.Fatalf("the fully braced control binds %q; every comparison below is "+
			"against it and means nothing if it binds nothing", want)
	}
	for _, sp := range []string{
		`family inet { filter input f4; }`,
		`family inet filter input f4;`,
		`family { inet { filter input f4; } }`,
		`family { inet filter input f4; }`,
	} {
		got, ok := filterInOf8755(t, ifaceSpelling8755(sp))
		if !ok {
			t.Errorf("%s did not compile; this cell measures nothing for it", sp)
			continue
		}
		if got != want {
			t.Errorf("%s binds %q, want %q as the fully braced spelling does. It "+
				"bound at ac03dce96 (#9446): either the pass stopped descending a "+
				"braced compoundKey node (#8763), or (inet,filter) / (filter,input) "+
				"left the normalizer scope", sp, got, want)
		}
	}
}

// The register's own claim, checked against the register — for the sites the
// claim is ABOUT.
//
// THIS CELL WAS OVER-BROAD ON ITS FIRST DAY and reddened master. It required a
// spelling-bound note from EVERY `open` entry, including two
// `security policies ... scheduler-name` sites another lane added minutes
// later. Those sites are not under a braced multi-key container and the bound
// says nothing about them, so the guard was demanding a claim that would have
// been false if written.
//
// A guard written for one population must SELECT that population, or it becomes
// a tax on every lane that appends to the same file — and the first person to
// pay it will make it green the cheapest way, which is by writing the note
// whether or not it is true.
//
// The selector is a proxy and is named as one: the bound applies to a site
// whose container passes through a braced MULTI-KEY node whose second token is
// a child keyword. In this register that is exactly `family inet` /
// `family inet6`; `unit <n>` does not qualify because its second token is an
// instance arg.
func siteIsUnderABracedMultiKey8755(site string) bool {
	return strings.Contains(site, " family inet ") || strings.HasSuffix(site, " family inet") ||
		strings.Contains(site, " family inet6 ") || strings.HasSuffix(site, " family inet6")
}

func TestEveryOpenEntryCarriesTheSpellingBound_8755(t *testing.T) {
	var missing, considered []string
	for _, l := range strings.Split(mustReadFile8690(t, "testdata/compact_block_permanent_exclusions_8690.txt"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) < 3 || strings.TrimSpace(f[1]) != "open" {
			continue
		}
		site := strings.TrimSpace(f[0])
		if !siteIsUnderABracedMultiKey8755(site) {
			continue
		}
		considered = append(considered, site)
		if !strings.Contains(f[2], "SPELLING BOUND") {
			missing = append(missing, site)
		}
	}
	// NON-VACUITY: a selector that matches nothing reports no failures too, and
	// this one is a string proxy that a register rename would silently defeat.
	if len(considered) == 0 {
		t.Fatal("the selector matched no `open` site, so the check below passed by " +
			"selecting nothing. Either every such site has been normalized — in " +
			"which case this cell can go — or the site-key shape changed and the " +
			"proxy stopped matching (#8755)")
	}
	if len(missing) > 0 {
		t.Errorf("%d `open` entries carry no spelling bound: %v.\n`open` reads as "+
			"\"available work, fully fixable\", and for the sites under a braced "+
			"multi-key container it is not: their losing spellings resolve to "+
			"different pairs, so one admission is not the whole fix. "+
			"TestSpellingBoundNotesAreMeasured_9446 holds each note to its own "+
			"measurement (#8755, #9446)", len(missing), missing)
	}
}
