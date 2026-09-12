package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #9446: the SPELLING BOUND a register entry states, MEASURED rather than
// pasted.
//
// For a site under a braced multi-key container (`family inet`), the losing
// spellings of one statement differ in WHICH (container, head) pair the
// compact-normalize pass has to admit. measureSpellingBound9446 runs
// production's own pass (normalizeCompactStanzasWithScope, with a predicate
// that records each question and then defers to compactNormalizeInScope). It
// compiles each spelling against the fully braced control and a baseline
// without the statement, so "drops" is a measurement and not an inference.
// TestSpellingBoundNotesAreMeasured_9446 holds every such register note to it.

type spellingRow9446 struct {
	label string // A..E, as #8755 and #9446 name them
	text  string
	pairs []string // (container,head) pairs the pass asked for this site's tail
	drops bool     // compiles differently from the braced control
}

type spellingBound9446 struct {
	site       string
	observable bool // the braced control differs from the baseline
	rows       []spellingRow9446
}

// renderSite9446 renders the census container with names a compile accepts:
// an interface and an address the address-bearing sites need. renderInstanceNames
// leaves `address xpfarg` unrendered, and a family with an unparseable address
// makes every statement beneath it unobservable.
func renderSite9446(container []string, fam string) []string {
	out := renderInstanceNames(container)
	for i, e := range out {
		switch {
		case e == "xpfname":
			out[i] = "ge-0/0/0"
		case e == "address xpfarg" && fam == "inet6":
			out[i] = "address 2001:db8::1/64"
		case e == "address xpfarg":
			out[i] = "address 10.0.0.1/24"
		}
	}
	return out
}

func measureSpellingBound9446(t *testing.T, s compactSite) (spellingBound9446, bool) {
	t.Helper()
	res := spellingBound9446{site: strings.Join(s.container, " ") + " " + s.leaf}
	fi := -1
	for i, e := range s.container {
		if e == "family" && i+1 < len(s.container) {
			fi = i
			break
		}
	}
	if fi < 0 {
		return res, false
	}
	fam := s.container[fi+1]
	rendered := renderSite9446(s.container, fam)
	prefix, rest := rendered[:fi], rendered[fi+2:]
	stmt := s.leaf + ";"
	if !s.flag {
		v, _, ok := synthPair(s.node)
		if !ok {
			return res, false
		}
		stmt = s.leaf + " " + v + ";"
	}
	restText := strings.Join(rest, " ")
	join := func(parts ...string) string {
		var keep []string
		for _, p := range parts {
			if p != "" {
				keep = append(keep, p)
			}
		}
		return strings.Join(keep, " ")
	}
	wrap := func(familyPart string) string { return nest(prefix, familyPart) }
	spellings := []struct{ label, family string }{
		{"A", "family " + fam + " { " + nest(rest, stmt) + " }"},
		{"B", "family " + fam + " { " + join(restText, stmt) + " }"},
		{"C", "family " + fam + " " + join(restText, stmt)},
		{"D", "family { " + fam + " " + join(restText, stmt) + " }"},
		{"E", "family { " + fam + " { " + nest(rest, stmt) + " } }"},
	}
	if len(rest) == 0 {
		spellings = append(spellings[:1], spellings[2:]...) // B is A when nothing sits between
	}
	control := compileText(t, wrap("family "+fam+" { "+nest(rest, stmt)+" }"))
	baseline := compileText(t, wrap("family "+fam+" { }"))
	res.observable = control != nil && baseline != nil && !cfgEqual(control, baseline)
	tail := map[string]bool{fam: true, s.leaf: true}
	for _, r := range rest {
		tail[strings.Fields(r)[0]] = true
	}
	for _, sp := range spellings {
		text := wrap(sp.family)
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			return res, false
		}
		seen := map[string]bool{}
		var pairs []string
		normalizeCompactStanzasWithScope(tree, func(kw, head string) bool {
			if tail[head] && !seen[kw+"\x00"+head] {
				seen[kw+"\x00"+head] = true
				pairs = append(pairs, fmt.Sprintf("(%q,%q)", kw, head))
			}
			return compactNormalizeInScope(kw, head)
		})
		sort.Strings(pairs)
		got := compileText(t, text)
		res.rows = append(res.rows, spellingRow9446{
			label: sp.label, text: sp.family, pairs: pairs,
			drops: !cfgEqual(got, control),
		})
	}
	return res, true
}

func registerFamilySites9446(t *testing.T) (map[string]compactSite, [][3]string) {
	t.Helper()
	sites := map[string]compactSite{}
	for _, s := range collectCompactSites() {
		sites[strings.Join(s.container, " ")+" "+s.leaf] = s
	}
	var entries [][3]string
	for _, l := range strings.Split(mustReadFile8690(t, "testdata/compact_block_permanent_exclusions_8690.txt"), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 3 || strings.TrimSpace(f[1]) != "open" || !siteIsUnderABracedMultiKey8755(f[0]) {
			continue
		}
		entries = append(entries, [3]string{strings.TrimSpace(f[0]), f[1], f[2]})
	}
	return sites, entries
}

// signature renders a measurement as one line a register note carries verbatim:
// each spelling, whether it compiles to the braced control's config, and the
// pairs the pass asked for it. The full stop anchors the end, so a note
// carrying a signature with an extra spelling does not contain a shorter one.
func (b spellingBound9446) signature() string {
	parts := make([]string, 0, len(b.rows))
	for _, r := range b.rows {
		verdict := "keeps"
		if r.drops {
			verdict = "drops"
		}
		parts = append(parts, r.label+" "+verdict+" ["+strings.Join(r.pairs, " ")+"]")
	}
	return "MEASURED SPELLINGS (#9446): " + strings.Join(parts, "; ") + "."
}

// falsifiedSpellingBound9446 are the #8755 claims #8763 made false. A note
// still carrying one is the pasted paragraph #9446 found, whatever else it says.
var falsifiedSpellingBound9446 = []string{
	"measured at 769f2f622",
	"closes ONE of four losing spellings",
}

// spellingBoundNoteProblems9446 is the per-entry check, extracted so the
// refusals can be driven by a fixture: on a correct register none of them fire,
// and a check that never fires cannot show it would.
func spellingBoundNoteProblems9446(note string, m spellingBound9446) []string {
	var out []string
	for _, p := range falsifiedSpellingBound9446 {
		if strings.Contains(note, p) {
			out = append(out, fmt.Sprintf("carries the falsified #8755 bound %q; "+
				"#8763 made the pass descend a compoundKey node, so every losing "+
				"spelling now asks a pair", p))
		}
	}
	if !m.observable {
		return append(out, "the fully braced control compiles to the same config as "+
			"the baseline without the statement, so no verdict about this site means anything")
	}
	if sig := m.signature(); !strings.Contains(note, sig) {
		out = append(out, "does not carry its measured spellings; measured now:\n\t"+sig)
	}
	return out
}

// THE GATE. Every `open` register entry under a braced multi-key container
// carries the measurement of its own site, verbatim.
//
// Not the pairs alone: the pairs the pass asks do not change when one is
// ADMITTED, because the recording predicate hears the question either way. A
// gate over pairs stays green through exactly the change that makes a note's
// "drops" false. The verdicts change, and the signature carries both.
//
// The prose is not checked. The signature is what reds, and the failure says
// to re-read the prose before replacing it: a paragraph that outlived the change
// that hollowed it is how the #8755 bound went stale.
func TestSpellingBoundNotesAreMeasured_9446(t *testing.T) {
	sites, entries := registerFamilySites9446(t)
	if len(entries) == 0 {
		t.Fatal("no `open` entry under a braced multi-key container, so nothing was " +
			"measured; if every such site has been normalized this cell can go (#9446)")
	}
	drops := 0
	for _, e := range entries {
		site, note := e[0], e[2]
		s, ok := sites[site]
		if !ok {
			t.Errorf("%s: the census does not enumerate this register site, so its "+
				"spelling bound cannot be measured (#9446)", site)
			continue
		}
		m, ok := measureSpellingBound9446(t, s)
		if !ok {
			t.Errorf("%s: its losing spellings could not be rendered and parsed, so "+
				"its bound is unmeasured (#9446)", site)
			continue
		}
		for _, r := range m.rows {
			if r.drops {
				drops++
			}
		}
		for _, p := range spellingBoundNoteProblems9446(note, m) {
			t.Errorf("%s: %s\nRe-read this entry's SPELLING BOUND prose against the "+
				"measurement before replacing its MEASURED SPELLINGS line (#9446)", site, p)
		}
	}
	// NON-VACUITY: every entry measured is `open`, so some spelling loses a value.
	if drops == 0 {
		t.Fatal("no measured spelling drops its value although every entry is `open`; " +
			"the instrument is not seeing the loss (#9446)")
	}
}

// Each refusal, driven. The positive control comes first: a checker refusing
// everything would pass every case below.
func TestSpellingBoundNoteCheckRefusesEachDefect_9446(t *testing.T) {
	m := spellingBound9446{site: "fixture", observable: true, rows: []spellingRow9446{
		{label: "A"},
		{label: "C", drops: true, pairs: []string{`("inet","mtu")`}},
		{label: "E"},
	}}
	good := "Prose. " + m.signature()
	if p := spellingBoundNoteProblems9446(good, m); len(p) != 0 {
		t.Fatalf("the correct note is refused: %v", p)
	}
	unobservable := m
	unobservable.observable = false
	flipped := m
	flipped.rows = []spellingRow9446{{label: "A"}, {label: "C", pairs: m.rows[1].pairs}, {label: "E"}}
	extra := m
	extra.rows = append(append([]spellingRow9446{}, m.rows...), spellingRow9446{label: "F"})
	for _, c := range []struct {
		name, note string
		m          spellingBound9446
	}{
		{"no signature", "Prose only.", m},
		{"a verdict flipped", "Prose. " + flipped.signature(), m},
		{"a signature with one spelling fewer", "Prose. " + m.signature(), extra},
		{"a signature with one spelling more", "Prose. " + extra.signature(), m},
		{"the 769f2f622 bound pasted back", good + " SPELLING BOUND (#8755, measured at 769f2f622): x", m},
		{"the one-of-four claim", good + " a scope entry closes ONE of four losing spellings", m},
		{"an unobservable control", good, unobservable},
	} {
		if p := spellingBoundNoteProblems9446(c.note, c.m); len(p) == 0 {
			t.Errorf("%s: accepted, want refused", c.name)
		}
	}
}
