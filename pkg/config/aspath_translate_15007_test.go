package config

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #15007 translator tests. The oracle is Junos' documented semantics
// (whole-AS-number matching, implicit ^...$, "." = one AS, "()" = null
// path): every translated pattern is evaluated as a POSIX ERE — the
// engine FRR uses — against AS-path strings.

func TestTranslateJunosASPathRegex15007Table(t *testing.T) {
	cases := []struct {
		junos string
		want  map[string]bool
	}{
		{"()", map[string]bool{"": true, "65000": false, "1 65000 2": false}},
		{"65000", map[string]bool{"65000": true, "165000": false, "650001": false, "1 65000": false, "": false}},
		{"65000 65001", map[string]bool{"65000 65001": true, "65000": false, "65000 650001": false}},
		{".*", map[string]bool{"": true, "65000": true, "1 65000 2": true}},
		{".* 65000 .*", map[string]bool{"65000": true, "1 65000": true, "65000 1": true, "1 65000 2": true, "165000": false, "650001": false, "1 650001 2": false, "": false}},
		{"65000 .*", map[string]bool{"65000": true, "65000 1": true, "1 65000": false, "": false}},
		{".* 65000", map[string]bool{"65000": true, "1 65000": true, "65000 1": false}},
		{"1234*", map[string]bool{"": true, "1234": true, "1234 1234": true, "123": false}},
		{"1234?", map[string]bool{"": true, "1234": true, "1234 1234": false}},
		{"12{1,4} 34", map[string]bool{"12 34": true, "12 12 34": true, "34": false, "12": false}},
		{"123-125", map[string]bool{"123": true, "124": true, "125": true, "126": false, "1234": false, "": false}},
		{"[123-125]*", map[string]bool{"": true, "123": true, "123 124": true, "125 125 125": true, "126": false}},
		{". (56 | 78)", map[string]bool{"1234 56": true, "1234 78": true, "9876 56": true, "56": false}},
		{"123 (56|78)", map[string]bool{"123 56": true, "123 78": true, "1234 56": false}},
		// Junos doc: ". (56 | 78)?" samples include "52 34 56" — the
		// OPTIONAL second term means any path whose SECOND AS is 56/78
		// OR any single-AS path (term absent) matches; "1234 52" does not.
		{". (56 | 78)?", map[string]bool{"1234": true, "1234 56": true, "1234 78": true, "1234 52": false, "52 34 56": false}},
		{"4 5 6 .*", map[string]bool{"4 5 6": true, "4 5 6 7": true, "9 4 5 6": false}},
		{".* 4 5 6", map[string]bool{"4 5 6": true, "1 2 3 4 5 6": true, "4 5 6 7": false}},
		{"5 | 12 | 18", map[string]bool{"5": true, "12": true, "18": true, "1": false, "": false}},
		{"9+", map[string]bool{"9": true, "9 9": true, "1234": false}},
		{"65000+", map[string]bool{"65000": true, "65000 65000": true, "65000 65001": false}},
		{"^65001 65002$", map[string]bool{"65001 65002": true, "65000 65001": false}},
		{"[123-125]", map[string]bool{"124": true, "126": false}},
		{". .", map[string]bool{"1 2": true, "1": false, "1 2 3": false}},
		{".* .*", map[string]bool{"": true, "1": true, "1 2 3": true}},
		{"65000? 65001", map[string]bool{"65001": true, "65000 65001": true, "65000": false}},
		{"65000 65001?", map[string]bool{"65000": true, "65000 65001": true, "65001": false}},
		{"1234{1,6} (56|47)? (78|101|112)* 9+", map[string]bool{"1234 9": true, "1234 47 101 9 9": true, "1234 56 9": true, "9": false, "1234": false}},
		{"[^65000]", map[string]bool{"65001": true, "65000": false, "1": true}},
		{"12{0,2} 34", map[string]bool{"34": true, "12 34": true, "12 12 34": true, "12 12 12 34": false}},
		{"65000-65999", map[string]bool{"65000": true, "65500": true, "65999": true, "66000": false, "6500": false}},
	}
	for _, tc := range cases {
		tr, err := TranslateJunosASPathRegex(tc.junos)
		if err != nil {
			t.Errorf("%q: translate error: %v", tc.junos, err)
			continue
		}
		re, err := regexp.CompilePOSIX(tr)
		if err != nil {
			t.Errorf("%q -> %q compile: %v", tc.junos, tr, err)
			continue
		}
		for path, want := range tc.want {
			if got := re.MatchString(path); got != want {
				t.Errorf("%q -> %q vs path %q: got %v want %v", tc.junos, tr, path, got, want)
			}
		}
	}
	if tr, _ := TranslateJunosASPathRegex("()"); tr != "^$" {
		t.Errorf("() translated %q, want ^$", tr)
	}
	if tr, _ := TranslateJunosASPathRegex("65000"); tr != "^65000$" {
		t.Errorf("65000 translated %q, want ^65000$", tr)
	}
}

// The Junos doc example ". (56 | 78)?" lists sample matches
// "1234 56 52", "34 56 1234", "794 78 2" — paths where 56/78 appears
// anywhere AFTER the first AS... those samples contradict the anchored
// reading; they reflect the doc's loose example set, NOT the normative
// "matches only if the AS path exactly matches" rule (the same page's
// Table 2 header row pattern ". (56 | 78)?" with full-path samples
// "1234 56", "1234" is the anchored reading). xpf implements the
// normative anchored rule; paths longer than the pattern do not match.
// This cell documents the choice explicitly so a future reader does not
// "fix" it to the loose samples.
func TestTranslateJunosDocLooseSamplesNotFollowed15007(t *testing.T) {
	tr, err := TranslateJunosASPathRegex(". (56 | 78)?")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompilePOSIX(tr)
	if re.MatchString("1234 56 52") {
		t.Errorf("anchored translation %q unexpectedly matches a longer path; if Junos semantics changed, revisit", tr)
	}
}

func TestTranslateJunosASPathRegex15007Rejects(t *testing.T) {
	for _, in := range []string{"", "   ", "(((", "65[0-9]+", "[0-9]+", "65000\\", "65.000", "0", "065000", "4294967296", "123{4,2}", "123{", "*65000", "65000**", "[123", "123-", "-123", "65000^65001", "65$000", "[^]", "65000 |", "| 65000", "65000 || 65001", "(65000", "65000)", "[^1-4294967295]", "65000 65001 |", "x", "65000;"} {
		if _, err := TranslateJunosASPathRegex(in); err == nil {
			tr, _ := TranslateJunosASPathRegex(in)
			t.Errorf("%q should reject, translated to %q", in, tr)
		}
		if err := ValidJunosASPathRegex(in); err == nil {
			t.Errorf("%q: ValidJunosASPathRegex accepts an untranslatable pattern", in)
		}
	}
}

// Numeric-range fragment oracle: brute-force every value 1..70000 plus
// boundary extremes against the [lo,hi] predicate.
func TestASNumericRangeRE15007Oracle(t *testing.T) {
	for _, tc := range [][2]uint64{{1, 9}, {1, 99}, {123, 125}, {65000, 65100}, {999, 1001}, {1, 4294967295}, {65535, 65536}, {100, 200}, {90, 110}, {5, 5000}, {4294967290, 4294967295}, {10, 19}, {65000, 65999}} {
		frag, err := asNumericRangeRE(tc[0], tc[1])
		if err != nil {
			t.Fatalf("%v: %v", tc, err)
		}
		re := regexp.MustCompilePOSIX("^" + frag + "$")
		check := func(v uint64) {
			s := strconv.FormatUint(v, 10)
			want := v >= tc[0] && v <= tc[1]
			if got := re.MatchString(s); got != want {
				t.Fatalf("range %v frag %q: %s got %v want %v", tc, frag, s, got, want)
			}
		}
		for v := uint64(1); v <= 70000; v++ {
			check(v)
		}
		for _, v := range []uint64{tc[0], tc[1], 4294967295, 4294967294, 100000, 1000000, 999999999, 4000000000} {
			check(v)
		}
		if strings.Contains(frag, "\n") {
			t.Fatalf("range %v frag contains newline", tc)
		}
	}
}

// Strict-commit acceptance/rejection through the real compiler: the
// canonical Junos patterns commit; FRR-dialect text does not.
func TestASPath15007StrictCommitGate(t *testing.T) {
	commit := func(re string) error {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(`set policy-options as-path AP1 "` + re + `"`)
		if err != nil {
			t.Fatalf("parse %q: %v", re, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", re, err)
		}
		_, err = CompileConfig(tree)
		return err
	}
	for _, re := range []string{"()", ".* 65000 .*", "^65000$", "65000", "[65000-65999]", "123-125", "1234{1,6} (56|47)? (78|101|112)* 9+", ".*", "^$", ". ."} {
		if err := commit(re); err != nil {
			t.Errorf("strict commit rejected Junos pattern %q: %v", re, err)
		}
	}
	for _, re := range []string{"65[0-9]+", "^65000 [0-9]+$", "[0-9]+", "0-9 +", "65000**"} {
		if err := commit(re); err == nil {
			t.Errorf("strict commit ACCEPTED untranslatable pattern %q — it would be omitted at render and its terms would silently not fire", re)
		}
	}
	// Tolerant path still boots with a stored untranslatable pattern.
	tree := &ConfigTree{}
	path, err := ParseSetCommand(`set policy-options as-path AP1 "65[0-9]+"`)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load rejected a stored config (#1960 brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "as-path AP1") {
			found = true
		}
	}
	if !found {
		t.Errorf("tolerant load produced no as-path warning; warnings=%v", cfg.Warnings)
	}
}
