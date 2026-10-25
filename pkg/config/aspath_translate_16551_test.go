package config

import (
	"regexp"
	"testing"
)

// #16551: two quantifier mistranslations in the Junos AS-path translator.
//
// (a) "{0}" / "{0,0}" attached to an unwrapped multi-character base bound
// to the base's last character: "65000{0}" emitted "65000{0}", which as a
// POSIX ERE zeroes only the final "0" and therefore matches the unrelated
// AS 6500. Junos repetition repeats the whole term, never its digits.
//
// (b) "B{m}" (and the {m,} / {m,n} forms with m>=1) on a nullable
// single-token base B demanded one separator per non-first copy even
// when that copy was empty: "(65000?){2}" rejected the single-token path
// "65000" that Junos accepts (one copy present, one empty).
//
// Every case is evaluated with the POSIX engine FRR uses, against the
// Junos whole-AS semantics. The control rows pin shapes that were
// already correct so the fix cannot silently change them.

func TestTranslateJunosASPath16551ZeroIntervalAndNullableRepetition(t *testing.T) {
	cases := []struct {
		junos string
		want  map[string]bool
	}{
		// (a) zero-count intervals on an unwrapped multi-digit AS.
		{"65000{0} 65001", map[string]bool{"65001": true, "6500 65001": false, "65000 65001": false, "": false}},
		{"65000{0,0} 65001", map[string]bool{"65001": true, "6500 65001": false, "65000 65001": false}},
		{"65000{0}", map[string]bool{"": true, "65000": false, "6500": false}},
		{"5{0}", map[string]bool{"": true, "5": false}},
		// (a) on other multi-character bases: a range fragment ending in
		// a character class, and the "." token.
		{"65000-65999{0} 65001", map[string]bool{"65001": true, "6500 65001": false, "65500 65001": false}},
		{"[123-125]{0} 65001", map[string]bool{"65001": true, "12 65001": false, "124 65001": false}},
		{".{0} 65001", map[string]bool{"65001": true, "1 65001": false}},
		// (b) exact repetition of a nullable single-token group.
		{"(65000?){2}", map[string]bool{"": true, "65000": true, "65000 65000": true, "65000 65000 65000": false, "65001": false}},
		{"(65000?){3}", map[string]bool{"": true, "65000": true, "65000 65000": true, "65000 65000 65000": true, "65000 65000 65000 65000": false}},
		{"((65000|65001)?){2}", map[string]bool{"": true, "65001": true, "65000 65001": true, "65000 65001 65000": false}},
		{"((65000|65001)?){1}", map[string]bool{"": true, "65000": true, "65001": true, "65000 65001": false}},
		// (b) ranged repetitions of a nullable single-token group.
		{"(65000?){2,3}", map[string]bool{"": true, "65000": true, "65000 65000 65000": true, "65000 65000 65000 65000": false}},
		{"(65000?){2,}", map[string]bool{"": true, "65000": true, "65000 65000 65000 65000": true}},
		{"(65000?){0}", map[string]bool{"": true, "65000": false}},
		// (b) in concatenation: separators around the repetition come
		// from parseConcat, empty copies inside it add none.
		{"(65000?){2} 65001", map[string]bool{"65001": true, "65000 65001": true, "65000 65000 65001": true, "65000 65000 65000 65001": false}},
		{"65001 (65000?){2}", map[string]bool{"65001": true, "65001 65000": true, "65001 65000 65000": true, "65001 65000 65000 65000": false}},
		// Controls (already correct pre-fix, must not change).
		{"65000{2}", map[string]bool{"65000 65000": true, "65000": false, "6500 6500": false}},
		{"65000{0,1} 65001", map[string]bool{"65001": true, "65000 65001": true, "6500 65001": false}},
		{"(65000 65001){0,1} 65002", map[string]bool{"65002": true, "65000 65001 65002": true, "65000 65002": false}},
		{".{0,2} 65002", map[string]bool{"65002": true, "1 65002": true, "1 2 65002": true, "1 2 3 65002": false}},
		{"(65000 (65001?)){2}", map[string]bool{"65000 65000": true, "65000 65001 65000 65001": true}},
		{"12{0,2} 34", map[string]bool{"34": true, "12 34": true, "12 12 34": true, "12 12 12 34": false}},
	}
	for _, tc := range cases {
		tr, err := TranslateJunosASPathRegex(tc.junos)
		if err != nil {
			t.Errorf("%q: translate error: %v", tc.junos, err)
			continue
		}
		if err := ValidJunosASPathRegex(tc.junos); err != nil {
			t.Errorf("%q: ValidJunosASPathRegex error: %v", tc.junos, err)
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
}

// The zero interval must zero the whole grouped term in the emitted
// pattern, not the last digit of the AS number.
func TestTranslateJunosASPath16551ZeroIntervalGroupsWholeTerm(t *testing.T) {
	for _, junos := range []string{"65000{0}", "65000{0,0}"} {
		tr, err := TranslateJunosASPathRegex(junos)
		if err != nil {
			t.Fatalf("%q: %v", junos, err)
		}
		if tr != "^((65000){0})$" && tr != "^(65000){0}$" {
			// Any grouping that makes {0} bind to the whole "65000"
			// term is acceptable; the ungrouped "65000{0}" is not.
			if tr == "^(65000{0})$" || tr == "^65000{0}$" {
				t.Errorf("%q -> %q: {0} binds to the last digit, not the term", junos, tr)
			}
		}
		re := regexp.MustCompilePOSIX(tr)
		if re.MatchString("6500") {
			t.Errorf("%q -> %q matches unrelated AS 6500", junos, tr)
		}
		if !re.MatchString("") {
			t.Errorf("%q -> %q must match the null path", junos, tr)
		}
	}
}
