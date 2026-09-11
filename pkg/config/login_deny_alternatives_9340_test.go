package config

import (
	"fmt"
	"strings"
	"testing"
)

// #9340: one enforceable alternative must not silence the advisory for an
// argument-text alternative beside it. The surface below stands in for the
// gRPC registered set: command paths, never argument text.

var surface9340 = []string{"show route", "show route table", "show route brief", "show interfaces", "request system reboot"}

func warningsMentioning9340(cfg *Config, substr string) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, substr) {
			out = append(out, w)
		}
	}
	return out
}

// The acceptance cell: the issue's combined pattern reports the gRPC surface
// and names the alternative it cannot enforce, and only that one.
func TestCombinedDenyReportsItsUnenforceableAlternative9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	cfg := loginClassCfg(t, "^(show route table secret-vrf|request system reboot)$")
	got := warningsMentioning9340(cfg, "only partly enforceable")
	if len(got) != 1 {
		t.Fatalf("want one partial-enforcement advisory, got %d; warnings: %q", len(got), cfg.Warnings)
	}
	w := got[0]
	for _, want := range []string{`"limited"`, "the gRPC surface", `"^show route table secret-vrf$"`, "REGISTERED command set", "on-box CLI"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory does not carry %q: %s", want, w)
		}
	}
	if strings.Contains(w, `"^request system reboot$"`) {
		t.Errorf("the enforceable alternative was reported as unenforceable: %s", w)
	}
}

// The issue's control: the single-restriction spelling keeps its #8189
// whole-pattern advisory and gains no second message. So does a combined
// pattern NONE of whose alternatives can fire.
func TestWholeUnenforceablePatternKeepsOneAdvisory9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	for _, pat := range []string{"^show route table secret-vrf$", "^(zzz-one|zzz-two)$"} {
		cfg := loginClassCfg(t, pat)
		if n := len(warningsMentioning9340(cfg, "REGISTERED command set")); n != 1 {
			t.Errorf("%q: want exactly the whole-pattern advisory, got %d; warnings: %q", pat, n, cfg.Warnings)
		}
		if p := warningsMentioning9340(cfg, "only partly enforceable"); len(p) != 0 {
			t.Errorf("%q: a pattern that cannot fire at all got a partial advisory too: %q", pat, p)
		}
	}
}

// The control that stops a fix passing by warning about everything: a
// pattern every alternative of which fires reports nothing.
func TestWhollyEnforceableDenyStaysSilent9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	for _, pat := range []string{
		"^show route$",
		"^(show route|request system reboot)$",
		"^show (route|interfaces)$",
		"show route|request system reboot",
		"^show route( brief)?$",
	} {
		if got := warningsMentioning9340(loginClassCfg(t, pat), "REGISTERED command set"); len(got) != 0 {
			t.Errorf("%q is enforceable in every alternative but warned: %q", pat, got)
		}
	}
}

// Spelling independence, the #7172 bar: every spelling of the same intent
// reports the same alternative.
func TestPartialAdvisoryIsSpellingIndependent9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	for _, pat := range []string{
		`^(show route table secret-vrf|request system reboot)$`,
		`^show route table secret-vrf$|^request system reboot$`,
		`(^show route table secret-vrf$)|(^request system reboot$)`,
		`^show route table secret-vrf$|request system reboot`,
		`^show route( table secret-vrf)?$`,
		`^show route (table secret-vrf|brief)$`,
	} {
		got := warningsMentioning9340(loginClassCfg(t, pat), "only partly enforceable")
		if len(got) != 1 || !strings.Contains(got[0], `"^show route table secret-vrf$"`) {
			t.Errorf("%q: want one advisory naming ^show route table secret-vrf$, got %q", pat, got)
		}
	}
}

// Exactness: a class whose deny is the whole pattern denies a command iff a
// class whose deny is one of its alternatives does. This is the property every
// report rests on, and it is what a renderer that lost an anchor, or a matcher
// that lost leftmost-longest, would break.
func TestAlternativesMatchExactlyWhatThePatternMatches9340(t *testing.T) {
	cmds := append(append([]string(nil), surface9340...),
		"show route table secret-vrf", "request system reboot now", "xshow route", "show routes", "show route brief extra", "")
	for _, pat := range []string{
		`^(show route table secret-vrf|request system reboot)$`,
		`(^show route table secret-vrf$)|(^request system reboot$)`,
		`^show route( table secret-vrf)?$`,
		`^show route (table secret-vrf|brief)$`,
		`show (route|interfaces)`,
		`[[:alpha:]]+ route$|^request`,
		`^show route( (table|brief)( [a-z-]+)?)?$`,
	} {
		whole, err := CompileLoginRegexes(LoginRegexPlainFamily, "", false, pat, true)
		if err != nil {
			t.Fatalf("%q: %v", pat, err)
		}
		alts, ok := denyPatternAlternatives9340(pat)
		if !ok || len(alts) < 2 {
			t.Fatalf("%q: premise broken: expected a split (ok=%v n=%d)", pat, ok, len(alts))
		}
		for _, cmd := range cmds {
			wholeDenies := !whole.Evaluate(cmd).Allowed
			anyDenies := false
			for _, alt := range alts {
				if !alternativeRules9340(whole, alt).Evaluate(cmd).Allowed {
					anyDenies = true
				}
			}
			if wholeDenies != anyDenies {
				t.Errorf("%q on %q: whole denies=%v, some alternative denies=%v", pat, cmd, wholeDenies, anyDenies)
			}
		}
	}
}

// A pattern past the cap is not split and resolves to silence, the #8189
// doctrine. Its whole-pattern answer is unchanged.
//
// The cap is enforced at three sites (alternation, optional, concatenation),
// and on a pattern that crosses it through one site the others do not see it,
// so each site has its own row. Each row pairs an over-cap pattern with the
// same shape one alternative smaller, which must split into exactly the cap:
// that pins the count, so a row cannot pass because the parser collapsed the
// alternatives instead of the cap refusing them.
func TestPatternPastTheCapIsNotSplit9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	pat := "^(show route|(aa|bb) (cc|dd) (ee|ff) (gg|hh) (ii|jj) (kk|ll) (mm|nn))$"
	if _, ok := denyPatternAlternatives9340(pat); ok {
		t.Fatalf("premise broken: %q (129 alternatives) was split under a cap of %d", pat, maxDenyAlternatives9340)
	}
	if got := warningsMentioning9340(loginClassCfg(t, pat), "REGISTERED command set"); len(got) != 0 {
		t.Errorf("an unsplit pattern that fires must stay silent: %q", got)
	}

	// Each site is exercised by a pattern whose TOP node is that site. An anchor
	// or a factored common prefix wraps the pattern in a concatenation, and the
	// concatenation cap would then refuse it first, whichever site was
	// removed. So these words rotate their first character (no two neighbours
	// share a prefix for the parser to factor), and the rows are unanchored.
	words := func(n int) string {
		w := make([]string, n)
		for i := range w {
			w[i] = fmt.Sprintf("%c%02dx", "abc"[i%3], i)
		}
		return strings.Join(w, "|")
	}
	for _, r := range []struct {
		name, over, under string
	}{
		{"concat product", "^(aa|bb) (cc|dd) (ee|ff) (gg|hh) (ii|jj) (kk|ll) (mm|nn)$", "^(aa|bb) (cc|dd) (ee|ff) (gg|hh) (ii|jj) (kk|ll)$"},
		{"wide alternation", words(maxDenyAlternatives9340 + 1), words(maxDenyAlternatives9340)},
		{"optional group", "(" + words(maxDenyAlternatives9340) + ")?", "(" + words(maxDenyAlternatives9340-1) + ")?"},
	} {
		t.Run(r.name, func(t *testing.T) {
			if _, ok := denyPatternAlternatives9340(r.over); ok {
				t.Errorf("%q crosses the cap of %d and must not be split", r.over, maxDenyAlternatives9340)
			}
			alts, ok := denyPatternAlternatives9340(r.under)
			if !ok {
				t.Fatalf("control %q is within the cap and must split", r.under)
			}
			if r.name == "concat product" {
				if len(alts) != 64 {
					t.Fatalf("control %q: %d alternatives, want 64", r.under, len(alts))
				}
				return
			}
			if len(alts) != maxDenyAlternatives9340 {
				t.Fatalf("control %q: %d alternatives, want %d", r.under, len(alts), maxDenyAlternatives9340)
			}
		})
	}
}

// Exactness against a COMPETING allow pattern, where the longest matched
// extents decide. The alternative `^a*(ab)*` matches "aabab" for 5 characters
// under leftmost-longest (the POSIX matcher CompileLoginRegexes builds) but for
// only 2 under leftmost-first, so an alternative compiled without Longest()
// would lose to allow `^aaba` (4 characters) where the whole pattern wins.
func TestAlternativesDecideAgainstAnAllowLikeTheWhole9340(t *testing.T) {
	for _, c := range []struct {
		allow, deny string
		cmds        []string
	}{
		{"^aaba", "^(zzz|a*(ab)*)", []string{"aabab", "aab", "aaba", "zzz", "ab"}},
		{"^request system reboot$", "^(show route table secret-vrf|request system reboot)$",
			[]string{"request system reboot", "show route table secret-vrf", "show route table"}},
	} {
		whole, err := CompileLoginRegexes(LoginRegexPlainFamily, c.allow, true, c.deny, true)
		if err != nil {
			t.Fatalf("%q/%q: %v", c.allow, c.deny, err)
		}
		alts, ok := denyPatternAlternatives9340(c.deny)
		if !ok || len(alts) < 2 {
			t.Fatalf("%q: premise broken: expected a split (ok=%v n=%d)", c.deny, ok, len(alts))
		}
		for _, cmd := range c.cmds {
			wholeDenies := !whole.Evaluate(cmd).Allowed
			anyDenies := false
			for _, alt := range alts {
				if !alternativeRules9340(whole, alt).Evaluate(cmd).Allowed {
					anyDenies = true
				}
			}
			if wholeDenies != anyDenies {
				t.Errorf("allow %q, deny %q, on %q: whole denies=%v, some alternative denies=%v",
					c.allow, c.deny, cmd, wholeDenies, anyDenies)
			}
		}
	}
}

// An alternative that spells the ALLOW pattern exactly is judged by the whole
// pattern's precedence: allow and deny tie at different sources, so it denies
// and is enforceable. Judged as an identical pair, allow would win, and the
// working `request system reboot` restriction would be reported unenforceable.
func TestAlternativeSpellingTheAllowPatternIsNotReported9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	rules, err := CompileLoginRegexes(LoginRegexPlainFamily,
		"^request system reboot$", true,
		"^(show route table secret-vrf|request system reboot)$", true)
	if err != nil {
		t.Fatal(err)
	}
	got := UnenforceableDenyAlternatives(rules)
	if len(got) != 1 || len(got[0].Alternatives) != 1 || got[0].Alternatives[0] != "^show route table secret-vrf$" {
		t.Fatalf("want only ^show route table secret-vrf$ reported, got %+v", got)
	}
}

// The same silence reached through the ALLOW list, which the predicate change
// in denyPatternDecides closes. With allow `^show`, every command outside the
// allow list is refused by the allow list. Counting those refusals as the deny
// firing silenced the whole-pattern advisory for a deny that decides nothing on
// the surface. The controls: a deny that does decide, one the allow list does
// not cover (`^request`), stays silent; and a deny-only class is unchanged.
func TestAllowListRefusalIsNotTheDenyFiring9340(t *testing.T) {
	withSurface(t, "the gRPC surface", surface9340)
	for _, c := range []struct {
		allow, deny string
		want        bool
	}{
		{"^show", "^show route table secret-vrf$", true},
		{"^show", "^request", false},
		{"", "^request", false},
		{"", "^show route table secret-vrf$", true},
	} {
		rules, err := CompileLoginRegexes(LoginRegexPlainFamily, c.allow, c.allow != "", c.deny, true)
		if err != nil {
			t.Fatal(err)
		}
		got := len(UnenforceableDenySurfaces(rules)) > 0
		if got != c.want {
			t.Errorf("allow %q deny %q: reported=%v, want %v", c.allow, c.deny, got, c.want)
		}
	}
}
