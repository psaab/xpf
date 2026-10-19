package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15007: Junos AS-path regexes were rendered VERBATIM into FRR
// `bgp as-path access-list` lines. FRR evaluates those as UNANCHORED
// character regexes; Junos matches whole AS numbers under an implicit
// ^...$. Divergences this file pins, each evaluated with Go's POSIX
// engine as the FRR-semantics oracle:
//
//   - "()" (Junos null path, the canonical anti-transit accept) matched
//     EVERY path in FRR — a provider-to-provider route leak.
//   - "65000" matched substrings: 165000, 650001, "1 65000".
//   - "N .*" (and ".* 65000 .*") at character level is not the Junos
//     token pattern.
//
// Asserting the exact translated FRR line is equivalent or stronger —
// the rendered line IS what FRR evaluates — and these tests fail on
// master where the verbatim line was emitted.

func renderASPath15007(t *testing.T, name, junos string) string {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{name: {Name: name, Regex: junos}},
	}
	return New().generatePolicyOptions(po)
}

func renderedPattern15007(t *testing.T, name, junos string) *regexp.Regexp {
	t.Helper()
	got := renderASPath15007(t, name, junos)
	prefix := "bgp as-path access-list " + name + " permit "
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, prefix) {
			return regexp.MustCompilePOSIX(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("no as-path line rendered for Junos %q:\n%s", junos, got)
	return nil
}

func TestASPathTranslate15007RenderedLinesExact(t *testing.T) {
	cases := map[string]string{
		"()":                                  "^$",
		"65000":                               "^65000$",
		"65000 65001":                         "^65000 65001$",
		"^65001 65002$":                       "^65001 65002$",
		".*":                                  "^(^$|([0-9]+( [0-9]+)*))$",
		".* 65000 .*":                         "^(([0-9]+( [0-9]+)*) )?65000( ([0-9]+( [0-9]+)*))?$",
		"65000 .*":                            "^65000( ([0-9]+( [0-9]+)*))?$",
		"1234*":                               "^(^$|(1234( 1234)*))$",
		"5 | 12 | 18":                         "^(5|12|18)$",
		"[123-125]":                           "^(123|124|125)$",
		"65000|65001":                         "^(65000|65001)$",
		"65000-65999":                         "^65[0-9][0-9]{2}$",
		"[65000-65999]":                       "^65[0-9][0-9]{2}$",
		". (56 | 78)":                         "^[0-9]+ (56|78)$",
		"123 (56|78)":                         "^123 (56|78)$",
		"12{1,4} 34":                          "^12( 12){0,3} 34$",
		"^65000$":                             "^65000$",
		"^$":                                  "^$",
		"1234{1,6} (56|47)? (78|101|112)* 9+": "^1234( 1234){0,5}( (56|47))?( ((78|101|112)( (78|101|112))*))? 9( 9)*$",
	}
	for junos, want := range cases {
		got := renderASPath15007(t, "AP1", junos)
		line := "bgp as-path access-list AP1 permit " + want + "\n"
		if !strings.Contains(got, line) {
			t.Errorf("Junos %q: want rendered %q, got:\n%s", junos, line, got)
		}
		if err := config.ValidJunosASPathRegex(junos); err != nil {
			t.Errorf("Junos %q: strict predicate rejects a translatable pattern: %v", junos, err)
		}
	}
}

// The anti-transit acceptance from the issue: policy accept-only-"()"
// must accept only the empty path. Evaluated against the rendered FRR
// pattern over representative AS-path strings — on master the rendered
// pattern was "()" which matches every one of these.
func TestASPathTranslate15007NullPathOnlyMatchesEmpty(t *testing.T) {
	re := renderedPattern15007(t, "AP1", "()")
	for path, want := range map[string]bool{
		"": true, "65000": false, "65001 65002": false, "1 2 3": false,
	} {
		if got := re.MatchString(path); got != want {
			t.Errorf("() vs path %q: got %v want %v", path, got, want)
		}
	}
}

func TestASPathTranslate15007RenderedSemantics(t *testing.T) {
	cases := []struct {
		junos string
		want  map[string]bool
	}{
		{"65000", map[string]bool{"65000": true, "165000": false, "650001": false, "1 65000": false, "65000 65001": false, "": false}},
		{".* 65000 .*", map[string]bool{"65000": true, "1 65000": true, "65000 2": true, "1 65000 2": true, "165000": false, "1 650001 2": false, "": false}},
		{"65000 .*", map[string]bool{"65000": true, "65000 1": true, "1 65000": false, "": false}},
		{".* 65000", map[string]bool{"65000": true, "1 65000": true, "65000 1": false}},
		{"1234*", map[string]bool{"": true, "1234": true, "1234 1234": true, "123": false}},
		{"123-125", map[string]bool{"123": true, "124": true, "125": true, "126": false, "1234": false}},
		{". (56 | 78)?", map[string]bool{"1234": true, "1234 56": true, "56": true, "1234 52": false}},
		{"12{1,4} 34", map[string]bool{"12 34": true, "12 12 34": true, "34": false}},
		{"[^65000]", map[string]bool{"65001": true, "1": true, "65000": false}},
	}
	for _, tc := range cases {
		re := renderedPattern15007(t, "AP1", tc.junos)
		for path, want := range tc.want {
			if got := re.MatchString(path); got != want {
				t.Errorf("Junos %q vs path %q: got %v want %v", tc.junos, path, got, want)
			}
		}
	}
}

// Untranslatable patterns are omitted (never emitted in a divergent
// form), and the strict predicate agrees.
func TestASPathTranslate15007OmitsUntranslatable(t *testing.T) {
	for _, junos := range []string{"", "(((", "65[0-9]+", "[0-9]+", "65000**", "123{4,2}", "0", "065000", "4294967296", "65000 |", "[^1-4294967295]", "65.000"} {
		if got := renderASPath15007(t, "AP1", junos); strings.Contains(got, "bgp as-path access-list AP1") {
			t.Errorf("Junos %q rendered a line that must be omitted:\n%s", junos, got)
		}
		if err := config.ValidJunosASPathRegex(junos); err == nil {
			t.Errorf("Junos %q: strict predicate accepts an untranslatable pattern", junos)
		}
	}
}

// End-to-end: the canonical Junos anti-transit export policy through
// CompileConfig + render. Term accept over "()", then reject; on master
// the accept term's list matched every path.
func TestASPathTranslate15007AntiTransitPolicyEndToEnd(t *testing.T) {
	src := "policy-options {\n" +
		"  as-path null-as \"()\";\n" +
		"  as-path transit \".* 65000 .*\";\n" +
		"  policy-statement only-my-routes {\n" +
		"    term just-my-as { from { as-path null-as; } then accept; }\n" +
		"    term nothing-else { then reject; }\n" +
		"  }\n" +
		"}\n"
	tree, errs := config.NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected the canonical Junos anti-transit policy: %v", err)
	}
	po := cfg.PolicyOptions
	got := New().generatePolicyOptions(&po)
	for _, want := range []string{
		"bgp as-path access-list null-as permit ^$\n",
		"bgp as-path access-list transit permit ^(([0-9]+( [0-9]+)*) )?65000( ([0-9]+( [0-9]+)*))?$\n",
		"route-map only-my-routes permit 10",
		"match as-path null-as",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// The accept term's list must match only the empty path.
	re := renderedPattern15007(t, "null-as", "()")
	if re.MatchString("65000 65001") {
		t.Errorf("anti-transit accept list matches a learned path — route leak")
	}
	if !re.MatchString("") {
		t.Errorf("anti-transit accept list does not match the null path")
	}
}

// A REJECT term over an untranslatable list renders deny-all (the
// existing fail-closed arm keyed on the same predicate).
func TestASPathTranslate15007RejectTermOverUntranslatableDeniesAll(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"BAD": {Name: "BAD", Regex: "65[0-9]+"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t-reject", FromASPath: []string{"BAD"}, Action: "reject"},
				{Name: "t-accept", Action: "accept"},
			}, DefaultAction: "accept"},
		},
	}
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") {
		t.Fatalf("a dangling match survived for an untranslatable list:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10") {
		t.Fatalf("reject term over untranslatable list did not render deny-all:\n%s", got)
	}
}
