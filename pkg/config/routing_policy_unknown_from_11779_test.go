package config

import (
	"fmt"
	"strings"
	"testing"
)

func policyUnknownFromTree11779(t *testing.T, shape, leaf, value string) *ConfigTree {
	t.Helper()
	switch shape {
	case "from block":
		src := fmt.Sprintf(`policy-options {
 policy-statement P {
  term T {
   from { %s %s; }
   then accept;
  }
 }
}`, leaf, value)
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse hierarchical from block: %v", errs)
		}
		return tree
	case "packed from":
		src := fmt.Sprintf(`policy-options {
 policy-statement P {
  term T {
   from %s %s;
   then accept;
  }
 }
}`, leaf, value)
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse packed from: %v", errs)
		}
		return tree
	case "packed term":
		src := fmt.Sprintf(`policy-options {
 policy-statement P {
  term T from %s %s then accept;
 }
}`, leaf, value)
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse packed term: %v", errs)
		}
		return tree
	case "flat set":
		return buildTreeFromSet(t, []string{
			fmt.Sprintf("set policy-options policy-statement P term T from %s %s", leaf, value),
			"set policy-options policy-statement P term T then accept",
		})
	default:
		t.Fatalf("unknown test spelling %q", shape)
		return nil
	}
}

// FAIL-ON-REVERT: restoring the five-case-only parsePolicyTermChildren switch
// (or removing the unknown-from strict gate) makes every case compile as an
// unconditional accept. The packed shapes also pin the raw-tail and inline
// parser paths so a fix limited to hierarchical child nodes cannot pass.
func TestRoutingPolicyUnknownFromDimensionsRejected11779(t *testing.T) {
	for _, tc := range []struct{ leaf, value string }{
		{"rib", "inet.0"},
		{"instance", "master"},
		{"neighbor", "10.0.0.1"},
		{"next-hop", "10.0.0.1"},
		{"metric", "10"},
		{"tag", "100"},
	} {
		for _, shape := range []string{"from block", "packed from", "packed term", "flat set"} {
			t.Run(shape+"/"+tc.leaf, func(t *testing.T) {
				_, err := CompileConfig(policyUnknownFromTree11779(t, shape, tc.leaf, tc.value))
				if err == nil {
					t.Fatalf("`from %s %s` in %s compiled clean; its constraint would vanish and widen the accept term",
						tc.leaf, tc.value, shape)
				}
			})
		}
	}
}

// Tolerant boot remains possible, but the unknown dimension must survive
// compilation and the term must not retain the widened accept action.
func TestRoutingPolicyUnknownFromFailsClosedOnTolerantLoad11779(t *testing.T) {
	for _, tc := range []struct{ leaf, value string }{
		{"rib", "inet.0"},
		{"instance", "master"},
		{"neighbor", "10.0.0.1"},
		{"next-hop", "10.0.0.1"},
		{"metric", "10"},
		{"tag", "100"},
	} {
		t.Run(tc.leaf, func(t *testing.T) {
			tree := policyUnknownFromTree11779(t, "flat set", tc.leaf, tc.value)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != tc.leaf {
				t.Fatalf("UnknownFrom = %v, want [%s]", term.UnknownFrom, tc.leaf)
			}
			if term.Action != "reject" || term.NextPolicy {
				t.Fatalf("unsupported from match did not fail closed: Action=%q NextPolicy=%v", term.Action, term.NextPolicy)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, tc.leaf) {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("tolerant warnings %v omit unsupported from leaf %q", cfg.Warnings, tc.leaf)
			}
		})
	}
}

// Positive control: none of the five compiled routing-policy from types is
// labeled unknown by the new recorder, and their typed fields remain intact.
func TestRoutingPolicySupportedFromDimensionsRemainCompiled11779(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options prefix-list PL 10.0.0.0/8",
		"set policy-options community COMM members 65000:1",
		`set policy-options as-path ASP "^65000"`,
		"set policy-options policy-statement P term T from protocol bgp",
		"set policy-options policy-statement P term T from prefix-list PL",
		"set policy-options policy-statement P term T from route-filter 10.0.0.0/8 exact",
		"set policy-options policy-statement P term T from community COMM",
		"set policy-options policy-statement P term T from as-path ASP",
		"set policy-options policy-statement P term T then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("supported routing-policy from types rejected: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.FromProtocols) != 1 || term.FromProtocols[0] != "bgp" ||
		len(term.PrefixList) != 1 || term.PrefixList[0] != "PL" ||
		len(term.RouteFilters) != 1 || term.RouteFilters[0].Prefix != "10.0.0.0/8" ||
		len(term.FromCommunity) != 1 || term.FromCommunity[0] != "COMM" ||
		len(term.FromASPath) != 1 || term.FromASPath[0] != "ASP" {
		t.Fatalf("supported from dimensions were not compiled intact: %+v", term)
	}
	if len(term.UnknownFrom) != 0 {
		t.Fatalf("supported from dimensions were marked unknown: %v", term.UnknownFrom)
	}
}

func parsePolicyTreeFromSource11779(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse test source: %v", errs)
	}
	return tree
}

// FAIL-ON-REVERT: a route-filter's trailing argument belongs to that leaf, not
// to UnknownFrom. Strictly supported match types preserve their typed fields;
// `through` remains rejected by its backend gate, not by #11779. Tolerant
// compilation must retain the typed term without forcing its action to reject.
func TestRoutingPolicyPackedRouteFilterTrailersRemainTyped11779(t *testing.T) {
	for _, tc := range []struct {
		matchType, trailing string
		wantUpto            int
		wantRangeLow        int
		wantRangeHigh       int
		wantThrough         string
		strictReject        bool
	}{
		{matchType: "upto", trailing: "/24", wantUpto: 24},
		{matchType: "prefix-length-range", trailing: "/16-/24", wantRangeLow: 16, wantRangeHigh: 24},
		{matchType: "through", trailing: "10.0.0.0/16", wantThrough: "10.0.0.0/16", strictReject: true},
	} {
		t.Run(tc.matchType, func(t *testing.T) {
			src := fmt.Sprintf(`policy-options {
 policy-statement P {
  term T {
   from route-filter 10.0.0.0/8 %s %s;
   then accept;
  }
 }
}`, tc.matchType, tc.trailing)
			check := func(path string, cfg *Config) {
				t.Helper()
				ps := cfg.PolicyOptions.PolicyStatements["P"]
				if ps == nil || len(ps.Terms) != 1 {
					t.Fatalf("%s compiled policy terms = %+v, want one term", path, ps)
				}
				term := ps.Terms[0]
				if len(term.UnknownFrom) != 0 || term.Action != "accept" {
					t.Fatalf("%s misclassified supported route-filter trailer: UnknownFrom=%v Action=%q",
						path, term.UnknownFrom, term.Action)
				}
				if len(term.RouteFilters) != 1 {
					t.Fatalf("%s compiled route-filters = %+v, want one", path, term.RouteFilters)
				}
				rf := term.RouteFilters[0]
				if rf.Prefix != "10.0.0.0/8" || rf.MatchType != tc.matchType ||
					rf.UptoLen != tc.wantUpto || rf.RangeLow != tc.wantRangeLow ||
					rf.RangeHigh != tc.wantRangeHigh || rf.ThroughPrefix != tc.wantThrough {
					t.Fatalf("%s compiled route-filter = %+v, want prefix=10.0.0.0/8 match=%s trailing=%s",
						path, rf, tc.matchType, tc.trailing)
				}
			}

			cfg, err := CompileConfig(parsePolicyTreeFromSource11779(t, src))
			if tc.strictReject {
				if err == nil {
					t.Fatalf("strict compile accepted unsupported through route-filter")
				}
			} else {
				if err != nil {
					t.Fatalf("supported route-filter trailer rejected on strict compile: %v", err)
				}
				check("strict", cfg)
			}

			cfg, err = CompileConfigLenient(parsePolicyTreeFromSource11779(t, src))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			check("tolerant", cfg)
		})
	}
}

// FAIL-ON-REVERT: each second bracketed value must remain part of its
// supported multi-value match, rather than being recorded as an unknown leaf.
func TestRoutingPolicyPackedTermBracketedFromValuesRemainAccepted11779(t *testing.T) {
	src := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 community C1 members 65000:1;
 community C2 members 65000:2;
 as-path AP1 "^65000";
 as-path AP2 "^65001";
 policy-statement P {
  term T-PL from prefix-list [ PL1 PL2 ] then accept;
  term T-COMM from community [ C1 C2 ] then accept;
  term T-ASPATH from as-path [ AP1 AP2 ] then accept;
 }
}`
	want := map[string][][]string{
		"T-PL":     {{"PL1", "PL2"}, nil, nil},
		"T-COMM":   {nil, {"C1", "C2"}, nil},
		"T-ASPATH": {nil, nil, {"AP1", "AP2"}},
	}
	for _, lenient := range []bool{false, true} {
		tree := parsePolicyTreeFromSource11779(t, src)
		var cfg *Config
		var err error
		if lenient {
			cfg, err = CompileConfigLenient(tree)
		} else {
			cfg, err = CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("lenient=%v compile: %v", lenient, err)
		}
		terms := cfg.PolicyOptions.PolicyStatements["P"].Terms
		if len(terms) != len(want) {
			t.Fatalf("lenient=%v compiled %d terms, want %d", lenient, len(terms), len(want))
		}
		for _, term := range terms {
			wantValues := want[term.Name]
			gotValues := [][]string{term.PrefixList, term.FromCommunity, term.FromASPath}
			for i := range gotValues {
				if len(gotValues[i]) != len(wantValues[i]) {
					t.Errorf("lenient=%v term %s values[%d]=%v, want %v",
						lenient, term.Name, i, gotValues[i], wantValues[i])
					continue
				}
				for j := range gotValues[i] {
					if gotValues[i][j] != wantValues[i][j] {
						t.Errorf("lenient=%v term %s values[%d]=%v, want %v",
							lenient, term.Name, i, gotValues[i], wantValues[i])
						break
					}
				}
			}
			if len(term.UnknownFrom) != 0 || term.Action != "accept" {
				t.Errorf("lenient=%v term %s changed supported match semantics: UnknownFrom=%v Action=%q",
					lenient, term.Name, term.UnknownFrom, term.Action)
			}
		}
	}
}

// A multi-value loop must stop at the bracket boundary. Otherwise the
// following unsupported leaf would be swallowed as another prefix-list name.
func TestRoutingPolicyUnknownAfterPackedBracketedFromStillFailsClosed11779(t *testing.T) {
	src := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 policy-statement P {
  term T from prefix-list [ PL1 PL2 ] rib inet.0 then accept;
 }
}`
	_, strictErr := CompileConfig(parsePolicyTreeFromSource11779(t, src))
	if strictErr == nil {
		t.Fatalf("unsupported leaf after bracketed values compiled cleanly")
	}

	cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "rib" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("unsupported trailing leaf did not fail closed: UnknownFrom=%v Action=%q NextPolicy=%v",
			term.UnknownFrom, term.Action, term.NextPolicy)
	}
}

// FAIL-ON-REVERT: a route-filter trailer must not absorb a following
// schema-known `prefix-list` sibling when its packed reader falls back.
func TestRoutingPolicyPackedRouteFilterPreservesTypedSibling11779(t *testing.T) {
	src := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T {
   from route-filter 10.0.0.0/8 upto /24 prefix-list PL1;
   then accept;
  }
 }
}`
	for _, lenient := range []bool{false, true} {
		tree := parsePolicyTreeFromSource11779(t, src)
		var cfg *Config
		var err error
		if lenient {
			cfg, err = CompileConfigLenient(tree)
		} else {
			cfg, err = CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("lenient=%v compile: %v", lenient, err)
		}
		term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
		if term.Action != "accept" || len(term.UnknownFrom) != 0 {
			t.Fatalf("lenient=%v lost supported from match: Action=%q UnknownFrom=%v",
				lenient, term.Action, term.UnknownFrom)
		}
		if len(term.RouteFilters) != 1 ||
			term.RouteFilters[0].Prefix != "10.0.0.0/8" ||
			term.RouteFilters[0].MatchType != "upto" ||
			term.RouteFilters[0].UptoLen != 24 {
			t.Fatalf("lenient=%v route-filter = %+v, want typed upto /24",
				lenient, term.RouteFilters)
		}
		if len(term.PrefixList) != 1 || term.PrefixList[0] != "PL1" {
			t.Fatalf("lenient=%v prefix-list = %v, want [PL1]", lenient, term.PrefixList)
		}
	}
}

// FAIL-ON-REVERT: compact-normalized `from` children must be re-split by
// schema arity so an opaque trailer fails closed and a supported sibling stays
// a distinct typed match.
func TestRoutingPolicyNormalizedFromTail11779(t *testing.T) {
	unknown := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T {
   from prefix-list [ PL1 ] rib inet.0;
   then accept;
  }
 }
}`
	if _, err := CompileConfig(parsePolicyTreeFromSource11779(t, unknown)); err == nil {
		t.Fatalf("unknown normalized trailer compiled cleanly")
	}
	cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, unknown))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.PrefixList) != 1 || term.PrefixList[0] != "PL1" ||
		len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "rib" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("unknown trailer widened tolerant term: PrefixList=%v UnknownFrom=%v Action=%q NextPolicy=%v",
			term.PrefixList, term.UnknownFrom, term.Action, term.NextPolicy)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("tolerant compile did not warn about the quarantined unknown match")
	}

	sibling := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T {
   from route-filter 10.0.0.0/8 exact prefix-list PL1;
   then accept;
  }
 }
}`
	for _, lenient := range []bool{false, true} {
		tree := parsePolicyTreeFromSource11779(t, sibling)
		var got *Config
		if lenient {
			got, err = CompileConfigLenient(tree)
		} else {
			got, err = CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("lenient=%v supported siblings rejected: %v", lenient, err)
		}
		term := got.PolicyOptions.PolicyStatements["P"].Terms[0]
		if term.Action != "accept" || len(term.UnknownFrom) != 0 ||
			len(term.PrefixList) != 1 || term.PrefixList[0] != "PL1" ||
			len(term.RouteFilters) != 1 ||
			term.RouteFilters[0].Prefix != "10.0.0.0/8" ||
			term.RouteFilters[0].MatchType != "exact" {
			t.Fatalf("lenient=%v supported siblings collapsed: PrefixList=%v RouteFilters=%+v UnknownFrom=%v Action=%q",
				lenient, term.PrefixList, term.RouteFilters, term.UnknownFrom, term.Action)
		}
	}
}

// FAIL-ON-REVERT: an unclosed bracketed match must stop before a clause
// keyword and fail closed instead of swallowing `then accept` as list values.
func TestRoutingPolicyUnclosedBracketedFromListFailsClosed11779(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "packed term",
			src: `policy-options {
 prefix-list PL1 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 policy-statement P {
  term T from prefix-list [ PL1 PL2 rib inet.0 then accept;
 }
}`,
		},
		{
			name: "bracketed then sibling",
			src: `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T {
   from prefix-list [ PL1 then;
   then accept;
  }
 }
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parsePolicyTreeFromSource11779(t, tc.src)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted an unclosed bracketed from-list")
			}
			cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, tc.src))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "reject" || term.NextPolicy {
				t.Fatalf("unclosed list did not fail closed: Action=%q NextPolicy=%v",
					term.Action, term.NextPolicy)
			}
			hasPL1 := false
			for _, name := range term.PrefixList {
				if name == "PL1" {
					hasPL1 = true
				}
				if name == "then" || name == "accept" {
					t.Fatalf("bracketed clause tokens became prefix-list values: %v", term.PrefixList)
				}
			}
			if !hasPL1 {
				t.Fatalf("supported prefix-list value was not retained: %v", term.PrefixList)
			}
		})
	}
}

// A quoted clause keyword remains a valid match-list value; only an unquoted
// clause boundary inside the bracketed run signals the missing closer.
func TestRoutingPolicyQuotedClauseKeywordInBracketedFromList11779(t *testing.T) {
	src := `policy-options {
 prefix-list then 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 policy-statement P {
  term T from prefix-list [ "then" PL2 ] then accept;
 }
}`
	for _, lenient := range []bool{false, true} {
		tree := parsePolicyTreeFromSource11779(t, src)
		var cfg *Config
		var err error
		if lenient {
			cfg, err = CompileConfigLenient(tree)
		} else {
			cfg, err = CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("lenient=%v compile: %v", lenient, err)
		}
		term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
		if len(term.UnknownFrom) != 0 || term.Action != "accept" ||
			len(term.PrefixList) != 2 ||
			term.PrefixList[0] != "then" || term.PrefixList[1] != "PL2" {
			t.Fatalf("lenient=%v quoted clause value changed: PrefixList=%v UnknownFrom=%v Action=%q",
				lenient, term.PrefixList, term.UnknownFrom, term.Action)
		}
	}
}

// FAIL-ON-REVERT: a bare `then` prefix-list name is a value in a balanced
// bracketed list for every term/from shape; quotes are optional.
func TestRoutingPolicyClosedBracketedBareClauseValues11779(t *testing.T) {
	for _, shape := range []string{"packed-term", "packed-from", "from-block"} {
		for _, value := range []string{"then", `"then"`} {
			t.Run(shape+"/"+strings.ReplaceAll(value, `"`, "quoted-"), func(t *testing.T) {
				src := `policy-options {
 prefix-list then 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 policy-statement P {
  term T ` + map[string]string{
					"packed-term": `from prefix-list [ ` + value + ` PL2 ] then accept;`,
					"packed-from": `{ from prefix-list [ ` + value + ` PL2 ]; then accept; }`,
					"from-block":  `{ from { prefix-list [ ` + value + ` PL2 ]; } then accept; }`,
				}[shape] + `
 }
}`
				for _, lenient := range []bool{false, true} {
					tree := parsePolicyTreeFromSource11779(t, src)
					var got *Config
					var err error
					if lenient {
						got, err = CompileConfigLenient(tree)
					} else {
						got, err = CompileConfig(tree)
					}
					if err != nil {
						t.Fatalf("lenient=%v compile: %v", lenient, err)
					}
					term := got.PolicyOptions.PolicyStatements["P"].Terms[0]
					if len(term.UnknownFrom) != 0 || term.Action != "accept" ||
						len(term.PrefixList) != 2 ||
						term.PrefixList[0] != "then" || term.PrefixList[1] != "PL2" {
						t.Fatalf("lenient=%v closed-list value changed: PrefixList=%v UnknownFrom=%v Action=%q",
							lenient, term.PrefixList, term.UnknownFrom, term.Action)
					}
				}
			})
		}
	}
}

// FAIL-ON-REVERT: unbracketed scalar leaves consume their schema arity only;
// a trailing unsupported dimension must remain separate and fail closed.
func TestRoutingPolicyUnbracketedScalarUnknownTrailerFailsClosed11779(t *testing.T) {
	unknown := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 prefix-list rib 172.16.0.0/12;
 policy-statement P {
  term T {
   from prefix-list PL1 rib inet.0;
   then accept;
  }
 }
}`
	if _, err := CompileConfig(parsePolicyTreeFromSource11779(t, unknown)); err == nil {
		t.Fatal("strict compile accepted an unsupported from trailer")
	}
	cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, unknown))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.PrefixList) != 1 || term.PrefixList[0] != "PL1" ||
		len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "rib" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("trailing dimension widened tolerant term: PrefixList=%v UnknownFrom=%v Action=%q NextPolicy=%v",
			term.PrefixList, term.UnknownFrom, term.Action, term.NextPolicy)
	}

	// One scalar value named "rib" is still the complete prefix-list leaf.
	single := `policy-options {
 prefix-list rib 172.16.0.0/12;
 policy-statement P {
  term T {
   from prefix-list rib;
   then accept;
  }
 }
}`
	cfg, err = CompileConfig(parsePolicyTreeFromSource11779(t, single))
	if err != nil {
		t.Fatalf("single-value prefix-list name rejected: %v", err)
	}
	term = cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.PrefixList) != 1 || term.PrefixList[0] != "rib" ||
		len(term.UnknownFrom) != 0 || term.Action != "accept" {
		t.Fatalf("single-value prefix-list was split: PrefixList=%v UnknownFrom=%v Action=%q",
			term.PrefixList, term.UnknownFrom, term.Action)
	}
}

// FAIL-ON-REVERT: canonical serializers remove bracket delimiters from leaf
// lists. Replaying their text must preserve every supported routing-policy
// value rather than turning later members into unknown leaves.
func TestRoutingPolicyFromMultiValuesSurviveCanonicalReplay11779(t *testing.T) {
	src := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 community C1 members 65000:1;
 community C2 members 65000:2;
 as-path AP1 "^65000";
 as-path AP2 "^65001";
 policy-statement P {
  term T {
   from protocol [ direct static ];
   from prefix-list [ PL1 PL2 ];
   from community [ C1 C2 ];
   from as-path [ AP1 AP2 ];
   then accept;
  }
 }
	}`
	tree := parsePolicyTreeFromSource11779(t, src)
	for _, replay := range []struct {
		name string
		text string
	}{
		{"Format", tree.Format()},
		{"FormatSet", tree.FormatSet()},
	} {
		t.Run(replay.name, func(t *testing.T) {
			var replayed *ConfigTree
			if replay.name == "FormatSet" {
				replayed = buildTreeFromSet(t, strings.Split(strings.TrimSpace(replay.text), "\n"))
			} else {
				replayed = parsePolicyTreeFromSource11779(t, replay.text)
			}
			for _, lenient := range []bool{false, true} {
				var cfg *Config
				var err error
				if lenient {
					cfg, err = CompileConfigLenient(replayed.Clone())
				} else {
					cfg, err = CompileConfig(replayed.Clone())
				}
				if err != nil {
					t.Fatalf("lenient=%v replay compile: %v", lenient, err)
				}
				term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
				if strings.Join(term.FromProtocols, ",") != "direct,static" ||
					strings.Join(term.PrefixList, ",") != "PL1,PL2" ||
					strings.Join(term.FromCommunity, ",") != "C1,C2" ||
					strings.Join(term.FromASPath, ",") != "AP1,AP2" ||
					len(term.UnknownFrom) != 0 || term.Action != "accept" {
					t.Fatalf("lenient=%v replay changed routing-policy semantics: %+v", lenient, term)
				}
			}
		})
	}
}

// FAIL-ON-REVERT: both packed keys and the child body of a compact term are
// semantic input. The unsupported packed `from` predicate cannot disappear
// just because the same node also has a `then` child.
func TestRoutingPolicyMixedPackedTermAndBodyFailsClosed11779(t *testing.T) {
	src := `policy-options {
 policy-statement P {
  term T from neighbor 10.0.0.1 { then accept; }
 }
}`
	tree := parsePolicyTreeFromSource11779(t, src)
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict compile ignored packed `from` keys because the term had children")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "neighbor" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("mixed term did not retain and fail closed on packed from: %+v", term)
	}
}

// FAIL-ON-REVERT: a policy-level `from` is not a term, but must not be silently
// ignored while an accompanying default accept remains active.
func TestRoutingPolicyPolicyLevelFromFailsClosed11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 policy-statement P {
  from neighbor 10.0.0.1;
  then accept;
  term T {
   from { protocol bgp; }
   then accept;
  }
 }
}`)
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict compile ignored unsupported policy-level from")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	stmt := cfg.PolicyOptions.PolicyStatements["P"]
	if stmt.DefaultAction != "reject" || len(stmt.UnknownFrom) != 1 ||
		stmt.UnknownFrom[0] != "neighbor" {
		t.Fatalf("policy-level from did not fail closed: %+v", stmt)
	}
	if len(stmt.Terms) != 1 || stmt.Terms[0].Action != "reject" ||
		stmt.Terms[0].NextPolicy {
		t.Fatalf("policy-level from did not fail closed for its terms: %+v", stmt.Terms)
	}
}

// FAIL-ON-REVERT: a from leaf with an opaque child body must not promote those
// child tokens into prefix-list names and lose the unsupported nested match.
func TestRoutingPolicyNestedUnknownUnderMultiValueFromFailsClosed11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T {
   from { prefix-list PL1 { neighbor 10.0.0.1; } }
   then accept;
  }
 }
}`)
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict compile accepted an opaque body beneath prefix-list")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "neighbor" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("nested unknown from did not fail closed: %+v", term)
	}
}

// FAIL-ON-REVERT: invalid route-filter operands are not typed trailer values.
// In particular `upto rib` must not become an unset /32-wide filter.
func TestRoutingPolicyInvalidRouteFilterTrailerFailsClosed11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 policy-statement P {
  term T {
   from { route-filter 10.0.0.0/8 upto rib; }
   then accept;
  }
 }
}`)
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict compile accepted nonnumeric route-filter upto operand")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) == 0 || term.UnknownFrom[0] != "rib" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("invalid trailer did not fail closed: %+v", term)
	}
}

// FAIL-ON-REVERT: clause-like words inside a bracket list do not prove that the
// list closed. A quoted "then" must not hide an absent closing bracket.
func TestRoutingPolicyQuotedClauseInUnclosedListFailsClosed11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T from prefix-list [ PL1 "then" reject;
 }
}`)
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict compile accepted quoted clause token in an unclosed from list")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "reject" || term.NextPolicy ||
		strings.Contains(strings.Join(term.PrefixList, " "), "reject") {
		t.Fatalf("quoted clause token masked malformed list: %+v", term)
	}
}

// FAIL-ON-REVERT: every term changed by tolerant compilation must be named in
// the warning; warning only for the first while rewriting all is misleading.
func TestRoutingPolicyTolerantWarningNamesEveryChangedTerm11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 policy-statement P {
  term FIRST { from { rib inet.0; } then accept; }
  term SECOND { from { neighbor 10.0.0.1; } then next policy; }
 }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, name := range []string{"FIRST", "SECOND"} {
		if !strings.Contains(warnings, name) {
			t.Errorf("tolerant warnings omit changed term %s: %v", name, cfg.Warnings)
		}
	}
	for _, term := range cfg.PolicyOptions.PolicyStatements["P"].Terms {
		if term.Action != "reject" || term.NextPolicy {
			t.Errorf("term %s was not forced to reject: %+v", term.Name, term)
		}
	}
}

// FAIL-ON-REVERT: the packed-term protocol reader must stop at the same
// unsupported match heads as the block reader and quarantine the unknown term.
func TestRoutingPolicyPackedProtocolUnknownTailFailsClosed11779(t *testing.T) {
	tree := parsePolicyTreeFromSource11779(t, `policy-options {
 policy-statement P {
  term T from protocol bgp neighbor 10.0.0.1 then accept;
 }
}`)
	if _, err := CompileConfig(tree.Clone()); err == nil ||
		!strings.Contains(err.Error(), "`from neighbor`") {
		t.Fatalf("strict compile did not report the unknown from leaf: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if strings.Join(term.FromProtocols, ",") != "bgp" ||
		len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "neighbor" ||
		term.Action != "reject" || term.NextPolicy {
		t.Fatalf("packed protocol tail was not quarantined: %+v", term)
	}
}

// FAIL-ON-REVERT: the bracketed term "then" is a value, and its balanced
// closure is sufficient even when the term has no local action sibling.
func TestRoutingPolicyActionlessClosedFromListRemainsBalanced11779(t *testing.T) {
	for _, src := range []string{
		`policy-options {
 prefix-list then 10.0.0.0/8;
 policy-statement P { term T { from { prefix-list [ then ]; } } }
}`,
		`policy-options {
 prefix-list then 10.0.0.0/8;
 policy-statement P {
  term T { from { prefix-list [ then ]; } }
  term T { then accept; }
 }
}`,
	} {
		cfg, err := CompileConfig(parsePolicyTreeFromSource11779(t, src))
		if err != nil {
			t.Fatalf("balanced actionless list was rejected: %v", err)
		}
		term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
		if len(term.PrefixList) != 1 || term.PrefixList[0] != "then" ||
			term.invalidFromSyntax11779 != "" {
			t.Fatalf("balanced clause-named list value changed: %+v", term)
		}
	}
}

// FAIL-ON-REVERT: provenance-less canonical text retains multi-values, while
// known unsupported Junos from heads still split into UnknownFrom.
func TestRoutingPolicyFromMultiValuesAndUnknownTailWithoutBrackets11779(t *testing.T) {
	for _, tc := range []struct {
		list string
		tail string
	}{
		{"prefix-list PL1 PL2", "rib inet.0"},
		{"community C1 C2", "neighbor 10.0.0.1"},
		{"as-path AP1 AP2", "tag 100"},
	} {
		src := `policy-options {
 prefix-list PL1 10.0.0.0/8; prefix-list PL2 172.16.0.0/12;
 community C1 members 65000:1; community C2 members 65000:2;
 as-path AP1 "^65000"; as-path AP2 "^65001";
 policy-statement P { term T { from ` + tc.list + ` ` + tc.tail + `; then accept; } }
}`
		cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, src))
		if err != nil {
			t.Fatalf("tolerant compile for %q: %v", tc.list, err)
		}
		term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
		if term.Action != "reject" || len(term.UnknownFrom) == 0 ||
			!strings.Contains(strings.Join(term.UnknownFrom, " "), strings.Fields(tc.tail)[0]) {
			t.Errorf("unsupported tail was not separated from %q: %+v", tc.list, term)
		}
	}
}
