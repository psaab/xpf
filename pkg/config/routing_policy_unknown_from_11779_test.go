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
				for _, want := range []string{"policy-statement \"P\"", "term \"T\"", tc.leaf, "#11779"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("strict rejection %q does not identify %q", err, want)
					}
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
				if strings.Contains(warning, "#11779") && strings.Contains(warning, tc.leaf) {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("tolerant warnings %v omit the #11779 finding for %q", cfg.Warnings, tc.leaf)
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
				if err == nil || !strings.Contains(err.Error(), "through") ||
					strings.Contains(err.Error(), "#11779") {
					t.Fatalf("strict compile error = %v, want the route-filter through gate and no #11779 error", err)
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
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#11779") {
					t.Fatalf("tolerant compile reported supported route-filter as unknown: %q", warning)
				}
			}
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
	if strictErr == nil || !strings.Contains(strictErr.Error(), "rib") ||
		!strings.Contains(strictErr.Error(), "#11779") {
		t.Fatalf("unsupported leaf after bracketed values was not rejected: %v", strictErr)
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

// FAIL-ON-REVERT: an unclosed bracketed match must stop before a clause
// keyword and fail closed instead of swallowing `then accept` as list values.
func TestRoutingPolicyUnclosedBracketedFromListFailsClosed11779(t *testing.T) {
	src := `policy-options {
 prefix-list PL1 10.0.0.0/8;
 policy-statement P {
  term T from prefix-list [ PL1 PL2 rib inet.0 then accept;
 }
}`
	tree := parsePolicyTreeFromSource11779(t, src)
	_, strictErr := CompileConfig(tree)
	if strictErr == nil || !strings.Contains(strictErr.Error(), "closing bracket") ||
		!strings.Contains(strictErr.Error(), "#11779") {
		t.Fatalf("unclosed bracketed from-list was not rejected: %v", strictErr)
	}

	cfg, err := CompileConfigLenient(parsePolicyTreeFromSource11779(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.invalidFromSyntax11779 == "" || term.Action != "reject" || term.NextPolicy {
		t.Fatalf("unclosed list did not fail closed: invalidFromSyntax=%q Action=%q NextPolicy=%v",
			term.invalidFromSyntax11779, term.Action, term.NextPolicy)
	}
	if len(term.PrefixList) != 4 || term.PrefixList[0] != "PL1" ||
		term.PrefixList[1] != "PL2" || term.PrefixList[2] != "rib" ||
		term.PrefixList[3] != "inet.0" {
		t.Fatalf("bracketed values crossed `then`: %v", term.PrefixList)
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
		if term.invalidFromSyntax11779 != "" || len(term.UnknownFrom) != 0 ||
			term.Action != "accept" || len(term.PrefixList) != 2 ||
			term.PrefixList[0] != "then" || term.PrefixList[1] != "PL2" {
			t.Fatalf("lenient=%v quoted clause value changed: term=%+v", lenient, term)
		}
	}
}
