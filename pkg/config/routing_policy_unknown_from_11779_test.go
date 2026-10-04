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
