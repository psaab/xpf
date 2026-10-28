package config

import (
	"fmt"
	"reflect"
	"testing"
)

// #17202: the four routing-policy `from` list arms (protocol, prefix-list,
// community, as-path) were copy-pasted with two different "opaque block"
// predicates. #11779's broader `!IsLeaf && Children` predicate regressed
// `leaf { a; b; }` for prefix-list/community/as-path while protocol (narrower
// `len(Keys) > 1 && Children`) kept working, and collectProtocolList was a
// verbatim copy of plainListValues. The fix collapses the four arms into one
// `policyFromListValues` reader. This test pins the parity: every leaf ×
// every spelling below must give the SAME verdict and the SAME values.
//
// FAIL-ON-REVERT: restoring the per-arm predicates (or collectProtocolList)
// makes the value-block rows for prefix-list/community/as-path strict-reject
// with UnknownFrom=[pa pb] and values=[], failing those cells.

var policyFromListLeaves17202 = []struct {
	leaf   string
	a, b   string
	values func(*PolicyTerm) []string
}{
	{"protocol", "bgp", "ospf", func(t *PolicyTerm) []string { return t.FromProtocols }},
	{"prefix-list", "pa", "pb", func(t *PolicyTerm) []string { return t.PrefixList }},
	{"community", "pa", "pb", func(t *PolicyTerm) []string { return t.FromCommunity }},
	{"as-path", "pa", "pb", func(t *PolicyTerm) []string { return t.FromASPath }},
}

// definitions17202 returns the policy-options definitions that make the
// typed values (pa/pb) resolvable for prefix-list/community/as-path. Protocol
// names need no definition.
func definitions17202(leaf string) string {
	switch leaf {
	case "prefix-list":
		return "prefix-list pa 10.0.0.0/8; prefix-list pb 172.16.0.0/12;"
	case "community":
		return "community pa members 65000:1; community pb members 65000:2;"
	case "as-path":
		return `as-path pa "^65000"; as-path pb "^65001";`
	default:
		return ""
	}
}

func definitionsSet17202(leaf string) []string {
	switch leaf {
	case "prefix-list":
		return []string{
			"set policy-options prefix-list pa 10.0.0.0/8",
			"set policy-options prefix-list pb 172.16.0.0/12",
		}
	case "community":
		return []string{
			"set policy-options community pa members 65000:1",
			"set policy-options community pb members 65000:2",
		}
	case "as-path":
		return []string{
			`set policy-options as-path pa "^65000"`,
			`set policy-options as-path pb "^65001"`,
		}
	default:
		return nil
	}
}

func hierPolicy17202(leaf, fromBody, defs string) string {
	return fmt.Sprintf(`policy-options {
 %s
 policy-statement P {
  term T {
   from { %s }
   then accept;
  }
 }
}`, defs, fromBody)
}

func checkTerm17202(t *testing.T, label string, tree *ConfigTree, leaf string, get func(*PolicyTerm) []string, want []string, wantOpaque bool) {
	t.Helper()
	_, strictErr := CompileConfig(tree.Clone())
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("%s: tolerant compile: %v", label, err)
	}
	if len(cfg.PolicyOptions.PolicyStatements) == 0 {
		t.Fatalf("%s: no policy compiled", label)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	got := get(term)
	if wantOpaque {
		if strictErr == nil {
			t.Errorf("%s: strict compile accepted opaque body; want #11779 reject", label)
		}
		if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "x" {
			t.Errorf("%s: UnknownFrom = %v, want [x]", label, term.UnknownFrom)
		}
		if term.Action != "reject" {
			t.Errorf("%s: Action = %q, want reject (fail closed)", label, term.Action)
		}
	} else {
		if strictErr != nil {
			t.Errorf("%s: strict compile rejected: %v", label, strictErr)
		}
		if len(term.UnknownFrom) != 0 {
			t.Errorf("%s: UnknownFrom = %v, want []", label, term.UnknownFrom)
		}
		if term.Action != "accept" {
			t.Errorf("%s: Action = %q, want accept", label, term.Action)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: values = %v, want %v", label, got, want)
	}
	_ = leaf
}

// TestRoutingPolicyFromListParity17202 runs the {4 leaves} × {bracket,
// value-block, flat-set repeated, flat-set bracket, opaque name{x;}} matrix.
// Value rows must compile both values for every leaf; the opaque row must
// stay strict-rejected (#11779) with the authored value kept, the child name
// quarantined, and the tolerant term rejecting.
func TestRoutingPolicyFromListParity17202(t *testing.T) {
	for _, lc := range policyFromListLeaves17202 {
		leaf, get, a, b := lc.leaf, lc.values, lc.a, lc.b
		t.Run(leaf+"/bracket", func(t *testing.T) {
			src := hierPolicy17202(leaf, fmt.Sprintf("%s [ %s %s ];", leaf, a, b), definitions17202(leaf))
			checkTerm17202(t, "bracket", parseHierText(t, src), leaf, get, []string{a, b}, false)
		})
		t.Run(leaf+"/value-block", func(t *testing.T) {
			src := hierPolicy17202(leaf, fmt.Sprintf("%s { %s; %s; }", leaf, a, b), definitions17202(leaf))
			checkTerm17202(t, "value-block", parseHierText(t, src), leaf, get, []string{a, b}, false)
		})
		t.Run(leaf+"/flat-set-repeated", func(t *testing.T) {
			cmds := append(definitionsSet17202(leaf),
				fmt.Sprintf("set policy-options policy-statement P term T from %s %s", leaf, a),
				fmt.Sprintf("set policy-options policy-statement P term T from %s %s", leaf, b),
				"set policy-options policy-statement P term T then accept")
			checkTerm17202(t, "flat-set-repeated", buildTreeFromSet(t, cmds), leaf, get, []string{a, b}, false)
		})
		t.Run(leaf+"/flat-set-bracket", func(t *testing.T) {
			cmds := append(definitionsSet17202(leaf),
				fmt.Sprintf("set policy-options policy-statement P term T from %s [ %s %s ]", leaf, a, b),
				"set policy-options policy-statement P term T then accept")
			checkTerm17202(t, "flat-set-bracket", buildTreeFromSet(t, cmds), leaf, get, []string{a, b}, false)
		})
		t.Run(leaf+"/opaque", func(t *testing.T) {
			src := hierPolicy17202(leaf, fmt.Sprintf("%s %s { x; }", leaf, a), definitions17202(leaf))
			checkTerm17202(t, "opaque", parseHierText(t, src), leaf, get, []string{a}, true)
		})
		t.Run(leaf+"/nested-value-block", func(t *testing.T) {
			// `leaf { a { x; } }`: leaf child with its own body and no
			// value on the leaf's keys — must also fail closed (#11779),
			// quarantining the child name without promoting a/x. For
			// prefix-list the strict error surfaces through the
			// dangling-reference gate as well; either way it must reject.
			src := hierPolicy17202(leaf, fmt.Sprintf("%s { %s { x; } }", leaf, a), definitions17202(leaf))
			_, strictErr := CompileConfig(parseHierText(t, src))
			if strictErr == nil {
				t.Fatalf("strict compile accepted nested opaque value block")
			}
			cfg, err := CompileConfigLenient(parseHierText(t, src))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if leaf == "prefix-list" {
				if term.Action != "reject" {
					t.Fatalf("nested opaque did not fail closed: Action=%q UnknownFrom=%v", term.Action, term.UnknownFrom)
				}
			} else if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != a || term.Action != "reject" {
				t.Fatalf("nested opaque did not fail closed: UnknownFrom=%v Action=%q", term.UnknownFrom, term.Action)
			}
			if got := get(term); len(got) != 0 {
				t.Fatalf("nested opaque promoted values %v, want none", got)
			}
		})
	}
}
