package config_test

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func findRouteFilter12529(nodes []*config.Node, want []string) *config.Node {
	for _, n := range nodes {
		for i, key := range n.Keys {
			if key == "route-filter" && reflect.DeepEqual(n.Keys[i:], want) {
				return n
			}
		}
		if found := findRouteFilter12529(n.Children, want); found != nil {
			return found
		}
	}
	return nil
}

func dumpKeys12529(nodes []*config.Node, into *[][]string) {
	for _, n := range nodes {
		*into = append(*into, append([]string(nil), n.Keys...))
		dumpKeys12529(n.Children, into)
	}
}

func TestExpandGroupsRetainsPackedRouteFilterRange12529(t *testing.T) {
	cases := []struct {
		name, filter string
		want         []string
		compileError bool
	}{
		{"upto", "from route-filter 10.0.0.0/8 upto /24", []string{"route-filter", "10.0.0.0/8", "upto", "/24"}, false},
		{"prefix-length-range", "from route-filter 10.0.0.0/8 prefix-length-range /16-/24", []string{"route-filter", "10.0.0.0/8", "prefix-length-range", "/16-/24"}, false},
		{"through", "from route-filter 10.0.0.0/8 through 10.0.0.0/24", []string{"route-filter", "10.0.0.0/8", "through", "10.0.0.0/24"}, true},
		{"protocol and range", "from protocol static route-filter 10.0.0.0/8 upto /24", []string{"route-filter", "10.0.0.0/8", "upto", "/24"}, false},
		{"exact control", "from route-filter 10.0.0.0/8 exact", []string{"route-filter", "10.0.0.0/8", "exact"}, false},
		{"orlonger control", "from route-filter 10.0.0.0/8 orlonger", []string{"route-filter", "10.0.0.0/8", "orlonger"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := "groups { G { policy-options { policy-statement P { term T " + tc.filter + "; } } } }\n" +
				"policy-options { apply-groups G; policy-statement P { term T then accept; } }"
			tree, errs := config.NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			if err := tree.ExpandGroups(); err != nil {
				t.Fatalf("ExpandGroups: %v", err)
			}
			if got := findRouteFilter12529(tree.Children, tc.want); got == nil {
				var keys [][]string
				dumpKeys12529(tree.Children, &keys)
				t.Fatalf("expanded tree lost inherited route-filter %q; keys=%q", tc.want, keys)
			}
			_, compileErr := config.CompileConfig(tree)
			if tc.compileError && compileErr == nil {
				t.Fatal("CompileConfig accepted unsupported `through` route-filter")
			}
			if !tc.compileError && compileErr != nil {
				t.Fatalf("CompileConfig after expansion: %v", compileErr)
			}
		})
	}
}

// Modifier followed by another clause in the same packed group
// statement: width over-consumption would swallow `then accept`
// into the filter and silently compile rf=[] (GLM R1 F1).
func TestExpandGroupsRouteFilterMidTailNotOverConsumed12529(t *testing.T) {
	text := "groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24 then accept; } } } }\n" +
		"policy-options { apply-groups G; policy-statement P { term T then reject; } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	want := []string{"route-filter", "10.0.0.0/8", "upto", "/24"}
	if got := findRouteFilter12529(tree.Children, want); got == nil {
		var keys [][]string
		dumpKeys12529(tree.Children, &keys)
		t.Fatalf("mid-tail route-filter over-consumed; keys=%q", keys)
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after expansion: %v", err)
	}
	found := false
	for _, pol := range compiled.PolicyOptions.PolicyStatements {
		for _, term := range pol.Terms {
			for _, rf := range term.RouteFilters {
				if rf.Prefix == "10.0.0.0/8" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("compiled policies lost the mid-tail route-filter: %+v", compiled.PolicyOptions)
	}
}

func TestExpandGroupsRetainsBracedTermRouteFilterRange12529(t *testing.T) {
	text := `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24; } } } }
policy-options { apply-groups G; policy-statement P { term T { then accept; } } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	want := []string{"route-filter", "10.0.0.0/8", "upto", "/24"}
	if findRouteFilter12529(tree.Children, want) == nil {
		var keys [][]string
		dumpKeys12529(tree.Children, &keys)
		t.Fatalf("expanded tree lost inherited route-filter %q; keys=%q", want, keys)
	}
}
