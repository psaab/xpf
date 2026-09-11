package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCommitValidationNormalizesBeforeGroupExpansion8921 pins the ORDER of the
// commit-check schema path against the compile path.
//
// ExpandGroups merges a group body into inline config by the statement's
// shape. It used to run on the tree as authored, and only then did schema
// validation normalize brace-elided statements. So a group body spelling
// `neighbor 192.0.2.1 hold-time 2;` packed did not meet the inline
// `neighbor 192.0.2.1 { hold-time 30; }`: it was appended beside it instead of
// being overridden, then normalized, and the invalid 2 was REFUSED -- while the
// braced group body merged, the inline 30 won, and the same configuration
// validated clean. The compiler normalizes before expanding and accepted both,
// so commit-check and compile disagreed about one config.
//
// FAIL-ON-REVERT: drop the NormalizeCompactForScan call in
// schemaValidateExpandedTreeForNode and the compact cells refuse the override.
func TestCommitValidationNormalizesBeforeGroupExpansion8921(t *testing.T) {
	const pre = `routing-options { autonomous-system 65000; } `
	const inline = `protocols { bgp { group g1 { neighbor 192.0.2.1 { hold-time 30; peer-as 65001; } } } }`
	groups := []struct{ name, body string }{
		{"braced group body",
			`groups { gg { protocols { bgp { group g1 { neighbor 192.0.2.1 { hold-time 2; } } } } } } apply-groups gg; `},
		{"compact group body",
			`groups { gg { protocols { bgp { group g1 { neighbor 192.0.2.1 hold-time 2; } } } } } apply-groups gg; `},
	}
	parse := func(t *testing.T, text string) *config.ConfigTree {
		t.Helper()
		tree, errs := config.NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("fixture does not parse: %v\n%s", errs, text)
		}
		return tree
	}
	for _, g := range groups {
		for _, nodeID := range []int{-1, 0} {
			t.Run(g.name, func(t *testing.T) {
				// CONTROL: with nothing overriding it, the inherited hold-time 2
				// is refused in this spelling -- the validator sees the value, so
				// an accepted override below is the merge working and not the
				// value going unobserved.
				err := schemaValidateExpandedTreeForNode(parse(t, pre+g.body), nodeID)
				if err == nil || !strings.Contains(err.Error(), "hold-time") {
					t.Fatalf("CONTROL (node %d): the inherited invalid hold-time was not refused "+
						"(err=%v), so this cell cannot observe the override", nodeID, err)
				}
				if err := schemaValidateExpandedTreeForNode(parse(t, pre+g.body+inline), nodeID); err != nil {
					t.Errorf("node %d: the inline hold-time 30 must override the group's 2, as it "+
						"does for the braced group body and in the compiler: %v", nodeID, err)
				}
			})
		}
	}
}
