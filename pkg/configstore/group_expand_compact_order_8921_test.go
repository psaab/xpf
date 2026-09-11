package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCommitValidationNormalizesBeforeGroupExpansion8921 pins the ORDER of the
// commit-check schema path against the compile path: strip inactive ->
// normalize brace-elided statements -> expand groups -> validate.
//
// ExpandGroups merges a group body into inline config by the statement's
// SHAPE. It used to run on the tree as authored, so a packed spelling on
// either side of a merge failed to meet its braced counterpart: the group's
// neighbor was appended beside the inline one instead of being overridden,
// was normalized afterwards, and its invalid hold-time 2 was REFUSED -- while
// the braced spelling merged, the inline 30 won, and the compiler (which
// strips, then normalizes, then expands) accepted every spelling.
//
// The inactive-sibling cell is why STRIP comes first: the fold declines when
// the next sibling continues the container it would build, so an inactive
// `hold-time 9` beside a packed inline neighbor -- a node the compiler never
// sees -- made commit-check decline the fold and the override failed again.
//
// FAIL-ON-REVERT: drop the NormalizeCompactForScan call and the compact
// group-body cell refuses; normalize before WithoutInactive and the
// inactive-sibling cell refuses.
func TestCommitValidationNormalizesBeforeGroupExpansion8921(t *testing.T) {
	const pre = `routing-options { autonomous-system 65000; } `
	const bracedGroup = `groups { gg { protocols { bgp { group g1 { neighbor 192.0.2.1 { hold-time 2; } } } } } } apply-groups gg; `
	const compactGroup = `groups { gg { protocols { bgp { group g1 { neighbor 192.0.2.1 hold-time 2; } } } } } apply-groups gg; `
	const bracedInline = `protocols { bgp { group g1 { neighbor 192.0.2.1 { hold-time 30; } } } }`
	cases := []struct {
		name, group, inline string
	}{
		{"braced group body, braced inline override", bracedGroup, bracedInline},
		{"compact group body, braced inline override", compactGroup, bracedInline},
		{"braced group body, compact inline override beside an inactive sibling", bracedGroup,
			`protocols { bgp { group g1 { neighbor 192.0.2.1 hold-time 30; inactive: hold-time 9; } } }`},
	}
	parse := func(t *testing.T, text string) *config.ConfigTree {
		t.Helper()
		tree, errs := config.NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("fixture does not parse: %v\n%s", errs, text)
		}
		return tree
	}
	for _, c := range cases {
		for _, nodeID := range []int{-1, 0} {
			t.Run(c.name, func(t *testing.T) {
				// CONTROL: with nothing overriding it, the inherited hold-time 2
				// is refused in this group spelling -- the validator sees the
				// value, so an accepted override below is the merge working and
				// not the value going unobserved.
				err := schemaValidateExpandedTreeForNode(parse(t, pre+c.group), nodeID)
				if err == nil || !strings.Contains(err.Error(), "hold-time") {
					t.Fatalf("CONTROL (node %d): the inherited invalid hold-time was not refused "+
						"(err=%v), so this cell cannot observe the override", nodeID, err)
				}
				if err := schemaValidateExpandedTreeForNode(parse(t, pre+c.group+c.inline), nodeID); err != nil {
					t.Errorf("node %d: the inline hold-time 30 must override the group's 2, as it "+
						"does for the braced spellings and in the compiler: %v", nodeID, err)
				}
			})
		}
	}
}
