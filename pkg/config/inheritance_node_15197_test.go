package config

import (
	"strings"
	"testing"
)

// #15197 A03-01: `show configuration | display inheritance` silently fell
// back to the raw config on every ${node} HA config, and path views omitted
// node-group-inherited leaves. FormatInheritance/FormatPathInheritance called
// ExpandGroupsTagged with no vars, so apply-groups "${node}" failed with
// `undefined group "${node}"` and the error arm returned t.Format() /
// t.FormatPath(path) — the raw, unexpanded tree — with no diagnostic.

const nodeInheritText15197 = `groups {
    node0 { system { host-name fw0; } }
    node1 { system { host-name fw1; } }
}
apply-groups "${node}";
system { domain-name example.com; }
`

func parse15197(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	return tree
}

// Acceptance: a ${node} config on node 1 shows
// `inherited from group 'node1'` (and node0's leaf does not leak).
func TestFormatInheritanceForNodeResolvesNodeGroup15197(t *testing.T) {
	for _, tc := range []struct {
		nodeID int
		want   string
		other  string
	}{
		{0, "fw0", "fw1"},
		{1, "fw1", "fw0"},
	} {
		out, err := parse15197(t, nodeInheritText15197).FormatInheritanceForNode(tc.nodeID)
		if err != nil {
			t.Fatalf("node %d: FormatInheritanceForNode: %v", tc.nodeID, err)
		}
		wantGroup := "node0"
		if tc.nodeID == 1 {
			wantGroup = "node1"
		}
		if !strings.Contains(out, "was inherited from group '"+wantGroup+"'") {
			t.Errorf("node %d: missing inheritance annotation for group %s:\n%s", tc.nodeID, wantGroup, out)
		}
		if !strings.Contains(out, "host-name "+tc.want) {
			t.Errorf("node %d: missing inherited leaf %s:\n%s", tc.nodeID, tc.want, out)
		}
		if strings.Contains(out, "host-name "+tc.other) {
			t.Errorf("node %d: peer leaf %s leaked:\n%s", tc.nodeID, tc.other, out)
		}
		if !strings.Contains(out, "domain-name example.com") {
			t.Errorf("node %d: inline leaf lost:\n%s", tc.nodeID, out)
		}
	}
}

// Path views must include node-group-inherited leaves under the path.
func TestFormatPathInheritanceForNodeResolvesNodeGroup15197(t *testing.T) {
	out, err := parse15197(t, nodeInheritText15197).FormatPathInheritanceForNode([]string{"system"}, 1)
	if err != nil {
		t.Fatalf("FormatPathInheritanceForNode: %v", err)
	}
	if !strings.Contains(out, "was inherited from group 'node1'") {
		t.Errorf("path view missing node1 inheritance annotation:\n%s", out)
	}
	if !strings.Contains(out, "host-name fw1") {
		t.Errorf("path view missing inherited leaf fw1:\n%s", out)
	}
	if strings.Contains(out, "host-name fw0") {
		t.Errorf("path view leaked peer leaf fw0:\n%s", out)
	}
}

// An expansion failure must surface as an error, never a silent raw fallback.
func TestFormatInheritanceForNodeErrorsOnUndefinedGroup15197(t *testing.T) {
	text := `groups { G { system { host-name fw0; } } } apply-groups missing; system { domain-name example.com; }`
	out, err := parse15197(t, text).FormatInheritanceForNode(1)
	if err == nil {
		t.Fatalf("undefined group must error, got output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should name the undefined group: %v", err)
	}
	out, err = parse15197(t, text).FormatPathInheritanceForNode([]string{"system"}, 1)
	if err == nil {
		t.Fatalf("path: undefined group must error, got output:\n%s", out)
	}
}

// Standalone (nodeID < 0): the generic view resolves ${node} to node0, the
// same fallback the generic compile uses (#15031), and annotates it.
func TestFormatInheritanceStandaloneFallsBackToNode015197(t *testing.T) {
	out, err := parse15197(t, nodeInheritText15197).FormatInheritanceForNode(-1)
	if err != nil {
		t.Fatalf("standalone FormatInheritanceForNode: %v", err)
	}
	if !strings.Contains(out, "was inherited from group 'node0'") {
		t.Errorf("standalone view must show node0 inheritance:\n%s", out)
	}
	if !strings.Contains(out, "host-name fw0") || strings.Contains(out, "host-name fw1") {
		t.Errorf("standalone view must show fw0 only:\n%s", out)
	}
}

// Control: a plain (non-${node}) group config renders identically through
// the legacy no-arg entry and the node-aware entry.
func TestFormatInheritancePlainGroupControl15197(t *testing.T) {
	text := `groups { G { system { host-name fw0; } } } apply-groups G; system { domain-name example.com; }`
	legacy := parse15197(t, text).FormatInheritance()
	nodeAware, err := parse15197(t, text).FormatInheritanceForNode(1)
	if err != nil {
		t.Fatalf("FormatInheritanceForNode: %v", err)
	}
	if legacy != nodeAware {
		t.Fatalf("plain-group display must be unchanged\n--- legacy ---\n%s\n--- node-aware ---\n%s", legacy, nodeAware)
	}
	if !strings.Contains(legacy, "was inherited from group 'G'") {
		t.Errorf("control missing G annotation:\n%s", legacy)
	}
}

// The display must not mutate the caller's tree.
func TestFormatInheritanceForNodeDoesNotMutate15197(t *testing.T) {
	tree := parse15197(t, nodeInheritText15197)
	before := tree.Format()
	if _, err := tree.FormatInheritanceForNode(1); err != nil {
		t.Fatalf("FormatInheritanceForNode: %v", err)
	}
	if _, err := tree.FormatPathInheritanceForNode([]string{"system"}, 1); err != nil {
		t.Fatalf("FormatPathInheritanceForNode: %v", err)
	}
	if after := tree.Format(); after != before {
		t.Fatalf("display mutated the tree\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}
