package configstore

import (
	"strings"
	"testing"
)

// #15031: the standalone (nodeID=-1) commit-check pipeline must reject
// the ${node}-fallback default-policy conflict the fresh node0 compile
// rejects. Before the fix, both the schema-expanded view
// (schemaValidateExpandedTreeForNode) and the generic compile retried
// the ${node} expansion on a partially merged tree, so the conflicting
// group pair never materialized and CheckText accepted permit-first.
const nodeFallbackConflictText15031 = "groups {\n" +
	"    GA { security { policies { default-policy permit-all; } } }\n" +
	"    node0 { security { policies { default-policy deny-all; } } }\n" +
	"}\n" +
	"apply-groups [ GA \"${node}\" ];\n" +
	"security { policies { } }\n"

func TestCheckTextStandaloneRejectsNodeFallbackConflict15031(t *testing.T) {
	// Oracle: the node0 view of the same text rejects.
	if _, err := CheckText(nodeFallbackConflictText15031, 0); err == nil {
		t.Fatal("oracle: CheckText node0 accepted the conflict (test is not exercising the claimed divergence)")
	}
	_, err := CheckText(nodeFallbackConflictText15031, -1)
	if err == nil {
		t.Fatal("standalone CheckText accepted a ${node}-fallback default-policy conflict the node0 compile rejects (#15031)")
	}
	for _, want := range []string{"default-policy", "permit-all", "deny-all"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("standalone CheckText error %q does not name %q", err, want)
		}
	}
}

func TestCheckTextStandaloneBenignNodeGroupStaysGreen15031(t *testing.T) {
	text := "groups {\n" +
		"    node0 { security { policies { default-policy deny-all; } } }\n" +
		"    node1 { security { policies { default-policy deny-all; } } }\n" +
		"}\n" +
		"apply-groups \"${node}\";\n" +
		"security { policies { } }\n"
	if _, err := CheckText(text, -1); err != nil {
		t.Fatalf("standalone CheckText rejected a benign ${node} config: %v", err)
	}
}
