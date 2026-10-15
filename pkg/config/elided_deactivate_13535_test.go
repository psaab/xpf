package config

import (
	"strings"
	"testing"
)

// #13535: DeactivatePath lacked deletePath's elided-node handling (#8992/#8997).
// `chassis cluster strict-session-auth;` is ONE node whose Keys carry the
// whole path. DeletePath finds it via findElidedNodeForPath; setInactiveAtPath
// descended looking for a `chassis` container and reported path not found.
// Parity: deactivate/activate must toggle that node; packed runs keep the
// #9793 refusal (toggling would apply to neighbours on the same line).
func elidedChassisInactive13535(t *testing.T, tr *ConfigTree) bool {
	t.Helper()
	var found *Node
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if len(n.Keys) > 0 && n.Keys[len(n.Keys)-1] == "strict-session-auth" {
				found = n
			}
			walk(n.Children)
		}
	}
	walk(tr.Children)
	if found == nil {
		return false
	}
	return found.Inactive
}

func TestElidedDeactivate13535(t *testing.T) {
	path := []string{"chassis", "cluster", "strict-session-auth"}
	for _, tc := range []struct {
		name string
		text string
	}{
		{"fully elided", `chassis cluster strict-session-auth;`},
		{"cluster brace elided", `chassis { cluster strict-session-auth; }`},
		{"fully braced (control)", `chassis { cluster { strict-session-auth; } }`},
		{"elided beside braced sibling", `chassis { cluster { cluster-id 22; } cluster strict-session-auth; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, perrs := NewParser(tc.text).Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse: %v", perrs)
			}
			tr := &ConfigTree{Children: root.Children}
			if err := tr.DeactivatePath(path); err != nil {
				t.Fatalf("DeactivatePath(%q): %v", path, err)
			}
			if !elidedChassisInactive13535(t, tr) {
				t.Fatal("deactivate succeeded but target node remains active")
			}
			if err := tr.ActivatePath(path); err != nil {
				t.Fatalf("ActivatePath(%q): %v", path, err)
			}
			if elidedChassisInactive13535(t, tr) {
				t.Fatal("activate succeeded but target node remains inactive")
			}
			if err := tr.DeletePath(path); err != nil {
				t.Fatalf("DeletePath parity: %v", err)
			}
			if strings.Contains(tr.FormatSet(), "strict-session-auth") {
				t.Fatalf("delete left target behind: %q", tr.FormatSet())
			}
		})
	}
}

func TestElidedDeactivateRefusesPackedRun13535(t *testing.T) {
	root, perrs := NewParser(`chassis cluster strict-session-auth control-link-recovery;`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	tr := &ConfigTree{Children: root.Children}
	before := strings.TrimSpace(tr.FormatSet())
	err := tr.DeactivatePath([]string{"chassis", "cluster", "strict-session-auth"})
	if err == nil || !strings.Contains(err.Error(), "one member of a statement that names others") {
		t.Fatalf("DeactivatePath packed run error = %v, want packed-member refusal", err)
	}
	if got := strings.TrimSpace(tr.FormatSet()); got != before || elidedChassisInactive13535(t, tr) {
		t.Fatalf("refused deactivate modified tree: before=%q after=%q", before, got)
	}
}
