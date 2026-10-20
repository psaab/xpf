package config

import (
	"strings"
	"testing"
)

// Fold of #15973 review (Codex P2 / Opus H2-03): a DESCENDANT scope
// (`snmp community public authorization`) reconstructs output context
// from the raw requested path — the set-line prefix and the compare
// `[edit …]` header — reprinting the secret identity the scope passed
// through. Those components are masked at their flattened position.
func TestRedactedDescendantScopeMasksAncestor15973(t *testing.T) {
	oldTree := buildRedactTree(t, []string{
		"set snmp community public authorization read-only",
		"set system host-name fw-a",
	})
	newTree := oldTree.Clone()
	if err := newTree.SetPath([]string{"snmp", "community", "public", "authorization", "read-write"}); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	path := []string{"snmp", "community", "public", "authorization"}

	setOut := oldTree.FormatPathSetRedacted(path)
	if setOut == "" {
		t.Fatalf("descendant set render returned \"\"")
	}
	if strings.Contains(setOut, "public") {
		t.Errorf("descendant set render reprinted the community identity:\n%s", setOut)
	}
	if !strings.Contains(setOut, SecretDataPlaceholder) || !strings.Contains(setOut, "read-only") {
		t.Errorf("descendant set render = %q, want masked identity + read-only", setOut)
	}

	diff := FormatCompareRedactedAtPath(oldTree, newTree, path)
	if diff == "" {
		t.Fatalf("descendant redacted compare returned \"\"")
	}
	if strings.Contains(diff, "public") {
		t.Errorf("descendant redacted compare reprinted the community identity:\n%s", diff)
	}
	if !strings.Contains(diff, SecretDataPlaceholder) {
		t.Errorf("descendant redacted compare missing masked identity:\n%s", diff)
	}
	if !strings.Contains(diff, "read-write") {
		t.Errorf("descendant redacted compare lost the change:\n%s", diff)
	}

	jsonOut := oldTree.FormatPathJSONRedacted(path)
	if strings.Contains(jsonOut, "public") {
		t.Errorf("descendant JSON render reprinted the community identity:\n%s", jsonOut)
	}
	// The source tree is never mutated.
	if strings.Contains(oldTree.Format(), SecretDataPlaceholder) {
		t.Error("descendant render mutated the source tree")
	}
}
