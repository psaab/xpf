package config

import (
	"strings"
	"testing"
)

// #15942 H2-03: FormatCompareRedactedAtPath redacted the whole tree
// BEFORE navigating, so a path naming a masked identity token
// (`snmp community <name>`, a credential-bearing archive-sites URL)
// matched nothing after masking and a changed subtree rendered "" /
// "[no changes]". The fix navigates on the unredacted trees and
// fingerprint-redacts only the matched subtrees.
func TestFormatCompareRedactedAtPathSecretIdentity15942(t *testing.T) {
	oldTree := buildRedactTree(t, []string{
		"set snmp community public authorization read-only",
		"set snmp community private authorization read-write",
		"set system host-name fw-a",
	})
	newTree := oldTree.Clone()
	if err := newTree.SetPath([]string{"snmp", "community", "public", "authorization", "read-write"}); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	got := FormatCompareRedactedAtPath(oldTree, newTree, []string{"snmp", "community", "public"})
	if got == "" {
		t.Fatalf("scoped redacted compare at [snmp community public] returned \"\"; the changed subtree must render (whole-tree control below)")
	}
	if !strings.Contains(got, "read-write") {
		t.Errorf("scoped compare must show the changed authorization, got %q", got)
	}
	if strings.Contains(got, "public") && !strings.Contains(got, SecretDataPlaceholder) {
		t.Errorf("scoped compare rendered the community identity unmasked: %q", got)
	}
	if strings.Contains(got, "private") {
		t.Errorf("scoped compare leaked the sibling community subtree: %q", got)
	}

	// Control: the whole-tree redacted compare sees the same change, so
	// the scoped form is not vacuous.
	if whole := FormatCompareRedacted(oldTree, newTree); !strings.Contains(whole, "read-write") {
		t.Fatalf("control: whole-tree redacted compare lost the change: %q", whole)
	}
	// Unchanged scoped path renders no diff.
	if same := FormatCompareRedactedAtPath(oldTree, oldTree, []string{"snmp", "community", "public"}); same != "" {
		t.Errorf("unchanged scoped compare = %q, want \"\"", same)
	}
	// A path that matches nothing on either side stays empty.
	if miss := FormatCompareRedactedAtPath(oldTree, newTree, []string{"snmp", "community", "nosuch"}); miss != "" {
		t.Errorf("non-matching scoped compare = %q, want \"\"", miss)
	}
}

// The scoped renders (FormatPath*Redacted) are the render-side twin:
// they navigate on the unredacted tree and mask only the matched
// subtree, so a secret-identity path renders its subtree masked where
// redact-then-navigate rendered "".
func TestFormatPathRedactedSecretIdentity15942(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set snmp community public authorization read-only",
		`set system archival configuration archive-sites "scp://host/dir" password "ARCHIVE-PW-15942"`,
		"set system host-name fw-a",
	})

	out := tree.FormatPathRedacted([]string{"snmp", "community", "public"})
	if out == "" {
		t.Fatalf("FormatPathRedacted([snmp community public]) returned \"\"; the subtree must render")
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("scoped render must mask the community identity: %q", out)
	}
	if strings.Contains(out, "public") {
		t.Errorf("scoped render leaked the community name: %q", out)
	}
	if !strings.Contains(out, "read-only") {
		t.Errorf("scoped render lost the subtree content: %q", out)
	}
	if setOut := tree.FormatPathSetRedacted([]string{"snmp", "community", "public"}); setOut == "" || strings.Contains(setOut, "public") {
		t.Errorf("scoped set render = %q, want masked non-empty", setOut)
	}

	// The archive-sites password leaf is masked inside its scoped render.
	siteOut := tree.FormatPathRedacted([]string{"system", "archival", "configuration", "archive-sites"})
	if siteOut == "" {
		t.Fatalf("scoped archive-sites render returned \"\"")
	}
	if strings.Contains(siteOut, "ARCHIVE-PW-15942") {
		t.Errorf("scoped archive-sites render leaked the password: %q", siteOut)
	}
	if !strings.Contains(siteOut, SecretDataPlaceholder) {
		t.Errorf("scoped archive-sites render did not mask the password: %q", siteOut)
	}

	// A non-matching path renders "" (never an unredacted leak), and the
	// source tree is never mutated.
	if miss := tree.FormatPathRedacted([]string{"snmp", "community", "nosuch"}); miss != "" {
		t.Errorf("non-matching scoped render = %q, want \"\"", miss)
	}
	if strings.Contains(tree.Format(), SecretDataPlaceholder) {
		t.Error("scoped render mutated the source tree")
	}
}
