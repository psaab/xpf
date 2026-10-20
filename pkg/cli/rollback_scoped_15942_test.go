package cli

import (
	"strings"
	"testing"
)

// #15942 H2-04 (local CLI arm): a bare pre-pipe subtree path
// (`show system rollback 1 interfaces`) was a syntax error, and
// `N <path> | compare` dropped rbPath and diffed the whole tree. Both
// now honour the requested scope, and the gate prices the path.
func TestLocalRollbackScopedPath15942(t *testing.T) {
	store := newCompareStore10094(t)

	// Bare scoped render: slot 1 holds the base config (host-name only,
	// no domain-name), scoped to `system`.
	c := &CLI{store: store, userClass: "read-only"}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 system"); err != nil {
			t.Fatalf("bare scoped rollback: %v", err)
		}
	})
	if !strings.Contains(out, "compare-10094-base") {
		t.Errorf("bare scoped rollback 1 system missing slot content:\n%s", out)
	}
	if strings.Contains(out, "syntax error") {
		t.Errorf("bare scoped rollback still a syntax error:\n%s", out)
	}

	// Scoped compare: only the `system` subtree diffs (domain-name was
	// added in the second commit); nothing outside it may appear.
	out = captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 system | compare"); err != nil {
			t.Fatalf("scoped pipe compare: %v", err)
		}
	})
	if !strings.Contains(out, "example.net") {
		t.Errorf("scoped compare missing the in-scope domain-name diff:\n%s", out)
	}
	if strings.Contains(out, compareCanary10094) {
		t.Errorf("scoped compare leaked the staged candidate:\n%s", out)
	}

	// A stray token that is not a config top-level stanza stays the
	// historic syntax error.
	out = captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 bogus-token"); err != nil {
			t.Fatalf("stray token dispatch: %v", err)
		}
	})
	if !strings.Contains(out, "syntax error") {
		t.Errorf("stray token should remain a syntax error:\n%s", out)
	}
}

// The gate side: a class denied the `security` configuration subtree
// must be refused a bare scoped rollback into it and a scoped compare
// over it, while an allowed subtree stays readable.
func TestLocalRollbackScopedGate15942(t *testing.T) {
	store := cli14707Store(t)
	c := &CLI{store: store, userClass: "limited-view"}
	if err := c.dispatchOperational("show system rollback 0 security"); err == nil {
		t.Error("bare scoped rollback into denied security was ALLOWED (#15942 H2-04)")
	}
	if err := c.dispatchOperational("show system rollback 0 security | compare"); err == nil {
		t.Error("scoped rollback compare over denied security was ALLOWED (#15942 H2-04)")
	}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 0 system"); err != nil {
			t.Errorf("scoped rollback into allowed system must stay admitted: %v", err)
		}
	})
	if !strings.Contains(out, "cli-14707") {
		t.Errorf("allowed scoped rollback lost its content:\n%s", out)
	}
}
