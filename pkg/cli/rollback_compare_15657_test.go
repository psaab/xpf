package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15657 (V45-03/V47-02/V48-02) on the local CLI surface. Fixture
// mirrors newCompareStore10094: commit base, commit base+domain
// (active), then stage a never-committed host-name canary. Active is
// "compare-10094-base" + domain; rollback 1 is the base alone, so the
// active-baseline diff mentions example.net — and the canary proves
// no candidate arm was read.

func TestLocalRollbackPipeCompare15657(t *testing.T) {
	store := newCompareStore10094(t)
	for _, line := range []string{
		"show system rollback 1 | compare",
		"show system rollback 1 compare",
		"show system rollback compare 1",
		"show system rollback compare 0",
		"show system rollback 0",
	} {
		t.Run(line, func(t *testing.T) {
			c := &CLI{store: store, userClass: "read-only"}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
			if runErr != nil {
				t.Fatalf("%q: %v", line, runErr)
			}
			if strings.Contains(out, "unknown pipe") {
				t.Errorf("%q hit unknown-pipe (V47-02):\n%s", line, out)
			}
			if strings.Contains(out, compareCanary10094) {
				t.Errorf("%q leaked the staged candidate:\n%s", line, out)
			}
		})
	}

	// The pipe compare actually renders the committed diff.
	c := &CLI{store: store, userClass: "read-only"}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 | compare"); err != nil {
			t.Fatalf("pipe compare: %v", err)
		}
	})
	if !strings.Contains(out, "example.net") {
		t.Errorf("pipe compare missing committed diff:\n%s", out)
	}
	// compare 0 is active-vs-active even with a dirty candidate.
	out = captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback compare 0"); err != nil {
			t.Fatalf("compare 0: %v", err)
		}
	})
	if !strings.Contains(out, "No differences") && !strings.Contains(out, "[no changes]") {
		t.Errorf("compare 0 should report no differences:\n%s", out)
	}
	// rollback 0 renders the active config.
	out = captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 0"); err != nil {
			t.Fatalf("rollback 0: %v", err)
		}
	})
	if !strings.Contains(out, "example.net") {
		t.Errorf("rollback 0 should render active:\n%s", out)
	}
}

func TestLocalRollbackDisplayFormats15657(t *testing.T) {
	store := newCompareStore10094(t)
	cases := []struct {
		line string
		want string
	}{
		{"show system rollback 1 | display json", "compare-10094-base"},
		{"show system rollback 1 | display xml", "<configuration"},
		{"show system rollback 1 | display inheritance", "compare-10094-base"},
		{"show system rollback 1 | display set", "set system host-name compare-10094-base"},
		{"show system rollback 1 system | display json", "compare-10094-base"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			c := &CLI{store: store, userClass: "read-only"}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(tc.line) })
			if runErr != nil {
				t.Fatalf("%q: %v", tc.line, runErr)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("%q missing %q:\n%s", tc.line, tc.want, out)
			}
			if strings.Contains(out, compareCanary10094) {
				t.Errorf("%q leaked the staged candidate:\n%s", tc.line, out)
			}
		})
	}

	// Path scoping scopes: security subtree of slot 1 has no host-name.
	c := &CLI{store: store, userClass: "read-only"}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 security | display json"); err != nil {
			t.Fatalf("scoped display: %v", err)
		}
	})
	if strings.Contains(out, "host-name") {
		t.Errorf("scoped display leaked out-of-path content:\n%s", out)
	}

	// Stray pre-pipe tokens fail loudly instead of being ignored (V47-02).
	out = captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1 bogus-token"); err != nil {
			t.Fatalf("stray token dispatch: %v", err)
		}
	})
	if !strings.Contains(out, "syntax error") {
		t.Errorf("stray pre-pipe token should be a syntax error:\n%s", out)
	}
	if strings.Contains(out, "compare-10094-base") {
		t.Errorf("stray token rendered the slot anyway:\n%s", out)
	}
}

// Regex-restricted classes (V47-02 second half): with allow-commands
// configured, `| compare` must be authorizable — pre-fix
// authorizablePipe("compare") was false and the gate refused the
// command before the handler ran.
func TestLocalRollbackPipeCompareRegexClass15657(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	base := []string{
		"set system host-name regex-base-15657",
		"set system login class regexops permissions [ view ]",
		"set system login class regexops allow-commands \"show.*\"",
		"set system login user ro-15657 class regexops",
	}
	for _, cmd := range base {
		if err := store.SetFromInput(strings.TrimPrefix(cmd, "set ")); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit base: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit slot: %v", err)
	}
	store.ExitConfigure()

	c := &CLI{store: store, userClass: "regexops"}
	var runErr error
	out := captureStdout(t, func() { runErr = c.dispatchOperational("show system rollback 1 | compare") })
	if runErr != nil {
		t.Fatalf("regex class pipe compare refused (authorizablePipe): %v", runErr)
	}
	if strings.Contains(out, "unknown pipe") {
		t.Errorf("regex class pipe compare hit unknown-pipe:\n%s", out)
	}
}
