package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #14715 (D17-02): `show configuration` and config-mode `show` selected their
// render format with `strings.Contains(rest, "| display set")` and built the
// path only from tokens BEFORE `|`. Trailing tokens after the format were
// silently discarded, so `show configuration | display set interfaces`
// rendered the WHOLE tree (ShowActiveSet()/redacted-nil) instead of the
// interfaces subtree or a syntax error.
//
// RED-on-revert: restoring the substring selection makes every malformed
// cell below emit `system host-name` (the whole-tree sentinel) instead of a
// syntax error, and the gate cells are allowed instead of denied.

func newDisplayPipeStore14715(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set system host-name XPF-14715-HOST",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return store
}

func TestShowConfigurationDisplayPipeTrailing14715(t *testing.T) {
	store := newDisplayPipeStore14715(t)
	formats := []string{"set", "json", "xml", "inheritance"}
	for _, format := range formats {
		format := format
		t.Run("operational/"+format, func(t *testing.T) {
			c := &CLI{store: store, userClass: "read-only"}
			args := []string{"configuration", "|", "display", format, "interfaces"}
			out := captureStdout(t, func() {
				if err := c.handleShow(append([]string(nil), args...)); err != nil {
					t.Fatalf("handleShow(%v): %v", args, err)
				}
			})
			if strings.Contains(out, "XPF-14715-HOST") {
				t.Errorf("malformed pipe %v dumped the whole configuration (host-name leaked):\n%s", args, out)
			}
			if !strings.Contains(out, "syntax error") {
				t.Errorf("malformed pipe %v: want syntax error, got:\n%s", args, out)
			}
		})
		t.Run("config/"+format, func(t *testing.T) {
			c := &CLI{store: store, userClass: "read-only"}
			args := []string{"|", "display", format, "interfaces"}
			out := captureStdout(t, func() {
				if err := c.handleConfigShow(append([]string(nil), args...)); err != nil {
					t.Fatalf("handleConfigShow(%v): %v", args, err)
				}
			})
			if strings.Contains(out, "XPF-14715-HOST") {
				t.Errorf("config-mode malformed pipe %v dumped the whole candidate (host-name leaked):\n%s", args, out)
			}
			if !strings.Contains(out, "syntax error") {
				t.Errorf("config-mode malformed pipe %v: want syntax error, got:\n%s", args, out)
			}
		})
	}

	// Control: the exact forms still render, path-scoped correctly.
	t.Run("control/exact-set-whole", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleShow([]string{"configuration", "|", "display", "set"}); err != nil {
				t.Fatalf("handleShow: %v", err)
			}
		})
		if !strings.Contains(out, "XPF-14715-HOST") {
			t.Errorf("exact `| display set` must render the whole tree:\n%s", out)
		}
	})
	t.Run("control/path-before-pipe", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleShow([]string{"configuration", "interfaces", "|", "display", "set"}); err != nil {
				t.Fatalf("handleShow: %v", err)
			}
		})
		if strings.Contains(out, "XPF-14715-HOST") {
			t.Errorf("path-scoped `show configuration interfaces | display set` must not include system host-name:\n%s", out)
		}
		if !strings.Contains(out, "ge-0/0/0") {
			t.Errorf("path-scoped render must include the interfaces subtree:\n%s", out)
		}
	})
	t.Run("control/config-exact-set", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleConfigShow([]string{"|", "display", "set"}); err != nil {
				t.Fatalf("handleConfigShow: %v", err)
			}
		})
		if !strings.Contains(out, "XPF-14715-HOST") {
			t.Errorf("config-mode exact `show | display set` must render the candidate:\n%s", out)
		}
	})
	t.Run("control/config-compare", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleConfigShow([]string{"|", "compare"}); err != nil {
				t.Fatalf("handleConfigShow compare: %v", err)
			}
		})
		// No candidate changes after commit: empty diff is fine, whole-tree
		// set output (host-name as a `set` line) is not.
		if strings.Contains(out, "set system host-name") {
			t.Errorf("config-mode `show | compare` must not render the candidate as set lines:\n%s", out)
		}
		_ = out
	})
	t.Run("control/unknown-display", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleShow([]string{"configuration", "|", "display", "bogus"}); err != nil {
				t.Fatalf("handleShow: %v", err)
			}
		})
		if !strings.Contains(out, "syntax error") || strings.Contains(out, "XPF-14715-HOST") {
			t.Errorf("unknown display option must be a syntax error with no render:\n%s", out)
		}
	})
	t.Run("control/rollback-exact-set", func(t *testing.T) {
		// A second commit pushes the secret-bearing config into slot 1.
		if _, err := store.LoadSet("set system domain-name example.net"); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		c := &CLI{store: store, userClass: "read-only"}
		out := captureStdout(t, func() {
			if err := c.handleShowSystem([]string{"rollback", "1", "|", "display", "set"}); err != nil {
				t.Fatalf("handleShowSystem: %v", err)
			}
		})
		if !strings.Contains(out, "XPF-14715-HOST") {
			t.Errorf("rollback exact `| display set` must render the slot:\n%s", out)
		}
		out = captureStdout(t, func() {
			if err := c.handleShowSystem([]string{"rollback", "1", "|", "display", "set", "interfaces"}); err != nil {
				t.Fatalf("handleShowSystem: %v", err)
			}
		})
		if strings.Contains(out, "XPF-14715-HOST") || !strings.Contains(out, "syntax error") {
			t.Errorf("rollback `| display set interfaces` must be a syntax error with no render:\n%s", out)
		}
	})
	t.Run("control/chained-filter-still-works", func(t *testing.T) {
		// dispatch splits the trailing SplitPipe filter first, so the
		// handler receives exactly `show configuration | display set`.
		rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "request system reboot", true)
		if err != nil {
			t.Fatalf("CompileLoginRegexes: %v", err)
		}
		if err := evaluateCommandRegex(rules, "restricted", "show configuration | display set", "match ge-"); err != nil {
			t.Errorf("chained `| display set | match ge-` must stay authorized: %v", err)
		}
	})
}

func TestDisplayPipeGate14715(t *testing.T) {
	denyDisplaySet := "^show configuration \\| display set$"
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, denyDisplaySet, true)
	if err != nil {
		t.Fatalf("CompileLoginRegexes: %v", err)
	}
	// Control: the exact denied form is denied.
	if err := evaluateCommandRegex(rules, "restricted", "show configuration | display set", ""); err == nil {
		t.Fatal("exact `show configuration | display set` must be denied by the anchored deny")
	}
	// The bypass spelling: trailing token evaded the anchored deny pre-fix
	// at the executor; the gate must now refuse the malformed pipe itself.
	if err := evaluateCommandRegex(rules, "restricted", "show configuration | display set interfaces", ""); err == nil {
		t.Fatal("`show configuration | display set interfaces` must be denied (malformed display pipe), not authorized past the anchored deny")
	}
	// An interfaces-scoped ALLOW must not authorize the whole-tree spelling:
	// the gate refuses it as malformed; the handler would syntax-error too.
	allowIfaces, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "^show configuration .*interfaces", true, "", false)
	if err != nil {
		t.Fatalf("CompileLoginRegexes allow: %v", err)
	}
	if err := evaluateCommandRegex(allowIfaces, "restricted", "show configuration | display set interfaces", ""); err == nil {
		t.Fatal("an interfaces-scoped allow must not authorize `| display set interfaces` (whole-tree render pre-fix)")
	}
	// Negative control: an unrelated command stays allowed under the deny.
	if err := evaluateCommandRegex(rules, "restricted", "show version", ""); err != nil {
		t.Errorf("unrelated command must stay allowed: %v", err)
	}
}
