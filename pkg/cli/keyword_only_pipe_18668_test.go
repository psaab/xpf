package cli

// #18668: the local (in-process) CLI lacked the keyword-only pipe gate the
// remote cli got in #18664. pkg/cli dispatchOperational had no
// ValidateOperationalGate call, so a bare `|` directly under a keyword-only
// node reached a handler that printed help (or ran the bare command) and
// returned nil: `clear security | display set`, `request chassis cluster |
// display set` and `show chassis | display set` exited 0 having done nothing,
// dropping the modifier.
//
// The gate now lives once in pkg/cmdtree (ValidateOperationalGate) and both
// surfaces call it. Here it is inserted in dispatchOperational AFTER
// checkPermission / checkCommandRegex / config-read adjudication and
// immediately BEFORE the handler switch, so local RBAC precedence is
// preserved and pager, filtered, direct and config-mode `run` re-entry paths
// are all covered (they all funnel through dispatchOperational). `?`/`help`
// return earlier and are never gated; dispatchConfig is not gated.
//
// Every defect row drives c.dispatch (the full entry path) or, where noted,
// dispatchOperational / dispatchConfig directly, and asserts the exact error
// AND that no `Possible completions:` help was printed.

import (
	"path/filepath"
	"strings"
	"testing"
)

// committedStore18668 builds a committed store holding
// `set system host-name fw0`, so the `show configuration` consumer control
// renders real active configuration.
func committedStore18668(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system host-name fw0"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	return &CLI{store: store}
}

// TestLocalKeywordOnlyPipeRefused18668: a bare `|` directly under a
// keyword-only node whose handler does not parse pipes refuses with the
// shared pipe-specific syntax error, before any handler runs.
func TestLocalKeywordOnlyPipeRefused18668(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"clear security | display set", `syntax error: "clear security" does not accept the output modifier "| display set"`},
		{"request chassis cluster | display set", `syntax error: "request chassis cluster" does not accept the output modifier "| display set"`},
		{"show chassis | display set", `syntax error: "show chassis" does not accept the output modifier "| display set"`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if strings.Contains(out, "Possible completions:") {
				t.Fatalf("dispatch(%q) printed help instead of refusing:\n%s", tc.line, out)
			}
		})
	}

	// One direct dispatchOperational row: the gate sits in
	// dispatchOperational itself, not only in the dispatch wrapper.
	t.Run("direct dispatchOperational", func(t *testing.T) {
		c := committedStore18668(t)
		var err error
		out := captureStdout(t, func() {
			err = c.dispatchOperational("show chassis | display set")
		})
		want := `syntax error: "show chassis" does not accept the output modifier "| display set"`
		if err == nil || err.Error() != want {
			t.Fatalf("dispatchOperational = %v; want %q", err, want)
		}
		if strings.Contains(out, "Possible completions:") {
			t.Fatalf("dispatchOperational printed help instead of refusing:\n%s", out)
		}
	})

	// One config-mode `run` re-entry row: dispatchConfig's `run` arm
	// re-enters dispatchOperational, so the gate must fire there too.
	t.Run("config-mode run re-entry", func(t *testing.T) {
		c := committedStore18668(t)
		var err error
		out := captureStdout(t, func() {
			err = c.dispatchConfig("run show chassis | display set")
		})
		want := `syntax error: "show chassis" does not accept the output modifier "| display set"`
		if err == nil || err.Error() != want {
			t.Fatalf("dispatchConfig(run ...) = %v; want %q", err, want)
		}
		if strings.Contains(out, "Possible completions:") {
			t.Fatalf("config-mode run printed help instead of refusing:\n%s", out)
		}
	})
}

// TestLocalKeywordOnlyUnknownRefused18668: an unknown or ambiguous token
// under a keyword-only node refuses exactly as on the remote surface
// (#16798), piped or not. The shared gate's glued-token spacing hint is
// table-pinned in pkg/cmdtree. On the local surface the tested rows
// previously fell through to help-printing handlers and returned nil.
func TestLocalKeywordOnlyUnknownRefused18668(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"clear security ike | display set", "unknown clear security command: ike"},
		{"clear security bogus", "unknown clear security command: bogus"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if strings.Contains(out, "Possible completions:") {
				t.Fatalf("dispatch(%q) printed help instead of refusing:\n%s", tc.line, out)
			}
		})
	}
	// Ambiguous abbreviations under a keyword-only node refuse as ambiguous.
	for _, tc := range []struct{ line, want string }{
		{"clear s", "ambiguous clear command: s"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if strings.Contains(out, "Possible completions:") {
				t.Fatalf("dispatch(%q) printed help instead of refusing:\n%s", tc.line, out)
			}
		})
	}
}

// TestLocalKeywordOnlyControls18668: shapes the gate must not refuse.
// Bare keyword nodes keep help+nil; `?`/`help` return before the gate; the
// one pipe consumer (`show configuration`) renders the committed config;
// pipes after a value slot / leaf are the handler's domain; and the two
// pre-existing refusal controls keep refusing exactly as before #18668.
func TestLocalKeywordOnlyControls18668(t *testing.T) {
	// Bare keyword nodes: help + nil.
	for _, line := range []string{
		"clear", "clear security", "request", "request chassis cluster",
		"show", "show security", "?", "help",
	} {
		t.Run("bare "+line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			captureStdout(t, func() { err = c.dispatch(line) })
			if err != nil {
				t.Fatalf("dispatch(%q) = %v; want nil (help)", line, err)
			}
		})
	}

	// The single OperationalPipeConsumers entry renders the committed
	// configuration through the handler-parsed display pipe.
	t.Run("show configuration | display set", func(t *testing.T) {
		c := committedStore18668(t)
		var err error
		out := captureStdout(t, func() { err = c.dispatch("show configuration | display set") })
		if err != nil {
			t.Fatalf("dispatch consumer = %v; want nil", err)
		}
		if !strings.Contains(out, "set system host-name fw0") {
			t.Fatalf("consumer output %q; want it to contain %q", out, "set system host-name fw0")
		}
	})

	// Config-mode `run` re-entry of the consumer also renders.
	t.Run("run show configuration | display set", func(t *testing.T) {
		c := committedStore18668(t)
		var err error
		out := captureStdout(t, func() {
			err = c.dispatchConfig("run show configuration | display set")
		})
		if err != nil {
			t.Fatalf("run consumer = %v; want nil", err)
		}
		if !strings.Contains(out, "set system host-name fw0") {
			t.Fatalf("run consumer output %q; want it to contain %q", out, "set system host-name fw0")
		}
	})

	// A pipe after a value slot is outside the gate (handler's domain):
	// it must not be refused with any gate message.
	t.Run("show system rollback 1 | display set", func(t *testing.T) {
		c := committedStore18668(t)
		var err error
		captureStdout(t, func() { err = c.dispatch("show system rollback 1 | display set") })
		if err != nil && (strings.Contains(err.Error(), "unknown") ||
			strings.Contains(err.Error(), "does not accept the output modifier") ||
			strings.Contains(err.Error(), "ambiguous")) {
			t.Fatalf("value-slot pipe gate-refused: %v", err)
		}
	})

	// Pre-existing refusal controls: already refused before #18668 (by
	// handler errors), so they must keep refusing — they are NOT defect
	// rows and must stay green even with the gate call neutered.
	for _, tc := range []struct{ line, want string }{
		{"request system software add", "unknown request system software command: add"},
		{"show bogus", ""},
	} {
		t.Run("pre-existing "+tc.line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || (tc.want != "" && err.Error() != tc.want) {
				t.Fatalf("dispatch(%q) = %v; want a refusal (message %q)", tc.line, err, tc.want)
			}
			if strings.Contains(out, "Possible completions:") {
				t.Fatalf("dispatch(%q) printed help instead of refusing:\n%s", tc.line, out)
			}
		})
	}
}
