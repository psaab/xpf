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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
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

func committedCoSStore18666(t *testing.T) *CLI {
	t.Helper()
	c := committedStore18668(t)
	if err := c.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure for CoS fixture: %v", err)
	}
	for _, line := range []string{
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth1 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address 192.0.2.1/24",
		"set interfaces reth1 unit 80 family inet address 198.51.100.1/24",
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10m",
		"set class-of-service interfaces reth1 unit 80 shaping-rate 20m",
	} {
		if _, err := c.store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := c.store.Commit(); err != nil {
		t.Fatalf("Commit CoS fixture: %v", err)
	}
	c.store.ExitConfigure()
	return c
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
// pipes after value slots and `AcceptsArgs` tails remain with their handlers;
// and the two pre-existing refusal controls keep refusing exactly as before
// #18668.
// #19015: the local CLI admits exactly the two HA loss probes on the
// data-plane statistics leaf (gate-level; the probe provider is unset in
// this fixture, so an admitted probe reaches the provider check, not the
// gate refusal).
func TestLocalDataPlaneStatisticsLossProbes19015(t *testing.T) {
	c := committedStore18668(t)
	for _, line := range []string{
		"show chassis cluster data-plane statistics loss-baseline",
		"show chassis cluster data-plane statistics loss-since opaque-token",
	} {
		err := c.dispatch(line)
		if err != nil && strings.Contains(err.Error(), "unknown show chassis cluster data-plane statistics command") {
			t.Errorf("dispatch(%q) gate-refused: %v", line, err)
		}
	}
	for _, line := range []string{
		"show chassis cluster data-plane statistics loss-baseline extra",
		"show chassis cluster data-plane statistics loss-since",
		"show chassis cluster data-plane statistics loss-since a b",
	} {
		err := c.dispatch(line)
		if err == nil || !strings.Contains(err.Error(), "unknown show chassis cluster data-plane statistics command") {
			t.Errorf("dispatch(%q) = %v; want gate refusal", line, err)
		}
	}
}

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

// TestLocalLeafOutputModifierRefused18666 proves that the local console's
// shared operational gate rejects a display modifier after a pure keyword
// leaf before its default-format handler can run and silently drop it.
func TestLocalLeafOutputModifierRefused18666(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"show version | display set", `syntax error: "show version" does not accept the output modifier "| display set"`},
		{"show chassis hardware | display xml", `syntax error: "show chassis hardware" does not accept the output modifier "| display xml"`},
		{"show system license | display json", `syntax error: "show system license" does not accept the output modifier "| display json"`},
		{"show version extra | display xml", "unknown show version command: extra"},
		{"show version |display xml", `unknown show version command: |display (separate the pipe with spaces: "| display")`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := committedStore18668(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if out != "" {
				t.Fatalf("dispatch(%q) output=%q; want refusal before handler", tc.line, out)
			}
		})
	}
}

// TestLocalLeafOutputFiltersStillWork18666 verifies full dispatch still peels
// implemented filters before the operational leaf gate.
func TestLocalLeafOutputFiltersStillWork18666(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		want       func(plain string) string
	}{
		{
			name: "match",
			line: "show version | match 18666",
			want: func(string) string { return "xpf stateful firewall 18666\n" },
		},
		{
			name: "count",
			line: "show version | count",
			want: func(plain string) string { return fmt.Sprintf("Count: %d lines\n", strings.Count(plain, "\n")) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := committedStore18668(t)
			c.SetVersion("18666")
			var plainErr error
			plain := captureStdout(t, func() { plainErr = c.dispatch("show version") })
			if plainErr != nil {
				t.Fatalf("dispatch(show version) = %v", plainErr)
			}

			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err != nil {
				t.Fatalf("dispatch(%q) = %v; want implemented filter to work", tc.line, err)
			}
			if want := tc.want(plain); out != want {
				t.Fatalf("dispatch(%q) output=%q; want %q", tc.line, out, want)
			}
		})
	}
}

// TestLocalCoSOptionalSelector18666 pins the CoS leaf's one optional selector
// through full dispatch and refuses pipes or a second suffix before rendering.
func TestLocalCoSOptionalSelector18666(t *testing.T) {
	c := committedCoSStore18666(t)
	var err error
	out := captureStdout(t, func() {
		err = c.dispatch("show class-of-service interface reth0.80")
	})
	if err != nil {
		t.Fatalf("dispatch(selector) = %v; want a filtered CoS view", err)
	}
	if !strings.Contains(out, "Interface: reth0.80") || strings.Contains(out, "Interface: reth1.80") {
		t.Fatalf("selector output did not filter the configured CoS view:\n%s", out)
	}

	for _, tc := range []struct{ line, want string }{
		{"show class-of-service interface | display xml", `syntax error: "show class-of-service interface" does not accept the output modifier "| display xml"`},
		{"show class-of-service interface reth0.80 | display xml", `syntax error: "show class-of-service interface" does not accept the output modifier "| display xml"`},
		{"show class-of-service interface |display xml", `unknown show class-of-service interface command: |display (separate the pipe with spaces: "| display")`},
		{"show class-of-service interface reth0.80 extra", "unknown show class-of-service interface command: extra"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := committedCoSStore18666(t)
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil || err.Error() != tc.want {
				t.Fatalf("dispatch(%q) = %v; want %q", tc.line, err, tc.want)
			}
			if out != "" {
				t.Fatalf("dispatch(%q) output=%q; want refusal before handler", tc.line, out)
			}
		})
	}
}

type optionsSummaryCLIDP18666 struct {
	*summaryMaxCLIDP
}

func (d *optionsSummaryCLIDP18666) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 7}}
}

func committedOptionsSummaryStore18666(t *testing.T) *CLI {
	t.Helper()
	c := committedStore18668(t)
	if err := c.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure for summary fixture: %v", err)
	}
	if _, err := c.store.LoadSet("set interfaces eth0 unit 0 family inet address 10.0.0.1/24"); err != nil {
		t.Fatalf("LoadSet trust interface: %v", err)
	}
	if _, err := c.store.LoadSet("set security zones security-zone trust interfaces eth0"); err != nil {
		t.Fatalf("LoadSet trust zone: %v", err)
	}
	if _, err := c.store.Commit(); err != nil {
		t.Fatalf("Commit trust zone: %v", err)
	}
	c.store.ExitConfigure()
	c.dp = &optionsSummaryCLIDP18666{
		summaryMaxCLIDP: &summaryMaxCLIDP{Manager: dataplane.New(), maxSessions: 100},
	}
	return c
}

// TestLocalOptionsReentryThroughDispatch18666 keeps the local full-dispatch
// `summary zone trust` handler path while refusing an unconsumed display pipe.
func TestLocalOptionsReentryThroughDispatch18666(t *testing.T) {
	c := committedOptionsSummaryStore18666(t)
	var err error
	out := captureStdout(t, func() {
		err = c.dispatch("show security flow session summary zone trust")
	})
	if err != nil {
		t.Fatalf("dispatch(summary zone trust) = %v; want valid Options re-entry", err)
	}
	if !strings.Contains(out, "Unicast-sessions: 0") || !strings.Contains(out, "Maximum-sessions: 100") {
		t.Fatalf("dispatch summary output missing local response:\n%s", out)
	}

	c = committedOptionsSummaryStore18666(t)
	out = captureStdout(t, func() {
		err = c.dispatch("show security flow session summary zone trust | display xml")
	})
	want := `syntax error: "show security flow session summary" does not accept the output modifier "| display xml"`
	if err == nil || err.Error() != want {
		t.Fatalf("dispatch(summary zone trust | display xml) = %v; want %q", err, want)
	}
	if out != "" {
		t.Fatalf("refused summary pipe output=%q; want refusal before handler", out)
	}
}
