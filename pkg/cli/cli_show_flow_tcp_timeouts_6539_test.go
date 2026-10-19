package cli

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// flowTimeoutStore commits the given set lines and returns the store.
func flowTimeoutStore(t *testing.T, lines []string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range lines {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// #6539: `show security flow` must not render the three tcp-session timeouts
// that have NO dataplane wire carrier in the same shape as established-timeout,
// which does. The annotation is read from config.TCPSessionTimeoutNote, binding
// this surface to the same authority the REST and gRPC surfaces use.
func TestShowFlowTimeoutsAnnotateUnenforced_6539(t *testing.T) {
	c := &CLI{store: flowTimeoutStore(t, []string{
		"set security flow tcp-session established-timeout 600",
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})}

	out := captureStdout(t, func() {
		if err := c.showFlowTimeouts(); err != nil {
			t.Fatalf("showFlowTimeouts() error = %v", err)
		}
	})

	lineWith := func(sub string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		return ""
	}

	for _, tc := range []struct {
		label string
		leaf  string
		value string
	}{
		{"TCP initial timeout", config.TCPSessionInitialTimeoutLeaf, "45s"},
		{"TCP closing timeout", config.TCPSessionClosingTimeoutLeaf, "15s"},
		{"TCP time-wait timeout", config.TCPSessionTimeWaitTimeoutLeaf, "90s"},
	} {
		line := lineWith(tc.label + ":")
		if line == "" {
			t.Errorf("no %q row rendered; the operator surface vanished.\n%s", tc.label, out)
			continue
		}
		if !strings.Contains(line, tc.value) {
			t.Errorf("%s row lost the configured value %s: %q", tc.label, tc.value, line)
		}
		// #7342: every tcp-session timeout is enforced now, so the shared
		// table hands back no annotation and the row must render the bare
		// value. Reading the note from the table rather than hard-coding "no
		// annotation" is what keeps this surface tied to the single authority:
		// if a future leaf becomes unenforced, this asserts the annotation
		// appears instead.
		note := config.TCPSessionTimeoutNote(tc.leaf)
		if note == "" {
			if strings.Contains(line, "not enforced") {
				t.Errorf("%s row still carries a not-enforced annotation for an ENFORCED leaf, "+
					"so the CLI reports a configured value as inert: %q", tc.label, line)
			}
			continue
		}
		if !strings.Contains(line, note) {
			t.Errorf("%s row does not carry the shared not-enforced annotation, so the CLI reports "+
				"a value in force.\n got: %q\nwant substring: %q", tc.label, line, note)
		}
	}

	est := lineWith("TCP established timeout:")
	if est == "" {
		t.Fatalf("no TCP established row rendered.\n%s", out)
	}
	if !strings.Contains(est, "600s") {
		t.Errorf("TCP established row lost its value: %q", est)
	}
	if strings.Contains(est, "not enforced") {
		t.Errorf("established-timeout is wire-carried and must render unannotated: %q", est)
	}
}

// With NO tcp-session stanza at all, every row must still render, and the
// "(default)" it prints must be the window the DATAPLANE falls back to — not
// the Junos default the CLI used to print. A default value is itself an
// enforcement claim: before #6539 the CLI said an unset established-timeout
// meant 1800s, when nothing in the Go path fills that in and the helper
// actually idles the session out at its own constant.
//
// time-wait has no dataplane window at all (no TIME_WAIT state), so it must
// NOT claim a default.
func TestShowFlowTimeoutsUnsetDefaultsAreTheDataplanes_6539(t *testing.T) {
	c := &CLI{store: flowTimeoutStore(t, []string{"set security zones security-zone trust"})}

	out := captureStdout(t, func() {
		if err := c.showFlowTimeouts(); err != nil {
			t.Fatalf("showFlowTimeouts() error = %v", err)
		}
	})

	lineWith := func(sub string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		return ""
	}

	est := lineWith("TCP established timeout:")
	if est == "" {
		t.Fatalf("no TCP established row rendered for an absent tcp-session stanza.\n%s", out)
	}
	// #15127: the dataplane fallback is now the Junos 1800 s itself, so the
	// rendered default must be exactly "1800s (default)" — sourced from the
	// config constant, never a divergent literal.
	wantEstCheck := strconv.Itoa(config.DataplaneTCPEstablishedWindowSecs) + "s (default)"
	if wantEstCheck != "1800s (default)" {
		t.Fatalf("dataplane established fallback is %q, want 1800s (default) (#15127)", wantEstCheck)
	}
	wantEst := strconv.Itoa(config.DataplaneTCPEstablishedWindowSecs) + "s (default)"
	if !strings.Contains(est, wantEst) {
		t.Errorf("unset established-timeout must render the dataplane fallback %q: %q", wantEst, est)
	}

	init := lineWith("TCP initial timeout:")
	wantInit := strconv.Itoa(config.DataplaneTCPOpeningWindowSecs) + "s (default)"
	if !strings.Contains(init, wantInit) {
		t.Errorf("unset initial-timeout must render the dataplane half-open window %q: %q", wantInit, init)
	}
	if strings.Contains(init, "not enforced") {
		t.Errorf("unset initial-timeout row still carries a not-enforced annotation: %q", init)
	}

	// #7342: time-wait HAS a state now, so it has a default to report. Before
	// the close-state split there was nothing distinct to time out and printing
	// "(default)" would have been an unbacked enforcement claim; the split is
	// what turned that from a lie into a fact.
	tw := lineWith("TCP time-wait timeout:")
	if tw == "" {
		t.Fatalf("no TCP time-wait row rendered.\n%s", out)
	}
	wantTW := strconv.Itoa(config.DataplaneTCPClosingWindowSecs) + "s (default)"
	if !strings.Contains(tw, wantTW) {
		t.Errorf("unset time-wait-timeout must render the dataplane window %q: %q", wantTW, tw)
	}
	// And it is deliberately the SAME window closing-timeout reports: an
	// operator who sets neither leaf must see the reaping they saw before the
	// state was split. A different default here would be a behaviour change
	// dressed as a rendering one.
	cl := lineWith("TCP closing timeout:")
	if !strings.Contains(cl, wantTW) {
		t.Errorf("closing and time-wait must report the SAME unset default (%q); closing: %q",
			wantTW, cl)
	}
}
