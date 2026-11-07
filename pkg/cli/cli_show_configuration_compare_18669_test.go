package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

const (
	activeDomain18669    = "active-18669.example"
	activeInterface18669 = "active-interface-18669"
	candidateCanary18669 = "candidate-baseline-canary-18669"
)

func showCompareStore18669(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	base := []string{
		"set system host-name compare-18669-base",
		"set interfaces ge-0/0/0 description old-interface-18669",
		"set system login class rollback-deny permissions [ view ]",
		"set system login class rollback-deny deny-configuration \"interfaces ge-0/0/0 description old-interface-18669\"",
		"set system login class compare-deny permissions [ view ]",
		"set system login class compare-deny deny-commands \"compare$\"",
	}
	if _, err := store.LoadSet(strings.Join(base, "\n")); err != nil {
		t.Fatalf("LoadSet(base): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	active := []string{
		"set system domain-name " + activeDomain18669,
		"set interfaces ge-0/0/0 description " + activeInterface18669,
	}
	if _, err := store.LoadSet(strings.Join(active, "\n")); err != nil {
		t.Fatalf("LoadSet(active): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(active): %v", err)
	}
	// Leave the active configuration different from a staged candidate so
	// a mutant that compares rollback 1 against the candidate is observable.
	staged := []string{
		"set system domain-name candidate-18669.invalid",
		"set system host-name " + candidateCanary18669,
	}
	if _, err := store.LoadSet(strings.Join(staged, "\n")); err != nil {
		t.Fatalf("LoadSet(candidate): %v", err)
	}
	return store
}

func TestCLIShowConfigurationCompareRollback18669(t *testing.T) {
	for _, tc := range []struct {
		line    string
		wantIn  []string
		wantOut []string
	}{
		{
			line:    "show configuration | compare rollback 1",
			wantIn:  []string{activeDomain18669, activeInterface18669},
			wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
		},
		{
			line:    "show configuration system | compare rollback 1",
			wantIn:  []string{activeDomain18669},
			wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
		},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := &CLI{store: showCompareStore18669(t)}
			var err error
			out := captureStdout(t, func() { err = c.dispatchOperational(tc.line) })
			if err != nil {
				t.Fatalf("dispatchOperational(%q): %v", tc.line, err)
			}
			for _, value := range tc.wantIn {
				if !strings.Contains(out, value) {
					t.Errorf("dispatchOperational(%q) output missing active-baseline value %q:\n%s", tc.line, value, out)
				}
			}
			for _, value := range tc.wantOut {
				if strings.Contains(out, value) {
					t.Errorf("dispatchOperational(%q) output contains out-of-scope or candidate value %q:\n%s", tc.line, value, out)
				}
			}
		})
	}
}

func TestCLIShowConfigurationCompareRefusals18669(t *testing.T) {
	for _, tc := range []struct{ line string }{
		{"show configuration | compare"},
		{"show configuration | compare rollback"},
		{"show configuration | compare rollback not-a-number"},
		{"show configuration | compare rollback -1"},
		{"show configuration | compare rollback 1 extra"},
		{"show configuration | compare rollback 99999999999999999999"},
		{"show configuration | compare other"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := &CLI{store: showCompareStore18669(t)}
			var err error
			out := captureStdout(t, func() { err = c.dispatchOperational(tc.line) })
			if err == nil {
				t.Fatalf("dispatchOperational(%q) returned nil, output %q; want a non-nil syntax error", tc.line, out)
			}
			if out != "" {
				t.Errorf("dispatchOperational(%q) printed %q before refusing", tc.line, out)
			}
			if tc.line == "show configuration | compare" && err.Error() != "syntax error: | compare on operational show configuration requires rollback <N>" {
				t.Errorf("bare compare error = %q; want the explicit rollback requirement", err)
			}
		})
	}
}

func TestCLIShowConfigurationOtherPipeUnchanged18669(t *testing.T) {
	c := &CLI{store: showCompareStore18669(t)}
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show configuration | frobnicate") })
	if err != nil || out != "syntax error: unknown pipe command 'frobnicate'\n" {
		t.Fatalf("unknown pipe result = (%q, %v); want existing print-and-nil behavior", out, err)
	}
}

func TestCLIShowConfigurationCompareRegexDenial18669(t *testing.T) {
	c := &CLI{store: showCompareStore18669(t), userClass: "compare-deny"}
	var err error
	out := captureStdout(t, func() { err = c.dispatchOperational("show configuration | compare") })
	if err == nil || !strings.Contains(err.Error(), `denies "show configuration"`) {
		t.Fatalf("bare compare denial = %v; want the configured deny-commands rule to price the pipe", err)
	}
	if out != "" {
		t.Errorf("denied compare printed output: %q", out)
	}
}

func TestCLIShowConfigurationComparePricesRollbackTree18669(t *testing.T) {
	for _, line := range []string{
		"show configuration | compare rollback 1",
		"show configuration interfaces | compare rollback 1",
	} {
		t.Run(line, func(t *testing.T) {
			c := &CLI{store: showCompareStore18669(t), userClass: "rollback-deny"}
			var err error
			out := captureStdout(t, func() { err = c.dispatchOperational(line) })
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("rollback-only denied subtree compare = %v; want a configuration-read refusal", err)
			}
			if out != "" {
				t.Errorf("denied rollback-only compare printed output: %q", out)
			}
		})
	}
}
