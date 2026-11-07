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
		"set system login class compare-view-18669 permissions [ view ]",
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

func foreignShowCompareStore18669(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf-foreign-18669.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(base): %v", err)
	}
	base := []string{
		"set system host-name compare-18669-base",
		"set interfaces ge-0/0/0 description old-interface-18669",
		"set system login class rollback-deny permissions [ view ]",
		"set system login class rollback-deny deny-configuration \"interfaces ge-0/0/0 description old-interface-18669\"",
		"set system login class compare-deny permissions [ view ]",
		"set system login class compare-deny deny-commands \"compare$\"",
		"set system login class compare-view-18669 permissions [ view ]",
	}
	if _, err := store.LoadSet(strings.Join(base, "\n")); err != nil {
		t.Fatalf("LoadSet(base): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	store.ExitConfigure()

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(active): %v", err)
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
	store.ExitConfigure()

	if err := store.EnterConfigureExclusive("foreign-compare-18669"); err != nil {
		t.Fatalf("EnterConfigureExclusive(foreign): %v", err)
	}
	staged := []string{
		"set system domain-name candidate-18669.invalid",
		"set system host-name " + candidateCanary18669,
	}
	if _, err := store.LoadSet(strings.Join(staged, "\n")); err != nil {
		t.Fatalf("LoadSet(candidate): %v", err)
	}
	return store
}

func TestCLIShowConfigurationCompareDispatchAcrossConfigHolders18669(t *testing.T) {
	fixtures := []struct {
		name  string
		store func(*testing.T) *configstore.Store
	}{
		{"foreign-holder", foreignShowCompareStore18669},
		{"unowned-shared-lock", showCompareStore18669},
	}
	for _, fixture := range fixtures {
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
				line:    "sh configuration | compare rollback 1",
				wantIn:  []string{activeDomain18669, activeInterface18669},
				wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration system | compare rollback 1",
				wantIn:  []string{activeDomain18669},
				wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show conf system | compare rollback 1",
				wantIn:  []string{activeDomain18669},
				wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
			},
		} {
			t.Run(fixture.name+"/"+tc.line, func(t *testing.T) {
				store := fixture.store(t)
				c := &CLI{store: store, userClass: "compare-view-18669"}
				if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
					t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
				}
				if !store.IsDirty() {
					t.Fatal("fixture candidate is not dirty")
				}
				var err error
				out := captureStdout(t, func() { err = c.dispatch(tc.line) })
				if err != nil {
					t.Fatalf("dispatch(%q): %v", tc.line, err)
				}
				for _, value := range tc.wantIn {
					if !strings.Contains(out, value) {
						t.Errorf("dispatch(%q) output missing active-baseline value %q:\n%s", tc.line, value, out)
					}
				}
				for _, value := range tc.wantOut {
					if strings.Contains(out, value) {
						t.Errorf("dispatch(%q) output contains candidate value %q:\n%s", tc.line, value, out)
					}
				}
			})
		}
	}

	for _, fixture := range fixtures {
		for _, line := range []string{
			"show configuration | compare",
			"show conf | compare",
			"sh configuration | compare",
			"show configuration |compare",
		} {
			t.Run(fixture.name+"/bare/"+line, func(t *testing.T) {
				c := &CLI{store: fixture.store(t), userClass: "compare-view-18669"}
				var err error
				out := captureStdout(t, func() { err = c.dispatch(line) })
				if err == nil {
					t.Fatalf("dispatch(%q) returned nil, output %q; want a non-nil operational compare refusal", line, out)
				}
				if strings.Contains(line, "| compare") &&
					err.Error() != "syntax error: | compare on operational show configuration requires rollback <N>" {
					t.Fatalf("bare compare error = %q; want explicit rollback requirement", err)
				}
			})
		}
	}
}
func TestCLIShowConfigurationCompareDispatchOwnerlessNoRBAC18669(t *testing.T) {
	newCLI := func(t *testing.T) (*CLI, *configstore.Store) {
		t.Helper()
		store := showCompareStore18669(t)
		c := &CLI{store: store}
		if c.UserClass() != "" {
			t.Fatalf("UserClass() = %q, want empty legacy no-RBAC class", c.UserClass())
		}
		if c.configOwnedNow() {
			t.Fatal("legacy no-RBAC CLI unexpectedly owns config mode")
		}
		if holder, _ := store.ConfigHolder(); holder != "" {
			t.Fatalf("ConfigHolder() = %q, want no holder", holder)
		}
		if !store.InConfigMode() {
			t.Fatal("fixture is not in config mode")
		}
		if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
			t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
		}
		return c, store
	}

	for _, tc := range []struct {
		name    string
		line    string
		wantIn  []string
		wantOut []string
	}{
		{
			name:    "global",
			line:    "show configuration | compare rollback 1",
			wantIn:  []string{activeDomain18669, activeInterface18669},
			wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
		},
		{
			name:    "scoped",
			line:    "show configuration system | compare rollback 1",
			wantIn:  []string{activeDomain18669},
			wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, store := newCLI(t)
			if !store.IsDirty() {
				t.Fatal("fixture candidate is not dirty")
			}
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err != nil {
				t.Fatalf("dispatch(%q): %v", tc.line, err)
			}
			for _, value := range tc.wantIn {
				if !strings.Contains(out, value) {
					t.Errorf("dispatch(%q) output missing active-baseline value %q:\n%s", tc.line, value, out)
				}
			}
			for _, value := range tc.wantOut {
				if strings.Contains(out, value) {
					t.Errorf("dispatch(%q) output contains candidate value %q:\n%s", tc.line, value, out)
				}
			}
		})
	}

	t.Run("bare", func(t *testing.T) {
		c, _ := newCLI(t)
		var err error
		out := captureStdout(t, func() { err = c.dispatch("show configuration | compare") })
		if err == nil || err.Error() != "syntax error: | compare on operational show configuration requires rollback <N>" {
			t.Fatalf("dispatch(bare compare) = (%q, %v); want operational compare refusal", out, err)
		}
		if out != "" {
			t.Errorf("bare compare printed before refusing: %q", out)
		}
	})
	t.Run("mutation-routing-unchanged", func(t *testing.T) {
		c, store := newCLI(t)
		const hostname = "legacy-no-rbac-mutation-18669"
		if err := c.dispatch("set system host-name " + hostname); err != nil {
			t.Fatalf("dispatch(no-RBAC mutation): %v", err)
		}
		if candidate := store.ShowCandidateSet(); !strings.Contains(candidate, hostname) {
			t.Fatalf("no-RBAC mutation did not update the config candidate:\n%s", candidate)
		}
	})
}

func TestCLIShowConfigurationOwnedCompareKeepsCandidateBaseline18669(t *testing.T) {
	store := showCompareStore18669(t)
	store.ExitConfigure()
	if err := store.EnterConfigureSession(localConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession(local): %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set system domain-name candidate-18669.invalid",
		"set system host-name " + candidateCanary18669,
	}, "\n")); err != nil {
		t.Fatalf("LoadSet(candidate): %v", err)
	}
	c := &CLI{store: store}
	c.setConfigOwned(true)
	if got, want := c.promptForCurrentMode(), c.configPrompt(); got != want {
		t.Fatalf("promptForCurrentMode() = %q, want config prompt %q", got, want)
	}
	var err error
	out := captureStdout(t, func() { err = c.dispatch("show | compare rollback 1") })
	if err != nil {
		t.Fatalf("owned config compare: %v", err)
	}
	if !strings.Contains(out, candidateCanary18669) {
		t.Fatalf("owned config compare omitted candidate canary %q:\n%s", candidateCanary18669, out)
	}
}

func staleOwnedForeignShowCompareCLI18669(t *testing.T) (*CLI, *configstore.Store) {
	t.Helper()
	store := showCompareStore18669(t)
	store.ExitConfigure()
	c := &CLI{store: store}
	if err := c.dispatch("configure"); err != nil {
		t.Fatalf("dispatch(configure): %v", err)
	}
	if !c.configOwnedNow() || !store.InConfigModeForSession(localConfigSessionID) {
		t.Fatal("CLI did not acquire its local config session")
	}

	store.ForceExitConfigure()
	if !c.configOwnedNow() {
		t.Fatal("force exit unexpectedly refreshed the CLI's cached ownership flag")
	}
	if err := store.EnterConfigureExclusive("foreign-stale-owner-18669"); err != nil {
		t.Fatalf("EnterConfigureExclusive(foreign): %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set system domain-name candidate-18669.invalid",
		"set system host-name " + candidateCanary18669,
	}, "\n")); err != nil {
		t.Fatalf("LoadSet(foreign candidate): %v", err)
	}
	if !store.IsDirty() {
		t.Fatal("foreign candidate is not dirty")
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "foreign-stale-owner-18669" {
		t.Fatalf("ConfigHolder() = (%q, %v), want foreign stale owner", holder, locked)
	}
	if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
		t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
	}
	return c, store
}

func TestCLIShowConfigurationCompareDispatchStaleOwned18669(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		wantIn  []string
		wantOut []string
	}{
		{
			name:    "global",
			line:    "show configuration | compare rollback 1",
			wantIn:  []string{activeDomain18669, activeInterface18669},
			wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
		},
		{
			name:    "scoped",
			line:    "show configuration system | compare rollback 1",
			wantIn:  []string{activeDomain18669},
			wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, store := staleOwnedForeignShowCompareCLI18669(t)
			if !c.configOwnedNow() || store.InConfigModeForSession(localConfigSessionID) {
				t.Fatal("fixture does not retain stale local ownership after foreign takeover")
			}
			var err error
			out := captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err != nil {
				t.Fatalf("dispatch(%q): %v", tc.line, err)
			}
			for _, value := range tc.wantIn {
				if !strings.Contains(out, value) {
					t.Errorf("dispatch(%q) output missing active-baseline value %q:\n%s", tc.line, value, out)
				}
			}
			for _, value := range tc.wantOut {
				if strings.Contains(out, value) {
					t.Errorf("dispatch(%q) output contains foreign candidate value %q:\n%s", tc.line, value, out)
				}
			}
		})
	}

	t.Run("bare", func(t *testing.T) {
		c, _ := staleOwnedForeignShowCompareCLI18669(t)
		var err error
		out := captureStdout(t, func() { err = c.dispatch("show configuration | compare") })
		if err == nil || err.Error() != "syntax error: | compare on operational show configuration requires rollback <N>" {
			t.Fatalf("dispatch(bare compare) = (%q, %v); want operational compare refusal", out, err)
		}
		if out != "" {
			t.Errorf("bare compare printed before refusing: %q", out)
		}
	})
}

func TestCLIShowConfigurationGluedCompareRollbackRefusedUnderForeignHolder18669(t *testing.T) {
	store := foreignShowCompareStore18669(t)
	c := &CLI{store: store, userClass: "super-user"}
	var err error
	out := captureStdout(t, func() { err = c.dispatch("show configuration|compare rollback 1") })
	if err == nil {
		t.Fatalf("dispatch(glued compare rollback) returned nil, output %q", out)
	}
	if out != "" {
		t.Errorf("glued compare rollback printed before refusing: %q", out)
	}
	if candidate := store.ShowCandidateSet(); !strings.Contains(candidate, candidateCanary18669) {
		t.Errorf("glued compare changed the foreign candidate:\n%s", candidate)
	}
}

func TestCLIShowConfigurationForeignCompareRoutingKeepsLockGuards18669(t *testing.T) {
	store := foreignShowCompareStore18669(t)
	c := &CLI{store: store, userClass: "super-user"}
	for _, line := range []string{
		"set system host-name blocked-foreign-18669",
		"delete system host-name",
		"commit",
		"configure",
		"run show route",
	} {
		if err := c.dispatch(line); err == nil || !strings.Contains(err.Error(), "configuration is locked by another session") {
			t.Errorf("dispatch(%q) = %v; want foreign-lock refusal", line, err)
		}
		if got := store.ShowCandidateSet(); !strings.Contains(got, candidateCanary18669) {
			t.Fatalf("dispatch(%q) changed the foreign candidate:\n%s", line, got)
		}
	}
	if holder, locked := store.ConfigHolder(); !locked || holder != "foreign-compare-18669" {
		t.Fatalf("foreign lock after refusals = %q/%v; want foreign-compare-18669/true", holder, locked)
	}

	var err error
	out := captureStdout(t, func() { err = c.dispatch("show system") })
	if err != nil || !strings.Contains(out, candidateCanary18669) {
		t.Fatalf("plain config-mode show system = (%q, %v); want candidate rendering through existing branch", out, err)
	}
}

func TestCLIShowConfigurationGluedBareCompareRefused18669(t *testing.T) {
	c := &CLI{store: foreignShowCompareStore18669(t)}
	if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
		t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
	}
	var err error
	out := captureStdout(t, func() { err = c.dispatch("show configuration |compare") })
	if err == nil {
		t.Fatalf("dispatch(glued bare compare) returned nil, output %q", out)
	}
}

func TestCLIShowConfigurationScopedGluedCompareRefused18669(t *testing.T) {
	fixtures := []struct {
		name      string
		store     func(*testing.T) *configstore.Store
		userClass string
	}{
		{"foreign-holder", foreignShowCompareStore18669, "super-user"},
		{"ownerless-no-rbac", showCompareStore18669, ""},
	}
	lines := []string{
		"show configuration system |compare rollback 1",
		"show configuration system domain-name|compare rollback 1",
	}
	for _, fixture := range fixtures {
		for _, line := range lines {
			t.Run(fixture.name+"/"+line, func(t *testing.T) {
				c := &CLI{store: fixture.store(t), userClass: fixture.userClass}
				if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
					t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
				}
				var err error
				out := captureStdout(t, func() { err = c.dispatch(line) })
				if err == nil {
					t.Fatalf("dispatch(%q) returned nil, output %q; want glued-pipe refusal", line, out)
				}
				if strings.Contains(out, "configuration path not found") {
					t.Errorf("dispatch(%q) printed candidate path-not-found output: %q", line, out)
				}
			})
		}
	}
}
