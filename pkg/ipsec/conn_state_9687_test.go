package ipsec

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// persistentManager9687 is newRecordingManager with the #9687 state file at
// path and the swanctl seam routed through run.
func persistentManager9687(t *testing.T, run func(args ...string) ([]byte, error), path string) *Manager {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = run
	m.statePath = path
	return m
}

func readState9687(t *testing.T, path string) connState {
	t.Helper()
	st, err := loadConnState(path)
	if err != nil {
		t.Fatalf("read state %s: %v", path, err)
	}
	return st
}

func writeState9687(t *testing.T, path string, st connState) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRestartKeepsFailedTerminateDebt9687 is the #6542 arm: a terminate that
// failed before an xpfd restart must be retried by the restarted daemon, whose
// Manager is new.
func TestRestartKeepsFailedTerminateDebt9687(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	rec := &swanctlRecorder{}
	m1 := persistentManager9687(t, rec.run, path)
	if err := m1.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a", "site-b")
	rec.terminateErr = map[string]error{"site-a": errTerminate}
	if err := m1.Apply(vpnCfg("site-b")); err == nil {
		t.Fatal("the delete Apply must report the failed terminate")
	}

	// xpfd restarts before the retry; strongSwan's SA for site-a survives it.
	rec2 := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m2 := persistentManager9687(t, rec2.run, path)
	if err := m2.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("first Apply after the restart: %v", err)
	}
	if got := rec2.terminateCalls(); !reflect.DeepEqual(got, []string{"site-a"}) {
		t.Fatalf("the restarted daemon must retry site-a's teardown, got terminate calls %v", got)
	}
	if st := readState9687(t, path); len(st.Pending) != 0 || !reflect.DeepEqual(st.Loaded, []string{"site-b"}) {
		t.Fatalf("a settled retry must leave loaded=[site-b] and no debt on disk, got %+v", st)
	}

	// Control: the same restart without the state file is the defect.
	rec3 := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m3 := newRecordingManager(t, rec3)
	if err := m3.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("CONTROL: %v", err)
	}
	if got := rec3.terminateCalls(); len(got) != 0 {
		t.Fatalf("CONTROL BROKE: a Manager with no state cannot know site-a departed, yet terminated %v", got)
	}
}

// TestRestartAfterADeferredRemovalStillTearsDown9687 is the #4898 arm: a failed
// reload keeps the previous loaded set, and a restart must not lose it.
func TestRestartAfterADeferredRemovalStillTearsDown9687(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	rec := &swanctlRecorder{}
	failLoad := false
	run := func(args ...string) ([]byte, error) {
		if failLoad && len(args) > 0 && args[0] == "--load-all" {
			return []byte("load failed"), errors.New("charon vici socket refused")
		}
		return rec.run(args...)
	}
	m1 := persistentManager9687(t, run, path)
	if err := m1.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	failLoad = true
	if err := m1.Apply(vpnCfg("site-b")); err == nil {
		t.Fatal("the reload failure must be returned")
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("a failed reload must terminate nothing (#4898), got %v", got)
	}
	if st := readState9687(t, path); !reflect.DeepEqual(st.Loaded, []string{"site-a", "site-b"}) {
		t.Fatalf("after a failed reload the persisted loaded set must still be the effective one, got %+v", st)
	}

	rec2 := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m2 := persistentManager9687(t, rec2.run, path)
	if err := m2.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("first Apply after the restart: %v", err)
	}
	if got := rec2.terminateCalls(); !reflect.DeepEqual(got, []string{"site-a"}) {
		t.Fatalf("the restarted daemon must tear down the deferred removal site-a, got %v", got)
	}
}

// TestStopMidTeardownLeavesDebtOnDisk9687 is the third arm: while a departed
// connection's terminate runs, the file must already name it as debt, and a
// completed teardown must leave no debt behind.
func TestStopMidTeardownLeavesDebtOnDisk9687(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	rec := &swanctlRecorder{}
	var during *connState
	run := func(args ...string) ([]byte, error) {
		if len(args) == 3 && args[0] == "--terminate" && args[2] == "site-a" {
			st, err := loadConnState(path)
			if err != nil {
				t.Errorf("state unreadable while the teardown runs: %v", err)
			} else {
				during = &st
			}
		}
		return rec.run(args...)
	}
	m := persistentManager9687(t, run, path)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a", "site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}
	if during == nil || !reflect.DeepEqual(during.Pending, []string{"site-a"}) {
		t.Fatalf("while site-a's terminate runs the file must name it as debt, got %+v", during)
	}
	if st := readState9687(t, path); len(st.Pending) != 0 {
		t.Fatalf("a completed teardown must leave no debt on disk, got %+v", st)
	}
}

// TestReaddedVPNDischargesPersistedDebt9687: persisted debt is never a licence
// to terminate a connection the new config loads.
func TestReaddedVPNDischargesPersistedDebt9687(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	writeState9687(t, path, connState{Loaded: []string{"site-b"}, Pending: []string{"site-a"}})
	rec := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m := persistentManager9687(t, rec.run, path)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("site-a is configured again; its persisted debt must discharge, not tear it down, got %v", got)
	}
	if st := readState9687(t, path); len(st.Pending) != 0 || !reflect.DeepEqual(st.Loaded, []string{"site-a", "site-b"}) {
		t.Fatalf("want loaded=[site-a site-b] and no debt, got %+v", st)
	}
}

// TestUnusableStateIsIgnored9687: a missing, corrupt or oversized file seeds
// nothing and fails nothing, which is the behaviour before #9687.
func TestUnusableStateIsIgnored9687(t *testing.T) {
	cases := []struct {
		name  string
		write func(t *testing.T, path string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"corrupt", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		// Valid JSON padded past the bound. Its first maxConnStateBytes+1
		// bytes still parse and name site-a, so only the size check keeps it
		// out; a plainly truncated document would be refused by the parser
		// whether the check existed or not.
		{"oversized", func(t *testing.T, p string) {
			big := `{"loaded":["site-a"],"pending_terminate":[]}` + strings.Repeat(" ", maxConnStateBytes)
			if err := os.WriteFile(p, []byte(big), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
			tc.write(t, path)
			rec := &swanctlRecorder{listSAs: liveSA("site-a")}
			m := persistentManager9687(t, rec.run, path)
			if err := m.Apply(vpnCfg("site-b")); err != nil {
				t.Fatalf("an unusable state file must not fail the apply: %v", err)
			}
			if got := rec.terminateCalls(); len(got) != 0 {
				t.Fatalf("nothing trustworthy names site-a, yet it was terminated: %v", got)
			}
		})
	}
}

// TestStateWriteFailureDoesNotFailApply9687: persistence is logged, never an
// apply failure.
func TestStateWriteFailureDoesNotFailApply9687(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &swanctlRecorder{}
	m := persistentManager9687(t, rec.run, filepath.Join(blocker, "ipsec-conn-state.json"))
	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("a failed state write must be logged, not fail the apply: %v", err)
	}
}

// TestDaemonManagerPersistsConnState9687 binds the wiring: the daemon builds
// its Manager with New, which must persist; NewWithConfigDir must not.
func TestDaemonManagerPersistsConnState9687(t *testing.T) {
	if got := New().statePath; got != DefaultConnStatePath {
		t.Fatalf("New() must persist to %s, got %q", DefaultConnStatePath, got)
	}
	if got := NewWithConfigDir(t.TempDir()).statePath; got != "" {
		t.Fatalf("NewWithConfigDir must not persist, got %q", got)
	}
}
