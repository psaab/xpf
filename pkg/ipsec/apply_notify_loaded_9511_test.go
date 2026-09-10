package ipsec

import (
	"errors"
	"strings"
	"testing"
)

// #9511: the HA IPsec attribution reads the generation strongSwan has actually
// LOADED, and learns it from ApplyNotifyLoaded's callback. These cells pin the three
// answers the daemon depends on, including WHEN the callback runs.

// A failed reload leaves the previous generation loaded, so the callback must not
// run; otherwise the daemon would attribute against a config charon never took.
func TestApplyNotifyLoadedSilentOnFailedReload9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return nil, errors.New("charon vici socket refused")
		}
		return nil, nil
	}
	called := 0
	if err := m.ApplyNotifyLoaded(vpnCfg("vpn1"), func() { called++ }); err == nil {
		t.Fatal("FIXTURE: the reload must fail")
	}
	if called != 0 {
		t.Errorf("a failed reload reported the config loaded (%d calls); charon still "+
			"runs the previous generation", called)
	}
}

// A successful reload reports it exactly once.
func TestApplyNotifyLoadedOnceOnSuccessfulReload9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	called := 0
	if err := m.ApplyNotifyLoaded(vpnCfg("vpn1"), func() { called++ }); err != nil {
		t.Fatalf("FIXTURE: apply must succeed, got %v", err)
	}
	if called != 1 {
		t.Errorf("loaded callback ran %d times after one successful load, want 1", called)
	}
}

// Teardown debt (#6542) is returned AFTER a successful reload, so the callback must
// still run. It must also run BEFORE the teardown, which can take tens of seconds
// while the new generation is already the one charon runs: the terminate double
// records whether the callback had already fired when the teardown reached swanctl.
func TestApplyNotifyLoadedBeforeTeardownDespiteDebt9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: first apply must succeed, got %v", err)
	}

	called := 0
	calledAtTerminate := -1
	m.swanctl = func(args ...string) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "--list-sas":
			return []byte("vpn1: #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r\n"), nil
		case len(args) > 0 && args[0] == "--terminate":
			calledAtTerminate = called
			return nil, errors.New("terminate refused")
		}
		return nil, nil
	}
	err := m.ApplyNotifyLoaded(vpnCfg("vpn2"), func() { called++ })
	if err == nil || !strings.Contains(err.Error(), "vpn1") {
		t.Fatalf("FIXTURE: replacing vpn1 with a live, unterminable SA must return "+
			"teardown debt naming vpn1, got %v", err)
	}
	if called != 1 {
		t.Errorf("loaded callback ran %d times; the reload of vpn2 SUCCEEDED before the "+
			"teardown debt was returned", called)
	}
	if calledAtTerminate != 1 {
		t.Errorf("teardown reached swanctl before the loaded callback ran (calls at "+
			"terminate: %d); re-initiation would attribute against the previous "+
			"generation for the whole teardown", calledAtTerminate)
	}
}
