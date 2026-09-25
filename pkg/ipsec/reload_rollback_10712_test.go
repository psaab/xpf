package ipsec

import (
	"errors"
	"os"
	"testing"
)

// RED on revert: after a rejected candidate reload, the next service reload must
// see the prior file, not silently activate the candidate after a charon restart.
func TestFailedReloadRestoresPriorConfigForRestart10712(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.Apply(vpnCfg("vpn-old")); err != nil {
		t.Fatalf("FIXTURE: initial config apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read initial config: %v", err)
	}

	reloadErr := errors.New("candidate rejected")
	loadCalls := 0
	var fileSeenOnRestart []byte
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			loadCalls++
			if loadCalls == 1 {
				candidate, err := os.ReadFile(m.configPath)
				if err != nil {
					t.Fatalf("FIXTURE: candidate must be installed for its reload: %v", err)
				}
				if string(candidate) == string(prior) {
					t.Fatal("FIXTURE: failed reload must have attempted the new config")
				}
				return []byte("unable to load candidate"), reloadErr
			}
			fileSeenOnRestart, err = os.ReadFile(m.configPath)
			if err != nil {
				t.Fatalf("read config during simulated service restart: %v", err)
			}
		}
		return nil, nil
	}

	if err := m.Apply(vpnCfg("vpn-new")); !errors.Is(err, reloadErr) {
		t.Fatalf("Apply error = %v, want candidate reload error", err)
	}
	if err := m.reload(); err != nil {
		t.Fatalf("simulated service restart reload: %v", err)
	}
	if string(fileSeenOnRestart) != string(prior) {
		t.Fatalf("restart would load a different config after failed Apply: got %q, want prior config %q", fileSeenOnRestart, prior)
	}
}

// The same invariant applies when clearing: a failed clear must put the removed
// file back so charon's next start does not load an unapplied empty config.
func TestFailedClearRestoresPriorConfigForRestart10712(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.Apply(vpnCfg("vpn-old")); err != nil {
		t.Fatalf("FIXTURE: initial config apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read initial config: %v", err)
	}

	reloadErr := errors.New("clear rejected")
	loadCalls := 0
	var fileSeenOnRestart []byte
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			loadCalls++
			if loadCalls == 1 {
				if _, err := os.Stat(m.configPath); !os.IsNotExist(err) {
					t.Fatalf("FIXTURE: clear must remove the file for its reload, stat err=%v", err)
				}
				return []byte("unable to clear"), reloadErr
			}
			fileSeenOnRestart, err = os.ReadFile(m.configPath)
			if err != nil {
				t.Fatalf("read config during simulated service restart: %v", err)
			}
		}
		return nil, nil
	}

	if err := m.Clear(); !errors.Is(err, reloadErr) {
		t.Fatalf("Clear error = %v, want clear reload error", err)
	}
	if err := m.reload(); err != nil {
		t.Fatalf("simulated service restart reload: %v", err)
	}
	if string(fileSeenOnRestart) != string(prior) {
		t.Fatalf("restart would load a different config after failed Clear: got %q, want prior config %q", fileSeenOnRestart, prior)
	}
}

func TestFailedFirstReloadRemovesUnloadedConfig10712(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	reloadErr := errors.New("initial candidate rejected")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return nil, reloadErr
		}
		return nil, nil
	}
	if err := m.Apply(vpnCfg("vpn-new")); !errors.Is(err, reloadErr) {
		t.Fatalf("Apply error = %v, want initial reload error", err)
	}
	if _, err := os.Stat(m.configPath); !os.IsNotExist(err) {
		t.Fatalf("a config that never loaded must not remain on disk, stat err=%v", err)
	}
}
