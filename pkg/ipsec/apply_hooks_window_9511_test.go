package ipsec

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9511 stopgap: ApplyWithHooks' Written hook marks the moment the on-disk swanctl
// config changes, which is when charon's own next start or reload would load something
// other than the generation xpfd last recorded. These cells pin WHEN each hook fires.

// Written fires after the new file is on disk and BEFORE `--load-all`. On a failed
// reload only Written fires.
func TestApplyHooksWrittenBeforeReloadOnlyOnFailure9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	written, loaded := 0, 0
	writtenAtReload, fileAtReload := -1, false
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			writtenAtReload = written
			_, err := os.Stat(m.configPath)
			fileAtReload = err == nil
			return nil, errors.New("charon vici socket refused")
		}
		return nil, nil
	}
	err := m.ApplyWithHooks(vpnCfg("vpn1"), ApplyHooks{
		Written: func() { written++ },
		Loaded:  func() { loaded++ },
	})
	if err == nil {
		t.Fatal("FIXTURE: the reload must fail")
	}
	if !fileAtReload {
		t.Fatal("FIXTURE: the new file must be on disk when the reload runs")
	}
	if writtenAtReload != 1 {
		t.Errorf("Written must have fired exactly once BEFORE --load-all, got %d at reload time", writtenAtReload)
	}
	if loaded != 0 {
		t.Errorf("a failed reload must not report Loaded, got %d", loaded)
	}
}

// Neither hook fires when the render fails: nothing reached the disk.
func TestApplyHooksSilentOnRenderFailure9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	cfg := vpnCfg("vpn1")
	cfg.IKEProposals = map[string]*config.IKEProposal{"prop-bad": {Name: "prop-bad", AuthMethod: "bogus"}}
	cfg.IKEPolicies = map[string]*config.IKEPolicy{"pol-bad": {Proposals: []string{"prop-bad"}}}
	cfg.Gateways = map[string]*config.IPsecGateway{"gw-bad": {Address: "172.16.9.9", IKEPolicy: "pol-bad"}}
	for _, v := range cfg.VPNs {
		v.Gateway = "gw-bad"
	}
	written, loaded := 0, 0
	if err := m.ApplyWithHooks(cfg, ApplyHooks{Written: func() { written++ }, Loaded: func() { loaded++ }}); err == nil {
		t.Fatal("FIXTURE: the render must fail on the bogus auth method")
	}
	if written != 0 || loaded != 0 {
		t.Errorf("a render failure wrote nothing; hooks must stay silent, got written=%d loaded=%d", written, loaded)
	}
}

// Neither hook fires when the write fails: the previous file is still on disk.
func TestApplyHooksSilentOnWriteFailure9511(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewWithConfigDir(filepath.Join(blocker, "conf.d"))
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	written, loaded := 0, 0
	if err := m.ApplyWithHooks(vpnCfg("vpn1"), ApplyHooks{
		Written: func() { written++ },
		Loaded:  func() { loaded++ },
	}); err == nil {
		t.Fatal("FIXTURE: the write into an unwritable dir must fail")
	}
	if written != 0 || loaded != 0 {
		t.Errorf("a write failure changed nothing on disk; hooks must stay silent, got written=%d loaded=%d", written, loaded)
	}
}

// The empty-config path REMOVES the file, which is an on-disk change, so Written fires
// before the reload there too.
func TestApplyHooksWrittenOnClearPath9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: the first apply must succeed, got %v", err)
	}
	written, loaded := 0, 0
	writtenAtReload, fileGoneAtReload := -1, false
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			writtenAtReload = written
			_, err := os.Stat(m.configPath)
			fileGoneAtReload = os.IsNotExist(err)
			return nil, errors.New("charon vici socket refused")
		}
		return nil, nil
	}
	if err := m.ApplyWithHooks(nil, ApplyHooks{Written: func() { written++ }, Loaded: func() { loaded++ }}); err == nil {
		t.Fatal("FIXTURE: the clear reload must fail")
	}
	if !fileGoneAtReload {
		t.Fatal("FIXTURE: the file must already be removed when the reload runs")
	}
	if writtenAtReload != 1 || loaded != 0 {
		t.Errorf("clear path: Written must fire once before --load-all and Loaded not at all, got written@reload=%d loaded=%d", writtenAtReload, loaded)
	}
}

// A successful apply runs Written, then Loaded.
func TestApplyHooksWrittenThenLoadedOnSuccess9511(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	var order []string
	if err := m.ApplyWithHooks(vpnCfg("vpn1"), ApplyHooks{
		Written: func() { order = append(order, "written") },
		Loaded:  func() { order = append(order, "loaded") },
	}); err != nil {
		t.Fatalf("FIXTURE: apply must succeed, got %v", err)
	}
	if len(order) != 2 || order[0] != "written" || order[1] != "loaded" {
		t.Errorf("hook order = %v, want [written loaded]", order)
	}
}
