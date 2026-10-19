package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15129 (A90-03): the #14589 partial-load branch in ApplyGeneration
// discarded the `changed` result of promoteConnNames and returned
// before reinitiateChangedConnections. A changed
// establish-tunnels=immediately survivor (e.g. rotated PSK) that charon
// DID load in the partial subset therefore had its stale live SA
// terminated and its new hash promoted, but was never re-initiated:
// start_action=start fires only on load, its SA is now gone, and no
// trap remains — fixing the refused VPN later cannot restore it
// because the hash already matches. This file pins that the partial
// branch re-initiates such a survivor exactly like the full-load path
// (#14140 intent gate included), while non-eager survivors and the
// full-load control keep their existing behaviour.
//
// The fake below extends partialCharon14589: on a partial --load-all
// charon loads only "a" (refusing "c"), and "a" has a live SA that the
// teardown must terminate before any re-initiation.

type partialReinitCharon15129 struct {
	loaded         map[string]bool
	loadedFromDisk func() map[string]bool
	partial        bool
	loadErr        error
	live           map[string]bool
	calls          [][]string
}

func (c *partialReinitCharon15129) run(args ...string) ([]byte, error) {
	c.calls = append(c.calls, append([]string{}, args...))
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "--load-all":
		if c.partial {
			c.partial = false
			c.loaded = map[string]bool{"a": true}
			return []byte("loading connection 'c' failed: config discarded\nloaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), c.loadErr
		}
		if c.loadedFromDisk != nil {
			c.loaded = c.loadedFromDisk()
		}
		return nil, nil
	case "--list-conns":
		var b strings.Builder
		for name := range c.loaded {
			b.WriteString("list-conn event {" + name + " {local_addrs=[10.0.1.1] remote_addrs=[10.0.2.1] children {" + name + " {}}}}\n")
		}
		b.WriteString("list-conns reply {}\n")
		return []byte(b.String()), nil
	case "--list-sas":
		return []byte(liveSA(mapsKeys15129(c.live)...)), nil
	}
	return nil, nil
}

func (c *partialReinitCharon15129) terminateCalls() []string {
	var names []string
	for _, call := range c.calls {
		if len(call) == 3 && call[0] == "--terminate" && call[1] == "--ike" {
			names = append(names, call[2])
		}
	}
	return names
}

func (c *partialReinitCharon15129) initiateCalls() []string {
	var names []string
	for _, call := range c.calls {
		if len(call) == 3 && call[0] == "--initiate" && call[1] == "--child" {
			names = append(names, call[2])
		}
	}
	return names
}

func mapsKeys15129(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func newPartialReinitManager15129(t *testing.T) (*Manager, *partialReinitCharon15129) {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	ch := &partialReinitCharon15129{loaded: map[string]bool{}, live: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	return m, ch
}

func cfg15129(mode string) *config.IPsecConfig {
	cfg := vpnCfg("a", "b")
	for _, vpn := range cfg.VPNs {
		vpn.EstablishTunnels = mode
	}
	return cfg
}

func rotatedCfg15129(mode string) *config.IPsecConfig {
	cfg := vpnCfg("a", "c")
	for _, vpn := range cfg.VPNs {
		vpn.EstablishTunnels = mode
	}
	cfg.VPNs["a"].PSK = config.Secret("rotated-secret-a")
	return cfg
}

// Core RED cell: partial load with a changed immediately survivor.
// Pre-fix: terminate(a) happens, no initiate(a) — the always-on
// tunnel stays down. Post-fix: initiate(a) after terminate(a), and
// the partial error is still returned.
func TestPartialLoadChangedImmediatelySurvivorIsReinitiated15129(t *testing.T) {
	m, ch := newPartialReinitManager15129(t)
	if err := m.Apply(cfg15129("immediately")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	ch.live = map[string]bool{"a": true, "b": true}
	oldHash := m.prevConnHashes["a"]

	ch.partial = true
	ch.loadErr = errors.New("exit status 22")
	err := m.Apply(rotatedCfg15129("immediately"))
	if err == nil {
		t.Fatal("partial load must still return an error")
	}
	// removed = {a(changed), b(deleted)}; both live SAs are torn down,
	// but only a survives in the candidate config to be re-initiated.
	terms := ch.terminateCalls()
	foundA := false
	for _, n := range terms {
		if n == "a" {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("changed survivor stale SA must be terminated, got terminate %v (calls %v)", terms, ch.calls)
	}
	if got := ch.initiateCalls(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("changed immediately survivor must be re-initiated after partial load, got initiate %v (calls %v)", got, ch.calls)
	}
	if m.prevConnHashes["a"] == oldHash || m.prevConnHashes["a"] == "" {
		t.Fatalf("prev hash for a must adopt rotated hash (old %q now %q)", oldHash, m.prevConnHashes["a"])
	}
	// Disk/charon consistency from #14589 must be preserved.
	data, rerr := os.ReadFile(m.configPath)
	if rerr != nil {
		t.Fatalf("read disk: %v", rerr)
	}
	if disk := connNamesInFile14589(t, string(data)); disk["b"] || disk["c"] || !disk["a"] {
		t.Fatalf("disk %v must name only loaded survivor {a}", disk)
	}
}

// Control: same partial load, but the survivor is on-traffic (trap).
// The #14140 gate must still suppress eager re-initiation — the trap
// re-establishes on traffic under the new config.
func TestPartialLoadChangedOnTrafficSurvivorIsNotReinitiated15129(t *testing.T) {
	m, ch := newPartialReinitManager15129(t)
	if err := m.Apply(cfg15129("on-traffic")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	ch.live = map[string]bool{"a": true}

	ch.partial = true
	ch.loadErr = errors.New("exit status 22")
	if err := m.Apply(rotatedCfg15129("on-traffic")); err == nil {
		t.Fatal("partial load must still return an error")
	}
	if got := ch.terminateCalls(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("changed survivor stale SA must be terminated, got %v", got)
	}
	if got := ch.initiateCalls(); len(got) != 0 {
		t.Fatalf("on-traffic survivor must not be eagerly re-initiated, got %v", got)
	}
}

// Control: partial load where the survivor is UNCHANGED (only the
// deleted/refused legs differ). No terminate, no initiate — the
// survivor's live SA was never torn down, so nothing to restore.
func TestPartialLoadUnchangedSurvivorIsNotReinitiated15129(t *testing.T) {
	m, ch := newPartialReinitManager15129(t)
	if err := m.Apply(cfg15129("immediately")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	ch.live = map[string]bool{"a": true, "b": true}

	ch.partial = true
	ch.loadErr = errors.New("exit status 22")
	// Candidate {a,c} with a's config byte-identical to gen1.
	candidate := vpnCfg("a", "c")
	for _, vpn := range candidate.VPNs {
		vpn.EstablishTunnels = "immediately"
	}
	if err := m.Apply(candidate); err == nil {
		t.Fatal("partial load must still return an error")
	}
	for _, n := range ch.terminateCalls() {
		if n == "a" {
			t.Fatalf("unchanged survivor must not be terminated, got %v", ch.terminateCalls())
		}
	}
	if got := ch.initiateCalls(); len(got) != 0 {
		t.Fatalf("unchanged survivor must not be re-initiated, got %v", got)
	}
}

// Control: the full-load path for the same change still re-initiates
// (existing #14140 behaviour, unchanged by this fix).
func TestFullLoadChangedImmediatelySurvivorStillReinitiated15129(t *testing.T) {
	m, ch := newPartialReinitManager15129(t)
	if err := m.Apply(cfg15129("immediately")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.live = map[string]bool{"a": true}
	if err := m.Apply(rotatedCfg15129("immediately")); err != nil {
		t.Fatalf("full-load changed Apply: %v", err)
	}
	if got := ch.initiateCalls(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("full-load changed immediately VPN must be re-initiated, got %v (calls %v)", got, ch.calls)
	}
}
