package ipsec

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #15261 (B02-03): after an xpfd restart the Manager's in-memory
// prevConnHashes is empty; the persisted fingerprints (#9687) are only
// folded in by seedFromStateLocked inside promoteConnNames. The #14589
// partial-load recovery calls priorSet14589 BEFORE any promotion, so
// prevHashFor14589 finds nothing and the prior-set hashes come back
// empty. Promoting that set then (a) marks every unchanged prior
// connection "changed" against the empty hash (known && oldHash !=
// newHashes[name] with newHashes[name]==""), tearing down tunnels
// charon kept running untouched, and (b) persists empty fingerprints,
// so the NEXT apply adopts the current hash as its baseline under the
// #10878 legacy-adoption rule and a later PSK rotation is never
// detected / never torn down.
//
// Probe shape (issue acceptance: "the restart arm of the probe matches
// the control arm"): the control arm runs the identical partial first
// apply on a warm Manager that already applied {a,b} in-process; the
// restart arm runs it on a fresh Manager whose only memory of {a,b}
// is the persisted conn-state file (written by a first Manager, as
// production does across an xpfd restart).
//
// Trigger arm: list-conns FAILS during recovery, so recovery falls
// back to the true rollback and promotes priorSet14589(prior).
// Control case: the identical sequence without the prior generation
// ever existing (a brand-new apply that partially loads with no prior
// file) still promotes the empty set and reports the error.

// restartCharon15261 models charon across an xpfd restart: it keeps
// the loaded connection set (strongSwan survives xpfd), loads whatever
// the on-disk file names on a clean --load-all, refuses the candidate
// carrying "c" once with a partial summary, and fails --list-conns on
// demand so recovery cannot discover the subset.
type restartCharon15261 struct {
	loaded         map[string]bool
	loadedFromDisk func() map[string]bool
	partialOnce    bool
	listConnsErr   bool
	calls          [][]string
}

func (c *restartCharon15261) run(args ...string) ([]byte, error) {
	c.calls = append(c.calls, append([]string{}, args...))
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "--load-all":
		if c.partialOnce {
			c.partialOnce = false
			c.loaded = map[string]bool{"a": true}
			return []byte("loading connection 'c' failed: config discarded\nloaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
		}
		if c.loadedFromDisk != nil {
			c.loaded = c.loadedFromDisk()
		}
		return nil, nil
	case "--list-conns":
		if c.listConnsErr {
			return nil, errors.New("vici socket unavailable")
		}
		var b strings.Builder
		for name := range c.loaded {
			b.WriteString("list-conn event {" + name + " {local_addrs=[10.0.1.1] remote_addrs=[10.0.2.1] children {" + name + " {}}}}\n")
		}
		b.WriteString("list-conns reply {}\n")
		return []byte(b.String()), nil
	case "--list-sas":
		// Both prior tunnels have live SAs that survive the restart.
		return []byte(liveSA("a", "b")), nil
	}
	return nil, nil
}

func (c *restartCharon15261) terminated(name string) bool {
	for _, call := range c.calls {
		if len(call) == 3 && call[0] == "--terminate" && call[1] == "--ike" && call[2] == name {
			return true
		}
	}
	return false
}

// runRestartProbe15261 drives one probe arm: apply gen1 {a,b} cleanly
// (warm arm only), then a first/again apply of candidate {a,c} whose
// --load-all partially loads {a} while --list-conns fails, forcing the
// priorSet14589 rollback branch. It returns the manager (for hash /
// prev inspection), the charon double (for terminate inspection), and
// the gen1 hashes (empty in the restart arm's fresh manager — the
// persisted file is the oracle there).
func runRestartProbe15261(t *testing.T, restart bool) (*Manager, *restartCharon15261, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "ipsec-conn-state.json")

	if restart {
		// First daemon lifetime: apply {a,b} cleanly; this persists
		// loaded=[a,b] + fingerprints to the conn-state file.
		rec := &swanctlRecorder{}
		m1 := persistentManager9687(t, rec.run, statePath)
		// persistentManager9687 uses its own config dir; re-point it at
		// this probe's dir so the prior swanctl file survives too
		// (charon's config dir is not xpfd's memory).
		m1.configDir = dir
		m1.configPath = filepath.Join(dir, BPFRXConfFile)
		if err := m1.Apply(vpnCfg("a", "b")); err != nil {
			t.Fatalf("gen1 (pre-restart) Apply: %v", err)
		}
	}

	ch := &restartCharon15261{loaded: map[string]bool{"a": true, "b": true}}
	var m *Manager
	if restart {
		m = NewWithConfigDir(dir)
		m.statePath = statePath
	} else {
		m = NewWithConfigDir(dir)
		// Warm control: no state file, in-memory prev from gen1 below.
	}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run

	var gen1Hashes map[string]string
	if !restart {
		if err := m.Apply(vpnCfg("a", "b")); err != nil {
			t.Fatalf("gen1 Apply: %v", err)
		}
		gen1Hashes = map[string]string{"a": m.prevConnHashes["a"], "b": m.prevConnHashes["b"]}
		if gen1Hashes["a"] == "" || gen1Hashes["b"] == "" {
			t.Fatalf("FIXTURE: gen1 hashes must be non-empty, got %v", m.prevConnHashes)
		}
	}

	// The triggering apply: candidate {a,c}, c refused (partial), and
	// --list-conns fails so recovery promotes priorSet14589(prior).
	ch.partialOnce = true
	ch.listConnsErr = true
	if err := m.Apply(vpnCfg("a", "c")); err == nil {
		t.Fatal("partial first apply must return an error, not success")
	}
	return m, ch, gen1Hashes
}

func TestPartialLoadRestartPriorSetKeepsFingerprints15261(t *testing.T) {
	// Control arm first: a warm Manager knows the gen1 hashes
	// in-memory, so the rollback promotion keeps them and tears
	// nothing unchanged down.
	warm, warmCh, gen1Hashes := runRestartProbe15261(t, false)
	if !reflect.DeepEqual(warm.prevConnHashes, gen1Hashes) {
		t.Fatalf("CONTROL BROKE: warm rollback promotion hashes %v, want gen1 %v", warm.prevConnHashes, gen1Hashes)
	}
	if warmCh.terminated("a") || warmCh.terminated("b") {
		t.Fatalf("CONTROL BROKE: warm rollback must terminate no unchanged tunnel, calls %v", warmCh.calls)
	}

	// Restart arm: identical traffic, fresh Manager, state file only.
	m, ch, _ := runRestartProbe15261(t, true)
	st := readState9687(t, filepath.Join(m.configDir, "ipsec-conn-state.json"))
	wantHashes := st.Fingerprints // persisted gen1 fingerprints are the oracle
	// NOTE: read after the triggering apply, so pre-fix this is the
	// clobbered (empty) map and the DeepEqual below trivially passes;
	// the terminate + persisted-fingerprint assertions are the teeth.
	_ = wantHashes

	if !sameSet14589(m.prevConnNames, map[string]bool{"a": true, "b": true}) {
		t.Fatalf("restart rollback must promote the prior set {a,b} charon still runs, got prev=%v", m.prevConnNames)
	}
	for _, name := range []string{"a", "b"} {
		if got := m.prevConnHashes[name]; got == "" {
			t.Fatalf("restart rollback promoted %q without its persisted fingerprint (prevConnHashes=%v): unchanged tunnel will be torn down and a later rotation adopted silently", name, m.prevConnHashes)
		}
	}
	if ch.terminated("a") || ch.terminated("b") {
		t.Fatalf("restart rollback tore down unchanged tunnel(s) charon kept running: calls %v", ch.calls)
	}

	// The persisted fingerprints must survive the promotion: with
	// empty fingerprints persisted, the next apply adopts whatever
	// hash it renders as the baseline (legacy-adoption), so a later
	// rotation is invisible.
	if st.Fingerprints["a"] == "" || st.Fingerprints["b"] == "" {
		t.Fatalf("persisted fingerprints clobbered by restart rollback promotion: %+v", st)
	}

	// Consequence leg: rotate a's PSK on the next apply. The restarted
	// manager must detect the change against the gen1 fingerprint and
	// terminate a's stale SA (b untouched).
	ch.listConnsErr = false
	rotated := vpnCfg("a", "b")
	rotated.VPNs["a"].PSK = "rotated-secret-a-15261"
	if err := m.Apply(rotated); err != nil {
		t.Fatalf("post-restart rotation Apply: %v", err)
	}
	if !ch.terminated("a") {
		t.Fatalf("post-restart PSK rotation for a was not detected: no --terminate for a; the stale SA keeps forwarding under the old secret (calls %v)", ch.calls)
	}
}

// Control case: no prior generation exists at all (no prior file, no
// state file). A partial first apply with failing list-conns still
// promotes the empty set, tears nothing down, and returns the error —
// the fix must not invent fingerprints or tunnels here.
func TestPartialLoadNoPriorPromotesEmpty15261(t *testing.T) {
	dir := t.TempDir()
	m := NewWithConfigDir(dir)
	ch := &restartCharon15261{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	ch.partialOnce = true
	ch.listConnsErr = true
	if err := m.Apply(vpnCfg("a", "c")); err == nil {
		t.Fatal("partial first apply with no prior must return an error")
	}
	if len(m.prevConnNames) != 0 {
		t.Fatalf("no-prior partial must promote the empty set, got %v", m.prevConnNames)
	}
	if ch.terminated("a") || ch.terminated("b") {
		t.Fatalf("no-prior partial must terminate nothing, calls %v", ch.calls)
	}
}
