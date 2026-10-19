package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14589: swanctl --load-all is not a transaction. A partial load
// ("loaded 1 of 2 connections, 1 failed to load", rc 22) leaves charon
// running the loaded subset {a} while the candidate file names {a,c}
// (b deleted, c refused). Restoring the prior file {a,b} — the #10712
// failure path — makes disk name a set charon is NOT running, and a
// charon-only restart resurrects the deleted/rotated b.
//
// Acceptance: after the run5 sequence through ApplyGeneration, the
// on-disk file, charon's loaded set, and prevConnNames all name the
// same set.

type partialCharon14589 struct {
	loaded         map[string]bool
	loadedFromDisk func() map[string]bool
	loadErr        error
	partial        bool
	calls          [][]string
}

func (c *partialCharon14589) run(args ...string) ([]byte, error) {
	c.calls = append(c.calls, append([]string{}, args...))
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "--load-all":
		if c.partial {
			c.partial = false
			// charon loads only "a" from candidate {a,c}; c is refused.
			c.loaded = map[string]bool{"a": true}
			return []byte("loading connection 'c' failed: config discarded\nloaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), c.loadErr
		}
		if c.loadErr != nil && c.loadErr.Error() == "vici refused" {
			return []byte("unable to load"), c.loadErr
		}
		// Successful (verification / rollback) load: charon now runs
		// whatever the on-disk file names. The fake cannot parse the
		// file, so the test's loaded set is driven by file inspection
		// in the --list-conns arm below via loadedFromDisk.
		if c.loadedFromDisk != nil {
			c.loaded = c.loadedFromDisk()
		}
		return nil, nil
	case "--list-conns":
		// --raw form parsed by ListLoadedConns.
		var b strings.Builder
		for name := range c.loaded {
			b.WriteString("list-conn event {" + name + " {local_addrs=[10.0.1.1] remote_addrs=[10.0.2.1] children {" + name + " {}}}}\n")
		}
		b.WriteString("list-conns reply {}\n")
		return []byte(b.String()), nil
	case "--list-sas":
		return nil, nil
	}
	return nil, nil
}

func TestPartialLoadKeepsDiskCharonAndPrevConsistent14589(t *testing.T) {
	dir := t.TempDir()
	m := NewWithConfigDir(dir)
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	// scSplit falls back to swanctl seam, fine.

	// gen1: a,b loads cleanly.
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1 Apply: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	if !m.prevConnNames["a"] || !m.prevConnNames["b"] || len(m.prevConnNames) != 2 {
		t.Fatalf("gen1 prev=%v want {a,b}", m.prevConnNames)
	}

	// gen2: b deleted, c added but charon refuses c (partial, rc22-like).
	ch.partial = true
	ch.loadErr = errors.New("exit status 22")
	err := m.Apply(vpnCfg("a", "c"))
	if err == nil {
		t.Fatal("partial load must return an error, not success")
	}
	// On-disk file conn names, charon loaded, prev must agree.
	data, rerr := os.ReadFile(m.configPath)
	if rerr != nil {
		t.Fatalf("read on-disk config: %v", rerr)
	}
	disk := connNamesInFile14589(t, string(data))
	loaded, lerr := m.ListLoadedConns()
	if lerr != nil {
		t.Fatalf("ListLoadedConns: %v", lerr)
	}
	loadedSet := map[string]bool{}
	for n := range loaded {
		loadedSet[n] = true
	}
	if !sameSet14589(disk, loadedSet) {
		t.Fatalf("disk %v != charon loaded %v (restart would resurrect/change VPNs)", disk, loadedSet)
	}
	if !sameSet14589(m.prevConnNames, loadedSet) {
		t.Fatalf("prevConnNames %v != charon loaded %v", m.prevConnNames, loadedSet)
	}
	// Specifically the deleted b must not be on disk.
	if disk["b"] {
		t.Fatalf("deleted b resurrected on disk: %v", disk)
	}
	if disk["c"] && !loadedSet["c"] {
		t.Fatalf("refused c left on disk but not loaded: disk=%v loaded=%v", disk, loadedSet)
	}
}

func TestNonPartialReloadFailureStillRestoresPrior14589(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	prior, _ := os.ReadFile(m.configPath)
	reloadErr := errors.New("vici refused")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return []byte("connecting failed"), reloadErr
		}
		return nil, nil
	}
	if err := m.Apply(vpnCfg("a", "c")); !errors.Is(err, reloadErr) {
		t.Fatalf("err=%v want reloadErr", err)
	}
	got, _ := os.ReadFile(m.configPath)
	if string(got) != string(prior) {
		t.Fatalf("non-partial failure must restore prior file")
	}
	if !m.prevConnNames["b"] || len(m.prevConnNames) != 2 {
		t.Fatalf("prev must stay {a,b}, got %v", m.prevConnNames)
	}
}

// rc=0 partial ("loaded 0 of 1, 1 failed" exits 0 per
// docs/ipsec-swanctl-load-proof.md) must also be treated as partial,
// not success.
func TestPartialLoadRc0IsNotSuccess14589(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	ch.partial = true
	ch.loadErr = nil // rc 0 partial
	if err := m.Apply(vpnCfg("a", "c")); err == nil {
		t.Fatal("rc0 partial must return an error")
	}
	data, _ := os.ReadFile(m.configPath)
	disk := connNamesInFile14589(t, string(data))
	if disk["b"] || disk["c"] {
		t.Fatalf("disk %v must name only the loaded subset {a}", disk)
	}
	if !sameSet14589(m.prevConnNames, map[string]bool{"a": true}) {
		t.Fatalf("prev=%v want {a}", m.prevConnNames)
	}
}

// Changed survivor with rotated PSK: candidate {a(rotated),c(refused)},
// charon loads {a(rotated)}. The subset file must carry a's NEW secret
// and no trace of c's secret, and prev must adopt a's new hash so the
// stale SA is torn down (promote's changed detection).
func TestPartialLoadChangedSurvivorKeepsNewSecret14589(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	oldHash := m.prevConnHashes["a"]
	rotated := vpnCfg("a", "c")
	rotated.VPNs["a"].PSK = "rotated-secret-a"
	ch.partial = true
	ch.loadErr = errors.New("exit status 22")
	if err := m.Apply(rotated); err == nil {
		t.Fatal("partial must error")
	}
	data, _ := os.ReadFile(m.configPath)
	if !strings.Contains(string(data), "rotated-secret-a") {
		t.Fatalf("subset file must carry rotated PSK for loaded a:\n%s", data)
	}
	if strings.Contains(string(data), "secret-c") {
		t.Fatalf("subset file must not carry refused c secret:\n%s", data)
	}
	if m.prevConnHashes["a"] == oldHash || m.prevConnHashes["a"] == "" {
		t.Fatalf("prev hash for a must adopt rotated hash (old %q now %q)", oldHash, m.prevConnHashes["a"])
	}
}

// Clear-path partial where charon still holds a prior connection:
// disk must be restored to the prior file (true rollback), not left
// absent while charon runs the old set.
func TestPartialClearRestoresPriorFile14589(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	prior, _ := os.ReadFile(m.configPath)
	// Partial clear: file removed, charon unloads b but a's unload fails.
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			// Distinguish candidate (no file) from rollback (prior file).
			if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
				ch.loaded = map[string]bool{"a": true}
				return []byte("loaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
			}
			ch.loaded = map[string]bool{"a": true, "b": true}
			return nil, nil
		}
		return ch.run(args...)
	}
	if err := m.Clear(); err == nil {
		t.Fatal("partial clear must error")
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("prior file must be restored after partial clear: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatalf("disk must equal prior file after partial clear rollback")
	}
	if !sameSet14589(m.prevConnNames, map[string]bool{"a": true, "b": true}) {
		t.Fatalf("prev=%v want prior {a,b}", m.prevConnNames)
	}
}

// #15128 (A90-01): the commit path reaches clearConfig via
// ApplyGeneration (empty config), not Clear(). On a partial clear where
// charon still holds a prior connection, clearConfig rolls charon back
// to the prior set {a,b} and returns pae{names:{a,b}, clear:true}.
// Clear() promotes pae.names; ApplyGeneration used to discard them and
// promote the empty set, so prev forgot VPNs charon still runs — their
// SAs were never terminated and the persisted record said none.
// Setup mirrors TestPartialClearRestoresPriorFile14589; the leg
// exercised here is ApplyGeneration with an empty config.
func TestA90PartialClearViaApplyEmpty(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	prior, _ := os.ReadFile(m.configPath)
	// Partial clear via the commit path: empty config -> clearConfig
	// removes the file; charon unloads b but a remains (partial), the
	// rollback reload then restores the prior set {a,b} in charon.
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
				ch.loaded = map[string]bool{"a": true}
				return []byte("loaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
			}
			ch.loaded = map[string]bool{"a": true, "b": true}
			return nil, nil
		}
		return ch.run(args...)
	}
	err := m.ApplyGeneration(&config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{}}, UnknownGeneration, ApplyHooks{})
	if err == nil {
		t.Fatal("partial clear via ApplyGeneration must error")
	}
	got, rerr := os.ReadFile(m.configPath)
	if rerr != nil {
		t.Fatalf("prior file must be restored after partial clear: %v", rerr)
	}
	if string(got) != string(prior) {
		t.Fatalf("disk must equal prior file after partial clear rollback")
	}
	// Charon still runs {a,b} after the rollback; prev must agree, not
	// the empty set the buggy promotion installed.
	if !sameSet14589(m.prevConnNames, map[string]bool{"a": true, "b": true}) {
		t.Fatalf("prev=%v want prior {a,b} (charon rolled back to it)", m.prevConnNames)
	}
	loaded, lerr := m.ListLoadedConns()
	if lerr != nil {
		t.Fatalf("ListLoadedConns: %v", lerr)
	}
	loadedSet := map[string]bool{}
	for n := range loaded {
		loadedSet[n] = true
	}
	if !sameSet14589(m.prevConnNames, loadedSet) {
		t.Fatalf("prevConnNames %v != charon loaded %v", m.prevConnNames, loadedSet)
	}
}

// Follow-up leg: after the partial clear above, a later successful
// commit deleting every VPN must terminate the SAs charon still runs.
// With the buggy empty promotion prev forgot {a,b}, so this apply saw
// no removals and terminated nothing. The fake charon reports live SAs
// for a and b; the successful clear must issue --terminate for both.
func TestA90FollowUpAfterApplyEmpty(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, err := os.ReadFile(m.configPath)
		if err != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	phase := "partial"
	var terminated []string
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				if phase == "partial" {
					if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
						ch.loaded = map[string]bool{"a": true}
						return []byte("loaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
					}
					ch.loaded = map[string]bool{"a": true, "b": true}
					return nil, nil
				}
				// Successful clear: file is gone, charon unloads all.
				ch.loaded = map[string]bool{}
				return nil, nil
			case "--list-sas":
				if phase == "followup" {
					return []byte(liveSA("a", "b")), nil
				}
				return nil, nil
			case "--terminate":
				// --terminate --ike <name>
				if len(args) >= 3 {
					terminated = append(terminated, args[2])
				}
				return nil, nil
			}
		}
		return ch.run(args...)
	}
	empty := &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{}}
	if err := m.ApplyGeneration(empty, UnknownGeneration, ApplyHooks{}); err == nil {
		t.Fatal("partial clear via ApplyGeneration must error")
	}
	if !sameSet14589(m.prevConnNames, map[string]bool{"a": true, "b": true}) {
		t.Fatalf("after partial clear prev=%v want {a,b}", m.prevConnNames)
	}
	phase = "followup"
	if err := m.ApplyGeneration(empty, UnknownGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("follow-up successful clear: %v", err)
	}
	got := map[string]bool{}
	for _, n := range terminated {
		got[n] = true
	}
	if !got["a"] || !got["b"] || len(got) != 2 {
		t.Fatalf("follow-up clear must terminate live SAs for a and b, terminated=%v", terminated)
	}
	if len(m.prevConnNames) != 0 {
		t.Fatalf("prev=%v want empty after successful clear", m.prevConnNames)
	}
}

func connNamesInFile14589(t *testing.T, text string) map[string]bool {
	t.Helper()
	// Reuse render parsing via Expected? Parse connections{ } top-level names.
	out := map[string]bool{}
	inConns := false
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "connections {" {
			inConns = true
			continue
		}
		if inConns {
			if trim == "}" {
				break
			}
			if strings.HasSuffix(trim, "{") && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
				name := strings.TrimSpace(strings.TrimSuffix(trim, "{"))
				out[name] = true
			}
		}
	}
	return out
}

func sameSet14589(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
