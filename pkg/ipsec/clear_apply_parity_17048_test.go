package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// #17048: Clear() and ApplyGeneration(empty) must settle a clear
// identically — one shared settleAfterReload, not two handwritten
// copies. The copies diverged once already (#15128): ApplyGeneration
// promoted {} for a clear partial while Clear promoted the recovered
// set, so deleted VPNs' SAs were never terminated. Each cell below
// drives both entry points from the same seeded state through the
// same fake charon and asserts prevConnNames, the --terminate calls,
// and the error class agree.

func sortedNames17048(names []string) []string {
	out := append([]string{}, names...)
	// Insertion sort is fine for the tiny slices in these cells.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// runClearParity17048 seeds a,b via Apply, then performs the clear on
// entry ("clear" or "apply") with the knob-driven fake charon. The
// knob selects the reload outcome: "success" (charon unloads all),
// "partial-empty" (partial load, charon unloads all), "partial-prior"
// (partial load, charon keeps a -> rollback to {a,b}), "down"
// (charon unreachable -> committed clear), "indeterminate" (live
// answer matching neither render). liveSAs names the SAs --list-sas
// reports during teardown; terminateFails makes --terminate fail so
// failed teardown is recorded as debt on both paths.
func runClearParity17048(t *testing.T, entry, knob string, liveSAs []string, terminateFails bool) (err error, prev []string, terminated []string, diskExists bool) {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, rerr := os.ReadFile(m.configPath)
		if rerr != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("FIXTURE gen1 apply: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}

	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) == 0 {
			return ch.run(args...)
		}
		switch args[0] {
		case "--load-all":
			switch knob {
			case "success":
				ch.loaded = map[string]bool{}
				return nil, nil
			case "partial-empty":
				// Candidate clear: file is gone. Rollback load: still gone.
				if _, serr := os.Stat(m.configPath); os.IsNotExist(serr) {
					ch.loaded = map[string]bool{}
					return []byte("loaded 0 of 1 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
				}
				return nil, nil
			case "partial-prior":
				if _, serr := os.Stat(m.configPath); os.IsNotExist(serr) {
					ch.loaded = map[string]bool{"a": true}
					return []byte("loaded 1 of 2 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
				}
				ch.loaded = map[string]bool{"a": true, "b": true}
				return nil, nil
			case "down", "indeterminate":
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
			}
			return nil, nil
		case "--list-pools":
			if knob == "indeterminate" {
				return []byte("get-pools reply {some-other-pool {base=192.0.2.9 size=1 online=0 offline=0}}\n"), nil
			}
			return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
		case "--list-conns":
			if knob == "indeterminate" {
				// Live answer naming an unrelated connection: matches
				// neither the prior render nor the empty clear.
				return []byte("list-conn event {zzz {local_addrs=[10.9.9.9] remote_addrs=[10.8.8.8] children {zzz {}}}}\nlist-conns reply {}\n"), nil
			}
			if knob == "down" {
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
			}
			return ch.run(args...)
		case "--list-sas":
			if len(liveSAs) > 0 {
				return []byte(liveSA(liveSAs...)), nil
			}
			return nil, nil
		case "--terminate":
			if terminateFails {
				return nil, errors.New("terminate refused")
			}
			if len(args) >= 3 {
				terminated = append(terminated, args[2])
			}
			return nil, nil
		}
		return ch.run(args...)
	}

	if entry == "clear" {
		err = m.Clear()
	} else {
		err = m.ApplyGeneration(nil, UnknownGeneration, ApplyHooks{})
	}
	if _, serr := os.Stat(m.configPath); serr == nil {
		diskExists = true
	}
	for name := range m.prevConnNames {
		prev = append(prev, name)
	}
	return err, sortedNames17048(prev), sortedNames17048(terminated), diskExists
}

func TestClearApplyParitySettle17048(t *testing.T) {
	cells := []struct {
		name           string
		knob           string
		liveSAs        []string
		terminateFails bool
		wantErr        bool
		wantPrev       []string
		wantTerminated []string
		wantDisk       bool
	}{
		{name: "success", knob: "success", liveSAs: []string{"a", "b"}, wantPrev: nil, wantTerminated: []string{"a", "b"}, wantDisk: false},
		{name: "total-failure-charon-down", knob: "down", liveSAs: []string{"a", "b"}, wantErr: true, wantPrev: nil, wantTerminated: []string{"a", "b"}, wantDisk: false},
		{name: "partial-to-empty", knob: "partial-empty", liveSAs: []string{"a", "b"}, wantErr: true, wantPrev: nil, wantTerminated: []string{"a", "b"}, wantDisk: false},
		{name: "partial-to-prior", knob: "partial-prior", wantErr: true, wantPrev: []string{"a", "b"}, wantTerminated: nil, wantDisk: true},
		{name: "indeterminate", knob: "indeterminate", liveSAs: []string{"a", "b"}, wantErr: true, wantPrev: []string{"a", "b"}, wantTerminated: []string{"a", "b"}, wantDisk: false},
		{name: "success-terminate-fails", knob: "success", liveSAs: []string{"a", "b"}, terminateFails: true, wantErr: true, wantPrev: nil, wantTerminated: nil, wantDisk: false},
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			clearErr, clearPrev, clearTerm, clearDisk := runClearParity17048(t, "clear", tc.knob, tc.liveSAs, tc.terminateFails)
			applyErr, applyPrev, applyTerm, applyDisk := runClearParity17048(t, "apply", tc.knob, tc.liveSAs, tc.terminateFails)

			if (clearErr != nil) != (applyErr != nil) {
				t.Fatalf("error class mismatch: Clear err=%v ApplyGeneration err=%v", clearErr, applyErr)
			}
			if !sameStringSet17048(clearPrev, applyPrev) {
				t.Fatalf("prev mismatch: Clear=%v ApplyGeneration=%v", clearPrev, applyPrev)
			}
			if !sameStringSet17048(clearTerm, applyTerm) {
				t.Fatalf("terminate mismatch: Clear=%v ApplyGeneration=%v", clearTerm, applyTerm)
			}
			if clearDisk != applyDisk {
				t.Fatalf("disk mismatch: Clear exists=%v ApplyGeneration exists=%v", clearDisk, applyDisk)
			}
			// Absolute expectations (not just parity): a parity-only
			// test would stay green if both paths broke together.
			if (clearErr != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", clearErr, tc.wantErr)
			}
			if !sameStringSet17048(clearPrev, tc.wantPrev) {
				t.Fatalf("prev=%v want %v", clearPrev, tc.wantPrev)
			}
			if !sameStringSet17048(clearTerm, tc.wantTerminated) {
				t.Fatalf("terminated=%v want %v", clearTerm, tc.wantTerminated)
			}
			if clearDisk != tc.wantDisk {
				t.Fatalf("disk exists=%v want %v", clearDisk, tc.wantDisk)
			}
			// Error class: reload failures stay the underlying error;
			// a failed terminate surfaces the teardown-debt error.
			if tc.terminateFails && clearErr != nil && !strings.Contains(clearErr.Error(), "terminate stale IPsec") {
				t.Fatalf("terminate-failure error must be teardown debt, got %v", clearErr)
			}
		})
	}
}

func sameStringSet17048(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

// F1 regression (#17048 fold): pre-existing deferred-start debt must
// survive a Clear whose reload probe is indeterminate. Parent Clear
// ran rememberDeferredReinitiation(changed) (no-op on the empty clear
// diff) and clearDeferredReinitiation(failed) only — it never ran
// filterDeferredReinitiation, so a deferred eager tunnel seeded by an
// earlier indeterminate/committed apply survived a delete and was
// re-initiated when the identical config was re-applied. The shared
// settleAfterReload indeterminate arm must preserve that: skip the
// total filter for the clear shape (its changed set is always empty,
// so filtering would wipe the whole pendingReinitiate set).
func TestClearIndeterminatePreservesDeferredReinitiation17048(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &partialCharon14589{loaded: map[string]bool{}}
	ch.loadedFromDisk = func() map[string]bool {
		data, rerr := os.ReadFile(m.configPath)
		if rerr != nil {
			return map[string]bool{}
		}
		return connNamesInFile14589(t, string(data))
	}
	m.swanctl = ch.run
	cfg := vpnCfg("a", "b")
	cfg.VPNs["a"].EstablishTunnels = "immediately"
	cfg.VPNs["b"].EstablishTunnels = "immediately"
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("FIXTURE gen1 apply: %v", err)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	// Seed deferred-start debt as an earlier indeterminate/committed
	// apply would: "a" was changed, its SA torn down, re-initiation
	// deferred until a candidate is proven.
	m.rememberDeferredReinitiation([]string{"a"})
	if got := m.pendingReinitiationNames(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("FIXTURE seed: pendingReinitiate=%v want [a]", got)
	}

	// Clear with an indeterminate probe: charon answers live but
	// matches neither the prior render nor the empty clear, and both
	// SAs are live and terminate successfully.
	var initiated []string
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) == 0 {
			return ch.run(args...)
		}
		switch args[0] {
		case "--load-all":
			return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
		case "--list-pools":
			return []byte("get-pools reply {some-other-pool {base=192.0.2.9 size=1 online=0 offline=0}}\n"), nil
		case "--list-conns":
			return []byte("list-conn event {zzz {local_addrs=[10.9.9.9] remote_addrs=[10.8.8.8] children {zzz {}}}}\nlist-conns reply {}\n"), nil
		case "--list-sas":
			return []byte(liveSA("a", "b")), nil
		case "--initiate":
			if len(args) >= 3 {
				initiated = append(initiated, args[2])
			}
			return nil, nil
		}
		return ch.run(args...)
	}
	if err := m.Clear(); err == nil {
		t.Fatal("indeterminate Clear must return the reload error")
	}
	if got := m.pendingReinitiationNames(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("Clear-indeterminate wiped deferred debt: pendingReinitiate=%v want [a] to survive", got)
	}

	// Re-add the identical config: hashes still match the retained
	// prior baseline, so the diff is clean — only the surviving
	// deferred debt can drive re-initiation of the eager tunnel.
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--initiate" {
			if len(args) >= 3 {
				initiated = append(initiated, args[2])
			}
			return nil, nil
		}
		if len(args) > 0 && args[0] == "--list-sas" {
			return nil, nil
		}
		return ch.run(args...)
	}
	ch.loaded = map[string]bool{"a": true, "b": true}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("re-add identical config: %v", err)
	}
	foundA := false
	for _, n := range initiated {
		if n == "a" {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("re-add must consider re-initiation of deferred eager tunnel a, initiated=%v", initiated)
	}
}

// F2 (#17048 fold): a partial clear whose teardown fails must clear
// deferred-start debt for the failed name (the deliberate unification:
// a stale SA may still forward, so it must not be re-initiated) while
// the terminate debt itself remains for retry on the next commit.
// Drives both Clear() and ApplyGeneration(nil, ...) — the head code
// clears deferred debt on the clear-partial arm for both entry points,
// where parent ApplyGeneration left it to the next proven load.
func TestPartialClearFailedTerminateClearsDeferred17048(t *testing.T) {
	for _, entry := range []string{"clear", "apply"} {
		t.Run(entry, func(t *testing.T) {
			m := NewWithConfigDir(t.TempDir())
			ch := &partialCharon14589{loaded: map[string]bool{}}
			ch.loadedFromDisk = func() map[string]bool {
				data, rerr := os.ReadFile(m.configPath)
				if rerr != nil {
					return map[string]bool{}
				}
				return connNamesInFile14589(t, string(data))
			}
			m.swanctl = ch.run
			if err := m.Apply(vpnCfg("a", "b")); err != nil {
				t.Fatalf("FIXTURE gen1 apply: %v", err)
			}
			ch.loaded = map[string]bool{"a": true, "b": true}
			// Seed deferred debt for both names; the partial clear
			// below promotes {} (charon unloaded all), so both are
			// removals whose teardown is attempted.
			m.rememberDeferredReinitiation([]string{"a", "b"})

			m.swanctl = func(args ...string) ([]byte, error) {
				if len(args) == 0 {
					return ch.run(args...)
				}
				switch args[0] {
				case "--load-all":
					if _, serr := os.Stat(m.configPath); os.IsNotExist(serr) {
						ch.loaded = map[string]bool{}
						return []byte("loaded 0 of 1 connections, 1 failed to load, 1 unloaded\n"), errors.New("exit status 22")
					}
					return nil, nil
				case "--list-sas":
					return []byte(liveSA("a", "b")), nil
				case "--terminate":
					return nil, errors.New("terminate refused")
				}
				return ch.run(args...)
			}
			var err error
			if entry == "clear" {
				err = m.Clear()
			} else {
				err = m.ApplyGeneration(nil, UnknownGeneration, ApplyHooks{})
			}
			if err == nil {
				t.Fatal("partial clear with failed terminate must return an error")
			}
			if got := m.pendingReinitiationNames(); len(got) != 0 {
				t.Fatalf("partial-clear failed teardown must clear deferred debt, pendingReinitiate=%v want empty", got)
			}
			m.mu.Lock()
			pendingTerm := []string{}
			for n := range m.pendingTerminate {
				pendingTerm = append(pendingTerm, n)
			}
			pendingChanged := []string{}
			for n := range m.pendingChanged {
				pendingChanged = append(pendingChanged, n)
			}
			m.mu.Unlock()
			pendingTerm = sortedNames17048(pendingTerm)
			if len(pendingTerm) != 2 {
				t.Fatalf("terminate debt must remain after partial-clear failed teardown, pendingTerminate=%v want [a b] (pendingChanged=%v)", pendingTerm, pendingChanged)
			}
		})
	}
}
