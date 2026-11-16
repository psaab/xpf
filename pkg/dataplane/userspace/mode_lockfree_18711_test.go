package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// #18711: the daemon's demotion path calls Manager.Mode()
// (injectBlackholeRoutes -> userspaceDataplaneActiveFor) before its bounded
// rg_active write. Mode() took mu, whose holders can sit in 3 s round trips
// against a wedged helper (an abandoned UpdateRGActive), so each RG's
// demotion waited behind the previous RG's write. Mode() now reads a
// lock-free mirror that setModeLocked, the only writer, publishes.

// Every branch of applyRuntimeModeLocked publishes its mode to Mode(). The
// mirror is reset to ModeEBPFOnly before each branch, so a writer that skips
// the publish is visible whatever the previous branch published.
func TestApplyRuntimeModePublishesEveryBranch18711(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		enabled               uint32
		configured            DataplaneMode
		livenessFailed, proof bool
		want                  DataplaneMode
	}{
		{"degraded, configured strict", 0, ModeUserspaceStrict, false, false, ModeUserspaceStrict},
		{"degraded, configured compat", 0, ModeUserspaceCompat, false, false, ModeUserspaceCompat},
		{"liveness failed, configured compat", 1, ModeUserspaceCompat, true, false, ModeUserspaceCompat},
		{"proven, configured strict", 1, ModeUserspaceStrict, false, true, ModeUserspaceStrict},
		{"proven, configured compat", 1, ModeUserspaceCompat, false, true, ModeUserspaceCompat},
		{"still probing", 1, ModeUserspaceStrict, false, false, ModeUserspaceCompat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.mu.Lock()
			m.configuredMode = tc.configured
			m.xskLivenessFailed = tc.livenessFailed
			m.xskLivenessProven = tc.proof
			m.setModeLocked(ModeEBPFOnly)
			ctrl := userspaceCtrlValue{Enabled: tc.enabled}
			m.applyRuntimeModeLocked(&ctrl)
			field := m.mode
			m.mu.Unlock()
			if field != tc.want {
				t.Fatalf("setup: mode field %v, want %v", field, tc.want)
			}
			if got := m.Mode(); got != tc.want {
				t.Fatalf("Mode() = %v, want %v: this branch did not publish to the lock-free mirror", got, tc.want)
			}
		})
	}
}

// Mode() answers while mu is held, as it is by a write sitting in a round
// trip against a wedged helper.
func TestModeDoesNotWaitOnManagerMutex18711(t *testing.T) {
	m := NewModeManagerForTest(ModeUserspaceStrict)
	release := m.HoldMuForTest()
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	got := make(chan DataplaneMode, 1)
	go func() { got <- m.Mode() }()
	select {
	case md := <-got:
		if md != ModeUserspaceStrict {
			t.Fatalf("Mode() = %v under a held mu, want the published %v", md, ModeUserspaceStrict)
		}
	case <-time.After(100 * time.Millisecond):
		release()
		released = true
		<-got
		t.Fatal("Mode() waited on the Manager's mu; the demotion path must not (#18711)")
	}
}

// The mirror stays exact only while setModeLocked is the ONLY writer of the
// mode field: no other assignment and no struct-literal initialisation in any
// non-test file of this package.
func TestModeFieldWrittenOnlyBySetModeLocked18711(t *testing.T) {
	assign := regexp.MustCompile(`\.mode\s*=[^=]`)
	literal := regexp.MustCompile(`(?m)^\s*mode:\s`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var writers []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := line
			if c := strings.Index(code, "//"); c >= 0 {
				code = code[:c]
			}
			if assign.MatchString(code) || literal.MatchString(code) {
				writers = append(writers, f+":"+itoa18711(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if len(writers) != 1 || !strings.Contains(writers[0], "m.mode = md") {
		t.Fatalf("mode field writers %q: want exactly setModeLocked's `m.mode = md`", writers)
	}
}

func itoa18711(n int) string {
	var b [20]byte
	i := len(b)
	for n > 0 || i == len(b) {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// managerWithModeForTest publishes md through setModeLocked, the mode field's
// only writer (#18711), for fixtures built as a Manager struct literal.
func managerWithModeForTest(m *Manager, md DataplaneMode) *Manager {
	m.setModeLocked(md)
	return m
}

// In-package test fixtures publish the mode through setModeLocked too
// (managerWithModeForTest for struct literals), so Mode() and the field agree
// in every fixture: no fixture writes the field directly or initialises it in
// a struct literal (r24 P3-3 on 95356af84b).
func TestModeFieldNotWrittenDirectlyByFixtures18711(t *testing.T) {
	assign := regexp.MustCompile(`(?m)^\s*\w+\.mode = Mode[A-Za-z]+\s*$`)
	literal := regexp.MustCompile(`(?m)^\s*mode:\s*Mode[A-Za-z]+,`)
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := assign.FindIndex(data); loc != nil {
			t.Errorf("%s writes the mode field directly (%q); use setModeLocked", f, data[loc[0]:loc[1]])
		}
		if loc := literal.FindIndex(data); loc != nil {
			t.Errorf("%s initialises mode in a struct literal (%q); wrap it in managerWithModeForTest", f, data[loc[0]:loc[1]])
		}
	}
}
