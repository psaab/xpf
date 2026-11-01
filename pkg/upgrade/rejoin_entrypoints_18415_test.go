package upgrade

// #18415 review fold: the --rejoin-deadline override is threaded Config ->
// RunRolling / RunRollingRollback -> RollingConfig -> runRollingWith /
// runRollingRollbackWith -> the step 6 and step 7 waits. The earlier cells
// drove rejoinAndConfirm directly, so dropping cfg.RejoinDeadline at either
// entry point, or using a constant in either driver, survived.
//
// These cells drive the REAL entry points (cluster built through the
// newRollingCluster seam, lock through the package-default no-op seam) with a
// short configured deadline against a slow sync or a slow prime. The correct
// code fails at the configured bound. A mutant that loses the override falls
// back to the 190s default, outlives the slow predicate, and returns success,
// so each short-deadline cell fails on it. Each has a long-deadline twin that
// must SUCCEED on the same fixture, proving the fixture is satisfiable and
// that the configured value is a bound, not a breakage.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The entry points poll at the default PollInterval (500ms). The slow
// predicate becomes true at slowAfter, observed at the next poll; the short
// deadline expires well before it (the pre-cut steps take a few hundred ms
// on a loaded host, hence the wide gap), the long one well after.
const (
	slowAfter18415     = 1500 * time.Millisecond
	shortDeadline18415 = 200 * time.Millisecond
	longDeadline18415  = 5 * time.Second
)

// slowCluster18415 is a healthy pre-cut cluster whose post-cut session sync
// (slowSync) or inbound bulk prime (slowPrime) only becomes true slowAfter
// after construction. The pre-cut steps take milliseconds, so the clock is
// effectively the post-cut clock.
type slowCluster18415 struct {
	*fakeCluster
	start     time.Time
	slowSync  bool
	slowPrime bool
	syncCalls int
}

func newSlowCluster18415(slowSync, slowPrime bool) *slowCluster18415 {
	return &slowCluster18415{
		fakeCluster: &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1},
		start:       time.Now(),
		slowSync:    slowSync,
		slowPrime:   slowPrime,
	}
}

func (c *slowCluster18415) ready() bool { return time.Since(c.start) >= slowAfter18415 }

func (c *slowCluster18415) SyncEstablished() (bool, error) {
	c.syncCalls++
	// Call #1 is the pre-cut precondition, which must pass.
	if c.slowSync && c.syncCalls > 1 && !c.ready() {
		return false, nil
	}
	return true, nil
}

func (c *slowCluster18415) SessionSyncBulkPrimed() (bool, error) {
	if c.slowPrime && !c.ready() {
		return false, nil
	}
	return true, nil
}

func installRollingCluster18415(t *testing.T, cl RollingCluster) {
	t.Helper()
	prev := newRollingCluster
	newRollingCluster = func(string) (RollingCluster, error) { return cl, nil }
	t.Cleanup(func() { newRollingCluster = prev })
}

type entryCase18415 struct {
	name      string
	slowSync  bool
	slowPrime bool
	wantErr   string // substring naming the phase that must time out
}

var entryCases18415 = []entryCase18415{
	{"slow sync (step 6)", true, false, "re-establish session sync within " + shortDeadline18415.String()},
	{"slow prime (step 7)", false, true, "rejoin not confirmed within " + shortDeadline18415.String()},
}

func TestRunRollingHonoursRejoinDeadline18415(t *testing.T) {
	for _, tc := range entryCases18415 {
		t.Run(tc.name+" short deadline fails at the configured bound", func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			seedInitialCurrent(t, r, cfg, "1.0.0")
			cl := newSlowCluster18415(tc.slowSync, tc.slowPrime)
			installRollingCluster18415(t, cl)
			cfg.RejoinDeadline = shortDeadline18415

			started := time.Now()
			err := RunRolling(r, cfg)
			elapsed := time.Since(started)
			if err == nil {
				t.Fatalf("RunRolling succeeded after %s: the slow predicate (true at %s) outlived the configured "+
					"%s rejoin deadline, so the override was not honoured (it fell back to the default)",
					elapsed, slowAfter18415, shortDeadline18415)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RunRolling error does not name the configured bound %q: %v", tc.wantErr, err)
			}
			if elapsed >= slowAfter18415 {
				t.Fatalf("RunRolling took %s, past the slow predicate at %s; it did not stop at %s",
					elapsed, slowAfter18415, shortDeadline18415)
			}
			if cl.resetCalled {
				t.Fatal("a rejoin timeout must leave the node held secondary (no ResetFailover)")
			}
		})
		t.Run(tc.name+" long deadline succeeds", func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			seedInitialCurrent(t, r, cfg, "1.0.0")
			cl := newSlowCluster18415(tc.slowSync, tc.slowPrime)
			installRollingCluster18415(t, cl)
			cfg.RejoinDeadline = longDeadline18415
			if err := RunRolling(r, cfg); err != nil {
				t.Fatalf("RunRolling with a %s deadline on a predicate true at %s: %v",
					longDeadline18415, slowAfter18415, err)
			}
			if !cl.resetCalled {
				t.Fatal("a completed rejoin must reset failover")
			}
		})
	}
}

func TestRunRollingRollbackHonoursRejoinDeadline18415(t *testing.T) {
	for _, tc := range entryCases18415 {
		t.Run(tc.name+" short deadline fails at the configured bound", func(t *testing.T) {
			fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
			cl := newSlowCluster18415(tc.slowSync, tc.slowPrime)
			installRollingCluster18415(t, cl)
			cfg := fx.cfg
			cfg.RejoinDeadline = shortDeadline18415

			started := time.Now()
			err := RunRollingRollback(fx.r, cfg, "")
			elapsed := time.Since(started)
			if err == nil {
				t.Fatalf("RunRollingRollback succeeded after %s: the slow predicate (true at %s) outlived the "+
					"configured %s rejoin deadline, so the override was not honoured", elapsed, slowAfter18415,
					shortDeadline18415)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RunRollingRollback error does not name the configured bound %q: %v", tc.wantErr, err)
			}
			if elapsed >= slowAfter18415 {
				t.Fatalf("RunRollingRollback took %s, past the slow predicate at %s", elapsed, slowAfter18415)
			}
			if cl.resetCalled {
				t.Fatal("a rejoin timeout must leave the node held secondary (no ResetFailover)")
			}
		})
		t.Run(tc.name+" long deadline succeeds", func(t *testing.T) {
			fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
			cl := newSlowCluster18415(tc.slowSync, tc.slowPrime)
			installRollingCluster18415(t, cl)
			cfg := fx.cfg
			cfg.RejoinDeadline = longDeadline18415
			if err := RunRollingRollback(fx.r, cfg, ""); err != nil {
				t.Fatalf("RunRollingRollback with a %s deadline on a predicate true at %s: %v",
					longDeadline18415, slowAfter18415, err)
			}
			if !cl.resetCalled {
				t.Fatal("a completed rejoin must reset failover")
			}
		})
	}
}

// A negative RejoinDeadline from a programmatic caller is refused before the
// node is demoted. (The CLI refuses it, and anything under MinRejoinDeadline,
// at parse time.)
func TestRollingRefusesNegativeRejoinDeadlineBeforeDrain18415(t *testing.T) {
	t.Run("forward", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := healthyRollingCluster()
		rc := fastRC()
		rc.RejoinDeadline = -time.Second
		if err := runRollingWith(r, cl, rc); err == nil || !strings.Contains(err.Error(), "negative") {
			t.Fatalf("runRollingWith with a negative deadline = %v; want a refusal", err)
		}
		if cl.forced {
			t.Fatal("ForceSecondary ran before the negative deadline was refused")
		}
	})
	t.Run("rollback", func(t *testing.T) {
		fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
		cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true}
		rc := fastRC()
		rc.RejoinDeadline = -time.Second
		if err := runRollingRollbackWith(fx.r, cl, rc, ""); err == nil || !strings.Contains(err.Error(), "negative") {
			t.Fatalf("runRollingRollbackWith with a negative deadline = %v; want a refusal", err)
		}
		if cl.forced {
			t.Fatal("ForceSecondary ran before the negative deadline was refused")
		}
	})
}

// Progress output: steps 6 and 7 log a line per ProgressInterval with the
// phase, elapsed against the deadline, the predicates and the last error. A
// wait that finishes before the first interval logs nothing.
func TestRollingPostCutWaitsLogProgress18415(t *testing.T) {
	run := func(t *testing.T, slowSync, slowPrime bool) []string {
		t.Helper()
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		var lines []string
		r.cfg.Logf = func(format string, args ...any) {
			lines = append(lines, sprintf18415(format, args...))
		}
		cl := newSlowCluster18415(slowSync, slowPrime)
		rc := RollingConfig{
			DrainDeadline:    2 * time.Second,
			RejoinDeadline:   3 * time.Second,
			PollInterval:     5 * time.Millisecond,
			ProgressInterval: 100 * time.Millisecond,
		}
		if err := runRollingWith(r, cl, rc); err != nil {
			t.Fatalf("runRollingWith: %v", err)
		}
		var progress []string
		for _, l := range lines {
			if strings.HasPrefix(l, "rolling: still waiting:") {
				progress = append(progress, l)
			}
		}
		return progress
	}

	t.Run("slow sync", func(t *testing.T) {
		p := run(t, true, false)
		if len(p) == 0 {
			t.Fatal("a 1.5s post-cut sync wait with a 100ms progress interval logged no progress line")
		}
		first := p[0]
		for _, want := range []string{"upgraded node re-establishing session sync", "of 3s deadline",
			"sync-established=false", "last error: none", "Ctrl-C is deferred"} {
			if !strings.Contains(first, want) {
				t.Errorf("first step-6 progress line lacks %q: %s", want, first)
			}
		}
		if len(p) > 1 && strings.Contains(p[1], "Ctrl-C is deferred") {
			t.Errorf("the Ctrl-C note repeats on every line: %s", p[1])
		}
	})
	t.Run("slow prime", func(t *testing.T) {
		p := run(t, false, true)
		if len(p) == 0 {
			t.Fatal("a 1.5s held-secondary prime wait with a 100ms progress interval logged no progress line")
		}
		first := p[0]
		for _, want := range []string{"rejoin, held secondary until the inbound bulk prime completes",
			"peer-alive=true", "sync-established=true", "bulk-primed=false",
			"local-rejoined=not-queried-before-reset",
			"last error: session-sync inbound bulk prime not complete"} {
			if !strings.Contains(first, want) {
				t.Errorf("first step-7 progress line lacks %q: %s", want, first)
			}
		}
	})
	t.Run("one line per progress event", func(t *testing.T) {
		var got []string
		p := newWaitProgress(func(format string, args ...any) {
			got = append(got, fmt.Sprintf(format, args...))
		}, "phase", "x", time.Second, time.Nanosecond)
		time.Sleep(time.Millisecond)
		p.observePredicate(false, errorsJoin18415("first", "second"))
		if len(got) != 1 || strings.Contains(got[0], "\n") || !strings.Contains(got[0], "first; second") {
			t.Fatalf("a joined last-error must stay on one progress line, got %q", got)
		}
	})
	t.Run("fast waits stay quiet", func(t *testing.T) {
		if p := run(t, false, false); len(p) != 0 {
			t.Fatalf("waits that finished before the first interval logged progress: %v", p)
		}
	})
}

func sprintf18415(format string, args ...any) string {
	return strings.TrimSpace(fmt.Sprintf(format, args...))
}

func errorsJoin18415(msgs ...string) error {
	errs := make([]error, 0, len(msgs))
	for _, m := range msgs {
		errs = append(errs, errors.New(m))
	}
	return errors.Join(errs...)
}
