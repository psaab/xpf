package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// newManager16016 builds a Manager that is stopped when the test ends (#19161).
// t.Cleanup runs last-in-first-out, so the Stop registered here runs BEFORE the
// clock, grace-path and grace-length restores a setup helper registered
// earlier. Without it, a #16016 manager outlived its test: its never-seen
// timer (armed by ControlInterface) fired after the restores, evaluated the
// fixture grace with the REAL monotonic clock, found it expired once uptime
// passed the 72 h grace, and persisted that expired grace into whatever path
// was then in force: the run-shared record. Every later Manager in the run
// loaded it, held its election, and a bare event receive hung the package
// (43 minutes on a root leg on a runner up 89 h; never on one up 7 h).
func newManager16016(t testing.TB, nodeID, clusterID int) *Manager {
	t.Helper()
	m := NewManager(nodeID, clusterID)
	t.Cleanup(m.Stop)
	return m
}

// TestLeakedAuthorityManagerCannotWriteTheSharedRecord19161 reproduces the
// leak independent of the runner's uptime: the subtest's fixture monotonic
// anchor sits 73 h behind the real clock, so once the restores put the real
// clock back, the fixture grace reads expired on any machine. The subtest
// ends with its manager's never-seen timer armed; the outer test then waits
// past that timer. A manager that outlives its subtest writes the outer
// ("shared") record; a stopped one cannot.
func TestLeakedAuthorityManagerCannotWriteTheSharedRecord19161(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	t.Cleanup(SetUnkeyedAuthorityGraceStatePathForTesting(shared))
	origGrace := neverSeenGrace
	neverSeenGrace = 100 * time.Millisecond
	t.Cleanup(func() { neverSeenGrace = origGrace })

	var leaked *Manager
	t.Run("fixture", func(t *testing.T) {
		clock := &authorityClock16016{
			wall: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
			mono: MonotonicNanos() - int64(73*time.Hour),
		}
		oldGrace := unkeyedAuthorityGrace
		unkeyedAuthorityGrace = 72 * time.Hour
		t.Cleanup(func() { unkeyedAuthorityGrace = oldGrace })
		t.Cleanup(SetFabricAuthGraceStatePathForTesting(filepath.Join(t.TempDir(), "fabric-auth-grace")))
		t.Cleanup(SetPeerEpochStatePathForTesting(filepath.Join(t.TempDir(), "peer-epoch")))
		t.Cleanup(SetUnkeyedAuthorityGraceStatePathForTesting(filepath.Join(t.TempDir(), "unkeyed-authority-grace")))
		t.Cleanup(SetUnkeyedAuthorityClocksForTesting(clock.wallNow, clock.monoNow))
		m := newManager16016(t, 0, 1)
		m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
		m.mu.Lock()
		armed := m.neverSeenTimer != nil
		m.mu.Unlock()
		if !armed {
			t.Fatal("FIXTURE: no never-seen timer armed; this cell would pass vacuously")
		}
		leaked = m
	})

	time.Sleep(10 * neverSeenGrace)
	if b, err := os.ReadFile(shared); err == nil {
		t.Fatalf("a manager outlived its test and wrote the shared grace record after the "+
			"restores (%q); every later Manager in the run would load it and hold its election", b)
	} else if !os.IsNotExist(err) {
		t.Fatalf("reading the shared record: %v", err)
	}
	leaked.mu.Lock()
	stopped := leaked.stopped
	leaked.mu.Unlock()
	if !stopped {
		t.Fatal("the subtest's manager is still running after its test ended")
	}
}

// The TestMain watch itself: a write of the watched record with an anchor
// before the run is reported, naming the record; a write stamped during the
// run, and a write to any other path, are not.
func TestSharedGraceRecordWatchReportsAFixtureAnchor19161(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	runStart := time.Now()
	stop := watchSharedGraceRecord19161(shared, runStart)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	if err := unkeyedAuthorityPersist(shared, runStart.Add(time.Second), runStart.Add(time.Second), 0); err != nil {
		t.Fatal(err)
	}
	if err := unkeyedAuthorityPersist(filepath.Join(dir, "own"), time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), runStart, 0); err != nil {
		t.Fatal(err)
	}
	if got := stop(); got != "" {
		t.Fatalf("a run-stamped write, or a write to another path, was reported:\n%s", got)
	}
	// A real wall anchor with more grace elapsed than the run has lasted: a
	// fixture MONOTONIC clock (pkg/daemon's cells inject only that one).
	stop = watchSharedGraceRecord19161(shared, runStart)
	if err := unkeyedAuthorityPersist(shared, runStart.Add(time.Second), runStart.Add(time.Second), 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := stop(); !strings.Contains(got, "elapsed=72h0m0s, more than this run has lasted") {
		t.Fatalf("a real-anchored write with 72h elapsed was not reported: %q", got)
	}
	stop = watchSharedGraceRecord19161(shared, runStart)
	fixture := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if err := unkeyedAuthorityPersist(shared, fixture, fixture.Add(72*time.Hour), 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	got := stop()
	stopped = true
	if !strings.Contains(got, shared) || !strings.Contains(got, "2026-11-03T12:00:00Z") || !strings.Contains(got, "goroutine") {
		t.Fatalf("a fixture-anchored write of the shared record was not reported with its stack: %q", got)
	}
}

// The cross-package check (pkg/daemon's TestMain): the record at the current
// path is read back and judged by the same predicate.
func TestUnkeyedGraceRecordLeakCheck19161(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	t.Cleanup(SetUnkeyedAuthorityGraceStatePathForTesting(path))
	runStart := time.Now()
	if got := UnkeyedGraceRecordLeakForTesting(runStart); got != "" {
		t.Fatalf("no record reported as a leak: %q", got)
	}
	cases := []struct {
		name     string
		earliest time.Time
		elapsed  time.Duration
		want     string
	}{
		{"real anchor, real elapsed", runStart.Add(time.Second), time.Second, ""},
		{"fixture wall anchor", time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), time.Second, "before this run started"},
		{"fixture monotonic elapsed", runStart.Add(time.Second), 72 * time.Hour, "more than this run has lasted"},
	}
	for _, c := range cases {
		if err := persistUnkeyedAuthorityRecord(path, c.earliest, c.earliest, c.elapsed); err != nil {
			t.Fatal(err)
		}
		got := UnkeyedGraceRecordLeakForTesting(runStart)
		if (c.want == "") != (got == "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("%s: got %q, want a report containing %q", c.name, got, c.want)
		}
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := UnkeyedGraceRecordLeakForTesting(runStart); !strings.Contains(got, "corrupt or legacy") {
		t.Errorf("a corrupt record: got %q", got)
	}
}
