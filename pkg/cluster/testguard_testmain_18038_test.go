package cluster

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/internal/testguard"
)

// #18038: pkg/cluster gained its first census-registered host-state mutation
// (the lo-up netlink call in sync_loopback_18038_test.go), so the package
// joins the guarded set: the test binary refuses to run outside a private
// net+mount namespace, like every other package in
// host-mutation-census.py's PACKAGES.
//
// #19161: every durable state path this package keeps under /var/lib/xpf
// (boot epoch and its lock/owner, peer epoch, fabric-auth grace,
// unkeyed-authority grace) is redirected into a per-run temporary directory
// before any test runs. Unredirected, a root leg wrote the production paths
// and later cells read what earlier ones left, while an unprivileged leg's
// writes simply failed. The two modes tested different things, and the host
// kept residue (#19162). Now both modes use the same writable, initially
// empty directory, and the host is never written.
func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
	dir, err := os.MkdirTemp("", "xpf-cluster-state-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pkg/cluster TestMain: cannot create the state dir: %v\n", err)
		os.Exit(2)
	}
	restore := SetStateDirForTesting(dir)
	stopWatch := watchSharedGraceRecord19161(unkeyedAuthorityGraceStatePath, time.Now())
	code := m.Run()
	if leak := stopWatch(); leak != "" {
		fmt.Fprint(os.Stderr, leak)
		if code == 0 {
			code = 1
		}
	}
	restore()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// watchSharedGraceRecord19161 reports a write of the run-shared unkeyed-grace
// record whose earliest anchor predates the run (#19161). Every Manager that
// legitimately writes that record stamps it with the real clock during the
// run, so an anchor from before the run can only be a test's fixture clock
// leaking out of its test: in #19161 a never-stopped manager's timer wrote a
// fixture grace there, every later Manager held its election, and the
// package hung far from the cell that leaked. The hour of slack absorbs a
// wall-clock step; fixture anchors are days away. The returned func restores
// the persist hook and returns the first offending write with its stack.
func watchSharedGraceRecord19161(shared string, runStart time.Time) func() string {
	var mu sync.Mutex
	var first string
	inner := unkeyedAuthorityPersist
	unkeyedAuthorityPersist = func(path string, earliest, highWater time.Time, elapsed time.Duration) error {
		if path == shared && earliest.Before(runStart.Add(-time.Hour)) {
			mu.Lock()
			if first == "" {
				first = fmt.Sprintf("pkg/cluster TestMain (#19161): the run-shared grace record %s was written "+
					"with earliest=%s, before this run started (%s): a test's fixture clock leaked out "+
					"of its test (a Manager not stopped before its restores?). Writer:\n%s\n",
					path, earliest.UTC().Format(time.RFC3339), runStart.UTC().Format(time.RFC3339), debug.Stack())
			}
			mu.Unlock()
		}
		return inner(path, earliest, highWater, elapsed)
	}
	return func() string {
		unkeyedAuthorityPersist = inner
		mu.Lock()
		defer mu.Unlock()
		return first
	}
}
