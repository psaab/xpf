package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17810 — the filter-syslog generation authority the daemon resolves lives
// behind an optional capability on the published dataplane:
//
//	appliedSnapshotGenerationOf (pkg/daemon/daemon_system.go) asserts
//	dataplane.Unwrap(rt).(interface{ AppliedSnapshotGeneration() uint64 })
//
// The method exists on *dpuserspace.Manager and reaches the daemon only
// through the hand-written forwarder on *LegacyDataPlaneAdapter — the type
// Boot() (and buildRuntimeDataPlane("")) publishes. Removing the forwarder
// (pkg/dataplane/userspace/legacy_dataplane.go:110-115) leaves the
// capability erased: the assertion silently fails, appliedSnapshotGenerationOf
// returns 0, the LastApplyResult fallback reinstalls under stale G, and
// H-stamped FILTER_LOG events mismatch indefinitely. Every neighbouring
// daemon cell supplies its own exporter/capability double, so none of them
// can see that regression; this cell follows the #9482/#17082 pin precedent
// and asks about the DYNAMIC type production actually publishes.
//
// Compile-time half: assert *LegacyDataPlaneAdapter satisfies the exact
// one-method capability interface the daemon asserts against.
var _ interface{ AppliedSnapshotGeneration() uint64 } = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

// TestPublishedUserspaceDataplaneSatisfiesAppliedSnapshotGeneration17810 is
// the runtime half: it obtains the dataplane through the daemon's real
// construction path, unwraps it the way appliedSnapshotGenerationOf does,
// and requires the published value to expose AppliedSnapshotGeneration.
// Deleting the adapter forwarder must FAIL this cell (Mutation-proven
// requirement, PR #18380 review) while the neighbouring daemon cells stay
// green, because they inject doubles rather than Boot()'s adapter.
func TestPublishedUserspaceDataplaneSatisfiesAppliedSnapshotGeneration17810(t *testing.T) {
	published, err := buildRuntimeDataPlane("")
	if err != nil {
		t.Fatalf("FIXTURE FAILED: buildRuntimeDataPlane(\"\"): %v, so this cell "+
			"cannot observe anything about the published type", err)
	}
	if published == nil {
		t.Fatal("FIXTURE FAILED: buildRuntimeDataPlane(\"\") returned nil")
	}
	provider, ok := dataplane.Unwrap(published).(interface {
		AppliedSnapshotGeneration() uint64
	})
	if !ok {
		t.Fatalf("#17810: the dataplane the daemon publishes (%T, unwrapped %T) "+
			"does not satisfy interface{ AppliedSnapshotGeneration() uint64 }; "+
			"the #17810 forwarder on *userspace.LegacyDataPlaneAdapter is "+
			"missing, so daemon_system's capability probe falls back to stale "+
			"LastApplyResult.Generation and H-stamped FILTER_LOG events are "+
			"suppressed indefinitely", published, dataplane.Unwrap(published))
	}
	// The call must be safe on a freshly booted (unstarted) backend: a
	// zero/unstarted Manager reports generation 0, which the daemon treats
	// as the LastApplyResult fallback rather than a panic.
	_ = provider.AppliedSnapshotGeneration()
}
