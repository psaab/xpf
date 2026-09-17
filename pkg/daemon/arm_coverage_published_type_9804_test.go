package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestPublishedUserspaceDataplaneSatisfiesArmCoverage9804 asks the daemon's
// real production construction path for its dynamic method set. The existing
// #7191 cells use fakeCoverageDP, so they cannot detect an adapter that erases
// ArmCoverageSummary before evaluateArmCoverage sees it.
func TestPublishedUserspaceDataplaneSatisfiesArmCoverage9804(t *testing.T) {
	dp, err := buildRuntimeDataPlane("")
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane(\"\"): %v", err)
	}
	if _, ok := any(dp).(*dpuserspace.LegacyDataPlaneAdapter); !ok {
		t.Fatalf("production runtime type = %T, want *userspace.LegacyDataPlaneAdapter", dp)
	}
	src, ok := any(dp).(armCoverageSource)
	if !ok {
		t.Fatalf("production runtime type %T does not satisfy armCoverageSource", dp)
	}
	uncovered, total, ran, seen := src.ArmCoverageSummary()
	if uncovered != 0 || total != 0 || ran || seen {
		t.Fatalf("a freshly booted production dataplane must expose the unknown tuple: "+
			"uncovered=%d total=%d ran=%v seen=%v", uncovered, total, ran, seen)
	}

	withTempTransitForwardSysctls(t, "0")
	withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(dp)
	d.markDataplaneArmed("test")
	d.evaluateArmCoverage("published-adapter")
	if !d.DataplaneArmed() {
		t.Fatal("the pre-first-apply production adapter proof must not disarm the box")
	}
}
