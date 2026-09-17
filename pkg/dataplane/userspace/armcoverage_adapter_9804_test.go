package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type armCoverageSource9804 interface {
	ArmCoverageSummary() (uncovered, total int, ran, seen bool)
}

// TestLegacyAdapterForwardsArmCoverage9804 uses the real userspace Manager and
// real retained dataplane.Manager, then asks the adapter's dynamic method set
// for the published primitive proof. A test fake satisfying the interface
// directly would not catch the production adapter omission.
func TestLegacyAdapterForwardsArmCoverage9804(t *testing.T) {
	shim := dataplane.New()
	rep := shim.ProveArmCoverage(&dataplane.CompileResult{})
	if !rep.Ran || rep.Uncovered != 0 {
		t.Fatalf("fixture must publish a complete proof: %+v", rep)
	}

	adapter := NewLegacyDataPlaneAdapter(&Manager{bpfShim: shim})
	src, ok := any(adapter).(armCoverageSource9804)
	if !ok {
		t.Fatalf("published adapter type %T does not satisfy ArmCoverageSummary", adapter)
	}
	uncovered, total, ran, seen := src.ArmCoverageSummary()
	if uncovered != 0 || total != 0 || !ran || !seen {
		t.Fatalf("adapter changed the retained proof: uncovered=%d total=%d ran=%v seen=%v",
			uncovered, total, ran, seen)
	}
}

// TestLegacyAdapterArmCoverageIsNilSafe9804 pins the same nil-safe behavior as
// the neighboring #9725 forwarders: unavailable managers have no fabricated
// proof.
func TestLegacyAdapterArmCoverageIsNilSafe9804(t *testing.T) {
	for _, tc := range []struct {
		name    string
		adapter *LegacyDataPlaneAdapter
	}{
		{name: "nil receiver"},
		{name: "nil manager", adapter: NewLegacyDataPlaneAdapter(nil)},
		{name: "nil shim", adapter: NewLegacyDataPlaneAdapter(&Manager{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, ok := any(tc.adapter).(armCoverageSource9804)
			if !ok {
				t.Fatal("adapter's method set must expose ArmCoverageSummary")
			}
			uncovered, total, ran, seen := src.ArmCoverageSummary()
			if uncovered != 0 || total != 0 || ran || seen {
				t.Fatalf("adapter must return the unknown tuple: uncovered=%d total=%d ran=%v seen=%v",
					uncovered, total, ran, seen)
			}
		})
	}
}
