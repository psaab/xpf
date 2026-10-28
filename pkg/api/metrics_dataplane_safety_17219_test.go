package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #17219: the #16202 table made every family — dataplane-safety
// included — initialize eagerly in newCollector, yet the newCollector
// comment claimed the family's sync.Once "still defers the NewDesc
// calls to Describe/Collect time" and the init kept that lazy idiom
// (plus a redundant emit-time re-init). Both are gone: init assigns
// directly, with no Once.
//
// RED pre-fix: restoring the lazy Once field (or the stale deferral
// comment) makes the issue's acceptance greps non-zero, and reverting
// init to lazy allocation would leave the fields nil after
// newCollector. The literal-collector half below is RED on the
// unguarded emit: with a real dataplane wired, mgmtview.Probe
// resolves, emit reaches emitConstMetric with nil descriptors, and
// client_golang NewConstMetric dereferences desc.err — a panic
// (proven firsthand). GREEN post-fix: newCollector allocates each
// dataplane-safety descriptor at construction, and a
// literal-constructed collector with a real dataplane emits
// nothing, does not panic, and counts one skipped series per
// nil descriptor in counterReadErrors.
func TestDataplaneSafetyDescriptorsEagerNoOnce17219(t *testing.T) {
	// Eager at construction: every descriptor the family row names is
	// non-nil immediately after newCollector, before any Describe or
	// Collect — the behaviour the stale comment denied.
	c := newCollector(nil)
	fields := map[string]**prometheus.Desc{
		"dataplaneObsoleteRegistryAccesses": &c.dataplaneObsoleteRegistryAccesses,
		"dataplaneXDPDetachDebtInterfaces":  &c.dataplaneXDPDetachDebtInterfaces,
		"dataplaneHostDivergenceMutations":  &c.dataplaneHostDivergenceMutations,
		"dataplaneArmUncoveredSurfaces":     &c.dataplaneArmUncoveredSurfaces,
		"dataplaneArmTotalSurfaces":         &c.dataplaneArmTotalSurfaces,
		"dataplaneXDPAttachModeSurfaces":    &c.dataplaneXDPAttachModeSurfaces,
	}
	for name, field := range fields {
		if *field == nil {
			t.Errorf("%s is nil after newCollector; want eager allocation at construction", name)
		}
	}

	// Literal collector with a REAL dataplane: Probe resolves, so
	// emit reaches every nil-Desc series. Pre-fix this panicked in
	// NewConstMetric (nil desc.err deref); post-fix each series is
	// skipped and counted, nothing is emitted, and no descriptor is
	// lazily allocated. The arm-proof series are not reached (no
	// completed proof), so exactly the first three series count.
	lit := &xpfCollector{deps: collectorDeps{dp: dataplane.New()}}
	ch := make(chan prometheus.Metric, 16)
	lit.emitDataplaneSafety(ch)
	if n := len(ch); n != 0 {
		t.Errorf("literal collector emitted %d metrics, want 0", n)
	}
	if got := lit.counterReadErrors.Load(); got != 3 {
		t.Errorf("literal collector counterReadErrors = %d, want 3 (one per skipped nil-Desc series)", got)
	}
	for name, field := range map[string]**prometheus.Desc{
		"dataplaneObsoleteRegistryAccesses": &lit.dataplaneObsoleteRegistryAccesses,
		"dataplaneXDPAttachModeSurfaces":    &lit.dataplaneXDPAttachModeSurfaces,
	} {
		if *field != nil {
			t.Errorf("literal collector %s allocated by emit, want nil (no lazy init)", name)
		}
	}
}
