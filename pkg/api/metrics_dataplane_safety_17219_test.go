package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
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
// init to lazy allocation would leave the
// fields nil after newCollector. GREEN post-fix: newCollector allocates
// dataplane-safety descriptor at construction, and a
// literal-constructed collector (which never ran newCollector) emits
// nothing and does not panic — emitConstMetric skips its nil
// descriptors instead of the old Once lazily allocating them.
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

	// Literal collector: never initialized, so emit is a no-op (via
	// mgmtview.Probe on a nil dp) and must not panic or allocate the
	// family lazily.
	lit := &xpfCollector{}
	ch := make(chan prometheus.Metric, 16)
	lit.emitDataplaneSafety(ch)
	if n := len(ch); n != 0 {
		t.Errorf("literal collector emitted %d metrics, want 0", n)
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
