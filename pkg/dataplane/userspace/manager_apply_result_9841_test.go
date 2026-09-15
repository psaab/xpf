package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// The #9841 carry through the userspace publish: recordApplyResultLocked
// preserves UnconvergedMTUs (it stamps capabilities+generation onto the
// result rather than rebuilding it field-by-field, so the field cannot be
// dropped here), and LastApplyResult serves isolated copies. Both success
// paths of applyCompiledSnapshot (normal publish and deferred XSK-startup
// publish) record through this one function.
func TestRecordApplyResultPreservesUnconvergedMTUs9841(t *testing.T) {
	m := &Manager{}
	in := &dataplane.ApplyResult{
		UnconvergedMTUs: []dataplane.MTUUnconverged{
			{Name: "ge-0-0-2", ConfigRef: "ge-0-0-2", WantMTU: 1400, LiveMTU: 1500},
		},
	}
	m.recordApplyResultLocked(in, UserspaceCapabilities{ForwardingSupported: true}, 7)
	got := m.LastApplyResult()
	if got == nil || len(got.UnconvergedMTUs) != 1 || got.UnconvergedMTUs[0].Name != "ge-0-0-2" {
		t.Fatalf("LastApplyResult = %+v, want the carried record", got)
	}
	if got.Generation != 7 {
		t.Fatalf("generation = %d, want the stamped 7", got.Generation)
	}
	in.UnconvergedMTUs[0].WantMTU = 999
	if got.UnconvergedMTUs[0].WantMTU != 1400 {
		t.Fatalf("post-record mutation leaked into the published result: %+v", got.UnconvergedMTUs)
	}
}

// The producer contract behind the daemon's generation guard: snapshot
// generations strictly increase per compile, so every recorded userspace
// apply advances the observed generation.
func TestBumpGenerationMonotonic9841(t *testing.T) {
	m := &Manager{}
	a, b := m.bumpGeneration(), m.bumpGeneration()
	if b <= a {
		t.Fatalf("generations %d then %d: must strictly increase", a, b)
	}
}
