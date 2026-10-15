package userspace

import (
	"encoding/json"
	"testing"
)

func TestWGUncoveredStatusWire13289(t *testing.T) {
	const payload = `{"wg_uncovered_enqueued_total":11,"wg_uncovered_stale_total":12,"wg_uncovered_malformed_total":13,"wg_uncovered_nonlocal_total":14,"wg_uncovered_queue_full_total":15,"wg_uncovered_queue_shed_total":16,"wg_uncovered_queue_orphan_total":17,"wg_uncovered_queue_poison_recoveries":18}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode WG uncovered status: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"enqueued", status.WgUncoveredEnqueuedTotal, 11},
		{"stale", status.WgUncoveredStaleTotal, 12},
		{"malformed", status.WgUncoveredMalformedTotal, 13},
		{"nonlocal", status.WgUncoveredNonlocalTotal, 14},
		{"queue_full", status.WgUncoveredQueueFullTotal, 15},
		{"queue_shed", status.WgUncoveredQueueShedTotal, 16},
		{"queue_orphan", status.WgUncoveredQueueOrphanTotal, 17},
		{"queue_poison_recoveries", status.WgUncoveredQueuePoisonRecoveries, 18},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	var older ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &older); err != nil {
		t.Fatalf("decode older status without WG counters: %v", err)
	}
	if older.WgUncoveredEnqueuedTotal != 0 || older.WgUncoveredQueuePoisonRecoveries != 0 {
		t.Fatalf("absent WG counters did not default to zero: %+v", older)
	}
}
