// #3343 key-pin: GetGlobalStats.screen_drop_details emits the canonical
// per-screen-reason keys from the dataplane.ScreenReasonCounters SSOT. Before
// #3343 these per-reason counters were always 0 (the userspace bridge published
// only the aggregate), so no per-reason key ever appeared in the detail map.
// Routing the map through the SSOT (#3343) both populated the values AND made
// the keys API-visible, renaming `tear-drop`->`teardrop` and
// `syn-fragment`->`syn-frag` to match the Rust ScreenVerdict::Drop strings.
// This test pins the emitted key set so a future accidental re-rename (or a
// wiring change away from rc.Reason) is caught.
//
// FAIL-ON-REVERT: changing server_show_status.go back to a hardcoded list with
// the old keys (or any key drift from dataplane.ScreenReasonCounters) fails the
// canonical-key assertions below.
package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// screenReasonKeyDP returns a distinct nonzero value (ordinal+1) for each
// per-screen-reason GlobalCtrScreen* index and 0 for every other counter, so
// GetGlobalStats includes exactly the per-reason keys in screen_drop_details.
type screenReasonKeyDP struct {
	*dataplane.Manager
}

func (screenReasonKeyDP) IsLoaded() bool { return true }

func (screenReasonKeyDP) ReadGlobalCounter(idx uint32) (uint64, error) {
	for i := range dataplane.ScreenReasonCounters {
		if dataplane.ScreenReasonCounters[i].Index == idx {
			return uint64(i + 1), nil
		}
	}
	return 0, nil
}

func TestGetGlobalStatsScreenDropDetailKeysAreCanonical(t *testing.T) {
	s := newViewServer(t, screenReasonKeyDP{Manager: dataplane.New()})

	resp, err := s.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		t.Fatalf("GetGlobalStats: %v", err)
	}

	// Exact canonical key set (and the per-ordinal value the fake returned),
	// independent of the SSOT struct so a same-direction edit to both can't
	// hide a regression.
	want := map[string]uint64{
		"syn-flood":              1,
		"icmp-flood":             2,
		"udp-flood":              3,
		"port-scan":              4,
		"ip-sweep":               5,
		"land-attack":            6,
		"ping-of-death":          7,
		"teardrop":               8,
		"tcp-syn-fin":            9,
		"tcp-no-flag":            10,
		"tcp-fin-no-ack":         11,
		"winnuke":                12,
		"ip-source-route":        13,
		"syn-frag":               14,
		"session-limit":          15,
		"icmp-fragment":          16,
		"ip-malformed":           17,
		"syn-cookie-unavailable": 18,
		"syn-cookie-invalid":     19,
	}
	for k, v := range want {
		got, ok := resp.ScreenDropDetails[k]
		if !ok {
			t.Errorf("screen_drop_details missing canonical key %q", k)
			continue
		}
		if got != v {
			t.Errorf("screen_drop_details[%q] = %d, want %d", k, got, v)
		}
	}

	// The keys #3343 renamed must not reappear under their pre-#3343 names.
	for _, legacy := range []string{"tear-drop", "syn-fragment"} {
		if _, ok := resp.ScreenDropDetails[legacy]; ok {
			t.Errorf("screen_drop_details still emits legacy key %q (key re-rename / hardcoded-list reintroduced?)", legacy)
		}
	}

	// No unexpected per-screen-reason key leaked in.
	if len(resp.ScreenDropDetails) != len(want) {
		t.Errorf("screen_drop_details has %d keys, want %d: %v", len(resp.ScreenDropDetails), len(want), resp.ScreenDropDetails)
	}
}
