package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type quarantineScreenDP10489 struct {
	dataplane.DataPlane
	apply   *dataplane.ApplyResult
	readIDs []uint16
}

func (d *quarantineScreenDP10489) IsLoaded() bool                          { return true }
func (d *quarantineScreenDP10489) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *quarantineScreenDP10489) ReadFloodCounters(id uint16) (dataplane.FloodState, error) {
	d.readIDs = append(d.readIDs, id)
	return dataplane.FloodState{SynCount: 7, ICMPCount: 3, UDPCount: 5}, nil
}

func TestShowScreenStatisticsQuarantineProfileRetained10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(`security {
    zones {
        security-zone z174;
        security-zone z214;
    }
}`, nil); err != nil {
		t.Fatalf("SyncApply colliding zones: %v", err)
	}
	cfg := store.ActiveConfig()
	cfg.Security.Zones["z174"].ScreenProfile = "prof-10489"
	cfg.Security.Zones["z214"].ScreenProfile = "prof-10489"
	id := config.StableZoneID("z174")
	dp := &quarantineScreenDP10489{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"z174": id, "z214": id}},
	}
	c := &CLI{store: store, dp: dp}

	survivorOut := captureStdout(t, func() {
		if err := c.showScreenStatistics("z174"); err != nil {
			t.Fatalf("showScreenStatistics survivor: %v", err)
		}
	})
	if !strings.Contains(survivorOut, "Screen profile: prof-10489") || !strings.Contains(survivorOut, "SYN flood events") {
		t.Fatalf("survivor screen stats missing profile/live counters:\n%s", survivorOut)
	}
	if len(dp.readIDs) != 1 || dp.readIDs[0] != id {
		t.Fatalf("survivor flood reads = %v, want exactly one survivor read", dp.readIDs)
	}

	dp.readIDs = nil
	loserOut := captureStdout(t, func() {
		if err := c.showScreenStatistics("z214"); err != nil {
			t.Fatalf("showScreenStatistics loser: %v", err)
		}
	})
	if !strings.Contains(loserOut, "Screen profile: prof-10489") {
		t.Fatalf("quarantined screen stats dropped authored profile:\n%s", loserOut)
	}
	if !strings.Contains(loserOut, config.ZoneQuarantineScreenCountersLine) {
		t.Fatalf("quarantined screen stats missing UNAVAILABLE line:\n%s", loserOut)
	}
	if strings.Contains(loserOut, "SYN flood events") {
		t.Fatalf("quarantined screen stats rendered live counters:\n%s", loserOut)
	}
	if len(dp.readIDs) != 0 {
		t.Fatalf("quarantined flood reads = %v, want zero (no survivor reuse)", dp.readIDs)
	}
}
