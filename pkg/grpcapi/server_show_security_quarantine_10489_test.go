package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type quarantineScreenGRPCDP10489 struct {
	*dataplane.Manager
	apply   *dataplane.ApplyResult
	readIDs []uint16
}

func (d *quarantineScreenGRPCDP10489) IsLoaded() bool                          { return true }
func (d *quarantineScreenGRPCDP10489) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *quarantineScreenGRPCDP10489) ReadFloodCounters(id uint16) (dataplane.FloodState, error) {
	d.readIDs = append(d.readIDs, id)
	return dataplane.FloodState{SynCount: 7, ICMPCount: 3, UDPCount: 5}, nil
}

func TestShowScreenStatisticsQuarantineProfileRetained10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174", ScreenProfile: "prof-10489"},
		"z214": {Name: "z214", ScreenProfile: "prof-10489"},
	}}}
	id := config.StableZoneID("z174")
	dp := &quarantineScreenGRPCDP10489{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"z174": id, "z214": id}},
	}
	s := &Server{dp: dp}

	var survivorBuf strings.Builder
	if _, err := s.showScreenStatistics(&pb.ShowTextRequest{Topic: "screen-statistics:z174"}, cfg, &survivorBuf); err != nil {
		t.Fatalf("showScreenStatistics survivor: %v", err)
	}
	survivorOut := survivorBuf.String()
	if !strings.Contains(survivorOut, "Screen profile: prof-10489") || !strings.Contains(survivorOut, "SYN flood events") {
		t.Fatalf("survivor screen stats missing profile/live counters:\n%s", survivorOut)
	}
	if len(dp.readIDs) != 1 || dp.readIDs[0] != id {
		t.Fatalf("survivor flood reads = %v, want exactly one survivor read", dp.readIDs)
	}

	dp.readIDs = nil
	var loserBuf strings.Builder
	if _, err := s.showScreenStatistics(&pb.ShowTextRequest{Topic: "screen-statistics:z214"}, cfg, &loserBuf); err != nil {
		t.Fatalf("showScreenStatistics loser: %v", err)
	}
	loserOut := loserBuf.String()
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
