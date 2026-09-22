package grpcapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type quarantineZoneDetailDP10489 struct {
	*dataplane.Manager
	apply   *dataplane.ApplyResult
	readIDs []uint16
}

func (d *quarantineZoneDetailDP10489) IsLoaded() bool { return true }

func (d *quarantineZoneDetailDP10489) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *quarantineZoneDetailDP10489) ReadZoneCounters(id uint16, direction int) (dataplane.CounterValue, error) {
	d.readIDs = append(d.readIDs, id)
	if direction == 0 {
		return dataplane.CounterValue{Packets: 11, Bytes: 1100}, nil
	}
	return dataplane.CounterValue{Packets: 3, Bytes: 300}, nil
}

func TestShowZonesDetailAnnotatesStableIDCollision10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"z174": {Name: "z174"},
				"z214": {Name: "z214"},
			},
		},
	}

	var buf strings.Builder
	(&Server{}).showZonesDetail(cfg, "", &buf)
	out := buf.String()
	collisionID := config.StableZoneID("z214")
	if !strings.Contains(out, fmt.Sprintf("Zone: z214 (id: %d)", collisionID)) {
		t.Fatalf("quarantined zone id missing from detail output:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("QUARANTINED (id %d collides with %q)", collisionID, "z174")) {
		t.Fatalf("quarantine headline missing survivor/id attribution:\n%s", out)
	}
	if !strings.Contains(out, config.ZoneQuarantineCountersLine) {
		t.Fatalf("quarantined zone rendered live counters instead of unavailable marker:\n%s", out)
	}
}
func TestShowZonesDetailReadsCountersOnlyForSurvivor10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"z174": {Name: "z174"},
				"z214": {Name: "z214"},
			},
		},
	}
	dp := &quarantineZoneDetailDP10489{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{
				"z174": config.StableZoneID("z174"),
				"z214": config.StableZoneID("z214"),
			},
		},
	}
	var buf strings.Builder
	(&Server{dp: dp}).showZonesDetail(cfg, "", &buf)
	out := buf.String()
	if !strings.Contains(out, "Input:  11 packets, 1100 bytes") {
		t.Fatalf("surviving zone did not render live counters:\n%s", out)
	}
	if len(dp.readIDs) != 2 || dp.readIDs[0] != config.StableZoneID("z174") ||
		dp.readIDs[1] != config.StableZoneID("z174") {
		t.Fatalf("counter reads = %v, want exactly two survivor reads", dp.readIDs)
	}
}
