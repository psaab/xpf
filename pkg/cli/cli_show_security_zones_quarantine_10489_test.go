package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type quarantineZoneDisplayDP10489 struct {
	*dataplane.Manager
	apply   *dataplane.ApplyResult
	readIDs []uint16
}

func (d *quarantineZoneDisplayDP10489) IsLoaded() bool { return true }

func (d *quarantineZoneDisplayDP10489) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *quarantineZoneDisplayDP10489) ReadZoneCounters(id uint16, direction int) (dataplane.CounterValue, error) {
	d.readIDs = append(d.readIDs, id)
	if direction == 0 {
		return dataplane.CounterValue{Packets: 11, Bytes: 1100}, nil
	}
	return dataplane.CounterValue{Packets: 3, Bytes: 300}, nil
}

func TestShowZonesDisplayReadsCountersOnlyForSurvivor10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174"},
		"z214": {Name: "z214"},
	}}}
	dp := &quarantineZoneDisplayDP10489{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
			"z174": config.StableZoneID("z174"),
			"z214": config.StableZoneID("z214"),
		}},
	}
	out := captureStdout(t, func() {
		if err := (&CLI{dp: dp}).showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if !strings.Contains(out, "Zone ID: 53547 (collides with \"z174\"") {
		t.Fatalf("quarantined zone lost stable ID attribution:\n%s", out)
	}
	if !strings.Contains(out, config.ZoneQuarantineCountersLine) {
		t.Fatalf("quarantined zone rendered live counters:\n%s", out)
	}
	if !strings.Contains(out, "Input:  11 packets, 1100 bytes") {
		t.Fatalf("surviving zone did not render live counters:\n%s", out)
	}
	if len(dp.readIDs) != 2 || dp.readIDs[0] != config.StableZoneID("z174") ||
		dp.readIDs[1] != config.StableZoneID("z174") {
		t.Fatalf("counter reads = %v, want exactly two survivor reads", dp.readIDs)
	}
}
