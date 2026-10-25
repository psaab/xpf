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
	readIDs []uint32
}

func (d *quarantineZoneDisplayDP10489) IsLoaded() bool { return true }

func (d *quarantineZoneDisplayDP10489) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *quarantineZoneDisplayDP10489) ReadZoneCounters(id uint32, direction int) (dataplane.CounterValue, error) {
	d.readIDs = append(d.readIDs, id)
	if direction == 0 {
		return dataplane.CounterValue{Packets: 11, Bytes: 1100}, nil
	}
	return dataplane.CounterValue{Packets: 3, Bytes: 300}, nil
}

func TestShowZonesDisplayReadsCountersOnlyForSurvivor10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
	}}}
	dp := &quarantineZoneDisplayDP10489{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
			"zzq17760": config.StableZoneID("zzq17760"),
			"zzq8100":  config.StableZoneID("zzq8100"),
		}},
	}
	out := captureStdout(t, func() {
		if err := (&CLI{dp: dp}).showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if !strings.Contains(out, "Zone ID: 1679679597 (collides with \"zzq17760\"") {
		t.Fatalf("quarantined zone lost stable ID attribution:\n%s", out)
	}
	if !strings.Contains(out, config.ZoneQuarantineCountersLine) {
		t.Fatalf("quarantined zone rendered live counters:\n%s", out)
	}
	if !strings.Contains(out, "Input:  11 packets, 1100 bytes") {
		t.Fatalf("surviving zone did not render live counters:\n%s", out)
	}
	if len(dp.readIDs) != 2 || dp.readIDs[0] != config.StableZoneID("zzq17760") ||
		dp.readIDs[1] != config.StableZoneID("zzq17760") {
		t.Fatalf("counter reads = %v, want exactly two survivor reads", dp.readIDs)
	}
}
func TestShowZonesDisplayQuarantineDPNilAndOrdinary10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{
			"zzq17760": {Name: "zzq17760", Interfaces: []string{"ge-0/0/0.0"}},
			"zzq8100":  {Name: "zzq8100", Interfaces: []string{"ge-0/0/1.0"}},
		},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "zzq8100",
			ToZone:   "zzq17760",
			Policies: []*config.Policy{{Name: "allow-zzq8100", Action: config.PolicyPermit}},
		}},
	}}
	out := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(cfg, true, "zzq8100"); err != nil {
			t.Fatalf("showZonesDisplay(dp-nil): %v", err)
		}
	})
	for _, want := range []string{
		"Security zone: zzq8100",
		"Zone ID: 1679679597 (collides with \"zzq17760\"",
		config.ZoneQuarantineDispositionText,
		config.ZoneQuarantineCountersLine,
		config.ZoneQuarantineInterfacesQualifier,
		config.ZoneQuarantinePoliciesQualifier,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("dp-nil quarantine output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, config.ZoneQuarantineDriftNote) ||
		strings.Contains(out, "Input:  11 packets") {
		t.Fatalf("dp-nil output claimed applied drift or live counters:\n%s", out)
	}

	ordinary := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"dmz":     {Name: "dmz"},
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}}}
	ordinaryOut := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(ordinary, false, ""); err != nil {
			t.Fatalf("showZonesDisplay(ordinary): %v", err)
		}
	})
	if strings.Contains(ordinaryOut, "QUARANTINED") ||
		strings.Contains(ordinaryOut, config.ZoneQuarantineInterfacesQualifier) ||
		strings.Contains(ordinaryOut, config.ZoneQuarantineCountersLine) {
		t.Fatalf("ordinary zones received quarantine output:\n%s", ordinaryOut)
	}
}
