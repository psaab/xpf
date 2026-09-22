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
func TestShowZonesDisplayQuarantineDPNilAndOrdinary10489(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{
			"z174": {Name: "z174", Interfaces: []string{"ge-0/0/0.0"}},
			"z214": {Name: "z214", Interfaces: []string{"ge-0/0/1.0"}},
		},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "z214",
			ToZone:   "z174",
			Policies: []*config.Policy{{Name: "allow-z214", Action: config.PolicyPermit}},
		}},
	}}
	out := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(cfg, true, "z214"); err != nil {
			t.Fatalf("showZonesDisplay(dp-nil): %v", err)
		}
	})
	for _, want := range []string{
		"Security zone: z214",
		"Zone ID: 53547 (collides with \"z174\"",
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
