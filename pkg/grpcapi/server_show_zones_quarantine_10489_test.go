package grpcapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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
func quarantineZonesConfig10489(withPolicy bool) *config.Config {
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174", Interfaces: []string{"ge-0/0/0.0"}},
		"z214": {Name: "z214", Interfaces: []string{"ge-0/0/1.0"}},
	}}}
	if withPolicy {
		cfg.Security.Policies = []*config.ZonePairPolicies{{
			FromZone: "z214",
			ToZone:   "z174",
			Policies: []*config.Policy{{Name: "allow-z214", Action: config.PolicyPermit}},
		}}
	}
	return cfg
}

func TestShowZonesDetailFilteredDispositionAndQualifiers10489(t *testing.T) {
	cfg := quarantineZonesConfig10489(true)
	cases := []struct {
		name        string
		filter      string
		quarantined bool
	}{
		{name: "quarantined loser", filter: "z214", quarantined: true},
		{name: "surviving zone", filter: "z174"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp := &quarantineZoneDetailDP10489{
				Manager: dataplane.New(),
				apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
					"z174": config.StableZoneID("z174"),
					"z214": config.StableZoneID("z214"),
				}},
			}
			var buf strings.Builder
			(&Server{dp: dp}).showZonesDetail(cfg, tc.filter, &buf)
			out := buf.String()
			if tc.quarantined {
				id := config.StableZoneID("z214")
				for _, want := range []string{
					fmt.Sprintf("Zone: z214 (id: %d) (collides with %q — would not be installed if this snapshot is applied)", id, "z174"),
					fmt.Sprintf("QUARANTINED (id %d collides with %q)", id, "z174"),
					config.ZoneQuarantineDispositionText,
					config.ZoneQuarantineCountersLine,
					config.ZoneQuarantineInterfacesQualifier,
					config.ZoneQuarantinePoliciesQualifier,
				} {
					if !strings.Contains(out, want) {
						t.Fatalf("filtered loser output missing %q:\n%s", want, out)
					}
				}
				if strings.Contains(out, "Zone: z174") || strings.Contains(out, "Input:") {
					t.Fatalf("filtered loser leaked survivor detail:\n%s", out)
				}
			} else {
				if strings.Contains(out, "QUARANTINED") ||
					strings.Contains(out, config.ZoneQuarantineInterfacesQualifier) ||
					strings.Contains(out, config.ZoneQuarantineCountersLine) {
					t.Fatalf("filtered survivor was falsely qualified:\n%s", out)
				}
				if !strings.Contains(out, "Zone: z174 (id:") {
					t.Fatalf("filtered survivor lost its applied ID:\n%s", out)
				}
				if strings.Contains(out, "Zone: z214") {
					t.Fatalf("filtered survivor leaked the quarantined zone:\n%s", out)
				}
			}
		})
	}
}

func TestShowZonesDetailNoFalsePositiveAndDriftNote10489(t *testing.T) {
	ordinary := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"dmz":     {Name: "dmz"},
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}}}
	var ordinaryBuf strings.Builder
	(&Server{}).showZonesDetail(ordinary, "", &ordinaryBuf)
	ordinaryOut := ordinaryBuf.String()
	if strings.Contains(ordinaryOut, "QUARANTINED") ||
		strings.Contains(ordinaryOut, config.ZoneQuarantineInterfacesQualifier) ||
		strings.Contains(ordinaryOut, config.ZoneQuarantineCountersLine) {
		t.Fatalf("ordinary zones received quarantine output:\n%s", ordinaryOut)
	}

	cfg := quarantineZonesConfig10489(false)
	id := config.StableZoneID("z174")
	for _, tc := range []struct {
		name      string
		applied   map[string]uint16
		wantDrift bool
	}{
		{name: "dp nil", wantDrift: false},
		{name: "matching applied inventory", applied: map[string]uint16{
			"z174": id, "z214": id,
		}, wantDrift: false},
		{name: "key skew", applied: map[string]uint16{"z174": id}, wantDrift: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			s := &Server{}
			if tc.applied != nil {
				s.dp = &quarantineZoneDetailDP10489{
					Manager: dataplane.New(),
					apply:   &dataplane.ApplyResult{ZoneIDs: tc.applied},
				}
			}
			s.showZonesDetail(cfg, "", &buf)
			got := strings.Count(buf.String(), config.ZoneQuarantineDriftNote)
			want := 0
			if tc.wantDrift {
				want = 1
			}
			if got != want {
				t.Fatalf("drift note count = %d, want %d:\n%s", got, want, buf.String())
			}
		})
	}
}

func TestShowTestZoneQuarantineAndOrdinaryMatches10489(t *testing.T) {
	cfg := quarantineZonesConfig10489(false)
	for _, tc := range []struct {
		name        string
		ifName      string
		quarantined bool
	}{
		{name: "quarantined loser", ifName: "ge-0/0/1.0", quarantined: true},
		{name: "surviving zone", ifName: "ge-0/0/0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			_, err := (&Server{}).showTestZone(
				&pb.ShowTextRequest{Topic: "test-zone:interface=" + tc.ifName},
				cfg, &buf)
			if err != nil {
				t.Fatalf("showTestZone: %v", err)
			}
			out := buf.String()
			if tc.quarantined {
				want := config.ZoneQuarantineTestZoneQualifierFor(
					config.StableZoneID("z214"), "z174")
				if !strings.Contains(out, want) {
					t.Fatalf("quarantined test-zone match missing %q:\n%s", want, out)
				}
			} else if strings.Contains(out, "quarantined") {
				t.Fatalf("surviving test-zone match was reclassified:\n%s", out)
			}
		})
	}

	ordinary := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/2.0"}},
	}}}
	var buf strings.Builder
	_, err := (&Server{}).showTestZone(
		&pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/2.0"},
		ordinary, &buf)
	if err != nil {
		t.Fatalf("ordinary showTestZone: %v", err)
	}
	if strings.Contains(buf.String(), "quarantined") {
		t.Fatalf("ordinary test-zone match changed:\n%s", buf.String())
	}
}
