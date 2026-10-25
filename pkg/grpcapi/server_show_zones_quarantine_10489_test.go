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
	readIDs []uint32
}

func (d *quarantineZoneDetailDP10489) IsLoaded() bool { return true }

func (d *quarantineZoneDetailDP10489) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *quarantineZoneDetailDP10489) ReadZoneCounters(id uint32, direction int) (dataplane.CounterValue, error) {
	d.readIDs = append(d.readIDs, id)
	if direction == 0 {
		return dataplane.CounterValue{Packets: 11, Bytes: 1100}, nil
	}
	return dataplane.CounterValue{Packets: 3, Bytes: 300}, nil
}

func TestShowZonesDetailAnnotatesStableIDCollision10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"zzq17760": {Name: "zzq17760"},
				"zzq8100":  {Name: "zzq8100"},
			},
		},
	}

	var buf strings.Builder
	(&Server{}).showZonesDetail(cfg, "", &buf)
	out := buf.String()
	collisionID := config.StableZoneID("zzq8100")
	if !strings.Contains(out, fmt.Sprintf("Zone: zzq8100 (id: %d)", collisionID)) {
		t.Fatalf("quarantined zone id missing from detail output:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("QUARANTINED (id %d collides with %q)", collisionID, "zzq17760")) {
		t.Fatalf("quarantine headline missing survivor/id attribution:\n%s", out)
	}
	if !strings.Contains(out, config.ZoneQuarantineCountersLine) {
		t.Fatalf("quarantined zone rendered live counters instead of unavailable marker:\n%s", out)
	}
}
func TestShowZonesDetailReadsCountersOnlyForSurvivor10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"zzq17760": {Name: "zzq17760"},
				"zzq8100":  {Name: "zzq8100"},
			},
		},
	}
	dp := &quarantineZoneDetailDP10489{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint32{
				"zzq17760": config.StableZoneID("zzq17760"),
				"zzq8100":  config.StableZoneID("zzq8100"),
			},
		},
	}
	var buf strings.Builder
	(&Server{dp: dp}).showZonesDetail(cfg, "", &buf)
	out := buf.String()
	if !strings.Contains(out, "Input:  11 packets, 1100 bytes") {
		t.Fatalf("surviving zone did not render live counters:\n%s", out)
	}
	if len(dp.readIDs) != 2 || dp.readIDs[0] != config.StableZoneID("zzq17760") ||
		dp.readIDs[1] != config.StableZoneID("zzq17760") {
		t.Fatalf("counter reads = %v, want exactly two survivor reads", dp.readIDs)
	}
}
func quarantineZonesConfig10489(withPolicy bool) *config.Config {
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760", Interfaces: []string{"ge-0/0/0.0"}},
		"zzq8100":  {Name: "zzq8100", Interfaces: []string{"ge-0/0/1.0"}},
	}}}
	if withPolicy {
		cfg.Security.Policies = []*config.ZonePairPolicies{{
			FromZone: "zzq8100",
			ToZone:   "zzq17760",
			Policies: []*config.Policy{{Name: "allow-zzq8100", Action: config.PolicyPermit}},
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
		{name: "quarantined loser", filter: "zzq8100", quarantined: true},
		{name: "surviving zone", filter: "zzq17760"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp := &quarantineZoneDetailDP10489{
				Manager: dataplane.New(),
				apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
					"zzq17760": config.StableZoneID("zzq17760"),
					"zzq8100":  config.StableZoneID("zzq8100"),
				}},
			}
			var buf strings.Builder
			(&Server{dp: dp}).showZonesDetail(cfg, tc.filter, &buf)
			out := buf.String()
			if tc.quarantined {
				id := config.StableZoneID("zzq8100")
				for _, want := range []string{
					fmt.Sprintf("Zone: zzq8100 (id: %d) (collides with %q — would not be installed if this snapshot is applied)", id, "zzq17760"),
					fmt.Sprintf("QUARANTINED (id %d collides with %q)", id, "zzq17760"),
					config.ZoneQuarantineDispositionText,
					config.ZoneQuarantineCountersLine,
					config.ZoneQuarantineInterfacesQualifier,
					config.ZoneQuarantinePoliciesQualifier,
				} {
					if !strings.Contains(out, want) {
						t.Fatalf("filtered loser output missing %q:\n%s", want, out)
					}
				}
				if strings.Contains(out, "Zone: zzq17760") || strings.Contains(out, "Input:") {
					t.Fatalf("filtered loser leaked survivor detail:\n%s", out)
				}
			} else {
				if strings.Contains(out, "QUARANTINED") ||
					strings.Contains(out, config.ZoneQuarantineInterfacesQualifier) ||
					strings.Contains(out, config.ZoneQuarantineCountersLine) {
					t.Fatalf("filtered survivor was falsely qualified:\n%s", out)
				}
				if !strings.Contains(out, "Zone: zzq17760 (id:") {
					t.Fatalf("filtered survivor lost its applied ID:\n%s", out)
				}
				if strings.Contains(out, "Zone: zzq8100") {
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
	id := config.StableZoneID("zzq17760")
	for _, tc := range []struct {
		name      string
		applied   map[string]uint32
		wantDrift bool
	}{
		{name: "dp nil", wantDrift: false},
		{name: "matching applied inventory", applied: map[string]uint32{
			"zzq17760": id, "zzq8100": id,
		}, wantDrift: false},
		{name: "key skew", applied: map[string]uint32{"zzq17760": id}, wantDrift: true},
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
					config.StableZoneID("zzq8100"), "zzq17760")
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

func TestShowTestZoneSortedDuplicateInterface10489(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760", Interfaces: []string{"ge-0/0/9.0"}},
		"zzq8100":  {Name: "zzq8100", Interfaces: []string{"ge-0/0/9.0"}},
		"nilzone":  nil,
	}}}
	for i := 0; i < 20; i++ {
		var buf strings.Builder
		if _, err := (&Server{}).showTestZone(
			&pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/9.0"},
			cfg, &buf); err != nil {
			t.Fatalf("showTestZone duplicate: %v", err)
		}
		if !strings.Contains(buf.String(), "belongs to zone: zzq17760") {
			t.Fatalf("duplicate interface resolved nondeterministically (want sorted-first zzq17760):\n%s", buf.String())
		}
	}
}
