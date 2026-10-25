package dataplane

// #13164 (D4-06): programZoneMaps and planPhysDesired ignored the
// config quarantine SSOTs. The quarantined zone must have no install:
// no ZoneIDs entry, no SetZoneConfig overwrite of the survivor, no
// interface/physical planning, and every repeated run must leave the
// survivor's HostInbound and TCPRst installed. Quarantined interface
// claims are likewise skipped from every non-quarantined zone.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type quarantineRecordingDP13164 struct {
	discardingDataPlane
	calls []ZoneConfig
}

func (*quarantineRecordingDP13164) xpfValidationPass() bool { return false }

func (d *quarantineRecordingDP13164) SetZoneConfig(_ uint32, zc ZoneConfig) error {
	d.calls = append(d.calls, zc)
	return nil
}

func collidingZoneName13164(t *testing.T) string {
	t.Helper()
	// #16557 residual pair vs zzq17760 (see collidingConfig).
	candidate := "zzq8100"
	if config.StableZoneID(candidate) != config.StableZoneID("zzq17760") {
		t.Fatal("premise: zzq8100/zzq17760 no longer collide")
	}
	return candidate
}

func collidingConfig13164(t *testing.T) (*config.Config, string, uint32) {
	t.Helper()
	colliding := collidingZoneName13164(t)
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"203.0.113.1/24"}},
			}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
			}},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"zzq17760": {Name: "zzq17760", TCPRst: true, Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
			"untrust":  {Name: "untrust", Interfaces: []string{"ge-0/0/1.0"}},
			colliding:  {Name: colliding, Interfaces: []string{"ge-0/0/1.0"}},
		}},
	}
	return cfg, colliding, config.StableZoneID("zzq17760")
}

func TestProgramZoneMapsQuarantineCollision13164(t *testing.T) {
	cfg, colliding, targetID := collidingConfig13164(t)
	if _, excluded := config.ZoneQuarantineExclusionsForConfig(cfg)[colliding]; !excluded {
		t.Fatalf("fixture does not quarantine %q", colliding)
	}
	// Duplicate claims by healthy zones are quarantined from both.
	if _, conflicted := config.QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/1.0"]; !conflicted {
		t.Fatalf("fixture does not quarantine ge-0/0/1.0 keys=%v", config.QuarantinedZoneInterfaceKeys(cfg))
	}

	plan := planPhysDesired(cfg)
	for _, pd := range plan {
		for _, addr := range pd.addrs {
			if addr == "198.51.100.1/24" {
				t.Fatalf("planPhysDesired planned quarantined interface addr %s in %+v", addr, pd)
			}
		}
	}

	for i := range 50 {
		res := &CompileResult{ZoneIDs: make(map[string]uint32)}
		assignZoneIDs(res, cfg)
		dp := &quarantineRecordingDP13164{}
		if _, err := programZoneMaps(dp, cfg, res); err != nil {
			t.Fatalf("run %d: programZoneMaps: %v", i, err)
		}
		var survivorWrites int
		for _, zc := range dp.calls {
			if zc.ZoneID == targetID {
				survivorWrites++
				if zc.TCPRst != 1 || zc.HostInbound&HostInboundSSH == 0 {
					t.Fatalf("run %d: quarantined zone overwrote survivor config: %+v", i, zc)
				}
			} else if uint32(zc.ZoneID) != config.StableZoneID("untrust") {
				t.Fatalf("run %d: unexpected zone config %+v", i, zc)
			}
		}
		if survivorWrites != 1 || len(dp.calls) != 2 {
			t.Fatalf("run %d: got calls %+v; want one survivor and one untrust config", i, dp.calls)
		}
	}
}
