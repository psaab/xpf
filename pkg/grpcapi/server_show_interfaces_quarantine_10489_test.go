package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowVLANsQualifiesQuarantinedZone10489(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"zzq17760": {Name: "zzq17760", Interfaces: []string{"ge-0/0/0"}},
			"zzq8100":  {Name: "zzq8100", Interfaces: []string{"ge-0/0/1"}},
		}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 10},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 20},
		}},
	}
	var buf strings.Builder
	(&Server{}).showVLANs(cfg, &buf)
	out := buf.String()
	var loserLine, survivorLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ge-0/0/1") {
			loserLine = line
		}
		if strings.Contains(line, "ge-0/0/0") {
			survivorLine = line
		}
	}
	if !strings.Contains(loserLine, "zzq8100") || !strings.Contains(loserLine, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("quarantined VLAN row missing zone/qualifier: %q\n%s", loserLine, out)
	}
	if strings.Contains(survivorLine, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("survivor VLAN row falsely qualified: %q\n%s", survivorLine, out)
	}
}
