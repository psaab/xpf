package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15944 H4-04 (snapshot arm): a logical-only parent-bound RETH VLAN
// unit substituted the parent's kernel MTU without consulting the
// configured unit/interface MTU, so a per-unit `mtu 1400` never
// reached InterfaceSnapshot.MTU (the field the Rust snapshot
// validator consumes). The configured MTU now wins; the parent MTU
// remains the fallback when nothing is authored.
//
// FAIL-ON-REVERT: restoring the parent-only substitution makes the
// unit-MTU cell below report the parent's 1500 instead of 1400.

func TestLogicalOnlyRethUnitMTU15944(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-2":
			return 12, 1500, "02:00:00:00:00:02", nil
		default:
			// The VLAN child does not exist as a Linux netdev.
			return 0, 0, "", nil
		}
	}

	mk := func(unitMTU, ifaceMTU int) InterfaceSnapshot {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {
				Name:            "reth0",
				MTU:             ifaceMTU,
				RedundancyGroup: 1,
				Units: map[int]*config.InterfaceUnit{
					100: {Number: 100, VlanID: 100, MTU: unitMTU, Addresses: []string{"10.100.0.2/24"}},
				},
			},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"reth0.100"}},
		}
		snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 1, RingEntries: 1024}, 1, 0)
		for _, iface := range snap.Interfaces {
			if iface.Name == "reth0.100" {
				return iface
			}
		}
		t.Fatalf("no reth0.100 snapshot row: %+v", snap.Interfaces)
		return InterfaceSnapshot{}
	}

	if got := mk(1400, 0); got.MTU != 1400 || !got.LogicalOnly {
		t.Errorf("unit MTU: snapshot = %+v, want MTU 1400 logical-only", got)
	}
	if got := mk(0, 1450); got.MTU != 1450 {
		t.Errorf("interface MTU: snapshot MTU = %d, want 1450", got.MTU)
	}
	if got := mk(0, 0); got.MTU != 1500 {
		t.Errorf("unconfigured: snapshot MTU = %d, want parent fallback 1500", got.MTU)
	}
}
