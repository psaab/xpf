package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

// #16631: on a cluster node that owns none of an OSPF instance's
// interfaces, filterOSPF used to keep a VL-only area, so the renderer
// emitted `area X virtual-link N` and ospfd (non-ABR) refused it —
// every FRR apply on the standby hard-failed. The filter now drops a
// VL whose transit area retains no renderable interface after RG
// pruning.
//
// FAIL-ON-REVERT: revert filterOSPF to the interface-or-VL keep rule
// and the standby cases below retain/render the VL again.

func ospfVLNames16631(ospf *config.OSPFConfig) []string {
	var out []string
	if ospf == nil {
		return out
	}
	for _, area := range ospf.Areas {
		if area == nil {
			continue
		}
		for _, vl := range area.VirtualLinks {
			if vl != nil {
				out = append(out, vl.TransitArea+"->"+vl.NeighborID)
			}
		}
	}
	return out
}

func ospfVLConfig16631(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	d, cfg := newFRRRGShutdownDaemon11415(t)
	// Separate units in RG1 give backbone and transit distinct devices;
	// FRR permits only one OSPF area per interface.
	cfg.Interfaces.Interfaces["reth0"].Units[1] = &config.InterfaceUnit{
		Number: 1, VlanID: 1, Addresses: []string{"198.51.101.1/24"},
	}
	cfg.Protocols.OSPF = &config.OSPFConfig{RouterID: "192.0.2.1", Areas: []*config.OSPFArea{
		{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "reth0.1"}}},
		{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "reth0.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
	}}
	return d, cfg
}

func TestOSPFVirtualLinkHAFilter16631(t *testing.T) {
	d, cfg := ospfVLConfig16631(t)

	// Primary for RG0+RG1: transit retains reth0.0, VL kept.
	fc := d.assembleFRRConfig(cfg, nil)
	if got := ospfVLNames16631(fc.OSPF); len(got) != 1 || got[0] != "0.0.0.1->10.0.0.2" {
		t.Fatalf("primary VLs = %v, want [0.0.0.1->10.0.0.2]", got)
	}

	// RG1 secondary (RG0 still primary): reth0.0 withdrawn everywhere,
	// so the transit area has no interface — VL must drop, and no
	// VL-only area may survive.
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	fc = d.assembleFRRConfig(cfg, nil)
	if got := ospfVLNames16631(fc.OSPF); len(got) != 0 {
		t.Errorf("RG1-secondary VLs = %v, want none", got)
	}
	if fc.OSPF != nil {
		for _, area := range fc.OSPF.Areas {
			if area != nil && len(area.Interfaces) == 0 && len(area.VirtualLinks) != 0 {
				t.Errorf("VL-only area survived filter: %+v", area)
			}
		}
	}

	// Full standby (RG0+RG1 secondary): still no VL.
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	fc = d.assembleFRRConfig(cfg, nil)
	if got := ospfVLNames16631(fc.OSPF); len(got) != 0 {
		t.Errorf("standby VLs = %v, want none", got)
	}

	// Promotion restores the VL through the same render path.
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	fc = d.assembleFRRConfig(cfg, nil)
	if got := ospfVLNames16631(fc.OSPF); len(got) != 1 {
		t.Errorf("promoted VLs = %v, want 1 restored", got)
	}

	// Committed config must be untouched by filtering.
	if len(cfg.Protocols.OSPF.Areas) != 2 || len(cfg.Protocols.OSPF.Areas[1].VirtualLinks) != 1 ||
		len(cfg.Protocols.OSPF.Areas[1].Interfaces) != 1 {
		t.Fatal("HA filtering mutated the committed OSPF config")
	}
}

// The standby's rendered FRR file carries no virtual-link (acceptance:
// standby render has no `virtual-link`, primary render keeps it).
func TestOSPFVirtualLinkStandbyRender16631(t *testing.T) {
	d, cfg := ospfVLConfig16631(t)
	render := func(label string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "frr.conf")
		manager := frr.NewForTest(path, &frr.RecordingExecutor{})
		t.Cleanup(manager.Stop)
		if err := manager.ApplyFull(d.assembleFRRConfig(cfg, nil)); err != nil {
			t.Fatalf("%s ApplyFull: %v", label, err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s ReadFile: %v", label, err)
		}
		return string(b)
	}
	primary := render("primary")
	activation := strings.Index(primary, " ip ospf area 0.0.0.1\n")
	link := strings.Index(primary, " area 0.0.0.1 virtual-link 10.0.0.2\n")
	if activation < 0 || link <= activation {
		t.Fatalf("primary must activate the transit area before its VL:\n%s", primary)
	}
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	if got := render("standby"); strings.Contains(got, "virtual-link") {
		t.Fatalf("standby render still carries a virtual-link:\n%s", got)
	}
}

// Direct filter cells: transit kept via a different area's interface,
// disabled-only transit, and spelling normalization.
func TestFilterOSPFVirtualLinkDirect16631(t *testing.T) {
	d, cfg := newFRRRGShutdownDaemon11415(t)
	state := newFRRHADemotionState(d, cfg)
	if state == nil {
		t.Fatal("premise: HA state nil")
	}
	mk := func(areas ...*config.OSPFArea) *config.OSPFConfig {
		return &config.OSPFConfig{RouterID: "192.0.2.1", Areas: areas}
	}
	// All-primary state: nothing is inactive, so only the VL rule bites.

	// VL transit is the backbone with an interface: #16631 does not
	// judge it (backbone-transit refusal is #15016, render/strict side).
	out := state.filterOSPF(cfg, mk(
		&config.OSPFArea{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "xe-0/0/0.0"}}},
		&config.OSPFArea{ID: "0.0.0.1", VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.0"}}},
	), nil)
	if got := ospfVLNames16631(out); len(got) != 1 {
		t.Errorf("backbone-transit VL = %v, want kept by #16631 filter (refused later by #15016 belt)", got)
	}

	// Disabled-only transit interface: VL drops.
	out = state.filterOSPF(cfg, mk(
		&config.OSPFArea{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "xe-0/0/0.0", Disable: true}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
	), nil)
	if got := ospfVLNames16631(out); len(got) != 0 {
		t.Errorf("disabled-transit VL = %v, want dropped", got)
	}

	// Integer-spelled transit ("1") matches dotted area 0.0.0.1.
	out = state.filterOSPF(cfg, mk(
		&config.OSPFArea{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "xe-0/0/0.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "1"}}},
	), nil)
	if got := ospfVLNames16631(out); len(got) != 1 {
		t.Errorf("integer-transit VL = %v, want kept", got)
	}
}
