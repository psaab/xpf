package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16697: REST must carry ha_state tri-state; "unknown" never collapses
// to Backup/false-only.
func TestSessionHAStateForView16697(t *testing.T) {
	// No RG probe: legacy standalone bool.
	if got := sessionHAStateForView(sessionView{haActive: true}, "", "", 0, 0); got != "Active" {
		t.Errorf("standalone active: %q", got)
	}
	if got := sessionHAStateForView(sessionView{haActive: false}, "", "", 0, 0); got != "Backup" {
		t.Errorf("standalone backup control: %q", got)
	}
	// RG probe wired, no RETH owners in cfg => unknown.
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},
	}
	view := sessionView{
		cfg:          cfg,
		haActiveRGFn: func(rg int) (bool, bool) { return true, true },
	}
	if got := sessionHAStateForView(view, "ge-0/0/0.0", "", 0, 0); got != "unknown" {
		t.Errorf("no-RETH: %q want unknown", got)
	}
	if sessionHAActiveForView(view, "ge-0/0/0.0", "", 0, 0) {
		t.Error("unknown must not report ha_active=true")
	}
	// Known: reth1 RG1 primary.
	cfg2 := &config.Config{}
	cfg2.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", RedundancyGroup: 1},
	}
	cfg2.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth1.0"}},
	}
	view2 := sessionView{cfg: cfg2, zoneNames: map[uint16]string{1: "trust"}, haActiveRGFn: func(rg int) (bool, bool) {
		if rg == 1 {
			return false, true
		}
		return false, false
	}}
	if got := sessionHAStateForView(view2, "reth1.0", "", 0, 0); got != "Backup" {
		t.Errorf("known backup: %q want Backup", got)
	}
	_ = dataplane.SessionValue{}
}

func TestSessionEntryFromPBHAState16697(t *testing.T) {
	got := sessionEntryFromPB(&pb.SessionEntry{HaActive: false, HaState: "unknown"})
	if got.HAState != "unknown" || got.HAActive {
		t.Errorf("peer unknown: %+v", got)
	}
	got = sessionEntryFromPB(&pb.SessionEntry{HaActive: true, HaState: "Active"})
	if got.HAState != "Active" || !got.HAActive {
		t.Errorf("peer active: %+v", got)
	}
	got = sessionEntryFromPB(&pb.SessionEntry{HaActive: false, HaState: "Backup"})
	if got.HAState != "Backup" || got.HAActive {
		t.Errorf("peer backup control: %+v", got)
	}
	// Direct REST constructors stamp HAState too.
	se := sessionEntryV4(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{}, 0, sessionView{haActive: true, cfg: &config.Config{}, haActiveRGFn: func(int) (bool, bool) { return true, true }})
	if se.HAState != "unknown" {
		t.Errorf("direct v4 no-RETH: HAState=%q want unknown", se.HAState)
	}
}
