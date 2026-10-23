package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildSnapshotSummaryCountsBuiltSections16056 (#16056 A6-06): the
// full builder's Summary.InterfaceCount/ZoneCount must count the BUILT
// sections the helper installs, reconciled post-quarantine — the Rust
// helper refuses a summary/section mismatch, so a count derived from the
// authored config maps (or left at its pre-quarantine value) would
// either install a dropped-section snapshot or refuse a legitimate
// quarantined one.
//
// FAIL-ON-REVERT: restoring InterfaceCount=len(cfg.Interfaces.Interfaces)
// / ZoneCount=len(cfg.Security.Zones) (or the collision-only resync)
// leaves Summary disagreeing with len(Interfaces)/len(Zones) below.
func TestBuildSnapshotSummaryCountsBuiltSections16056(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw-16056"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name:  "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"192.0.2.1/24"}}},
		},
		"ge-0/0/1": {
			Name:  "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0"}},
	}
	cfg.Security.DefaultPolicy = config.PolicyDeny

	oldLinkSnapshot := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = oldLinkSnapshot })
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		switch name {
		case "ge-0-0-0":
			return 10, 1500, "02:00:00:00:00:10", nil
		case "ge-0-0-1":
			return 11, 1500, "02:00:00:00:00:11", nil
		default:
			return 0, 0, "", nil
		}
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 11, 5)
	// Premise: the builder expands 2 authored interfaces into base+unit
	// rows, so the built section is larger than the authored map.
	if len(snap.Interfaces) == len(cfg.Interfaces.Interfaces) {
		t.Fatalf("fixture premise broken: built Interfaces = %d rows, authored map = %d; counts cannot discriminate",
			len(snap.Interfaces), len(cfg.Interfaces.Interfaces))
	}
	if snap.Summary.InterfaceCount != len(snap.Interfaces) {
		t.Errorf("Summary.InterfaceCount = %d, want len(Interfaces) = %d (built rows, not authored map %d)",
			snap.Summary.InterfaceCount, len(snap.Interfaces), len(cfg.Interfaces.Interfaces))
	}
	if snap.Summary.ZoneCount != len(snap.Zones) {
		t.Errorf("Summary.ZoneCount = %d, want len(Zones) = %d", snap.Summary.ZoneCount, len(snap.Zones))
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		t.Errorf("Summary.PolicyCount = %d, want len(Policies) = %d", snap.Summary.PolicyCount, len(snap.Policies))
	}
	// The built snapshot must pass the Go send-site gate.
	m := New()
	if err := m.validateSnapshotForSend(snap); err != nil {
		t.Fatalf("built snapshot refused by send gate: %v", err)
	}
}

// TestBuildSnapshotQuarantinedZoneCountReconciled16056: a StableZoneID
// collision quarantines the later-sorting zone, shrinking the published
// Zones section below len(cfg.Security.Zones). The summary must follow
// the published section, or the helper's mismatch refusal bricks a
// legitimate no-brick quarantine.
//
// FAIL-ON-REVERT: removing the unconditional post-quarantine resync
// leaves ZoneCount at the authored count and this goes RED.
func TestBuildSnapshotQuarantinedZoneCountReconciled16056(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw-16056q"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name:  "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"192.0.2.1/24"}}},
		},
	}
	// z174/z214 is the verified colliding pair (z214 later-sorting loser).
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174": {Name: "z174", Interfaces: []string{"ge-0/0/0"}},
		"z214": {Name: "z214"},
	}
	cfg.Security.DefaultPolicy = config.PolicyDeny

	oldLinkSnapshot := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = oldLinkSnapshot })
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if name == "ge-0-0-0" {
			return 10, 1500, "02:00:00:00:00:10", nil
		}
		return 0, 0, "", nil
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 12, 5)
	if len(snap.zoneIDCollisions) == 0 {
		t.Fatalf("fixture premise broken: no zone quarantined; zones=%v", snap.Zones)
	}
	if len(snap.Zones) >= len(cfg.Security.Zones) {
		t.Fatalf("fixture premise broken: published Zones = %d, authored = %d; quarantine did not shrink the section",
			len(snap.Zones), len(cfg.Security.Zones))
	}
	if snap.Summary.ZoneCount != len(snap.Zones) {
		t.Errorf("Summary.ZoneCount = %d, want post-quarantine len(Zones) = %d (authored %d)",
			snap.Summary.ZoneCount, len(snap.Zones), len(cfg.Security.Zones))
	}
	if snap.Summary.InterfaceCount != len(snap.Interfaces) {
		t.Errorf("Summary.InterfaceCount = %d, want len(Interfaces) = %d",
			snap.Summary.InterfaceCount, len(snap.Interfaces))
	}
}

// TestValidateSnapshotForSendRefusesSectionMismatch16056: the Go send
// gate refuses a dropped-section snapshot (summary retained, section
// emptied) known-unsent, mirroring the policy arm — a partial publisher
// that zeroed Interfaces/Zones must never reach the helper.
//
// FAIL-ON-REVERT: removing the section arm from validateSnapshotForSend
// admits every case below.
func TestValidateSnapshotForSendRefusesSectionMismatch16056(t *testing.T) {
	base := &ConfigSnapshot{
		Generation: 3,
		Summary: SnapshotSummary{
			InterfaceCount: 2,
			ZoneCount:      2,
			PolicyCount:    0,
		},
		Interfaces: []InterfaceSnapshot{{Name: "ge-0/0/0"}, {Name: "ge-0/0/1"}},
		Zones:      []ZoneSnapshot{{Name: "trust"}, {Name: "untrust"}},
	}
	m := New()
	if err := m.validateSnapshotForSend(base); err != nil {
		t.Fatalf("consistent snapshot refused: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*ConfigSnapshot)
	}{
		{"interfaces dropped, summary retained", func(s *ConfigSnapshot) { s.Interfaces = nil }},
		{"zones dropped, summary retained", func(s *ConfigSnapshot) { s.Zones = nil }},
		{"interface count inflated", func(s *ConfigSnapshot) { s.Summary.InterfaceCount = 5 }},
		{"zone count inflated", func(s *ConfigSnapshot) { s.Summary.ZoneCount = 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := *base
			snap.Interfaces = append([]InterfaceSnapshot(nil), base.Interfaces...)
			snap.Zones = append([]ZoneSnapshot(nil), base.Zones...)
			tc.mutate(&snap)
			err := m.validateSnapshotForSend(&snap)
			if !errors.Is(err, errSnapshotPolicyMismatch) {
				t.Fatalf("validateSnapshotForSend = %v, want errSnapshotPolicyMismatch", err)
			}
			if !strings.Contains(err.Error(), "interface_count") && !strings.Contains(err.Error(), "zone_count") {
				t.Fatalf("error does not name the section counts: %v", err)
			}
		})
	}
}
