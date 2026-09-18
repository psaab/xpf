package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

func TestDHCPLeaseScopeAuthorityIgnoresRGZero10170(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 0},
	}}}
	if rg, ok := dhcpLeaseRGForInterface(cfg, "reth0.80", cfg.RethRGOwners()); ok || rg != 0 {
		t.Fatalf("RG0 must not become an authoritative HA scope: rg=%d ok=%v", rg, ok)
	}
}

func TestDHCPLeaseScopeAuthorityOmitsMixedGroup10170(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 2},
		"fxp0":  {Name: "fxp0", RedundancyGroup: 0},
	}}, System: config.SystemConfig{DHCPServer: config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{"mixed": {
			Interfaces: []string{"reth0.80", "fxp0.0"},
			Pools:      []*config.DHCPPool{{Subnet: "10.0.2.0/24"}},
		}},
	}}}}
	if got := dhcpLeaseScopeAuthorities(cfg, 4, 1, true, map[int]bool{2: true}); len(got) != 0 {
		t.Fatalf("mixed RG/node-local group became authoritative: %#v", got)
	}
}

type authorityReaderApplier10170 struct {
	*recordingDHCPApplier9349
	generation uint64
	scopes     []dhcpserver.LeaseScopeAuthority
	applied    bool
}

func (r *authorityReaderApplier10170) LeaseAuthorityResult(int) (uint64, []dhcpserver.LeaseScopeAuthority, bool) {
	return r.generation, r.scopes, r.applied
}

func TestMakeDHCPLeaseSnapshotRejectsStaleAuthorityGeneration10170(t *testing.T) {
	r := &authorityReaderApplier10170{
		recordingDHCPApplier9349: &recordingDHCPApplier9349{},
		generation:               1,
		scopes:                   []dhcpserver.LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 1, Served: true, Applied: true}},
		applied:                  true,
	}
	d := &Daemon{dhcpServer: r, dhcpLeaseSync: dhcpLeaseSyncState{authorityGeneration: 2}}
	snapshot := d.makeDHCPLeaseSnapshot(nil, 4, nil)
	if snapshot.Generation != 2 || len(snapshot.Scopes) != 0 {
		t.Fatalf("stale authority result overwrote current generation: %+v", snapshot)
	}

	r.generation = 2
	snapshot = d.makeDHCPLeaseSnapshot(nil, 4, nil)
	if snapshot.Generation != 2 || len(snapshot.Scopes) != 0 {
		t.Fatalf("same-generation authority scope without a current local scope was accepted: %+v", snapshot)
	}
}

func TestMakeDHCPLeaseSnapshotRejectsSameGenerationStaleServedScope10170(t *testing.T) {
	r := &authorityReaderApplier10170{
		recordingDHCPApplier9349: &recordingDHCPApplier9349{},
		generation:               7,
		scopes: []dhcpserver.LeaseScopeAuthority{{
			Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 7, Served: true, Applied: true,
		}},
		applied: true,
	}
	d := &Daemon{
		dhcpServer:    r,
		dhcpLeaseSync: dhcpLeaseSyncState{authorityGeneration: 7},
		rgStates:      make(map[int]*rgStateMachine),
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 2},
		}},
		System: config.SystemConfig{DHCPServer: config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{"g": {
				Interfaces: []string{"reth0.80"},
				Pools:      []*config.DHCPPool{{Subnet: "10.0.2.0/24"}},
			}},
		}}},
	}
	d.getOrCreateRGState(2).SetCluster(true)
	snapshot := d.makeDHCPLeaseSnapshot(cfg, 4, nil)
	if len(snapshot.Scopes) != 1 || !snapshot.Scopes[0].Served || !snapshot.Scopes[0].Applied {
		t.Fatalf("matching generation/current mastership did not accept proof: %+v", snapshot)
	}

	d.getOrCreateRGState(2).SetCluster(false)
	snapshot = d.makeDHCPLeaseSnapshot(cfg, 4, nil)
	if len(snapshot.Scopes) != 1 || snapshot.Scopes[0].Served || snapshot.Scopes[0].Applied {
		t.Fatalf("same-generation stale Served proof survived mastership change: %+v", snapshot)
	}
}
