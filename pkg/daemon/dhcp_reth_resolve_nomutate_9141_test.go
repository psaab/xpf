package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9141: resolveDHCPRethInterfaces used to rewrite `group.Interfaces[i]` IN
// PLACE, and every call site reached that slice from the daemon's SHARED active
// config. Two callers did `dhcpCfg := cfg.System.DHCPServer` first, which LOOKS
// like a copy but is a shallow struct copy over a pointer (DHCPLocalServer), a
// map of pointers (Groups) and a slice (Interfaces) — all shared. The third
// passed &cfg.System.DHCPServer with no copy at all.
//
// The harm is not in DHCP. rgForInterfaces (daemon_ddns.go) looks a group's
// member up in cfg.Interfaces.Interfaces, which is keyed by JUNOS names, so
// after the rewrite (`reth1.0` -> `ge-0-0-1.0`) the lookup misses and the pool
// scores RG 0 = "not HA-owned". ddnsReconcileOptions then sees anyRGOwnedPool
// false and the unattributable-lease branch flips from FAIL-CLOSED to admit —
// the #2664 per-lease double-write guard is disarmed, ORDER-DEPENDENTLY (the
// guard behaves differently before and after the first apply in a process
// lifetime).
//
// Measured before the fix:
//
//	BEFORE: Groups[g1].Interfaces = [reth1.0]    rgForInterfaces = 1
//	AFTER : Groups[g1].Interfaces = [ge-0-0-1.0] rgForInterfaces = 0
//
// FAIL-ON-REVERT: restore the in-place rewrite (a *config.DHCPServerConfig
// parameter writing group.Interfaces[i]) and every cell below goes RED.

func rethDHCPCfg9141(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// #9407: unit 0 is DECLARED. It was not before, and that made this
		// fixture unrepresentative in the direction that hides a defect: with
		// no unit table, ResolveKernelIfName falls through to its verbatim
		// arm, so the cells below could not tell the canonical resolver from
		// the two-arm LinuxIfName(ResolveReth(...)) they were pinning. Every
		// config that can actually serve DHCP declares the unit — that is
		// where the address lives.
		"reth1": {
			Name:            "reth1",
			RedundancyGroup: 1,
			Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
	}
	pool := &config.DHCPPool{Name: "p1", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.200"}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"g1": {Name: "g1", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{pool}},
		},
	}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"g6": {Name: "g6", Interfaces: []string{"reth1.0"}},
		},
	}
	return cfg
}

// The core assertion: the SHARED active config is untouched, and the RETURNED
// copy carries the resolved Linux names. Both halves matter — a resolver that
// simply returned its input unchanged would satisfy the first half alone.
func TestResolveDHCPRethInterfacesDoesNotMutateActiveConfig9141(t *testing.T) {
	cfg := rethDHCPCfg9141(t)

	out := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)

	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "reth1.0" {
		t.Errorf("shared active config MUTATED: v4 group interface is %q, want the authored %q", got, "reth1.0")
	}
	if got := cfg.System.DHCPServer.DHCPv6LocalServer.Groups["g6"].Interfaces[0]; got != "reth1.0" {
		t.Errorf("shared active config MUTATED: v6 group interface is %q, want the authored %q", got, "reth1.0")
	}
	// Positive control: the resolution still happens, in the returned copy.
	//
	// #9407 CHANGED THIS EXPECTATION, deliberately. It used to be
	// "ge-0-0-1.0" — a dangling unit suffix, which is not a device — pinned as
	// intended output. That was the defect being pinned, not a contract: only
	// the CLUSTER path stripped it (#4647), so the standalone builder handed
	// Kea a phantom device on identical config. The canonical resolver
	// collapses unit 0, so both topologies now name ge-0-0-1.
	if got := out.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "ge-0-0-1" {
		t.Errorf("returned copy did not resolve the v4 RETH name: got %q, want %q", got, "ge-0-0-1")
	}
	if got := out.DHCPv6LocalServer.Groups["g6"].Interfaces[0]; got != "ge-0-0-1" {
		t.Errorf("returned copy did not resolve the v6 RETH name: got %q, want %q", got, "ge-0-0-1")
	}
	// The copy must not ALIAS the source slice either — a copy that shares the
	// backing array is mutated by the next resolve just the same.
	out.DHCPLocalServer.Groups["g1"].Interfaces[0] = "sentinel"
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "reth1.0" {
		t.Errorf("returned copy ALIASES the active config's slice: writing it changed the source to %q", got)
	}
}

// The assertion that names the harm: the DDNS RG attribution survives an apply.
// This is the consequence the mutation actually had — the DHCP side kept working.
func TestDDNSRGAttributionSurvivesApply9141(t *testing.T) {
	cfg := rethDHCPCfg9141(t)
	d := &Daemon{}

	before := rgForInterfaces(cfg, cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces)
	if before != 1 {
		t.Fatalf("fixture is wrong: rgForInterfaces = %d before any apply, want 1", before)
	}
	if subnetRG := d.buildLeaseSubnetRGMap(cfg); len(subnetRG) != 1 || subnetRG[0].rg != 1 {
		t.Fatalf("fixture is wrong: lease subnet map = %+v before any apply, want one entry with rg 1", subnetRG)
	}

	// Drive the REAL wiring, not the helper directly: this is the cluster
	// applier's entry point and it is what performed the mutation in production.
	_ = d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())

	after := rgForInterfaces(cfg, cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces)
	if after != 1 {
		t.Errorf("rgForInterfaces flipped %d -> %d across an apply — the #2664 DDNS "+
			"double-write guard reads this and would score the pool as non-HA (#9141)",
			before, after)
	}
	subnetRG := d.buildLeaseSubnetRGMap(cfg)
	if len(subnetRG) != 1 || subnetRG[0].rg != 1 {
		t.Errorf("lease subnet map lost its RG owner across an apply: %+v — "+
			"anyRGOwnedPool goes false and the unattributable-lease branch stops "+
			"failing closed (#9141)", subnetRG)
	}
}

// The mutation was ORDER-DEPENDENT and cumulative: repeated applies must be
// identical, and the operator-facing view (`show dhcp server`, which renders
// cfg.System.DHCPServer directly) must keep showing what was CONFIGURED.
func TestRepeatedApplyLeavesConfigStable9141(t *testing.T) {
	cfg := rethDHCPCfg9141(t)
	d := &Daemon{}
	for i := 0; i < 3; i++ {
		_ = d.filterDHCPConfigForMasterRGsWithMasters(cfg, d.snapshotRethMasterState())
		if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "reth1.0" {
			t.Fatalf("apply %d rewrote the operator-visible config to %q; `show dhcp server` "+
				"would render a kernel name where the operator configured reth1.0", i, got)
		}
	}
}

// The standalone applier (daemon_apply_routing.go) is the one site that passed
// &cfg.System.DHCPServer with no copy at all. Its derivation is now the named
// desiredStandaloneDHCPConfig — the sibling of desiredClusterDHCPConfig — so it
// has a seam this cell can drive. Pin that the value it hands to
// dhcpserver.Apply is resolved while the source stays authored.
func TestStandaloneApplyShapeUsesResolvedCopy9141(t *testing.T) {
	cfg := rethDHCPCfg9141(t)
	resolved := desiredStandaloneDHCPConfig(cfg)
	// #9407 changed this expectation from "ge-0-0-1.0" for the reason given at
	// the positive control above: the dangling ".0" was never a device.
	if got := resolved.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "ge-0-0-1" {
		t.Errorf("Kea would be handed %q, want the resolved kernel name %q", got, "ge-0-0-1")
	}
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; got != "reth1.0" {
		t.Errorf("standalone apply mutated the active config to %q", got)
	}
}

// Nil/empty shapes must not panic or invent structure.
func TestResolveDHCPRethInterfacesNilShapes9141(t *testing.T) {
	cfg := &config.Config{}
	out := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)
	if out.DHCPLocalServer != nil || out.DHCPv6LocalServer != nil {
		t.Fatalf("empty config produced %+v, want both families nil", out)
	}

	cfg2 := rethDHCPCfg9141(t)
	cfg2.System.DHCPServer.DHCPLocalServer.Groups = nil
	cfg2.System.DHCPServer.DHCPv6LocalServer.Groups["g6"] = nil
	out2 := resolveDHCPRethInterfaces(cfg2.System.DHCPServer, cfg2)
	if out2.DHCPLocalServer == nil || out2.DHCPLocalServer.Groups != nil {
		t.Errorf("nil Groups map must stay nil, got %+v", out2.DHCPLocalServer)
	}
	if g, ok := out2.DHCPv6LocalServer.Groups["g6"]; !ok || g != nil {
		t.Errorf("nil group entry must be preserved as nil, got %v (present=%v)", g, ok)
	}
}

// desiredStandaloneDHCPConfig must tolerate a nil config the same way
// desiredClusterDHCPConfig does — applyServicesReconcile reaches it on the boot
// path before anything is committed.
func TestDesiredStandaloneDHCPConfigNilConfig9141(t *testing.T) {
	out := desiredStandaloneDHCPConfig(nil)
	if out.DHCPLocalServer != nil || out.DHCPv6LocalServer != nil {
		t.Fatalf("nil config produced %+v, want the zero DHCPServerConfig", out)
	}
}
