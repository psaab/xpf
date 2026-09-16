package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9956 F-032: a routing instance quarantined on the lenient path is REMOVED
// from cfg.RoutingInstances (compiler_routing.go), so buildInterfaceRoutingInstances
// (routes.go, via forEachRoutingInstanceInterfaceKey) emits no entry for the
// dropped tenant's interfaces. The map read then yields "" and
// routingInstanceDomain("") returns 0 — the DEFAULT session domain. The
// quarantined tenant's interfaces inherit the default domain instead of an
// isolated one.
//
// This cell uses the #9622 reserved-name quarantine ("mgmt") as the reachable
// arm: it commits clean on the strict path's rejection, survives on the lenient
// path with exactly one warning, and exercises the identical downstream
// (slice removal -> map miss -> domain 0) as the #3855 table-id collision door.
// The surviving tenant is the in-run positive control: its domain must be its
// stable table id, which rules out "every interface reads 0 for some unrelated
// reason".
//
// RED on base: the quarantined row reads RoutingDomain 0.
func TestQuarantinedInstanceInterfacesNeverInheritDefaultDomain9956(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.1.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.2.2.1/24",
		"set routing-instances mgmt instance-type virtual-router",
		"set routing-instances mgmt interface ge-0/0/1.0",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/2.0",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	// Precondition: the lenient compile quarantined mgmt and kept tenant-a.
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	if len(names) != 1 || names[0] != "tenant-a" {
		t.Fatalf("fixture: lenient compile must quarantine %q and keep %q, got %v",
			"mgmt", "tenant-a", names)
	}

	snaps := buildInterfaceSnapshots(cfg)

	// Positive control: the survivor keeps its own isolated domain.
	survivor := snapshotByName9132(t, snaps, "ge-0/0/2.0")
	if survivor.RoutingInstance != "tenant-a" {
		t.Errorf("survivor %q RoutingInstance = %q, want %q",
			survivor.Name, survivor.RoutingInstance, "tenant-a")
	}
	wantSurvivor := uint32(config.StableRoutingInstanceTableID("tenant-a"))
	if survivor.RoutingDomain != wantSurvivor {
		t.Errorf("survivor %q RoutingDomain = %d, want %d (its stable table id)",
			survivor.Name, survivor.RoutingDomain, wantSurvivor)
	}

	// THE DEFECT: the quarantined tenant's interface must not fold into the
	// default session domain. Pinned to the sentinel: 0 would share the
	// default session space, and the stable id would collide with a #3855
	// survivor by construction — 2 is neither (HA-refused on import).
	quarantined := snapshotByName9132(t, snaps, "ge-0/0/1.0")
	if quarantined.RoutingDomain != QuarantinedRoutingInstanceDomain {
		t.Errorf("quarantined %q RoutingDomain = %d, want sentinel %d "+
			"(RoutingInstance = %q)",
			quarantined.Name, quarantined.RoutingDomain,
			QuarantinedRoutingInstanceDomain, quarantined.RoutingInstance)
	}
}

// Survivor-wins + quarantined-bare fanout (#9956 F-032).
//
// A contradictory double-claim — survivor tenant-a and quarantined mgmt both
// naming ge-0/0/2.0 — must keep the survivor's byte-identical domain: the
// quarantined set never overwrites a key the survivor map claims. And a
// quarantined BARE ref (ge-0/0/1, no unit) must fan down onto its addressed
// unit row exactly like #9132 — a keys[0]-only set would leave ge-0/0/1.0 at
// domain 0, silently preserving the defect for that shape.
func TestQuarantinedDoubleClaimKeepsSurvivorDomain9956(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.1.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.2.2.1/24",
		"set routing-instances mgmt instance-type virtual-router",
		"set routing-instances mgmt interface ge-0/0/1",
		"set routing-instances mgmt interface ge-0/0/2.0",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/2.0",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != "tenant-a" {
		t.Fatalf("fixture: lenient compile must keep only tenant-a, got %+v",
			cfg.RoutingInstances)
	}
	if len(cfg.QuarantinedRoutingInstances) != 1 ||
		cfg.QuarantinedRoutingInstances[0].Name != "mgmt" {
		t.Fatalf("fixture: the compile must record the mgmt evictee with its "+
			"membership, got %+v", cfg.QuarantinedRoutingInstances)
	}

	snaps := buildInterfaceSnapshots(cfg)

	// Double-claim: the survivor's domain is byte-identical.
	contested := snapshotByName9132(t, snaps, "ge-0/0/2.0")
	wantSurvivor := uint32(config.StableRoutingInstanceTableID("tenant-a"))
	if contested.RoutingInstance != "tenant-a" || contested.RoutingDomain != wantSurvivor {
		t.Errorf("contested %q = (%q, %d), want (%q, %d): a quarantined "+
			"ref must never overwrite a survivor's key",
			contested.Name, contested.RoutingInstance, contested.RoutingDomain,
			"tenant-a", wantSurvivor)
	}

	// Quarantined-bare fanout: the bare ref reaches the addressed unit row.
	fanned := snapshotByName9132(t, snaps, "ge-0/0/1.0")
	if fanned.RoutingDomain != QuarantinedRoutingInstanceDomain {
		t.Errorf("quarantined-bare %q RoutingDomain = %d, want sentinel %d: "+
			"a quarantined bare ref must fan down like #9132",
			fanned.Name, fanned.RoutingDomain, QuarantinedRoutingInstanceDomain)
	}
}
