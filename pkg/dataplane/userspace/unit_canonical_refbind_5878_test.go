package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5878 phase 2 — reference-binder canonicalization. The interface defines a
// single logical unit (`unit 1`); zone / routing-instance / host-inbound
// references spell the SAME unit as `.01` (leading-zero alias). The reference
// binders must resolve `.01` to the interface's canonical runtime unit `.1`, so
// the per-unit snapshot (which keys the binder maps by the canonical "%s.%d"
// unit name) inherits the zone, routing-instance, and host-inbound override the
// operator bound.
//
// These are fail-on-revert: restore the raw-suffix key in a binder and the
// canonical unit-1 lookup misses — the unit binds to NO zone / NO routing
// instance / NO override — and the matching subtest goes RED.

// canonRefBindCfg5878 compiles (STRICT path — the commit path) a config whose
// interface has `unit 1` and whose zone/routing-instance/host-inbound references
// all use the `.01` leading-zero alias. Strict compile confirms `.01` is an
// accepted (valid) logical-unit reference — the divergence #5878 phase 2 closes
// is in BINDING, not acceptance.
func canonRefBindCfg5878(t *testing.T) *config.Config {
	t.Helper()
	cmds := []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1 family inet address 10.0.0.1/24",
		"set routing-instances ri1 interface ge-0/0/0.01",
		"set security zones security-zone trust interfaces ge-0/0/0.01",
		"set security zones security-zone trust interfaces ge-0/0/0.01 host-inbound-traffic system-services ssh",
	}
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (strict): %v", err)
	}
	return cfg
}

// canonUnitName returns the canonical "%s.%d" runtime name of the sole
// configured interface's unit — the exact key the per-unit snapshot consumer
// uses to look up the reference-binder maps.
func canonUnitName(t *testing.T, cfg *config.Config, unit int) string {
	t.Helper()
	if n := len(cfg.Interfaces.Interfaces); n != 1 {
		t.Fatalf("expected exactly 1 configured interface, got %d", n)
	}
	for name := range cfg.Interfaces.Interfaces {
		return fmt.Sprintf("%s.%d", name, unit)
	}
	return ""
}

func TestCanonicalZoneRefBind5878(t *testing.T) {
	cfg := canonRefBindCfg5878(t)
	unitName := canonUnitName(t, cfg, 1)

	// Direct binder-map assertion: the canonical unit key carries the zone.
	if got := buildInterfaceZoneMap(cfg)[unitName]; got != "trust" {
		t.Fatalf("buildInterfaceZoneMap[%q] = %q, want \"trust\" "+
			"(`.01` zone member must bind canonical unit 1)", unitName, got)
	}

	// End-to-end: the per-unit InterfaceSnapshot inherits the zone.
	var found bool
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name == unitName {
			found = true
			if snap.Zone != "trust" {
				t.Fatalf("unit snapshot %q Zone = %q, want \"trust\"", unitName, snap.Zone)
			}
		}
	}
	if !found {
		t.Fatalf("no InterfaceSnapshot named %q", unitName)
	}
}

func TestCanonicalRoutingInstanceRefBind5878(t *testing.T) {
	cfg := canonRefBindCfg5878(t)
	unitName := canonUnitName(t, cfg, 1)

	if got := buildInterfaceRoutingInstances(cfg)[unitName]; got != "ri1" {
		t.Fatalf("buildInterfaceRoutingInstances[%q] = %q, want \"ri1\" "+
			"(`.01` RI member must bind canonical unit 1)", unitName, got)
	}
	v4, v6 := buildInterfaceRouteTables(cfg)
	if got := v4[unitName]; got != "ri1.inet.0" {
		t.Fatalf("buildInterfaceRouteTables v4[%q] = %q, want \"ri1.inet.0\"", unitName, got)
	}
	if got := v6[unitName]; got != "ri1.inet6.0" {
		t.Fatalf("buildInterfaceRouteTables v6[%q] = %q, want \"ri1.inet6.0\"", unitName, got)
	}

	// End-to-end: the per-unit snapshot inherits the routing instance.
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name == unitName && snap.RoutingInstance != "ri1" {
			t.Fatalf("unit snapshot %q RoutingInstance = %q, want \"ri1\"", unitName, snap.RoutingInstance)
		}
	}
}

func TestCanonicalHostInboundRefBind5878(t *testing.T) {
	cfg := canonRefBindCfg5878(t)
	unitName := canonUnitName(t, cfg, 1)

	ovr := buildInterfaceHostInboundMap(cfg)[unitName]
	if ovr == nil {
		t.Fatalf("buildInterfaceHostInboundMap[%q] = nil, want the `.01` unit override "+
			"(must bind canonical unit 1)", unitName)
	}
	var hasSSH bool
	for _, s := range ovr.SystemServices {
		if s == "ssh" {
			hasSSH = true
		}
	}
	if !hasSSH {
		t.Fatalf("host-inbound override for %q = %v, want it to admit ssh", unitName, ovr.SystemServices)
	}

	// The operator-facing ingress-interface validator resolves the `.01` spelling
	// to the canonical unit's zone (no false "unknown ingress-interface").
	if err := ResolveHostInboundIngressInterface(cfg, "trust", "ge-0/0/0.01"); err != nil {
		t.Fatalf("ResolveHostInboundIngressInterface(.01) = %v, want nil", err)
	}
}
