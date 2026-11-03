package config

import "testing"

// #18923: the exported hoisted resolver must be a behaviour-identical twin of
// ResolveKernelIfName for every ref class the belt (and any other external
// caller) can produce, including the documented nil-map degradation.
// FAIL-ON-REVERT: delete the ResolveKernelIfNameWith export and this cell
// no longer compiles; route it through a divergent derivation and the
// corpus comparison reds.
func TestResolveKernelIfNameWithMatchesLegacy18923(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
					0:  {Number: 0},
					80: {Number: 80, VlanID: 180},
					9:  nil,
				}},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
				"reth1": {Name: "reth1", RedundancyGroup: 1, VlanTagging: true, Units: map[int]*InterfaceUnit{
					0:  {Number: 0},
					80: {Number: 80, VlanID: 180},
				}},
				"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*InterfaceUnit{
					0: {Number: 0, Tunnel: &TunnelConfig{Name: "gr-0-0-0", Source: "10.0.0.1"}},
					1: {Number: 1, Tunnel: &TunnelConfig{Name: "gr-0-0-0u1", Source: "10.0.0.3"}},
				}},
				"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: &TunnelConfig{Source: "10.0.1.1", Destination: "10.0.1.2"}, Units: map[int]*InterfaceUnit{
					0: {Number: 0},
					2: {Number: 2},
				}},
				"ge-0/0/7": nil,
			},
		},
	}
	refs := []string{
		"", "ge-0/0/0", "ge-0-0-0", "ge-0/0/0.0", "ge-0-0-0.0", "ge-0/0/0.80",
		"ge-0-0-0.80", "ge-0/0/0.9", "reth1", "reth1.0", "reth1.80", "reth1.7",
		"gr-0/0/0.0", "gr-0-0-0.0", "gr-0/0/0.1", "gr-0-0-0.1", "gr-0/0/1.0",
		"gr-0/0/1.2", "ge-0/0/7", "ge-0/0/9.0", "ge-0/0/0.foo", "st0.0",
		"irb.0", "fab0", "lo",
	}
	tunMap := cfg.TunnelNameMap()
	for _, ref := range refs {
		want := cfg.ResolveKernelIfName(ref)
		if got := cfg.ResolveKernelIfNameWith(ref, tunMap); got != want {
			t.Errorf("ResolveKernelIfNameWith(%q, tunMap) = %q, want ResolveKernelIfName %q", ref, got, want)
		}
		// Explicit expectations for the classes the belt depends on.
		switch ref {
		case "gr-0/0/0.1":
			if want != "gr-0-0-0u1" {
				t.Errorf("per-unit tunnel: ResolveKernelIfName(%q) = %q, want gr-0-0-0u1", ref, want)
			}
		case "reth1.7":
			// Undeclared unit of a declared RETH: the parent resolves to its
			// physical member (reth1 -> ge-0-0-1) and the unit suffix rides
			// along — not the verbatim ref.
			if want != "ge-0-0-1.7" {
				t.Errorf("undeclared reth unit: ResolveKernelIfName(%q) = %q, want ge-0-0-1.7", ref, want)
			}
		}
		// Nil map must not panic and must still derive plain/VLAN devices
		// via the unit arm (today's unexported behaviour, now pinned).
		_ = cfg.ResolveKernelIfNameWith(ref, nil)
	}
	if got := cfg.ResolveKernelIfNameWith("ge-0/0/0.80", nil); got != "ge-0-0-0.180" {
		t.Errorf("nil map VLAN derivation = %q, want ge-0-0-0.180", got)
	}
	// Empty config: no panic, legacy fallback.
	empty := &Config{}
	for _, ref := range refs {
		if got, want := empty.ResolveKernelIfNameWith(ref, empty.TunnelNameMap()), empty.ResolveKernelIfName(ref); got != want {
			t.Errorf("empty cfg ResolveKernelIfNameWith(%q) = %q, want %q", ref, got, want)
		}
	}
}
