package config

import "testing"

// #18923: the exported hoisted resolver must resolve every ref class the
// Kea belt (and any other external caller) can produce exactly as
// documented. The PRIMARY oracle is the explicit expectation table below —
// every value derived from the resolver's documented arms, never from
// running the implementation under test: an exact declared stanza wins
// (#8994); a RETH parent resolves to its physical member; a per-unit
// tunnel resolves to its own device; a unit under an interface-level
// tunnel shares the base device; a VLAN unit resolves to base.vlan-id;
// unit 0 collapses to the base; a nil unit entry, an undeclared base, or a
// malformed suffix keeps the suffix with slashes translated. Comparing
// against ResolveKernelIfName alone would be self-oracular — it delegates
// to this very function — so its agreement is asserted only as a SECONDARY
// cross-check.
//
// The nil-map column pins the degradation for a caller that (against the
// contract above) passes nil instead of TunnelNameMap(): no panic, every
// per-unit tunnel still resolves through its unit stanza, and exactly ONE
// class changes — an interface-level tunnel's shared base device degrades
// to the literal unit device (gr-0/0/1.2 -> gr-0-0-1.2).
//
// FAIL-ON-REVERT: delete the ResolveKernelIfNameWith export and this cell
// no longer compiles; diverge any derivation arm inside it and the table
// reds naming the offending ref.
func TestResolveKernelIfNameWithExplicitCorpus18923(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
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
		}},
	}
	corpus := []struct {
		ref        string
		want       string // with cfg.TunnelNameMap(): the documented resolution
		wantNilMap string // with nil: the documented degradation
	}{
		{"", "", ""},
		{"ge-0/0/0", "ge-0-0-0", "ge-0-0-0"},             // declared stanza: bare arm
		{"ge-0-0-0", "ge-0-0-0", "ge-0-0-0"},             // bare ref, linux spelling
		{"ge-0/0/0.0", "ge-0-0-0", "ge-0-0-0"},           // unit 0 collapses to the base
		{"ge-0-0-0.0", "ge-0-0-0", "ge-0-0-0"},           // cross-spelled unit 0 (#9821)
		{"ge-0/0/0.80", "ge-0-0-0.180", "ge-0-0-0.180"},  // VLAN unit -> base.vlan-id
		{"ge-0-0-0.80", "ge-0-0-0.180", "ge-0-0-0.180"},  // cross-spelled VLAN unit
		{"ge-0/0/0.9", "ge-0-0-0.9", "ge-0-0-0.9"},       // nil unit entry: fallback keeps suffix
		{"reth1", "ge-0-0-1", "ge-0-0-1"},                // reth parent -> physical member
		{"reth1.0", "ge-0-0-1", "ge-0-0-1"},              // member unit 0 collapses to member
		{"reth1.80", "ge-0-0-1.180", "ge-0-0-1.180"},     // member VLAN unit
		{"reth1.7", "ge-0-0-1.7", "ge-0-0-1.7"},          // undeclared unit rides member fallback
		{"gr-0/0/0.0", "gr-0-0-0", "gr-0-0-0"},           // per-unit tunnel device
		{"gr-0-0-0.0", "gr-0-0-0", "gr-0-0-0"},           // cross-spelling probe (#9815)
		{"gr-0/0/0.1", "gr-0-0-0u1", "gr-0-0-0u1"},       // per-unit tunnel, uN device (#1910)
		{"gr-0-0-0.1", "gr-0-0-0u1", "gr-0-0-0u1"},       // cross-spelling probe
		{"gr-0/0/1.0", "gr-0-0-1", "gr-0-0-1"},           // iface-level tunnel: unit 0 shares base
		{"gr-0/0/1.2", "gr-0-0-1", "gr-0-0-1.2"},         // nil map degrades the shared device
		{"ge-0/0/7", "ge-0-0-7", "ge-0-0-7"},             // present-but-nil stanza: name resolves
		{"ge-0/0/9.0", "ge-0-0-9.0", "ge-0-0-9.0"},       // undeclared base: verbatim fallback
		{"ge-0/0/0.foo", "ge-0-0-0.foo", "ge-0-0-0.foo"}, // malformed unit: verbatim fallback
		{"st0.0", "st0.0", "st0.0"},                      // secure-tunnel unit, no VPN: authored ref
		{"irb.0", "irb.0", "irb.0"},                      // no bridge domain: fallback
		{"fab0", "fab0", "fab0"},                         // passthrough
		{"lo", "lo", "lo"},                               // passthrough
	}
	tunMap := cfg.TunnelNameMap()
	for _, c := range corpus {
		if got := cfg.ResolveKernelIfNameWith(c.ref, tunMap); got != c.want {
			t.Errorf("ResolveKernelIfNameWith(%q, tunMap) = %q, want %q", c.ref, got, c.want)
		}
		if got := cfg.ResolveKernelIfNameWith(c.ref, nil); got != c.wantNilMap {
			t.Errorf("ResolveKernelIfNameWith(%q, nil) = %q, want %q (documented nil-map degradation)",
				c.ref, got, c.wantNilMap)
		}
		// SECONDARY oracle only: the convenience wrapper builds its own map
		// and must agree with the primary table.
		if got := cfg.ResolveKernelIfName(c.ref); got != c.want {
			t.Errorf("ResolveKernelIfName(%q) = %q, want %q", c.ref, got, c.want)
		}
	}

	// Empty config: nothing is declared, so every ref takes the verbatim
	// fallback (slash translation only); a reth with no declared member
	// stays itself, and unit 0 does NOT collapse — there is no stanza to
	// collapse onto. TunnelNameMap() on an empty config is a non-nil empty
	// map and must behave exactly like nil here.
	emptyCorpus := []struct{ ref, want string }{
		{"", ""},
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0-0-0"},
		{"ge-0/0/0.0", "ge-0-0-0.0"},
		{"ge-0-0-0.0", "ge-0-0-0.0"},
		{"ge-0/0/0.80", "ge-0-0-0.80"},
		{"ge-0-0-0.80", "ge-0-0-0.80"},
		{"ge-0/0/0.9", "ge-0-0-0.9"},
		{"reth1", "reth1"},
		{"reth1.0", "reth1.0"},
		{"reth1.80", "reth1.80"},
		{"reth1.7", "reth1.7"},
		{"gr-0/0/0.0", "gr-0-0-0.0"},
		{"gr-0-0-0.0", "gr-0-0-0.0"},
		{"gr-0/0/0.1", "gr-0-0-0.1"},
		{"gr-0-0-0.1", "gr-0-0-0.1"},
		{"gr-0/0/1.0", "gr-0-0-1.0"},
		{"gr-0/0/1.2", "gr-0-0-1.2"},
		{"ge-0/0/7", "ge-0-0-7"},
		{"ge-0/0/9.0", "ge-0-0-9.0"},
		{"ge-0/0/0.foo", "ge-0-0-0.foo"},
		{"st0.0", "st0.0"},
		{"irb.0", "irb.0"},
		{"fab0", "fab0"},
		{"lo", "lo"},
	}
	empty := &Config{}
	for _, c := range emptyCorpus {
		if got := empty.ResolveKernelIfNameWith(c.ref, empty.TunnelNameMap()); got != c.want {
			t.Errorf("empty cfg ResolveKernelIfNameWith(%q, TunnelNameMap()) = %q, want %q", c.ref, got, c.want)
		}
		if got := empty.ResolveKernelIfNameWith(c.ref, nil); got != c.want {
			t.Errorf("empty cfg ResolveKernelIfNameWith(%q, nil) = %q, want %q", c.ref, got, c.want)
		}
	}
}
