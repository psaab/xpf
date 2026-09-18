package config

import "testing"

// unit.MTU is the MIN of the family's mtu statements, independent of authored
// order (#10050). The inet arm used to OVERWRITE unit.MTU unconditionally while
// the inet6 arm min-folded, so parent 1400 + inet6/1300-then-inet/9000 compiled
// 9000 while the reverse order compiled 1300 — and the compiled value feeds
// both the #9837 strict gate and the runtime writer
// (applyVLANSubInterfaceMTU9757), so the commit verdict itself depended on
// statement order. Both arms now min-fold (0 = unset), so both orders compile
// the lower family value and gate and runtime stay consistent.
//
// The compiled value is read back through the lenient path so the assertion
// holds however the strict gate judges it; the strict legs below pin that the
// gate accepts both orders once the min compiles below the parent.
func TestUnitMTUOrderIndependent10050(t *testing.T) {
	flat := []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
	}
	flatCases := map[string][]string{
		"inet before inet6": {
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
		},
		"inet6 before inet": {
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
		},
	}
	for name, order := range flatCases {
		t.Run("flat "+name, func(t *testing.T) {
			sets := append(append([]string{}, flat...), order...)
			cfg, err := CompileConfigLenient(flatTreeFromSets(t, sets...))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 1300 {
				t.Errorf("compiled unit.MTU = %d, want 1300 (min of families, either order)", got)
			}
		})
	}

	hierCases := map[string]string{
		"inet before inet6": `interfaces {
    ge-0-0-2 {
        vlan-tagging;
        mtu 1400;
        unit 50 {
            vlan-id 50;
            family inet { mtu 9000; }
            family inet6 { mtu 1300; }
        }
    }
}`,
		"inet6 before inet": `interfaces {
    ge-0-0-2 {
        vlan-tagging;
        mtu 1400;
        unit 50 {
            vlan-id 50;
            family inet6 { mtu 1300; }
            family inet { mtu 9000; }
        }
    }
}`,
	}
	for name, src := range hierCases {
		t.Run("hier "+name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree(t, src))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 1300 {
				t.Errorf("compiled unit.MTU = %d, want 1300 (min of families, either order)", got)
			}
		})
	}
}

// The min is symmetric: whichever family carries the lower value wins, in
// either order. This distinguishes min-of-families from an "inet6 wins"
// precedence — inet 1300 + inet6 9000 compiles 1300 both ways.
func TestUnitMTUMinIsSymmetric10050(t *testing.T) {
	base := []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
	}
	cases := map[string][]string{
		"inet before inet6": {
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1300",
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 9000",
		},
		"inet6 before inet": {
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 9000",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1300",
		},
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			sets := append(append([]string{}, base...), order...)
			cfg, err := CompileConfigLenient(flatTreeFromSets(t, sets...))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 1300 {
				t.Errorf("compiled unit.MTU = %d, want 1300 (the lower family value)", got)
			}
		})
	}
}

// Once the min compiles below the parent, the strict gate accepts BOTH
// authoring orders: the commit verdict no longer depends on statement order.
// Pre-fix the inet6-first leg compiled 9000 and the gate rejected it.
func TestUnitMTUOrderIndependentGateAccepts10050(t *testing.T) {
	base := []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
	}
	cases := map[string][]string{
		"inet before inet6": {
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
		},
		"inet6 before inet": {
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
		},
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			sets := append(append([]string{}, base...), order...)
			cfg := assertCommitAccepts(t, flatTreeFromSets(t, sets...))
			if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 1300 {
				t.Errorf("compiled unit.MTU = %d, want 1300", got)
			}
		})
	}
}

// Single-family shapes still compile their one value, and no mtu statement
// still compiles 0: the min-fold's 0-means-unset must not swallow a lone
// value or conjure one. Untagged with no parent mtu so the #9837 gate (tagged
// units only) stays out of the picture.
func TestUnitMTUSingleFamilyUnchanged10050(t *testing.T) {
	cases := map[string]struct {
		sets []string
		want int
	}{
		"inet only": {
			sets: []string{
				"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
				"set interfaces ge-0-0-0 unit 0 family inet mtu 9000",
			},
			want: 9000,
		},
		"inet6 only": {
			sets: []string{
				"set interfaces ge-0-0-0 unit 0 family inet6 address fd00::8/64",
				"set interfaces ge-0-0-0 unit 0 family inet6 mtu 9000",
			},
			want: 9000,
		},
		"no mtu": {
			sets: []string{
				"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
				"set interfaces ge-0-0-0 unit 0 family inet6 address fd00::8/64",
			},
			want: 0,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, flatTreeFromSets(t, tc.sets...))
			if got := cfg.Interfaces.Interfaces["ge-0-0-0"].Units[0].MTU; got != tc.want {
				t.Errorf("compiled unit.MTU = %d, want %d", got, tc.want)
			}
		})
	}
}
