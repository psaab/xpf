package config

import (
	"strings"
	"testing"
)

// #14435 (DR17-H6): `unit 0 point-to-point family inet { ... }` and
// `unit 0 tunnel ... family inet { ... }` pack the whole family body onto
// the unit node's Keys. The unit loop's FindChild/FindChildren("family")
// reads see only Children, so the family subtree (addresses + filters)
// was dropped; the unit compiled empty yet still got a zoned snapshot
// row (fail-open).

func hierTree14435(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}
func unit14435(t *testing.T, src, ifName string, num int) *InterfaceUnit {
	t.Helper()
	cfg, err := CompileConfig(hierTree14435(t, src))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces[ifName]
	if ifc == nil {
		t.Fatalf("interface %s missing in %q", ifName, src)
	}
	u := ifc.Units[num]
	if u == nil {
		t.Fatalf("unit %d missing on %s in %q", num, ifName, src)
	}
	return u
}

const filterDefs14435 = `firewall { family inet { filter DISCARD-BAD { term t0 { then discard; } } filter OUT-F { term t0 { then accept; } } } family inet6 { filter V6-F { term t0 { then discard; } } } } `

const bracedTwin14435 = filterDefs14435 + `interfaces {
    ge-0/0/0 {
        unit 0 {
            point-to-point;
            family inet {
                address 10.0.0.1/24;
                filter {
                    input DISCARD-BAD;
                    output OUT-F;
                }
            }
        }
    }
}`

const packedP2P14435 = filterDefs14435 + `interfaces {
    ge-0/0/0 {
        unit 0 point-to-point family inet {
            address 10.0.0.1/24;
            filter {
                input DISCARD-BAD;
                output OUT-F;
            }
        }
    }
}`

func TestPackedUnitPointToPointFirstFamily14435(t *testing.T) {
	braced := unit14435(t, bracedTwin14435, "ge-0/0/0", 0)
	packed := unit14435(t, packedP2P14435, "ge-0/0/0", 0)
	if !packed.PointToPoint {
		t.Errorf("packed: PointToPoint=false, want true")
	}
	if !packed.FamilyInet {
		t.Errorf("packed: FamilyInet=false, want true (braced=%v)", braced.FamilyInet)
	}
	if len(packed.Addresses) != 1 || packed.Addresses[0] != "10.0.0.1/24" {
		t.Errorf("packed: Addresses=%v, want [10.0.0.1/24] (braced=%v)", packed.Addresses, braced.Addresses)
	}
	if packed.FilterInputV4 != "DISCARD-BAD" {
		t.Errorf("packed: FilterInputV4=%q, want DISCARD-BAD", packed.FilterInputV4)
	}
	if packed.FilterOutputV4 != "OUT-F" {
		t.Errorf("packed: FilterOutputV4=%q, want OUT-F", packed.FilterOutputV4)
	}
}

func TestPackedUnitTunnelFirstFamily14435(t *testing.T) {
	// tunnel-first spelling from the issue: family rides after `tunnel`.
	braced := filterDefs14435 + `interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel {
                source 192.0.2.1;
                destination 198.51.100.2;
            }
            family inet {
                address 10.1.0.1/30;
                filter {
                    input DISCARD-BAD;
                }
            }
        }
    }
}`
	packed := filterDefs14435 + `interfaces {
    gr-0/0/0 {
        unit 0 tunnel source 192.0.2.1 destination 198.51.100.2 family inet {
            address 10.1.0.1/30;
            filter {
                input DISCARD-BAD;
            }
        }
    }
}`
	bu := unit14435(t, braced, "gr-0/0/0", 0)
	pu := unit14435(t, packed, "gr-0/0/0", 0)
	if pu.Tunnel == nil {
		t.Fatalf("packed tunnel-first: Tunnel=nil, want non-nil (braced tunnel=%+v)", bu.Tunnel)
	}
	if pu.Tunnel.Source != "192.0.2.1" || pu.Tunnel.Destination != "198.51.100.2" {
		t.Errorf("packed tunnel=%+v, want source 192.0.2.1 dest 198.51.100.2", pu.Tunnel)
	}
	if !pu.FamilyInet {
		t.Errorf("packed tunnel-first: FamilyInet=false, want true")
	}
	if len(pu.Addresses) != 1 || pu.Addresses[0] != "10.1.0.1/30" {
		t.Errorf("packed tunnel-first: Addresses=%v, want [10.1.0.1/30]", pu.Addresses)
	}
	if pu.FilterInputV4 != "DISCARD-BAD" {
		t.Errorf("packed tunnel-first: FilterInputV4=%q, want DISCARD-BAD", pu.FilterInputV4)
	}
}

func TestPackedUnitFamilyControls14435(t *testing.T) {
	// Braced twin unchanged / valid.
	u := unit14435(t, bracedTwin14435, "ge-0/0/0", 0)
	if !u.PointToPoint || !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" {
		t.Errorf("braced control broken: %+v", u)
	}
	// Bare leaf: loses only flag today per spec — must remain unit present,
	// no family invented.
	bare := unit14435(t, filterDefs14435+`interfaces { ge-0/0/0 { unit 0 point-to-point; } }`, "ge-0/0/0", 0)
	if bare.FamilyInet || len(bare.Addresses) != 0 || bare.FilterInputV4 != "" {
		t.Errorf("bare leaf must have no family: %+v", bare)
	}
	// Single packed vlan-id + family (already-admitted head family) control:
	// family-first packed form must also work via same expansion.
	fam := unit14435(t, filterDefs14435+`interfaces { ge-0/0/0 { unit 0 family inet { address 10.2.0.1/24; filter { input DISCARD-BAD; } } } }`, "ge-0/0/0", 0)
	if !fam.FamilyInet || fam.FilterInputV4 != "DISCARD-BAD" || len(fam.Addresses) != 1 {
		t.Errorf("family-first packed control broken: %+v", fam)
	}
	// inet6 packed p2p variant.
	v6 := unit14435(t, filterDefs14435+`interfaces { ge-0/0/0 { unit 0 point-to-point family inet6 { address 2001:db8::1/64; filter { input V6-F; } } } }`, "ge-0/0/0", 0)
	if !v6.FamilyInet6 || v6.FilterInputV6 != "V6-F" || len(v6.Addresses) != 1 {
		t.Errorf("packed inet6 broken: %+v", v6)
	}
}

// TestPackedUnitFilterFirstFamilyRejects14629 is the #14629 regression cell:
// the #14435 gate exemption must require `filter` inside/after the family
// segment packedBody expands, not anywhere in the unit Keys tail.
//
// RED (pre-fix): `unit 0 filter input DISCARD-BAD family inet { ... }`
// strict-compiled to an empty Unit{Number:0} (no addresses, no filter, no
// family) because the old helper returned true on the trailing
// `family inet` alone while packedBody dropped the leading filter (and,
// with it, the whole family body). Lenient also compiled empty with no
// warning — accepted-but-dropped fail-open on both paths.
//
// GREEN (this fix): the same spelling is strict-rejected by the #12090
// gate (naming `filter input`) and lenient-warned with #12090. The
// genuinely consumed spellings (family-first, point-to-point-first,
// tunnel-first, family-packed `family inet filter input …`) must stay
// accepted with NO #12090 diagnostic and their hooks populated.
func TestPackedUnitFilterFirstFamilyRejects14629(t *testing.T) {
	rejects := []struct {
		name string
		src  string
	}{
		{"inet braced body", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 filter input DISCARD-BAD family inet { address 10.0.0.1/24; } } }`},
		{"inet6 braced body", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 filter input V6-F family inet6 { address 2001:db8::1/64; } } }`},
		{"inet output direction", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 filter output OUT-F family inet { address 10.0.0.1/24; } } }`},
		{"inet packed family body", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 filter input DISCARD-BAD family inet address 10.0.0.1/24; } }`},
		{"simple-filter first", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 simple-filter input DISCARD-BAD family inet { address 10.0.0.1/24; } } }`},
		{"filter first then braced family filter", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 filter input X family inet { address 10.0.0.1/24; filter { input DISCARD-BAD; } } } }`},
	}
	for _, tc := range rejects {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("filter-first spelling strict-compiled clean; want #12090 rejection (pre-fix: empty Unit{Number:0})")
			}
			if !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("strict error %q must name the #12090 gate", err)
			}
			if !strings.Contains(err.Error(), "filter") {
				t.Fatalf("strict error %q must name the filter binding", err)
			}
			// Lenient must warn (#12090), not silently accept.
			tree2, perrs2 := NewParser(tc.src).Parse()
			if len(perrs2) > 0 {
				t.Fatalf("parse lenient: %v", perrs2)
			}
			cfg, err := CompileConfigLenient(tree2)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#12090") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient warnings %q must contain a #12090 diagnostic for the filter-first spelling", cfg.Warnings)
			}
		})
	}

	accepts := []struct {
		name   string
		src    string
		ifName string
		check  func(t *testing.T, u *InterfaceUnit)
	}{
		{"family-first braced filter", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 family inet { address 10.0.0.1/24; filter { input DISCARD-BAD; } } } }`, "ge-0/0/0", func(t *testing.T, u *InterfaceUnit) {
			if !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || len(u.Addresses) != 1 {
				t.Errorf("family-first control broken: %+v", u)
			}
		}},
		{"point-to-point-first", packedP2P14435, "ge-0/0/0", func(t *testing.T, u *InterfaceUnit) {
			if !u.PointToPoint || !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || u.FilterOutputV4 != "OUT-F" || len(u.Addresses) != 1 {
				t.Errorf("p2p-first control broken: %+v", u)
			}
		}},
		{"family-packed filter", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 family inet filter input DISCARD-BAD address 10.0.0.1/24; } }`, "ge-0/0/0", func(t *testing.T, u *InterfaceUnit) {
			if !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || len(u.Addresses) != 1 {
				t.Errorf("family-packed control broken: %+v", u)
			}
		}},
		{"description value family then real family", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 description family family inet { address 10.0.0.1/24; filter { input DISCARD-BAD; } } } }`, "ge-0/0/0", func(t *testing.T, u *InterfaceUnit) {
			if u.Description != "family" || !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || len(u.Addresses) != 1 {
				t.Errorf("description-value control broken: %+v", u)
			}
		}},
		{"description value spells filter", filterDefs14435 + `interfaces { ge-0/0/0 { unit 0 description filter family inet { address 10.0.0.1/24; filter { input DISCARD-BAD; } } } }`, "ge-0/0/0", func(t *testing.T, u *InterfaceUnit) {
			// `filter` here is description's scalar VALUE (args:1), consumed
			// by the compiler — not a unit-level filter keyword. The gate
			// must consume it by arity, not mistake it for a filter hit
			// that precedes (and therefore blocks) the family segment.
			if u.Description != "filter" || !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || len(u.Addresses) != 1 {
				t.Errorf("description-filter-value control broken: %+v", u)
			}
		}},
	}
	for _, tc := range accepts {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("consumed spelling must stay accepted, got %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#12090") {
					t.Fatalf("consumed spelling drew a #12090 diagnostic: %q (all warnings %q)", w, cfg.Warnings)
				}
			}
			ifc := cfg.Interfaces.Interfaces[tc.ifName]
			if ifc == nil {
				t.Fatalf("interface %s missing", tc.ifName)
			}
			u := ifc.Units[0]
			if u == nil {
				t.Fatalf("unit 0 missing on %s", tc.ifName)
			}
			tc.check(t, u)
		})
	}

	// Tunnel-first consumed spelling (gr- interface) stays accepted.
	t.Run("accept/tunnel-first", func(t *testing.T) {
		src := filterDefs14435 + `interfaces { gr-0/0/0 { unit 0 tunnel source 192.0.2.1 destination 198.51.100.2 family inet { address 10.1.0.1/30; filter { input DISCARD-BAD; } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("tunnel-first must stay accepted, got %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#12090") {
				t.Fatalf("tunnel-first drew #12090: %q", w)
			}
		}
		u := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[0]
		if u == nil || u.Tunnel == nil || !u.FamilyInet || u.FilterInputV4 != "DISCARD-BAD" || len(u.Addresses) != 1 {
			t.Fatalf("tunnel-first control broken: %+v", u)
		}
	})
}
