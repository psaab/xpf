package config

import "testing"

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
