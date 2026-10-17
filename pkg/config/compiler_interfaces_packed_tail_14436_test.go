package config

import (
	"reflect"
	"strings"
	"testing"
)

// #14436 (DR17-H7): interface-instance packed tail.
//
// `ge-0/0/0 bandwidth 1g unit 0 family inet { ... }` parses to ONE node
// Keys=[ge-0/0/0 bandwidth 1g unit 0 family inet], Children=[filter...].
// Only bandwidth was rescued, so the interface was created but no unit
// (and no filter/address) was compiled — a zoned, unfiltered base row.

const packedTail14436 = `interfaces {
    ge-0/0/0 bandwidth 1g unit 0 family inet {
        address 10.0.0.1/24;
        filter {
            input F;
        }
    }
}
firewall {
    family inet {
        filter F {
            term t {
                then discard;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
`

const bracedTwin14436 = `interfaces {
    ge-0/0/0 {
        bandwidth 1g;
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                filter {
                    input F;
                }
            }
        }
    }
}
firewall {
    family inet {
        filter F {
            term t {
                then discard;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
`

func compile14436(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := CompileConfig(hierTree(t, src))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestInterfacePackedTailBandwidthBrace14436(t *testing.T) {
	packed := compile14436(t, packedTail14436)
	braced := compile14436(t, bracedTwin14436)

	pIf := packed.Interfaces.Interfaces["ge-0/0/0"]
	if pIf == nil {
		t.Fatalf("packed form: interface ge-0/0/0 missing; interfaces=%v", packed.Interfaces.Interfaces)
	}
	bIf := braced.Interfaces.Interfaces["ge-0/0/0"]
	if bIf == nil {
		t.Fatalf("braced twin: interface ge-0/0/0 missing")
	}
	if pIf.Bandwidth != bIf.Bandwidth || pIf.Bandwidth == 0 {
		t.Errorf("bandwidth: packed=%d braced=%d, want equal non-zero", pIf.Bandwidth, bIf.Bandwidth)
	}
	if !pIf.AuthoredUnits {
		t.Errorf("packed form: AuthoredUnits=false, want true")
	}
	pUnit, ok := pIf.Units[0]
	if !ok || pUnit == nil {
		t.Fatalf("packed form: unit 0 missing; units=%v", pIf.Units)
	}
	bUnit := bIf.Units[0]
	if bUnit == nil {
		t.Fatalf("braced twin: unit 0 missing")
	}
	if !reflect.DeepEqual(pUnit.Addresses, bUnit.Addresses) || len(pUnit.Addresses) == 0 {
		t.Errorf("addresses: packed=%v braced=%v", pUnit.Addresses, bUnit.Addresses)
	}
	if pUnit.FilterInputV4 != "F" || pUnit.FilterInputV4 != bUnit.FilterInputV4 {
		t.Errorf("FilterInputV4: packed=%q braced=%q, want F", pUnit.FilterInputV4, bUnit.FilterInputV4)
	}
	if pUnit.FamilyInet != bUnit.FamilyInet {
		t.Errorf("FamilyInet: packed=%v braced=%v", pUnit.FamilyInet, bUnit.FamilyInet)
	}
}

// Interface-tail-only: interface tail packed, unit body braced.
func TestInterfacePackedTailOnly14436(t *testing.T) {
	src := `interfaces {
    ge-0/0/0 bandwidth 1g unit 0 {
        family inet {
            address 10.0.0.1/24;
            filter { input F; }
        }
    }
}
firewall { family inet { filter F { term t { then discard; } } } }
`
	cfg := compile14436(t, src)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatalf("interface missing")
	}
	u := ifc.Units[0]
	if u == nil {
		t.Fatalf("unit 0 missing; units=%v", ifc.Units)
	}
	if u.FilterInputV4 != "F" {
		t.Errorf("FilterInputV4=%q want F", u.FilterInputV4)
	}
	if len(u.Addresses) != 1 || u.Addresses[0] != "10.0.0.1/24" {
		t.Errorf("Addresses=%v", u.Addresses)
	}
	if ifc.Bandwidth == 0 {
		t.Errorf("Bandwidth=0 want 1g")
	}
}

// Packed interface-level leaves beside the unit must also survive.
func TestInterfacePackedTailLeaves14436(t *testing.T) {
	src := `interfaces {
    ge-0/0/0 mtu 9000 bandwidth 1g unit 0 family inet {
        address 10.0.0.1/24;
    }
}
`
	cfg := compile14436(t, src)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatalf("interface missing")
	}
	if ifc.MTU != 9000 {
		t.Errorf("MTU=%d want 9000", ifc.MTU)
	}
	if ifc.Units[0] == nil {
		t.Fatalf("unit 0 missing")
	}
}

// Bare unknown leaf is still skipped on strict compile (fail-closed);
// packed KNOWN leaves now compile per #14442 (supersedes the pre-#14442
// "bare-leaf skipped" wording for modelled leaves).
func TestInterfaceBareLeafStillSkipped14436(t *testing.T) {
	cfg := compile14436(t, `interfaces { ge-0/0/0 frobnicate 7; }`)
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc != nil {
		t.Errorf("unknown bare leaf: interface present %+v, want skipped", ifc)
	}
	// Modelled packed leaves compile (post-#14442 semantics).
	cfg = compile14436(t, `interfaces { ge-0/0/0 mtu 9000; }`)
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || ifc.MTU != 9000 {
		t.Errorf("packed mtu leaf: %+v, want MTU 9000", ifc)
	}
}

// Interface-tail with multiple units in one run? Braced control stays green.
func TestInterfaceBracedTwinControl14436(t *testing.T) {
	cfg := compile14436(t, bracedTwin14436)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].FilterInputV4 != "F" {
		t.Fatalf("braced control broken: %+v", ifc)
	}
}

// Token form: the family filter is packed on the Keys tail, no braces.
func TestInterfacePackedTailTokenFilter14436(t *testing.T) {
	src := `interfaces { ge-0/0/0 bandwidth 1g unit 0 family inet filter input F; }
firewall { family inet { filter F { term t { then discard; } } } }
`
	cfg := compile14436(t, src)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatalf("unit 0 missing: %+v", ifc)
	}
	if ifc.Units[0].FilterInputV4 != "F" {
		t.Errorf("FilterInputV4=%q want F", ifc.Units[0].FilterInputV4)
	}
}

// A packed mpls filter has no consumer and must still reject (#12090),
// not be widened by the packed-instance exemption.
func TestInterfacePackedTailMplsFilterStillRejects14436(t *testing.T) {
	src := `interfaces {
    ge-0/0/0 bandwidth 1g unit 0 family mpls {
        filter { input F; }
    }
}
`
	_, err := CompileConfig(hierTree(t, src))
	if err == nil || !strings.Contains(err.Error(), "#12090") {
		t.Fatalf("err=%v want #12090 rejection", err)
	}
}

// Lenient path compiles the packed form identically.
func TestInterfacePackedTailLenient14436(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree(t, packedTail14436))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].FilterInputV4 != "F" {
		t.Fatalf("lenient packed form dropped unit/filter: %+v", ifc)
	}
}

// Gate parity: unsupported stanzas packed onto the instance tail must
// reject exactly like their braced twins (#2008 H9/H10, #5879).
func TestInterfacePackedTailGateParity14436(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{
			"policer-arp",
			"interfaces {\n ge-0/0/0 bandwidth 1g unit 0 family inet { address 10.0.0.1/24; policer { arp P; } }\n}\n",
			"#2008 H9",
		},
		{
			"qinq-inner",
			"interfaces {\n ge-0/0/0 bandwidth 1g unit 0 vlan-id 10 inner-vlan-id 20 family inet { address 10.0.0.1/24; }\n}\n",
			"inner-vlan-id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(hierTree(t, tc.src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want containing %q", err, tc.want)
			}
		})
	}
	// Unit-scope mac on a packed unit tail.
	_, err := CompileConfig(hierTree(t, "interfaces { ge-0/0/0 { unit 0 mac 00:11:22:33:44:55; } }"))
	if err == nil || !strings.Contains(err.Error(), "#2008 H10") {
		t.Fatalf("unit mac err=%v want #2008 H10", err)
	}
}

// Description packed on the instance tail compiles like the braced twin.
func TestInterfacePackedTailDescription14436(t *testing.T) {
	cfg := compile14436(t, "interfaces {\n ge-0/0/0 description foo bandwidth 1g unit 0 family inet { address 10.0.0.1/24; }\n}\n")
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Description != "foo" {
		t.Fatalf("desc=%v want foo", ifc)
	}
}

// Split family form under a packed instance tail compiles identically.
func TestInterfacePackedTailSplitFamily14436(t *testing.T) {
	src := "interfaces {\n ge-0/0/0 bandwidth 1g unit 0 family { inet { address 10.0.0.1/24; filter { input F; } } }\n}\nfirewall { family inet { filter F { term t { then discard; } } } }"
	cfg := compile14436(t, src)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].FilterInputV4 != "F" {
		t.Fatalf("split family packed: %+v", ifc)
	}
}

// More gate parity: interface-level mac and vlan-map packed tails.
func TestInterfacePackedTailGateParity2_14436(t *testing.T) {
	_, err := CompileConfig(hierTree(t, "interfaces {\n ge-0/0/0 mac 00:11:22:33:44:55 bandwidth 1g unit 0 family inet { address 10.0.0.1/24; }\n}\n"))
	if err == nil || !strings.Contains(err.Error(), "#2008 H10") {
		t.Fatalf("iface mac err=%v want #2008 H10", err)
	}
	_, err = CompileConfig(hierTree(t, "interfaces {\n ge-0/0/0 bandwidth 1g unit 0 { input-vlan-map { swap; vlan-id 10; } family inet { address 10.0.0.1/24; } }\n}\n"))
	if err == nil || !strings.Contains(err.Error(), "#6178") {
		t.Fatalf("vlan-map err=%v want #6178", err)
	}
}

// Unit-tail-only composition (DR17-H6 #14435 merged): interface braced,
// unit tail packed — both fixes compose to the same unit.
func TestInterfaceUnitTailOnlyComposition14436(t *testing.T) {
	src := "interfaces { ge-0/0/0 { bandwidth 1g; unit 0 family inet { address 10.0.0.1/24; filter { input F; } } } }\nfirewall { family inet { filter F { term t { then discard; } } } }"
	cfg := compile14436(t, src)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].FilterInputV4 != "F" {
		t.Fatalf("unit-tail-only composition: %+v", ifc)
	}
}
