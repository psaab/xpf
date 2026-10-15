// #13137 (D2-05): unit-0 lifelines. A chassis-cluster control/fabric role
// spelled with its unit (`control-interface em0.0`, `fabric-interface
// ge-0/0/0.0`) identifies the UNIT-0 lifeline; unit 0 of an untagged interface
// shares the parent's single kernel netdev, so the bare parent row carries the
// same traffic and must inherit the lifeline exemption — otherwise a
// `to-zone junos-host` deny is installed on the lifeline's own netdev
// (ge-0-0-0) and the #11365 device-map warning fires for the bare parent
// (em0). Fabric-options member-interfaces are themselves fabric lifelines.
// #12848's declared-name exactness must survive: dotted siblings of a declared
// lifeline (hb.2 of declared hb.1) and unrelated interfaces stay ordinary, and
// a lifeline rooted only at a non-zero unit does not exempt the parent.
//
// FAIL-ON-REVERT: reverting HostInboundLifelineSet/Interface to exact-name
// matching makes the em0/ge-0/0/0/ge-0/0/2 true-assertions and both end-to-end
// assertions below go RED.
package config

import "testing"

const lifelineUnit0Src13137 = `
chassis {
    device-map {
        em0 eth3;
    }
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "0123456789abcdef0123456789abcdef";
        control-interface em0.0;
        fabric-interface ge-0/0/0.0;
    }
}
interfaces {
    em0 {
        unit 0 {
            family inet {
                address 10.255.0.1/24;
            }
        }
    }
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.255.1.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.255.2.1/24;
            }
        }
    }
    fab0 {
        fabric-options {
            member-interfaces {
                ge-0/0/2;
            }
        }
    }
}
security {
    zones {
        security-zone mgmt {
            interfaces {
                em0;
            }
        }
        security-zone control {
            host-inbound-traffic {
                system-services {
                    all;
                }
            }
            interfaces {
                ge-0/0/0;
            }
        }
    }
    policies {
        from-zone control to-zone junos-host {
            policy deny-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}
`

func compileLifelineUnit013137(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(lifelineUnit0Src13137).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestLifelineUnit0ParentAndFabricMembers13137(t *testing.T) {

	cfg := compileLifelineUnit013137(t)
	// Declared non-zero VLAN units have distinct kernel netdevs and must not
	// inherit the unit-0 parent's exemption.
	cfg.Interfaces.Interfaces["ge-0/0/0"].Units[1] = &InterfaceUnit{Number: 1, VlanID: 1}
	cfg.Interfaces.Interfaces["ge-0/0/2"].Units[1] = &InterfaceUnit{Number: 1, VlanID: 1}
	set := HostInboundLifelineSet(cfg)
	// The unit-0 lifeline, its untagged bare parent row, and the fabric
	// member's unit-0 row are all lifelines.
	for _, name := range []string{
		"em0.0", "em0", "ge-0/0/0.0", "ge-0/0/0", "ge-0/0/2", "ge-0/0/2.0",
	} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (unit-0/fabric-member lifeline)", name)
		}
	}
	// Unrelated interfaces and declared sibling units stay ordinary.
	for _, name := range []string{"ge-0/0/1", "ge-0/0/1.0", "ge-0/0/0.1", "ge-0/0/2.1"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (not the lifeline unit)", name)
		}
	}
}

func TestLifelineUnit0EndToEnd13137(t *testing.T) {
	cfg := compileLifelineUnit013137(t)
	cfg.Chassis.DeviceMap = &DeviceMapConfig{Entries: []DeviceMapEntry{{LogicalName: "em0"}}}
	if warns := validateDeviceMapHostInboundLifelineWarnings11365(cfg); len(warns) != 0 {
		t.Errorf("validateDeviceMapHostInboundLifelineWarnings11365 = %v, want none (em0 is the em0.0 control lifeline)", warns)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	for _, prog := range proj.Programs {
		for _, nd := range prog.IngressNetdevs {
			if nd == "ge-0-0-0" {
				t.Errorf("deny program %+v installs a junos-host deny on the ge-0/0/0.0 lifeline netdev ge-0-0-0", prog)
			}
		}
		if len(prog.IngressNetdevs) != 0 || len(prog.IngressVRFScopes) != 0 {
			t.Errorf("BuildJunosHostDenyProjection = %+v, want no ingress scope for lifeline-only zone", prog)
		}
	}
}

// A lifeline rooted only at a non-zero unit must not exempt the bare parent
// (whose netdev carries other units) or unit 0.
func TestLifelineNonZeroUnitKeepsParentOrdinary13137(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{FabricInterface: "ge-0/0/0.100"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 100: {Number: 100, VlanID: 100}}},
	}
	set := HostInboundLifelineSet(cfg)
	if !HostInboundLifelineInterface("ge-0/0/0.100", set) {
		t.Errorf("HostInboundLifelineInterface(%q) = false, want true", "ge-0/0/0.100")
	}
	for _, name := range []string{"ge-0/0/0", "ge-0/0/0.0"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (non-zero-unit lifeline only)", name)
		}
	}
}
