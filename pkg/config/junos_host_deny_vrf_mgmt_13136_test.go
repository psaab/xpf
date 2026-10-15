package config

import (
	"slices"
	"testing"
)

// #13136 (D2-04): junosHostVRFMasterNetdevs never mapped management-class
// interfaces to vrf-mgmt even though junosHostVRFEnslavedNetdevs marks them
// enslaved, so BuildJunosHostDenyProjection emitted dead iifname "em0" rules
// (at LOCAL_IN the packet's iifname is vrf-mgmt, sdifname is em0) with no
// VRF scope and Representable=true. It also kept master mappings for
// #11060-quarantined tunnel devices, and HostInboundDHCPVRFEnslavedNetdevs
// omitted management VLAN subinterfaces.

const mgmtZoneSrc13136 = `
interfaces {
    em0 {
        vlan-tagging;
        unit 0 {
            family inet {
                address 10.10.0.1/24;
            }
        }
        unit 100 {
            vlan-id 100;
            family inet {
                address 10.10.100.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone mgmt {
            host-inbound-traffic {
                system-services {
                    ssh;
                }
            }
            interfaces {
                em0.0;
                em0.100;
            }
        }
    }
    policies {
        from-zone mgmt to-zone junos-host {
            policy deny-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application junos-ssh;
                }
                then {
                    deny;
                }
            }
        }
    }
}
`

func compile13136(t *testing.T, src string) *Config {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestJunosHostMgmtInterfacesScopedToVRFMgmt13136(t *testing.T) {
	cfg := compile13136(t, mgmtZoneSrc13136)

	masters := junosHostVRFMasterNetdevs(cfg, cfg.TunnelNameMap())
	for _, nd := range []string{"em0", "em0.100"} {
		if got := masters[nd]; got != ManagementVRFDeviceName {
			t.Errorf("junosHostVRFMasterNetdevs[%q] = %q, want %q", nd, got, ManagementVRFDeviceName)
		}
	}

	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 {
		t.Fatalf("programs = %+v, want exactly one mgmt program", proj.Programs)
	}
	prog := proj.Programs[0]
	if len(prog.IngressNetdevs) != 0 {
		t.Errorf("IngressNetdevs = %v, want none (dead iifname rules on VRF-enslaved mgmt devices)", prog.IngressNetdevs)
	}
	if len(prog.IngressVRFScopes) != 1 {
		t.Fatalf("IngressVRFScopes = %+v, want one vrf-mgmt scope", prog.IngressVRFScopes)
	}
	scope := prog.IngressVRFScopes[0]
	if scope.Master != ManagementVRFDeviceName {
		t.Errorf("scope master = %q, want %q", scope.Master, ManagementVRFDeviceName)
	}
	slaves := append([]string(nil), scope.Slaves...)
	slices.Sort(slaves)
	if !slices.Equal(slaves, []string{"em0", "em0.100"}) {
		t.Errorf("scope slaves = %v, want [em0 em0.100]", slaves)
	}
	if !prog.Representable {
		t.Errorf("program should be representable via the vrf-mgmt scope: %+v", prog)
	}
}

func TestHostInboundDHCPMgmtVLANSubinterfaces13136(t *testing.T) {
	cfg := compile13136(t, mgmtZoneSrc13136)
	dhcp := HostInboundDHCPVRFEnslavedNetdevs(cfg)
	for _, nd := range []string{"em0", "em0.100"} {
		if !dhcp[nd] {
			t.Errorf("HostInboundDHCPVRFEnslavedNetdevs missing %q: %v", nd, dhcp)
		}
	}
	enslaved := HostInboundVRFEnslavedNetdevs(cfg)
	for _, nd := range []string{"em0", "em0.100"} {
		if !enslaved[nd] {
			t.Errorf("HostInboundVRFEnslavedNetdevs missing %q: %v", nd, enslaved)
		}
	}
}

func TestJunosHostVRFMasterSkipsQuarantinedTunnel13136(t *testing.T) {
	// Two routing instances claim the same GRE device via explicit tunnel
	// stanzas: the device is #11060-quarantined, so no master may be guessed.
	src := `
interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel {
                source 192.0.2.1;
                destination 192.0.2.2;
                routing-instance blue;
            }
            family inet {
                address 10.20.0.1/30;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.30.0.1/24;
            }
        }
    }
}
routing-instances {
    blue {
        instance-type virtual-router;
        interface ge-0/0/1.0;
    }
    red {
        instance-type virtual-router;
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}
`
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	// Force the quarantine evidence for the tunnel device claimed by both
	// blue (explicit stanza) and red (hand-built second claim below).
	cfg.QuarantinedRIMemberDeviceConflicts = append(
		cfg.QuarantinedRIMemberDeviceConflicts,
		RoutingInstanceMemberDeviceConflict{LinuxName: "gr-0-0-0"})

	masters := junosHostVRFMasterNetdevs(cfg, cfg.TunnelNameMap())
	if got, ok := masters["gr-0-0-0"]; ok && got != "" {
		t.Errorf("quarantined tunnel master = %q, want absent or empty (unresolved)", got)
	}
	if got := masters["ge-0-0-1"]; got != "vrf-blue" {
		t.Errorf("uncontested member master = %q, want vrf-blue", got)
	}
}
