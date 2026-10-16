package config

import "testing"

// #14192 (D10-01): a BARE control/fabric lifeline base (control-interface
// ge-0/0/0) must not cover DECLARED transit VLAN units on that physical
// interface. Declared units have distinct kernel netdevs (<parent>.<vlan>),
// so exempting ge-0/0/0.100 would remove a zone-assigned transit unit from
// junos-host default-deny. Only unit 0 — which shares the parent netdev —
// and undeclared numeric unit spellings (pinned #13137, e.g. ge-0/0/0.1
// backed only by unit 0, and #12848 hb.2) may inherit a bare lifeline.
// NOT changed: fxp0.1+ was verified not a failing control on master (an
// undeclared fxp0.100 is exempt today and stays exempt).
//
// FAIL-ON-REVERT: reverting the declared-unit registration makes the
// ge-0/0/0.100 matcher assertion and the BuildJunosHostDenyProjection
// ingress-scope assertion below go RED.

const lifelineBareTransit14192Src = `
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "0123456789abcdef0123456789abcdef";
        control-interface ge-0/0/0;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.255.1.1/24;
            }
        }
        unit 100 {
            vlan-id 100;
            family inet {
                address 203.0.113.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 203.0.113.129/24;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                ge-0/0/0.100;
                ge-0/0/1.0;
            }
        }
    }
    policies {
        from-zone untrust to-zone junos-host {
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

func compileLifelineBareTransit14192(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(lifelineBareTransit14192Src).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestLifelineBareParentDeclaredVLANUnit14192(t *testing.T) {
	cfg := compileLifelineBareTransit14192(t)
	set := HostInboundLifelineSet(cfg)

	// Bare parent and unit 0 share a netdev and stay lifelines.
	// (ge-0/0/0.00 is covered by #12848-style unit-0 strip semantics, not
	// asserted here: its last-dot remainder is "0" and the registered
	// ge-0/0/0.0 key carries the unit-0 lifeline prior.)
	for _, name := range []string{"ge-0/0/0", "ge-0/0/0.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (bare unit-0 lifeline)", name)
		}
	}
	// Declared transit VLAN unit is ordinary. Explicit ".0" control:
	// ge-0/0/0.100 has no ".0" suffix, so it stays ordinary. Aliases such as
	// ge-0/0/0.0100 resolve through the same registered unit, not the matcher.
	for _, name := range []string{"ge-0/0/0.100"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (declared transit VLAN unit)", name)
		}
	}
	// Standalone transit parent controls stay ordinary.
	for _, name := range []string{"ge-0/0/1", "ge-0/0/1.0", "ge-0/0/1.100"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (standalone transit control)", name)
		}
	}

	// End-to-end: the declared VLAN unit must survive non-lifeline refs and
	// appear as an ingress netdev in the host-deny projection.
	zone := cfg.Security.Zones["untrust"]
	refs := junosHostNonLifelineRefs(zone, set)
	found := false
	for _, ref := range refs {
		if ref == "ge-0/0/0.100" {
			found = true
		}
	}
	if !found {
		t.Errorf("junosHostNonLifelineRefs = %v, want ge-0/0/0.100 present (declared VLAN unit is not a lifeline)", refs)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	foundNetdev := false
	for _, prog := range proj.Programs {
		for _, nd := range prog.IngressNetdevs {
			if nd == "ge-0-0-0.100" {
				foundNetdev = true
			}
		}
	}
	// The parent netdev ge-0-0-0 remains as a conservative parent-superset
	// candidate for the VLAN unit (pinned coverage doctrine: a VLAN subunit's
	// frames may ride the physical parent, #12839) — that is not a lifeline
	// deny on unit 0, it is the unit 100 deny scope widened to its carrier.
	if !foundNetdev {
		t.Errorf("BuildJunosHostDenyProjection programs = %+v, want ingress netdev ge-0-0-0.100 (declared VLAN unit deny scope)", proj.Programs)
	}
}
