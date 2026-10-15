package config

import "testing"

// #13144 (D2-13): a bare `st0` host-inbound override must fan down to the
// `st0.0` unit of a #7949 bind-interface-only tunnel (no `interfaces st0`
// stanza) in the STAMPED per-zone view ZoneConfig.InterfaceHostInboundEffective
// consults, exactly as ResolveInterfaceHostInbound resolves it; and the stamp
// must honour the #3720 M01 / #5489 quarantine guards ResolveInterfaceHostInbound
// applies, so a contested interface resolves to NO override in either view.

const st0BindOnlySrc13144 = `
security {
    ike {
        policy ike-pol {
            mode main;
            pre-shared-key ascii-text "secret";
        }
        gateway gw1 {
            ike-policy ike-pol;
            address 198.51.100.2;
            external-interface ge-0/0/0.0;
        }
    }
    ipsec {
        proposal esp-aes128-sha256 {
            authentication-algorithm hmac-sha-256-128;
            encryption-algorithm aes-128-cbc;
        }
        policy ipsec-pol {
            proposals esp-aes128-sha256;
        }
        vpn vpn1 {
            bind-interface st0;
            ike {
                gateway gw1;
                ipsec-policy ipsec-pol;
            }
        }
    }
    zones {
        security-zone vpn {
            host-inbound-traffic {
                system-services {
                    ssh;
                }
            }
            interfaces {
                st0 {
                    host-inbound-traffic {
                        system-services {
                            ping;
                        }
                    }
                }
                st0.0;
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 198.51.100.1/24;
            }
        }
    }
}
`

func TestBareSt0OverrideFansDownToBindOnlyUnit13144(t *testing.T) {
	p := NewParser(st0BindOnlySrc13144)
	tree, parseErrs := p.Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse config: %v", parseErrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if hib := ResolveInterfaceHostInbound(cfg)["st0.0"]; hib == nil ||
		!eqTokens(hib.SystemServices, []string{"ping"}) {
		t.Fatalf("runtime view: st0.0 override = %v, want [ping]", hib)
	}
	zone := cfg.Security.Zones["vpn"]
	svc, _, overridden := zone.InterfaceHostInboundEffective("st0.0")
	if !overridden || !eqTokens(svc, []string{"ping"}) {
		t.Fatalf("stamped view: st0.0 effective = %v overridden=%v, want [ping] true "+
			"(bare st0 override must fan down to the bind-interface-only unit)", svc, overridden)
	}
}

func TestContestedUnitOverrideAbsentFromStampedView13144(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone alpha host-inbound-traffic system-services ssh",
		"set security zones security-zone alpha interfaces ge-0/0/0.0",
		"set security zones security-zone alpha interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
		"set security zones security-zone beta host-inbound-traffic system-services ssh",
		"set security zones security-zone beta interfaces ge-0/0/0.0",
		"set security zones security-zone beta interfaces ge-0/0/0.0 host-inbound-traffic system-services telnet",
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if _, contested := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !contested {
		t.Fatal("fixture: ge-0/0/0.0 must be contested across alpha and beta")
	}
	if hib := ResolveInterfaceHostInbound(cfg)["ge-0/0/0.0"]; hib != nil {
		t.Fatalf("runtime view: contested ge-0/0/0.0 override = %v, want absent", hib.SystemServices)
	}
	for _, name := range []string{"alpha", "beta"} {
		svc, _, overridden := cfg.Security.Zones[name].InterfaceHostInboundEffective("ge-0/0/0.0")
		if overridden || !eqTokens(svc, []string{"ssh"}) {
			t.Fatalf("stamped view (%s): contested ge-0/0/0.0 effective = %v overridden=%v, "+
				"want zone-level [ssh] false (views must agree)", name, svc, overridden)
		}
	}
}
