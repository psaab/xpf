package config

import "testing"

// #13133 (D2-01): junos-host projection must refuse mixed direct+term
// applications after application-set expansion synthesizes term members, and
// reduce valid named IP protocols to their IANA numbers.
func TestJunosHostResolveApplications13133(t *testing.T) {
	t.Run("mixed direct+term via set expansion is unrepresentable", func(t *testing.T) {
		tree, parseErrs := NewParser(`applications {
    application mixed-app {
        protocol tcp;
        destination-port 22;
        term t1 protocol tcp destination-port 8080;
    }
}`).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse: %v", parseErrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		if len(cfg.Applications.MixedDirectTermApps) == 0 {
			t.Fatalf("expected MixedDirectTermApps populated, got %+v", cfg.Applications)
		}
		if _, _, ok := junosHostResolveApplications(cfg, []string{"mixed-app"}); ok {
			t.Fatal("mixed-app must be unrepresentable (direct match body dropped by expansion)")
		}
		cfg.Applications.ApplicationSets["wrap-mixed"] = &ApplicationSet{Name: "wrap-mixed", Applications: []string{"mixed-app"}}
		if _, _, ok := junosHostResolveApplications(cfg, []string{"wrap-mixed"}); ok {
			t.Fatal("mixed-app nested in application-set must be unrepresentable")
		}
	})

	t.Run("named IP protocols reduce to IANA numbers", func(t *testing.T) {
		cases := map[string]uint8{
			"gre": 47, "ipip": 4, "ospf": 89, "igmp": 2, "pim": 103,
			"sctp": 132, "vrrp": 112, "egp": 8, "ipv6": 41,
		}
		for proto, want := range cases {
			cfg := &Config{}
			cfg.Applications.Applications = map[string]*Application{
				"app": {Name: "app", Protocol: proto},
			}
			l4, _, ok := junosHostResolveApplications(cfg, []string{"app"})
			if !ok || len(l4) != 1 || l4[0].Proto != want {
				t.Errorf("protocol %s: got ok=%v l4=%+v want proto %d", proto, ok, l4, want)
			}
		}
		for _, proto := range []string{"ah", "esp"} {
			cfg := &Config{}
			cfg.Applications.Applications = map[string]*Application{
				"app": {Name: "app", Protocol: proto},
			}
			if _, _, ok := junosHostResolveApplications(cfg, []string{"app"}); ok {
				t.Errorf("protocol %s is owned by exempt tuple path and must remain unrepresentable", proto)
			}
		}
	})

	t.Run("predefined junos-gre does not withdraw sibling deny", func(t *testing.T) {
		tree, parseErrs := NewParser(`interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            host-inbound-traffic {
                system-services { all; }
            }
            interfaces { ge-0/0/0.0; }
        }
    }
    policies {
        from-zone untrust to-zone junos-host {
            policy deny-gre {
                match { source-address any; destination-address any; application junos-gre; }
                then { deny; }
            }
            policy deny-ssh {
                match { source-address any; destination-address any; application junos-ssh; }
                then { deny; }
            }
        }
    }
}`).Parse()
		if len(parseErrs) != 0 {
			t.Fatalf("parse: %v", parseErrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		proj := BuildJunosHostDenyProjection(cfg)
		if len(proj.Programs) != 1 || !proj.Programs[0].Representable {
			t.Fatalf("junos-gre must not withdraw zone program: %+v", proj.Programs)
		}
		foundGRE, foundSSH := false, false
		for _, r := range proj.Programs[0].RulesV4 {
			for _, l4 := range r.L4 {
				foundGRE = foundGRE || l4.Proto == 47
				foundSSH = foundSSH || l4.Proto == 6
			}
		}
		if !foundGRE || !foundSSH {
			t.Fatalf("expected GRE(47) and SSH(6) rules, got %+v", proj.Programs[0].RulesV4)
		}
	})
}
