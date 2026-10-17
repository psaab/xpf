package config

import "testing"

// #14590: `dynamic hostname <fqdn>` is an IKE identity for a dynamic-IP peer,
// not a DNS-resolved dial address. Compilation must mark the gateway
// responder-only (the FQDN is kept as the expected identity), across the flat
// and block spellings, while a bare `dynamic` stays responder-only with no
// identity and an explicit remote-identity is preserved.
func TestCompilerDynamicHostnameIsResponderIdentity14590(t *testing.T) {
	const head = `security {
    ike {
        proposal ike-phase1 {
            authentication-method pre-shared-keys;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm sha-256;
            dh-group group14;
        }
        policy ike-pol {
            proposals ike-phase1;
            pre-shared-key ascii-text secret123;
        }
        gateway gw1 {
            ike-policy ike-pol;
            external-interface ge-0/0/0.0;
            `
	const tail = `
        }
    }
    ipsec {
        policy ipsec-pol {
            proposal-set standard;
        }
        vpn tun1 {
            bind-interface st0.1;
            ike {
                gateway gw1;
                ipsec-policy ipsec-pol;
            }
        }
    }
    zones {
        security-zone trust;
    }
    policies {
        from-zone trust to-zone trust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`
	forms := map[string]string{
		"flat":             "dynamic hostname branch.example.net;",
		"block-leaf-value": "dynamic { hostname branch.example.net; }",
		"nested-block":     "dynamic { hostname { branch.example.net; } }",
	}
	for name, dynamicLine := range forms {
		t.Run(name, func(t *testing.T) {
			tree, errs := NewParser(head + dynamicLine + tail).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse errors: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}
			gw := cfg.Security.IPsec.Gateways["gw1"]
			if gw == nil {
				t.Fatal("missing gateway gw1")
			}
			if gw.DynamicHostname != "branch.example.net" {
				t.Errorf("DynamicHostname = %q, want branch.example.net (identity)", gw.DynamicHostname)
			}
			if !gw.ResponderOnly {
				t.Errorf("ResponderOnly = false, want true (dynamic peer is never dialed)")
			}
		})
	}

	t.Run("set-syntax", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike policy ike-pol pre-shared-key ascii-text secret123",
			"set security ike gateway gw1 ike-policy ike-pol",
			"set security ike gateway gw1 dynamic hostname branch.example.net",
			"set security ipsec vpn tun1 ike gateway gw1",
			"set security ipsec vpn tun1 bind-interface st0.1",
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		gw := cfg.Security.IPsec.Gateways["gw1"]
		if gw == nil || gw.DynamicHostname != "branch.example.net" || !gw.ResponderOnly {
			t.Fatalf("set-syntax gateway = %+v, want DynamicHostname=branch.example.net ResponderOnly=true", gw)
		}
	})
}
