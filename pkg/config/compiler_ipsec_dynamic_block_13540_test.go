package config

import (
	"reflect"
	"testing"
)

// #13540: the block spelling `dynamic { hostname { peer.example.com; } }`
// (and `dynamic { hostname peer.example.com; }`) compiled through
// CompileConfig must produce gateway state identical to the flat
// `dynamic hostname peer.example.com;` spelling. Before the fix the block
// spellings were silently dropped in the IKE gateway path: the hostname
// child only invoked `nodeVal(c)`-equivalent logic when the FQDN was a
// second key on the hostname leaf, so a nested block left
// DynamicHostname empty and flipped the gateway to ResponderOnly.
func TestCompilerIPsecDynamicHostnameBlock13540(t *testing.T) {
	const proposals = `
        proposal ike-phase1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
            lifetime-seconds 28800;
        }
        policy ike-pol {
            mode main;
            proposals ike-phase1;
            pre-shared-key ascii-text "secret123";
        }
`
	forms := map[string]string{
		"flat-in-connector":  "dynamic hostname peer.example.com;",
		"block-leaf-value":   "dynamic { hostname peer.example.com; }",
		"block-nested-block": "dynamic { hostname { peer.example.com; } }",
	}

	// The `security ipsec` gateway compiler also handles a `dynamic`
	// hostname and previously masked the IKE-path defect by correcting the
	// shared gateway struct afterward. Isolate `security ike` here so this
	// regression actually observes the affected path.
	gateways := make(map[string]*IPsecGateway, len(forms))
	for name, dynamicLine := range forms {
		t.Run(name, func(t *testing.T) {
			input := `security {
    ike {
` + proposals + `
        gateway gw1 {
            ike-policy ike-pol;
            ` + dynamicLine + `
            version v2-only;
        }
    }
}`
			parser := NewParser(input)
			tree, errs := parser.Parse()
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
			gateways[name] = gw
			if gw.DynamicHostname != "peer.example.com" {
				t.Errorf("DynamicHostname = %q, want %q", gw.DynamicHostname, "peer.example.com")
			}
			if gw.ResponderOnly {
				t.Errorf("ResponderOnly = true, want false (explicit hostname present)")
			}
		})
	}

	// All discovered spellings must compile to identical gateway state.
	flat := gateways["flat-in-connector"]
	if flat == nil {
		t.Fatal("flat form missing")
	}
	for name, gw := range gateways {
		if name == "flat-in-connector" {
			continue
		}
		if !reflect.DeepEqual(gw, flat) {
			t.Errorf("%s gateway %+v differs from flat %+v", name, gw, flat)
		}
	}
}

// The bare `dynamic;` / empty-block responder-only behaviour must remain:
// no hostname anywhere still yields ResponderOnly.
func TestCompilerIPsecDynamicBareResponderOnly13540(t *testing.T) {
	input := `security {
    ike {
        proposal ike-phase1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
        }
        policy ike-pol {
            mode main;
            proposals ike-phase1;
            pre-shared-key ascii-text "secret123";
        }
        gateway gw1 {
            ike-policy ike-pol;
            dynamic;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
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
	if !gw.ResponderOnly {
		t.Errorf("ResponderOnly = false, want true (bare dynamic)")
	}
	if gw.DynamicHostname != "" {
		t.Errorf("DynamicHostname = %q, want empty", gw.DynamicHostname)
	}
}
