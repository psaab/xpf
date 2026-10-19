package config

import (
	"strings"
	"testing"
)

// #15136 (A89-04): OSPFv3 interface auth spellings and OSPFv2 virtual-link
// auth are open-world drops. The compiler has no case for them, FRR renders
// no auth, and the adjacency forms unauthenticated while the config reads
// as protected. Modelled ONLY so they are REFUSED, in the #8443/#14402
// shape.

func ospf3AuthTreeHier15136(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 { ` + inner + ` } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

func ospf3AuthTreeSet15136(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	line := "set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0 " + tail
	path, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	tree.SetPath(path)
	return tree
}

func check15136(t *testing.T, tree *ConfigTree, wantErr string) {
	t.Helper()
	err := SchemaValidate(tree, nil)
	if wantErr == "" {
		if err != nil {
			t.Fatalf("must commit, got: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("must be rejected, but SchemaValidate accepted it")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("rejected for wrong reason want %q got %v", wantErr, err)
	}
	// Credential values must never leak. An ipsec-sa NAME is not a
	// credential (quoted by the typed-leaf wrapper like any value).
	for _, secret := range []string{"SEKRIT", "secret1"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks secret %q: %v", secret, err)
		}
	}
}

func TestOSPFv3InterfaceAuthRefused15136(t *testing.T) {
	rows := []struct {
		name    string
		hier    string
		set     string
		wantErr string
	}{
		{name: "ipsec-sa refused", hier: `ipsec-sa sa-secret;`, set: `ipsec-sa sa-secret`, wantErr: "ipsec-sa"},
		{name: "authentication block refused", hier: `authentication { md5 1 { key "SEKRIT"; } }`, set: `authentication md5 1 key "SEKRIT"`, wantErr: "authentication"},
		{name: "authentication-key refused", hier: `authentication-key secret1;`, set: `authentication-key secret1`, wantErr: "authentication-key"},
		{name: "authentication-type refused", hier: `authentication-type md5;`, set: `authentication-type md5`, wantErr: "authentication-type"},
		{name: "keychain refused", hier: `keychain kc1;`, set: `keychain kc1`, wantErr: "keychain"},
		// Controls: legitimate OSPFv3 interface leaves still commit.
		{name: "hello-interval control", hier: `hello-interval 5;`, set: `hello-interval 5`},
		{name: "cost control", hier: `cost 10;`, set: `cost 10`},
		{name: "passive control", hier: `passive;`, set: `passive`},
		{name: "bfd control", hier: `bfd-liveness-detection { minimum-interval 300; multiplier 3; }`, set: `bfd-liveness-detection minimum-interval 300`},
		// Scope pin: interface world stays open (same as #8443).
		{name: "frobnicate stays open", hier: `frobnicate 7;`, set: `frobnicate 7`},
	}
	for _, row := range rows {
		t.Run(row.name+" [hier]", func(t *testing.T) { check15136(t, ospf3AuthTreeHier15136(t, row.hier), row.wantErr) })
		t.Run(row.name+" [set]", func(t *testing.T) { check15136(t, ospf3AuthTreeSet15136(t, row.set), row.wantErr) })
	}
}

func TestOSPFv3AuthRoutingInstance15136(t *testing.T) {
	for _, inner := range []string{
		`ipsec-sa sa-secret;`,
		`authentication { md5 1 { key "SEKRIT"; } }`,
		`authentication-key secret1;`,
		`authentication-type md5;`,
		`keychain kc1;`,
	} {
		src := `routing-instances { VRF-A { protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 { ` + inner + ` } } } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("RI ospf3 %q must be refused", inner)
		}
	}
	// Control: RI ospf3 hello-interval commits.
	src := `routing-instances { VRF-A { protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 { hello-interval 5; } } } } } }`
	tree, _ := NewParser(src).Parse()
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("RI ospf3 control must commit: %v", err)
	}
}

func vlTreeHier15136(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `protocols { ospf { area 0.0.0.1 { virtual-link 10.0.0.2 { ` + inner + ` } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

func vlTreeSet15136(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	line := "set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 " + tail
	path, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	tree.SetPath(path)
	return tree
}

func TestOSPFVirtualLinkAuthRefused15136(t *testing.T) {
	rows := []struct {
		name    string
		hier    string
		set     string
		wantErr string
	}{
		{name: "authentication block refused", hier: `authentication { md5 1 { key "SEKRIT"; } }`, set: `authentication md5 1 key "SEKRIT"`, wantErr: "authentication"},
		{name: "authentication simple refused", hier: `authentication { simple-password "SEKRIT"; }`, set: `authentication simple-password "SEKRIT"`, wantErr: "authentication"},
		{name: "authentication-key refused", hier: `authentication-key secret1;`, set: `authentication-key secret1`, wantErr: "authentication-key"},
		{name: "authentication-type refused", hier: `authentication-type md5;`, set: `authentication-type md5`, wantErr: "authentication-type"},
		{name: "ipsec-sa refused", hier: `ipsec-sa sa-secret;`, set: `ipsec-sa sa-secret`, wantErr: "ipsec-sa"},
		{name: "keychain refused", hier: `keychain kc1;`, set: `keychain kc1`, wantErr: "keychain"},
		// Controls.
		{name: "transit-area control", hier: `transit-area 0.0.0.1;`, set: `transit-area 0.0.0.1`},
		{name: "bare virtual-link control", hier: ``, set: ``},
		{name: "frobnicate stays open", hier: `frobnicate 7;`, set: `frobnicate 7`},
	}
	for _, row := range rows {
		t.Run(row.name+" [hier]", func(t *testing.T) { check15136(t, vlTreeHier15136(t, row.hier), row.wantErr) })
		if row.set != "" || row.wantErr == "" {
			t.Run(row.name+" [set]", func(t *testing.T) {
				if row.set == "" {
					// bare VL via set line without tail
					tree := &ConfigTree{}
					path, err := ParseSetCommand("set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2")
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					tree.SetPath(path)
					check15136(t, tree, row.wantErr)
					return
				}
				check15136(t, vlTreeSet15136(t, row.set), row.wantErr)
			})
		}
	}
}

func TestOSPFVirtualLinkAuthRoutingInstance15136(t *testing.T) {
	for _, inner := range []string{
		`authentication { md5 1 { key "SEKRIT"; } }`,
		`authentication-key secret1;`,
		`authentication-type md5;`,
		`ipsec-sa sa-secret;`,
		`keychain kc1;`,
	} {
		src := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.1 { virtual-link 10.0.0.2 { ` + inner + ` } } } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("RI virtual-link %q must be refused", inner)
		}
	}
	src := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.1 { virtual-link 10.0.0.2 { transit-area 0.0.0.1; } } } } } }`
	tree, _ := NewParser(src).Parse()
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("RI VL control must commit: %v", err)
	}
}

// Neighbouring legitimate behaviour: OSPFv2 interface md5 still commits
// (the issue's named control), and the compiler premise holds — the
// refused spellings compile to no auth (schema is the gate).
func TestOSPFv2InterfaceMD5Control15136(t *testing.T) {
	tree := ospfAuthTreeHier8443(t, `authentication { md5 1 { key "SEKRIT"; } }`)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("OSPFv2 md5 control must commit: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile md5: %v", err)
	}
	if cfg.Protocols.OSPF.Areas[0].Interfaces[0].AuthType != "md5" {
		t.Fatalf("md5 control AuthType=%q", cfg.Protocols.OSPF.Areas[0].Interfaces[0].AuthType)
	}
	// Premise: ospf3 auth spelling compiles with no auth field (dropped).
	tree3 := ospf3AuthTreeHier15136(t, `ipsec-sa sa-secret;`)
	cfg3, err := CompileConfig(tree3)
	if err != nil {
		t.Fatalf("compile ospf3 premise: %v", err)
	}
	if cfg3.Protocols.OSPFv3 == nil || len(cfg3.Protocols.OSPFv3.Areas) == 0 {
		t.Fatalf("premise: no ospfv3 compiled: %+v", cfg3.Protocols)
	}
	// Premise: virtual-link auth spelling compiles to a VL with no auth.
	treeVL := vlTreeHier15136(t, `authentication { md5 1 { key "SEKRIT"; } }`)
	cfgVL, err := CompileConfig(treeVL)
	if err != nil {
		t.Fatalf("compile VL premise: %v", err)
	}
	if len(cfgVL.Protocols.OSPF.Areas[0].VirtualLinks) != 1 {
		t.Fatalf("premise: VL missing: %+v", cfgVL.Protocols.OSPF)
	}
}
