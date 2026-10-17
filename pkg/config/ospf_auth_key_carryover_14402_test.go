package config

import (
	"strings"
	"testing"
)

// #14402: `authentication-key` carried over from RIP/IS-IS/BGP under an OSPF
// interface is silently dropped; adjacency forms unauthenticated.

func ospfAuthKeyTreeHier14402(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + inner + ` } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

func ospfAuthKeyTreeSet14402(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	line := "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 " + tail
	path, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	tree.SetPath(path)
	return tree
}

func TestOSPFAuthKeyCarryoverRefused14402(t *testing.T) {
	rows := []struct {
		name    string
		hier    string
		set     string
		wantErr string
	}{
		{
			name:    "authentication-key carried over is refused",
			hier:    `authentication-key secret1;`,
			set:     `authentication-key secret1`,
			wantErr: "authentication-key",
		},
		{
			name: "md5 still commits",
			hier: `authentication { md5 1 { key "SEKRIT"; } }`,
			set:  `authentication md5 1 key "SEKRIT"`,
		},
		{
			name: "simple-password still commits",
			hier: `authentication { simple-password "SEKRIT"; }`,
			set:  `authentication simple-password "SEKRIT"`,
		},
		{
			name:    "authentication-type still refused",
			hier:    `authentication-type md5;`,
			set:     `authentication-type md5`,
			wantErr: "authentication-type",
		},
		{
			name: "hello-interval still commits",
			hier: `hello-interval 5;`,
			set:  `hello-interval 5`,
		},
	}
	check := func(t *testing.T, tree *ConfigTree, wantErr string) {
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
		if wantErr == "authentication-key" {
			// Must name nested grammar and must not echo secret.
			if !strings.Contains(err.Error(), "authentication {") {
				t.Fatalf("error must name nested grammar: %v", err)
			}
			if strings.Contains(err.Error(), "secret1") {
				t.Fatalf("error leaks secret: %v", err)
			}
		}
	}
	for _, row := range rows {
		t.Run(row.name+" [hier]", func(t *testing.T) { check(t, ospfAuthKeyTreeHier14402(t, row.hier), row.wantErr) })
		t.Run(row.name+" [set]", func(t *testing.T) { check(t, ospfAuthKeyTreeSet14402(t, row.set), row.wantErr) })
	}
}

func TestOSPFAuthKeyRoutingInstance14402(t *testing.T) {
	src := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication-key secret1; } } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("RI copy must refuse, got %v", err)
	}
	// Control RI md5
	src2 := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 1 { key "SEKRIT"; } } } } } } } }`
	tree2, _ := NewParser(src2).Parse()
	if err := SchemaValidate(tree2, nil); err != nil {
		t.Fatalf("RI md5 must commit: %v", err)
	}
}

func TestOSPFAuthKeyCompileAndOtherProtocols14402(t *testing.T) {
	// Controls: same leaf under rip/isis must still compile via SchemaValidate
	for _, src := range []string{
		`protocols { rip { authentication-key secret1; authentication-type md5; } }`,
		`protocols { isis { authentication-key secret1; authentication-type md5; } }`,
	} {
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %v", perrs)
		}
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("legal leaf rejected %q: %v", src, err)
		}
	}
	// Valid OSPF compiles and renders auth (via CompileConfig)
	tree := ospfAuthKeyTreeHier14402(t, `authentication { md5 1 { key "SEKRIT"; } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile md5: %v", err)
	}
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) == 0 || len(cfg.Protocols.OSPF.Areas[0].Interfaces) == 0 {
		t.Fatalf("no ospf iface: %+v", cfg.Protocols)
	}
	iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.AuthType != "md5" {
		t.Fatalf("AuthType=%q want md5", iface.AuthType)
	}
	tree2 := ospfAuthKeyTreeHier14402(t, `authentication { simple-password "SEKRIT"; }`)
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile simple: %v", err)
	}
	if cfg2.Protocols.OSPF.Areas[0].Interfaces[0].AuthType != "simple" {
		t.Fatalf("simple AuthType=%q", cfg2.Protocols.OSPF.Areas[0].Interfaces[0].AuthType)
	}
	// Buggy spelling compiles (compiler doesn't gate) but Auth empty — schema is gate
	tree3 := ospfAuthKeyTreeHier14402(t, `authentication-key secret1;`)
	cfg3, err := CompileConfig(tree3)
	if err != nil {
		t.Fatalf("compile carryover: %v", err)
	}
	if cfg3.Protocols.OSPF.Areas[0].Interfaces[0].AuthType != "" {
		t.Fatalf("premise: AuthType should be empty pre-fix")
	}
	// Interface world stays open
	tree4 := ospfAuthKeyTreeHier14402(t, `frobnicate 7;`)
	if err := SchemaValidate(tree4, nil); err != nil {
		t.Fatalf("interface world must stay open: %v", err)
	}
}
