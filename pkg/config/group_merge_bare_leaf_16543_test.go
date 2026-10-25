package config

import (
	"strings"
	"testing"
)

// #16543: a `<*>` group never bound to a bare named OSPF interface or
// BGP neighbor leaf, so a wildcard OSPF-MD5 / neighbor BGP-MD5 template
// left those adjacencies/sessions unauthenticated on a clean commit.
// The bare spelling (`interface ge-0/0/0.0;`, `neighbor 192.0.2.2;`)
// is the usual one for an instance that inherits everything from its
// group. The rows below pin def-bare-* == ctl-attr-wild for every
// instance, with FRR render proof for the two auth cases, plus the
// #9838 no-group / bare controls unchanged.

// ospfIface16543 compiles text strictly and returns the single OSPF interface.
func ospfIface16543(t *testing.T, text string) *OSPFInterface {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("no OSPF compiled")
	}
	var out []*OSPFInterface
	for _, a := range cfg.Protocols.OSPF.Areas {
		out = append(out, a.Interfaces...)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 OSPF interface, got %d (%v)", len(out), out)
	}
	return out[0]
}

func TestWildcardBareOSPFInterfaceTakesGroup16543(t *testing.T) {
	group := `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface <*> { authentication { md5 1 { key K; } } } } } } } } apply-groups AUTH; `
	for _, c := range []struct{ name, text string }{
		{"def-bare-wild", group + `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`},
		{"ctl-attr-wild", group + `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 10; } } } }`},
		{"ctl-braced-wild", group + `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { } } } }`},
		{"ctl-exact-bare", `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 1 { key K; } } } } } } } } apply-groups AUTH; protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			iface := ospfIface16543(t, c.text)
			if iface.AuthType != "md5" || iface.AuthKeyID != 1 || iface.AuthKey.Reveal() != "K" {
				t.Errorf("iface = auth=%q keyid=%d key=%q, want md5/1/K: bare leaf lost the wildcard OSPF-MD5 template (#16543)", iface.AuthType, iface.AuthKeyID, iface.AuthKey.Reveal())
			}
		})
	}
	// No-group control: bare leaf alone compiles with no auth (unchanged).
	iface := ospfIface16543(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`)
	if iface.AuthType != "" {
		t.Errorf("no-group bare: auth=%q, want empty (#16543 must not invent auth)", iface.AuthType)
	}
}

// bgpNeighbor16543 compiles text strictly and returns the single BGP neighbor.
func bgpNeighbor16543(t *testing.T, text string) *BGPNeighbor {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("want 1 BGP neighbor, got %+v", cfg.Protocols.BGP)
	}
	return cfg.Protocols.BGP.Neighbors[0]
}

func TestWildcardBareBGPNeighborTakesGroup16543(t *testing.T) {
	group := `groups { AUTH { protocols { bgp { group G { neighbor <*> { authentication-key K; } } } } } } apply-groups AUTH; `
	for _, c := range []struct{ name, text string }{
		{"def-bare-wild", group + `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2; } } }`},
		{"ctl-attr-wild", group + `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2 { description x; } } } }`},
		{"ctl-braced-wild", group + `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2 { } } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := bgpNeighbor16543(t, c.text)
			if n.AuthPassword.Reveal() != "K" {
				t.Errorf("neighbor pw=%q, want K: bare leaf lost the wildcard BGP-MD5 template (#16543)", n.AuthPassword.Reveal())
			}
		})
	}
	n := bgpNeighbor16543(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 192.0.2.2; } } }`)
	if n.AuthPassword.Reveal() != "" {
		t.Errorf("no-group bare: pw=%q, want empty", n.AuthPassword.Reveal())
	}
}

func TestWildcardBareInstancesTakeGroup16543(t *testing.T) {
	// RA interface: bare leaf must take the wildcard's interval.
	raText := `groups { AUTH { protocols { router-advertisement { interface <*> { max-advertisement-interval 100; } } } } } apply-groups AUTH; protocols { router-advertisement { interface ge-0/0/0.0; } }`
	tree, perrs := NewParser(raText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile RA: %v", err)
	}
	if len(cfg.Protocols.RouterAdvertisement) != 1 || cfg.Protocols.RouterAdvertisement[0].MaxAdvInterval != 100 {
		t.Errorf("RA bare leaf: got %+v, want MaxAdvInterval=100 (#16543)", cfg.Protocols.RouterAdvertisement)
	}

	// OSPFv3 interface: bare leaf must take the wildcard's cost.
	o3Text := `groups { AUTH { protocols { ospf3 { area 0.0.0.0 { interface <*> { cost 10; } } } } } } apply-groups AUTH; protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0; } } }`
	tree, perrs = NewParser(o3Text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile OSPFv3: %v", err)
	}
	if cfg.Protocols.OSPFv3 == nil || len(cfg.Protocols.OSPFv3.Areas) != 1 || len(cfg.Protocols.OSPFv3.Areas[0].Interfaces) != 1 || cfg.Protocols.OSPFv3.Areas[0].Interfaces[0].Cost != 10 {
		t.Errorf("OSPFv3 bare leaf: got %+v, want Cost=10 (#16543)", cfg.Protocols.OSPFv3)
	}

	// IS-IS interface: bare leaf must take the wildcard's metric.
	isisText := `groups { AUTH { protocols { isis { interface <*> { metric 10; } } } } } apply-groups AUTH; protocols { isis { interface ge-0/0/0.0; } }`
	tree, perrs = NewParser(isisText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile IS-IS: %v", err)
	}
	if cfg.Protocols.ISIS == nil || len(cfg.Protocols.ISIS.Interfaces) != 1 || cfg.Protocols.ISIS.Interfaces[0].Metric != 10 {
		t.Errorf("IS-IS bare leaf: got %+v, want Metric=10 (#16543)", cfg.Protocols.ISIS)
	}

	// LLDP interface: bare leaf must take the wildcard's disable.
	lldpText := `groups { AUTH { protocols { lldp { interface <*> { disable; } } } } } apply-groups AUTH; protocols { lldp { interface ge-0/0/0.0; } }`
	tree, perrs = NewParser(lldpText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile LLDP: %v", err)
	}
	if cfg.Protocols.LLDP == nil || len(cfg.Protocols.LLDP.Interfaces) != 1 || !cfg.Protocols.LLDP.Interfaces[0].Disable {
		t.Errorf("LLDP bare leaf: got %+v, want Disabled=true (#16543)", cfg.Protocols.LLDP)
	}
}

// SetPath (flat `set`) spelling of the same defect: the bare OSPF
// interface / BGP neighbor stored as a 2-key leaf must also bind.
func TestWildcardBareFlatSetTakesGroup16543(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set groups AUTH protocols ospf area 0.0.0.0 interface <*> authentication md5 1 key K",
		"set apply-groups AUTH",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var iface *OSPFInterface
	for _, a := range cfg.Protocols.OSPF.Areas {
		for _, i := range a.Interfaces {
			iface = i
		}
	}
	if iface == nil || iface.AuthType != "md5" || iface.AuthKey.Reveal() != "K" {
		t.Errorf("flat-set bare OSPF: got %+v, want md5/K (#16543)", iface)
	}
}

// #9838 pins unchanged: a bare top-level interface / routing-instance
// leaf must NOT be created by a wildcard group.
func TestWildcardBare9838SlotsUnchanged16543(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"interface", `groups { G { interfaces { <*> { description fromgroup; } } } } apply-groups G; interfaces { ge-0/0/0; }`, "interfaces ge-0/0/0"},
		{"routing-instance", `groups { G { routing-instances { <*> { instance-type virtual-router; } } } } apply-groups G; routing-instances { ri1; }`, "routing-instances ri1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want #9838 refusal naming %q, got %v (#16543 must keep the exclusion)", c.want, err)
			}
		})
	}
}

// Expanded-tree shape: the bare leaf becomes a container holding the
// group's statement, so every reader of the expanded tree sees it.
func TestWildcardBareLeafBecomesContainer16543(t *testing.T) {
	tree := expand9801(t, `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface <*> { authentication { md5 1 { key K; } } } } } } } } apply-groups AUTH; protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }`)
	var iface *Node
	for _, p := range tree.FindChildren("protocols") {
		for _, o := range p.FindChildren("ospf") {
			for _, a := range o.FindChildren("area") {
				for _, i := range a.FindChildren("interface") {
					if len(i.Keys) == 2 && i.Keys[1] == "ge-0/0/0.0" {
						iface = i
					}
				}
			}
		}
	}
	if iface == nil {
		t.Fatalf("no OSPF interface in expanded tree")
	}
	if iface.IsLeaf || iface.FindChild("authentication") == nil {
		t.Errorf("expanded iface: IsLeaf=%v children=%d, want container holding authentication (#16543)", iface.IsLeaf, len(iface.Children))
	}
}

// FRR render proof lives in pkg/frr (bare_leaf_wildcard_16543_test.go
// there drives the same fixtures through generateProtocols).
