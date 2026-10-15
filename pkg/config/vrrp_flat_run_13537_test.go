package config

import (
	"reflect"
	"testing"
)

func vrrpGroupsOf13537(t *testing.T, cfg *Config) map[string]*VRRPGroup {
	t.Helper()
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, u := range ifc.Units {
			if len(u.VRRPGroups) > 0 {
				return u.VRRPGroups
			}
		}
	}
	t.Fatalf("no VRRP groups compiled; cfg=%+v", cfg.Interfaces)
	return nil
}

func TestVRRPFlatRun13537(t *testing.T) {
	flat := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150 virtual-address 10.9.0.100/16",
	})
	hier := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 virtual-address 10.9.0.100/16",
	})
	if err := SchemaValidate(flat, nil); err != nil {
		t.Fatalf("strict schema rejected supported flat run: %v", err)
	}
	fcfg, ferr := CompileConfig(flat)
	if ferr != nil {
		t.Fatalf("flat run rejected: %v", ferr)
	}
	hcfg, herr := CompileConfig(hier)
	if herr != nil {
		t.Fatalf("hier rejected: %v", herr)
	}
	fg, hg := vrrpGroupsOf13537(t, fcfg), vrrpGroupsOf13537(t, hcfg)
	if !reflect.DeepEqual(fg, hg) {
		t.Fatalf("flat != hier:\nflat=%+v %+v\nhier=%+v %+v", fg, fg["10.9.0.1/16_grp1"], hg, hg["10.9.0.1/16_grp1"])
	}
	g := fg["10.9.0.1/16_grp1"]
	if g == nil || g.Priority != 150 || len(g.VirtualAddresses) != 1 || g.VirtualAddresses[0] != "10.9.0.100/16" {
		t.Fatalf("bad group: %+v", g)
	}
	// Missing virtual-address still rejected
	missing := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150",
	})
	if _, err := CompileConfig(missing); err == nil {
		t.Fatalf("missing virtual-address must still reject")
	}
	unknown := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150 virtual-address 10.9.0.100/16 bogus-token 7",
	})
	if err := SchemaValidate(unknown, nil); err == nil {
		t.Fatal("strict schema accepted an unknown VRRP property in a flat run")
	}
	// IPv6 shares the same property grammar.
	v6 := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 vrrp-group 2 priority 120 virtual-address 2001:db8::100/64",
	})
	c6, e6 := CompileConfig(v6)
	if e6 != nil {
		t.Fatalf("v6 flat rejected: %v", e6)
	}
	g6 := vrrpGroupsOf13537(t, c6)["2001:db8::1/64_grp2"]
	if g6 == nil || g6.Priority != 120 || len(g6.VirtualAddresses) != 1 {
		t.Fatalf("bad v6 group: %+v groups=%v", g6, vrrpGroupsOf13537(t, c6))
	}
	// Multiple virtual addresses remain attached to their one property.
	multi := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 virtual-address 10.9.0.100/16",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 virtual-address 10.9.0.101/16",
	})
	cm, em := CompileConfig(multi)
	if em != nil {
		t.Fatalf("multi rejected: %v", em)
	}
	gm := vrrpGroupsOf13537(t, cm)["10.9.0.1/16_grp1"]
	if gm == nil || len(gm.VirtualAddresses) != 2 || gm.Priority != 150 {
		t.Fatalf("bad multi group: %+v", gm)
	}
}
