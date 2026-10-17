package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14574 control at the networkd writer: with `vlan-tagging` (the shape
// the strict gate now requires alongside a positive vlan-id), the tagged
// unit's address lands ONLY on the VLAN sub-interface ge-0-0-1.100 and
// the parent carries no addresses. This is the "control above unchanged"
// half of the issue's acceptance criterion; the untagged half can no
// longer reach this writer through strict compile (rejected in
// pkg/config, TestVlanIDWithoutTaggingRejected14574).

func TestVlanTaggingControlNetworkdModel14574(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("tagged control must compile: %v", err)
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-1": {Index: 10, Name: "ge-0-0-1", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	var parent, sub bool
	for _, m := range result.ManagedInterfaces {
		switch m.Name {
		case "ge-0-0-1":
			parent = true
			if !m.IsVLANParent {
				t.Errorf("parent ge-0-0-1 IsVLANParent=false, want true")
			}
			if len(m.Addresses) != 0 {
				t.Errorf("parent ge-0-0-1 Addresses=%v, want none (address belongs on .100)", m.Addresses)
			}
		case "ge-0-0-1.100":
			sub = true
			if len(m.Addresses) != 1 || m.Addresses[0] != "10.0.1.1/24" {
				t.Errorf("ge-0-0-1.100 Addresses=%v, want [10.0.1.1/24]", m.Addresses)
			}
		}
	}
	if !parent || !sub {
		t.Fatalf("missing models parent=%v sub=%v in %+v", parent, sub, result.ManagedInterfaces)
	}
}
